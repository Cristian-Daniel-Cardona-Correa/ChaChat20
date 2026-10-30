#!/usr/bin/env python3
"""
ChaCha20, Poly1305 y ChaCha20-Poly1305 (AEAD) en Python puro.
Sigue el RFC 8439.  Solo biblioteca estándar.

Ejecuta `python chacha20.py` para correr el autotest con los vectores
de prueba oficiales del RFC.

AVISO: es una implementación didáctica.  Python no garantiza tiempo
constante ni borrado de memoria; para producción usa una biblioteca
auditada (por ejemplo `cryptography`).
"""
import hashlib
import hmac
import os
import struct

MASK = 0xFFFFFFFF
# "expand 32-byte k" en ASCII, como 4 palabras de 32 bits (little-endian)
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
BLOCK_SIZE = 64


# --------------------------------------------------------------------------
# Núcleo de ChaCha20
# --------------------------------------------------------------------------
def rotl32(v, n):
    """Rotación a la izquierda de n bits sobre 32 bits."""
    return ((v << n) & MASK) | (v >> (32 - n))


# Los 4 pasos del quarter round: (x, y, z, rotación)
#   x += y;  z ^= x;  z <<<= rotación
_QR_STEPS = ((0, 1, 3, 16), (2, 3, 1, 12), (0, 1, 3, 8), (2, 3, 1, 7))


def quarter_round(s, a, b, c, d):
    """Quarter round sobre las posiciones a, b, c, d de la lista de estado."""
    idx = (a, b, c, d)
    for x, y, z, r in _QR_STEPS:
        ix, iy, iz = idx[x], idx[y], idx[z]
        s[ix] = (s[ix] + s[iy]) & MASK
        s[iz] = rotl32(s[iz] ^ s[ix], r)


def initial_state(key, counter, nonce):
    if len(key) != KEY_SIZE:
        raise ValueError("La clave debe tener 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("El nonce debe tener 12 bytes")
    return (
        list(CONSTANTS)
        + list(struct.unpack("<8L", key))
        + [counter & MASK]
        + list(struct.unpack("<3L", nonce))
    )


def _block_words(key, counter, nonce):
    """Devuelve (estado_inicial, estado_tras_20_rondas, salida_final)."""
    state = initial_state(key, counter, nonce)
    w = state[:]
    for _ in range(10):  # 10 "double rounds" = 20 rondas
        # Rondas de columnas
        quarter_round(w, 0, 4, 8, 12)
        quarter_round(w, 1, 5, 9, 13)
        quarter_round(w, 2, 6, 10, 14)
        quarter_round(w, 3, 7, 11, 15)
        # Rondas de diagonales
        quarter_round(w, 0, 5, 10, 15)
        quarter_round(w, 1, 6, 11, 12)
        quarter_round(w, 2, 7, 8, 13)
        quarter_round(w, 3, 4, 9, 14)
    out = [(a + b) & MASK for a, b in zip(w, state)]
    return state, w, out


def chacha20_block(key, counter, nonce):
    """Genera un bloque de 64 bytes de keystream."""
    _, _, out = _block_words(key, counter, nonce)
    return struct.pack("<16L", *out)


def chacha20_xor(key, counter, nonce, data):
    """Cifra o descifra (es la misma operación): data XOR keystream."""
    n_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if counter + n_blocks > 2**32:
        raise ValueError("Mensaje demasiado largo para este nonce")
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ks = chacha20_block(key, counter + i // BLOCK_SIZE, nonce)
        chunk = data[i:i + BLOCK_SIZE]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


# --------------------------------------------------------------------------
# Poly1305 (autenticación)
# --------------------------------------------------------------------------
def poly1305_mac(key, msg):
    if len(key) != 32:
        raise ValueError("La clave de Poly1305 debe tener 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


# --------------------------------------------------------------------------
# ChaCha20-Poly1305 (AEAD, RFC 8439 sección 2.8)
# --------------------------------------------------------------------------
def _pad16(x):
    return b"\x00" * (-len(x) % 16)


def _mac_data(aad, ct):
    return aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))


def aead_encrypt(key, nonce, plaintext, aad=b""):
    """Devuelve (cifrado, tag)."""
    otk = chacha20_block(key, 0, nonce)[:32]  # clave de un solo uso para Poly1305
    ct = chacha20_xor(key, 1, nonce, plaintext)  # el cifrado empieza en contador 1
    return ct, poly1305_mac(otk, _mac_data(aad, ct))


def aead_decrypt(key, nonce, ct, tag, aad=b""):
    """Verifica el tag y descifra.  Lanza ValueError si fue manipulado."""
    otk = chacha20_block(key, 0, nonce)[:32]
    expected = poly1305_mac(otk, _mac_data(aad, ct))
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Tag inválido: mensaje manipulado o clave incorrecta")
    return chacha20_xor(key, 1, nonce, ct)


# --------------------------------------------------------------------------
# Utilidades para el chat
# --------------------------------------------------------------------------
def derive_key(passphrase):
    """Deriva una clave de 256 bits desde una contraseña compartida."""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), b"chat-chacha20-v1", 200_000, KEY_SIZE
    )


def seal(key, plaintext):
    """nonce(12) || cifrado || tag(16).  Nonce aleatorio nuevo por mensaje."""
    nonce = os.urandom(NONCE_SIZE)
    ct, tag = aead_encrypt(key, nonce, plaintext)
    return nonce + ct + tag


def open_sealed(key, blob):
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Paquete demasiado corto")
    nonce, ct, tag = blob[:NONCE_SIZE], blob[NONCE_SIZE:-TAG_SIZE], blob[-TAG_SIZE:]
    return aead_decrypt(key, nonce, ct, tag)


# --------------------------------------------------------------------------
# Demostraciones didácticas (las usa el comando /demo y /ronda del cliente)
# --------------------------------------------------------------------------
def format_state(state):
    return "\n".join(
        "   " + "  ".join(f"{state[r * 4 + c]:08x}" for c in range(4)) for r in range(4)
    )


def demo_block(key, counter=1, nonce=None):
    nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
    state, work, out = _block_words(key, counter, nonce)
    ks = struct.pack("<16L", *out)
    return (
        f"Nonce usado : {nonce.hex()}\n"
        f"Contador    : {counter}\n\n"
        "1) Estado inicial (constantes | clave | contador+nonce):\n"
        f"{format_state(state)}\n\n"
        "2) Estado tras las 20 rondas (10 de columnas + 10 de diagonales):\n"
        f"{format_state(work)}\n\n"
        "3) Suma final (estado inicial + estado mezclado, módulo 2^32):\n"
        f"{format_state(out)}\n\n"
        f"Keystream (64 bytes, primeros 32): {ks[:32].hex()}"
    )


def explain_quarter_round(a=0x11111111, b=0x01020304, c=0x9B8D6F43, d=0x01234567):
    v = [a, b, c, d]
    names = "abcd"
    lines = [f"Entrada: a={a:08x}  b={b:08x}  c={c:08x}  d={d:08x}", ""]
    for x, y, z, r in _QR_STEPS:
        v[x] = (v[x] + v[y]) & MASK
        lines.append(f"  {names[x]} += {names[y]}        -> {names[x]} = {v[x]:08x}")
        v[z] ^= v[x]
        lines.append(f"  {names[z]} ^= {names[x]}        -> {names[z]} = {v[z]:08x}")
        v[z] = rotl32(v[z], r)
        lines.append(f"  {names[z]} <<<= {r:<2}     -> {names[z]} = {v[z]:08x}")
        lines.append("")
    lines.append(f"Salida:  a={v[0]:08x}  b={v[1]:08x}  c={v[2]:08x}  d={v[3]:08x}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Autotest con los vectores oficiales del RFC 8439
# --------------------------------------------------------------------------
def self_test():
    # 2.1.1 Quarter round
    s = [0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567]
    quarter_round(s, 0, 1, 2, 3)
    assert s == [0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB], "quarter round"

    # 2.3.2 Bloque ChaCha20
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, 1, nonce)
    assert block[:16].hex() == "10f1e7e4d13b5915500fdd1fa32071c4", "bloque"

    # 2.5.2 Poly1305
    pkey = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    tag = poly1305_mac(pkey, b"Cryptographic Forum Research Group")
    assert tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9", "poly1305"

    # 2.8.2 AEAD
    akey = bytes(range(0x80, 0xA0))
    anonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    ct, tag = aead_encrypt(akey, anonce, pt, aad)
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691", "aead tag"
    assert aead_decrypt(akey, anonce, ct, tag, aad) == pt, "aead roundtrip"

    # Detección de manipulación
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    try:
        aead_decrypt(akey, anonce, bad, tag, aad)
        raise AssertionError("no detectó la manipulación")
    except ValueError:
        pass
    print("OK: todos los vectores de prueba del RFC 8439 pasan.")


if __name__ == "__main__":
    self_test()
