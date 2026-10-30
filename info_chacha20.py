"""Apartados informativos sobre ChaCha20 (se muestran con /info en el cliente)."""

TOPICS = [
    (
        "¿Qué es ChaCha20?",
        """\
ChaCha20 es un cifrador de flujo (stream cipher) diseñado por Daniel J.
Bernstein en 2008 como una variante mejorada de su cifrador Salsa20.
Está estandarizado en el RFC 8439.

Idea básica: a partir de una clave secreta y un nonce, genera una secuencia
larga de bytes pseudoaleatorios llamada KEYSTREAM. Para cifrar, se hace XOR
entre el mensaje y el keystream; para descifrar, se repite exactamente la
misma operación:

    cifrado = mensaje  XOR keystream
    mensaje = cifrado  XOR keystream

Parámetros (versión del RFC 8439):
  - Clave   : 256 bits (32 bytes)
  - Nonce   : 96 bits  (12 bytes)
  - Contador: 32 bits  (numera los bloques de 64 bytes)
  - Rondas  : 20

Dónde se usa: TLS 1.3, WireGuard, OpenSSH, Chrome/Android (HTTPS en móviles)
y el generador de números aleatorios del kernel de Linux.""",
    ),
    (
        "El estado interno (matriz 4x4)",
        """\
ChaCha20 trabaja con un estado de 16 palabras de 32 bits (512 bits), que se
organiza como una matriz 4x4:

    const  const  const  const
    clave  clave  clave  clave
    clave  clave  clave  clave
    cont.  nonce  nonce  nonce

  - Fila 0: 4 constantes que forman el texto ASCII "expand 32-byte k".
            Garantizan que el estado inicial nunca sea todo ceros y
            separan este cifrador de otros usos de la misma clave.
  - Filas 1-2: la clave de 256 bits (8 palabras).
  - Fila 3: contador de bloque (1 palabra) + nonce de 96 bits (3 palabras).

Prueba el comando /demo para ver esta matriz con valores reales.""",
    ),
    (
        "El quarter round (suma, XOR, rotación)",
        """\
La mezcla se hace con el "quarter round", que opera sobre 4 palabras
(a, b, c, d) usando solo tres operaciones:

    a += b;   d ^= a;   d <<<= 16
    c += d;   b ^= c;   b <<<= 12
    a += b;   d ^= a;   d <<<= 8
    c += d;   b ^= c;   b <<<= 7

  +   suma módulo 2^32
  ^   XOR
  <<< rotación de bits a la izquierda

A este diseño se le llama ARX (Add-Rotate-XOR). Sus ventajas:
  - No usa tablas de búsqueda (S-boxes), así que no sufre ataques de
    temporización por caché como algunas implementaciones de AES.
  - Es muy rápido en software, incluso en CPUs sin instrucciones AES.
  - Es fácil de implementar en tiempo constante.

Comando /ronda: muestra un quarter round paso a paso con el vector de
prueba del RFC 8439.""",
    ),
    (
        "Las 20 rondas y la suma final",
        """\
Un bloque de keystream se calcula así:

  1. Se construye el estado inicial (matriz 4x4).
  2. Se hace una copia y se aplican 10 "double rounds" (= 20 rondas):
       - Ronda de COLUMNAS : QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
       - Ronda de DIAGONALES: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
     Alternar columnas y diagonales hace que cada palabra termine
     influida por todas las demás (difusión).
  3. Se SUMA el estado mezclado con el estado inicial (módulo 2^32).
     Esta suma es clave: sin ella, las rondas serían invertibles y se
     podría recuperar la clave a partir de la salida.
  4. Se serializa en little-endian: 64 bytes de keystream.

Para el siguiente bloque se incrementa el contador en 1 y se repite.""",
    ),
    (
        "Cifrar y descifrar (keystream XOR)",
        """\
Para un mensaje de N bytes se generan ceil(N / 64) bloques de keystream
(contador = 1, 2, 3, ...), se concatenan y se hace XOR byte a byte.

Propiedades importantes:
  - El texto cifrado mide exactamente lo mismo que el original (sin relleno).
  - Se puede cifrar cualquier longitud, sin necesidad de bloques completos.
  - Cifrar y descifrar son la misma función.
  - Máximo por (clave, nonce): 2^32 bloques de 64 bytes = 256 GiB.

Con /cifrado puedes activar la vista que muestra, para cada mensaje, el
nonce, los bytes cifrados y el tag de autenticación tal como viajan por la red.""",
    ),
    (
        "El nonce: la regla de oro",
        """\
NUNCA se debe reutilizar el mismo par (clave, nonce) para dos mensajes.

Si se reutiliza, ambos mensajes se cifran con el MISMO keystream:

    C1 = P1 XOR K        C2 = P2 XOR K
    C1 XOR C2 = P1 XOR P2        (¡el keystream desaparece!)

Un atacante que vea ambos cifrados obtiene P1 XOR P2, y con análisis
estadístico (o conociendo parte de uno de los textos) puede recuperar ambos
mensajes. Es el error clásico de los cifradores de flujo.

En este chat cada mensaje usa un nonce de 96 bits generado con
os.urandom(). Con 2^96 posibilidades, la probabilidad de colisión es
despreciable para un chat. El nonce no es secreto: viaja junto al mensaje.""",
    ),
    (
        "Poly1305 y el modo AEAD",
        """\
ChaCha20 SOLO da confidencialidad. Si un atacante modifica bits del cifrado,
los bits correspondientes del texto plano cambian de forma predecible
(es maleable) y el receptor no se entera.

Por eso se combina con Poly1305, un autenticador de mensajes (MAC) creado
también por Bernstein. El resultado es ChaCha20-Poly1305 (AEAD):

  1. Con (clave, nonce, contador 0) se genera un bloque; sus primeros
     32 bytes son la clave de un solo uso de Poly1305.
  2. El mensaje se cifra con ChaCha20 empezando en contador 1.
  3. Poly1305 calcula un tag de 16 bytes sobre el texto cifrado.
  4. El receptor recalcula el tag; si no coincide, rechaza el mensaje
     SIN descifrarlo.

Formato de cada paquete en este chat:

    [ nonce: 12 bytes ][ cifrado: N bytes ][ tag: 16 bytes ]""",
    ),
    (
        "ChaCha20 frente a AES",
        """\
                     ChaCha20-Poly1305          AES-GCM
  Tipo               Cifrador de flujo          Cifrador de bloque + modo
  Operaciones        Suma, XOR, rotación        S-boxes, XOR, GF(2^128)
  Sin hardware       Muy rápido                 Más lento
  Con AES-NI         Algo más lento             Muy rápido
  Tiempo constante   Natural                    Difícil sin hardware
  Nonce              96 bits                    96 bits (igual de crítico)

Regla práctica: en servidores con AES-NI, AES-GCM suele ganar; en móviles
o dispositivos sin aceleración AES, ChaCha20-Poly1305 suele ganar. Ambos se
consideran seguros cuando se usan correctamente. Por eso TLS 1.3 incluye los dos.""",
    ),
    (
        "Cómo funciona este chat (y sus límites)",
        """\
Arquitectura:

    cliente A  <--->  ngrok  <--->  servidor relay  <--->  ngrok/local  <--->  cliente B

  - Todos los participantes comparten una CONTRASEÑA. De ella se deriva la
    clave de 256 bits con PBKDF2-HMAC-SHA256 (200 000 iteraciones).
  - Cada mensaje se cifra en el cliente con ChaCha20-Poly1305 y un nonce
    aleatorio. El nombre de usuario y la hora también van cifrados.
  - El servidor (y ngrok) solo ven bytes opacos: reenvían paquetes sin poder
    leerlos ni modificarlos sin que se detecte.

Límites que conviene conocer:
  - La contraseña se comparte por un canal aparte; si es débil, la clave
    también lo es. Usa una frase larga.
  - No hay intercambio de claves (tipo Diffie-Hellman) ni secreto hacia
    adelante: si la contraseña se filtra, se pueden descifrar capturas antiguas.
  - No hay protección contra repetición: alguien con acceso a la red podría
    reenviar un paquete viejo y se mostraría de nuevo.
  - El servidor ve metadatos: quién se conecta, cuándo y el tamaño de los mensajes.
  - Es un proyecto didáctico: para algo serio usa Signal, Matrix (E2EE), etc.""",
    ),
]
