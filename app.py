#!/usr/bin/env python3
"""
ChaCha20 & Poly1305 Real-Time Chat & Interactive Lab.
Backend con FastAPI + WebSockets + Criptografía nativa en Python.
"""
import argparse
import asyncio
import json
import os
import socket
import struct
import sys
import time
from typing import List

import qrcode
import qrcode.image.svg
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from chacha20 import (
    BLOCK_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    _block_words,
    chacha20_block,
    derive_key,
    explain_quarter_round,
    open_sealed,
    seal,
)
from info_chacha20 import TOPICS

app = FastAPI(title="ChaCha20 Chat & Lab")

# --------------------------------------------------------------------------
# Red y Conexiones WebSockets
# --------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def generate_qr_svg(url: str) -> str:
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(url, image_factory=factory)
    return img.to_string().decode("utf-8")


# --------------------------------------------------------------------------
# Modelos de Datos
# --------------------------------------------------------------------------
class EncryptRequest(BaseModel):
    text: str
    password: str
    user: str

class DecryptRequest(BaseModel):
    frame_hex: str
    password: str


# --------------------------------------------------------------------------
# Endpoints de Criptografía
# --------------------------------------------------------------------------
@app.post("/api/encrypt")
def api_encrypt(req: EncryptRequest):
    key = derive_key(req.password)
    
    # Cifrado autenticado AEAD (ChaCha20 + Poly1305)
    payload_obj = {
        "user": req.user,
        "text": req.text,
        "time": time.strftime("%H:%M:%S")
    }
    payload_bytes = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
    sealed_frame = seal(key, payload_bytes)
    
    nonce_bytes = sealed_frame[:NONCE_SIZE]
    ciphertext_bytes = sealed_frame[NONCE_SIZE:-TAG_SIZE]
    tag_bytes = sealed_frame[-TAG_SIZE:]
    
    # Bloque 1 de keystream para el mensaje y telemetría de matriz
    st1, w1, out1 = _block_words(key, 1, nonce_bytes)
    keystream_block = chacha20_block(key, 1, nonce_bytes)

    def format_matrix(words):
        # 16 palabras en matriz 4x4 en formato hex (0x12345678)
        return [[f"0x{words[r * 4 + c]:08x}" for c in range(4)] for r in range(4)]

    return {
        "user": req.user,
        "time": payload_obj["time"],
        "plaintext": req.text,
        "frame_hex": sealed_frame.hex(),
        "key_hex": key.hex(),
        "nonce_hex": nonce_bytes.hex(),
        "ciphertext_hex": ciphertext_bytes.hex(),
        "tag_hex": tag_bytes.hex(),
        "keystream_block_hex": keystream_block.hex(),
        "matrix_initial": format_matrix(st1),
        "matrix_rounds": format_matrix(w1),
        "matrix_final": format_matrix(out1),
        "total_bytes": len(sealed_frame)
    }


@app.post("/api/decrypt")
def api_decrypt(req: DecryptRequest):
    try:
        frame_bytes = bytes.fromhex(req.frame_hex)
        key = derive_key(req.password)
        plaintext_bytes = open_sealed(key, frame_bytes)
        payload = json.loads(plaintext_bytes.decode("utf-8"))
        return {
            "success": True,
            "data": payload
        }
    except ValueError as e:
        # Error de autenticación Poly1305 (contraseña equivocada o paquete manipulado)
        return {
            "success": False,
            "error": "Autenticación Poly1305 fallida. La contraseña no coincide o el paquete fue alterado."
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error al procesar el paquete: {str(e)}"
        }


@app.get("/api/topics")
def api_topics():
    topics = []
    for i, (title, content) in enumerate(TOPICS, 1):
        topics.append({
            "id": i,
            "title": title,
            "content": content
        })
    return topics


@app.get("/api/quarter_round")
def api_quarter_round():
    return {
        "explanation": explain_quarter_round()
    }


@app.get("/api/network_info")
def api_network_info():
    local_ip = get_local_ip()
    port = getattr(app.state, "port", 8000)
    url = f"http://{local_ip}:{port}"
    qr_svg = generate_qr_svg(url)
    return {
        "local_ip": local_ip,
        "port": port,
        "url": url,
        "qr_svg": qr_svg
    }


# --------------------------------------------------------------------------
# WebSocket para Chat y Sniffer en Tiempo Real
# --------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Enviar notificación de conexión inicial
    await websocket.send_json({
        "type": "system",
        "message": "Conectado al servidor de retransmisión seguro ChaCha20."
    })
    try:
        while True:
            data = await websocket.receive_json()
            # Retransmitir a todos los clientes conectados
            await manager.broadcast({
                "type": "chat_message",
                "payload": data
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# --------------------------------------------------------------------------
# Servir Interfaz Web
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: no se encontró static/index.html</h1>"


def main():
    parser = argparse.ArgumentParser(description="ChaCha20 & Poly1305 Chat & Lab")
    parser.add_argument("--host", default="0.0.0.0", help="Dirección host (0.0.0.0 para acceso en red local)")
    parser.add_argument("--port", type=int, default=8000, help="Puerto del servidor (por defecto 8000)")
    args = parser.parse_args()

    app.state.port = args.port
    local_ip = get_local_ip()

    print("\n" + "=" * 65)
    print("  SERVIDOR CHAT CHACHA20 + POLY1305")
    print("=" * 65)
    print(f"  Local en esta PC : http://localhost:{args.port}")
    print(f"  En tu red Wi-Fi  : http://{local_ip}:{args.port}")
    print("=" * 65 + "\n")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
