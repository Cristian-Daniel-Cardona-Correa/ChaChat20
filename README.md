# ChaCha20 & Poly1305 — Chat Seguro y Laboratorio Criptográfico

Proyecto de red y criptografía que implementa el cifrador de flujo ChaCha20 y el autenticador Poly1305 (RFC 8439) en Python puro con un chat en tiempo real vía WebSockets y paneles didácticos interactivos.

## Requisitos previos

- Python 3.10 o superior.

## Instalación y Ejecución

### Opción 1: Con pip estándar

1. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

2. Iniciar el servidor:
   ```bash
   python app.py
   ```

3. Abrir en el navegador:
   - En tu equipo: `http://localhost:8000`
   - O desde otro dispositivo en la misma red Wi-Fi: `http://<TU_IP_LOCAL>:8000`

---

### Opción 2: Con uv (rápido)

```bash
uv run app.py
```

---

## Estructura del Proyecto

- `app.py`: Servidor backend (FastAPI + WebSockets + telemetría criptográfica).
- `chacha20.py`: Implementación pura en Python de ChaCha20, Poly1305 y AEAD según el RFC 8439.
- `info_chacha20.py`: Banco de datos didáctico con apartados informativos sobre el algoritmo.
- `static/index.html`: Interfaz web interactiva (Chat E2EE, Sniffer MITM, visualizador de Matriz 4x4 y Quarter Round).
- `requirements.txt`: Dependencias mínimas del proyecto.
