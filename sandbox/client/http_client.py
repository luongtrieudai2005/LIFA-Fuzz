"""
sandbox/client/http_client.py
──────────────────────────────
Honest HTTP Client — sends legitimate HTTP traffic for the
fuzzer to capture, mutate, and replay against HTTP targets
(e.g. lighttpd, nginx, Apache).

Sends a rotating sequence of HTTP/1.1 requests:
    1. GET / (root)
    2. GET /index.html
    3. POST with Content-Length + body
    4. GET with Range header
    5. POST with chunked Transfer-Encoding
    6. GET with varied headers (Accept, User-Agent, Cookie)
    7. HEAD / (no body)
    8. GET with query string
    9. POST with Content-Type: application/x-www-form-urlencoded
   10. GET with If-Modified-Since / If-None-Match

Usage:
    python sandbox/client/http_client.py
    TARGET_HOST=172.16.0.2 TARGET_PORT=9000 python sandbox/client/http_client.py
"""

from __future__ import annotations

import os
import sys
import time
import socket
import logging

logger = logging.getLogger("lifa-http-client")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

# ── Configuration ──────────────────────────────────────────────────
TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8001"))
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "500"))


# ── HTTP Request Templates ──────────────────────────────────────────

def _build_request(seq: int) -> bytes:
    """Build an HTTP/1.1 request based on sequence number."""
    idx = seq % 10

    if idx == 0:
        # Simple GET /
        return (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 1:
        # GET /index.html
        return (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Accept: text/html,*/*\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 2:
        # POST with Content-Length
        body = b"username=admin&password=test123"
        return (
            b"POST /login HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n"
            b"\r\n"
            + body
        )
    elif idx == 3:
        # GET with Range header
        return (
            b"GET /largefile.bin HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Range: bytes=0-1023\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 4:
        # POST chunked encoding
        chunk1 = b"Hello, "
        chunk2 = b"World!"
        return (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + f"{len(chunk1):x}\r\n".encode() + chunk1 + b"\r\n"
            + f"{len(chunk2):x}\r\n".encode() + chunk2 + b"\r\n"
            + b"0\r\n\r\n"
        )
    elif idx == 5:
        # GET with varied headers
        return (
            b"GET /api/data HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Accept: application/json\r\n"
            b"User-Agent: LIFA-Fuzz/1.0\r\n"
            b"Cookie: session=abc123; token=xyz789\r\n"
            + b"X-Request-ID: req-" + f"{seq:06d}".encode() + b"\r\n"
            + b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 6:
        # HEAD request
        return (
            b"HEAD / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 7:
        # GET with query string
        return (
            b"GET /search?q=test&page=" + f"{seq % 100}".encode() + b" HTTP/1.1\r\n"
            + b"Host: localhost\r\n"
            b"Accept: text/html\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
    elif idx == 8:
        # POST form data
        body = b"name=foo&email=bar%40example.com&message=" + b"A" * (10 + seq % 20)
        return (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n"
            b"\r\n"
            + body
        )
    else:
        # Conditional GET (caching headers)
        return (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + b"If-None-Match: \"etag-" + f"{seq:06d}".encode() + b"\"\r\n"
            + b"If-Modified-Since: Sat, 01 Jan 2024 00:00:00 GMT\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )


def main() -> None:
    """Connect to target and send periodic HTTP traffic."""
    logger.info(
        f"HTTP Client starting: "
        f"target={TARGET_HOST}:{TARGET_PORT}, "
        f"interval={SEND_INTERVAL_MS}ms"
    )

    seq = 0
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TARGET_HOST, TARGET_PORT))

            request = _build_request(seq)
            sock.sendall(request)

            method = request.split(b" ")[0].decode()
            path = request.split(b" ")[1].decode()
            logger.info(
                f"[seq={seq}] {method} {path} ({len(request)} bytes)"
            )

            # Read response (if any)
            try:
                response = sock.recv(4096)
                if response:
                    status = response.split(b"\r\n")[0].decode(errors="replace")
                    logger.info(f"[seq={seq}] Response: {status}")
                else:
                    logger.warning(f"[seq={seq}] Empty response")
            except socket.timeout:
                pass  # Server may not respond to malformed requests

            seq += 1

        except ConnectionRefusedError:
            logger.warning("Server not ready, retrying in 2s...")
            time.sleep(2)
            continue
        except ConnectionResetError:
            logger.warning("Connection reset (server may have crashed), retrying in 1s...")
            time.sleep(1)
            continue
        except socket.timeout:
            logger.warning("Connection timed out, retrying...")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        time.sleep(SEND_INTERVAL_MS / 1000.0)


if __name__ == "__main__":
    main()
