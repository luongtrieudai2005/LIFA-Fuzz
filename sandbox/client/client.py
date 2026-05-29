"""
sandbox/client/client.py
────────────────────────
Dummy TCP client — placeholder for the actual protocol client.

In a real fuzz campaign, replace this with the legitimate client
for your target protocol (e.g., a game client, IoT controller).

Behavior:
    - Connect to the target server (or Fast Loop proxy).
    - Send periodic messages with a simulated protocol header.
    - Read responses and log them.
"""

import os
import sys
import time
import socket
import logging
import struct

# TODO: Replace with the actual client binary / script.

logger = logging.getLogger("client")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "9000"))
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "1000"))

# Simulated protocol header:
#   Magic: 4 bytes (0xDEADBEEF)
#   Length: 2 bytes (uint16 LE) — length of the payload
#   Payload: variable length
MAGIC = b"\xDE\xAD\xBE\xEF"


def build_packet(payload: bytes) -> bytes:
    """Build a simulated protocol packet: magic + length + payload."""
    header = MAGIC + struct.pack("<H", len(payload))
    return header + payload


def main() -> None:
    """Connect to target and send periodic traffic."""
    logger.info(
        f"Client starting: target={TARGET_HOST}:{TARGET_PORT}, "
        f"interval={SEND_INTERVAL_MS}ms"
    )

    seq = 0
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TARGET_HOST, TARGET_PORT))

            # Build a packet with a simple payload
            payload = f"HELLO_{seq:05d}".encode("ascii")
            packet = build_packet(payload)

            logger.info(
                f"[seq={seq}] Sending {len(packet)} bytes: {packet.hex()}"
            )
            sock.sendall(packet)

            # Read response
            response = sock.recv(4096)
            if response:
                logger.info(
                    f"[seq={seq}] Response {len(response)} bytes: {response.hex()}"
                )
            else:
                logger.warning(f"[seq={seq}] Empty response")

            seq += 1

        except socket.timeout:
            logger.warning("Connection timed out, retrying...")
        except ConnectionRefusedError:
            logger.warning("Server not ready, retrying in 2s...")
            time.sleep(2)
            continue
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            if sock:
                sock.close()

        time.sleep(SEND_INTERVAL_MS / 1000.0)


if __name__ == "__main__":
    main()
