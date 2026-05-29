"""
sandbox/client/client.py
────────────────────────
Honest TCP Client — sends legitimate LIFA-protocol traffic for the
fuzzer to capture, mutate, and replay.

Protocol:
    Bytes 0-3:  Magic "LIFA" (0x4C 0x49 0x46 0x41)
    Byte  4:    Opcode (0x01=PING, 0x02=PROCESS_DATA)
    Byte  5:    Payload Length (uint8)
    Bytes 6+:   Payload

Behavior:
    - Alternates between PING and PROCESS_DATA packets.
    - PROCESS_DATA payloads are small (8–15 bytes) — well within the
      server's 32-byte buffer, so they never crash the server normally.
    - The fuzzer's Mutator will mutate these packets to trigger the
      buffer overflow (e.g., set length byte to 0xFF or inject 1000+ bytes).

Usage:
    python sandbox/client/client.py
    # Or via environment variables:
    TARGET_HOST=127.0.0.1 TARGET_PORT=8001 python sandbox/client/client.py
"""

from __future__ import annotations

import os
import sys
import time
import socket
import struct
import logging

logger = logging.getLogger("lifa-client")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

# ── Configuration (overridable via env vars) ─────────────────────
TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8001"))
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "1000"))

# ── Protocol Constants ────────────────────────────────────────────
MAGIC = b"LIFA"                   # 0x4C 0x49 0x46 0x41
OPCODE_PING = 0x01
OPCODE_PROCESS = 0x02


def build_ping_packet(payload: bytes = b"PONG") -> bytes:
    """Build a PING packet: MAGIC + 0x01 + len + payload."""
    assert len(payload) <= 255
    return MAGIC + bytes([OPCODE_PING, len(payload)]) + payload


def build_process_packet(payload: bytes) -> bytes:
    """Build a PROCESS_DATA packet: MAGIC + 0x02 + len + payload."""
    assert len(payload) <= 255
    return MAGIC + bytes([OPCODE_PROCESS, len(payload)]) + payload


def main() -> None:
    """Connect to target and send periodic LIFA traffic."""
    logger.info(
        f"LIFA Honest Client starting: "
        f"target={TARGET_HOST}:{TARGET_PORT}, "
        f"interval={SEND_INTERVAL_MS}ms"
    )
    logger.info(f"Protocol: MAGIC='LIFA', opcodes=PING(0x01)/PROCESS(0x02)")

    seq = 0
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TARGET_HOST, TARGET_PORT))

            # Alternate between PING and PROCESS_DATA
            if seq % 2 == 0:
                # PING with a simple payload
                payload = f"SEQ{seq:05d}".encode("ascii")
                packet = build_ping_packet(payload)
            else:
                # PROCESS_DATA with a small payload (8-15 bytes, safe)
                data_size = 8 + (seq % 8)
                payload = bytes(range(data_size))  # 0x00, 0x01, 0x02, ...
                packet = build_process_packet(payload)

            logger.info(
                f"[seq={seq}] Sending {len(packet)} bytes: {packet.hex()} "
                f"(opcode=0x{packet[4]:02x}, len={packet[5]})"
            )
            sock.sendall(packet)

            # Read response
            try:
                response = sock.recv(4096)
                if response:
                    logger.info(
                        f"[seq={seq}] Response {len(response)} bytes: "
                        f"{response.hex()}"
                    )
                else:
                    logger.warning(f"[seq={seq}] Empty response")
            except socket.timeout:
                logger.warning(f"[seq={seq}] Response timeout (server may be processing)")

            seq += 1

        except ConnectionRefusedError:
            logger.warning("Server not ready, retrying in 2s...")
            time.sleep(2)
            continue
        except ConnectionResetError:
            logger.warning("Connection reset (server may have crashed), retrying in 3s...")
            time.sleep(3)
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
