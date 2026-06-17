"""
sandbox/client/client.py
────────────────────────
Honest TCP Client — sends legitimate LIFA-protocol traffic for the
fuzzer to capture, mutate, and replay.

Protocol (LIFA Binary Protocol v2 — 8-byte header):
    Bytes 0-3:  Magic "LIFA" (0x4C 0x49 0x46 0x41)
    Byte  4:    Version (0x01)
    Byte  5:    Opcode (0x01=PING, 0x02=PROCESS, 0x03=STATUS, 0x04=RESET)
    Bytes 6-7:  Payload Length (uint16, little-endian)
    Bytes 8+:   Payload

State machine (per-connection): INIT ──[PING]──▶ AUTHENTICATED.
    PROCESS is the vulnerable opcode but is SILENTLY REJECTED (ERR_BAD_STATE)
    unless the connection is in AUTHENTICATED state. A valid PING transitions
    INIT → AUTH.

Behavior (CRITICAL for honest traffic):
    The fuzzer learns the PING-before-PROCESS ordering from THIS traffic.
    Therefore each iteration opens ONE connection and sends a full session
    inside it:
        [new conn] → PING (→ PONG, INIT→AUTH) → PROCESS_DATA(safe) (→ ACK)
    Sending one packet per connection would leave every PROCESS in INIT state
    (rejected), so the captured seeds would never demonstrate the auth
    sequence — the mutator's `_execute_sequence` replays the prefix (PING)
    before fuzzing the target (PROCESS), and it needs honest traffic shaped
    exactly this way.

    PROCESS payloads are small (8–15 bytes) — well within the server's 64-byte
    buffer, so they never crash the server. The fuzzer's Mutator grows the
    payload (buffer_overflow / payload_extend) to trigger the overflow.

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
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "100"))

# ── Protocol Constants (v2) ────────────────────────────────────────
MAGIC = b"LIFA"                   # 0x4C 0x49 0x46 0x41
VERSION = 0x01
HEADER_LEN = 8                    # magic(4) + version(1) + opcode(1) + len_le16(2)

# Client → Server opcodes
OPCODE_PING = 0x01
OPCODE_PROCESS = 0x02
OPCODE_STATUS = 0x03
OPCODE_RESET = 0x04


def build_packet(opcode: int, payload: bytes = b"") -> bytes:
    """Build a LIFA v2 packet: MAGIC + VERSION + opcode + len_le16 + payload."""
    plen = len(payload)
    assert plen <= 0xFFFF, "v2 length is uint16_le; payload too large"
    return MAGIC + bytes([VERSION, opcode]) + struct.pack("<H", plen) + payload


def build_ping_packet(payload: bytes = b"PONG") -> bytes:
    """Build a PING packet (auth handshake: INIT → AUTH)."""
    return build_packet(OPCODE_PING, payload)


def build_process_packet(payload: bytes) -> bytes:
    """Build a PROCESS_DATA packet (vulnerable path — keep payload ≤ 64B)."""
    return build_packet(OPCODE_PROCESS, payload)


def _recv_response(sock: socket.socket, timeout: float = 2.0) -> bytes:
    """Read one LIFA v2 response frame (8-byte header + declared payload)."""
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < HEADER_LEN:
            chunk = sock.recv(HEADER_LEN - len(hdr))
            if not chunk:
                return hdr  # short / EOF — caller decides
            hdr += chunk
        plen = struct.unpack("<H", hdr[6:8])[0]
        payload = b""
        while len(payload) < plen:
            chunk = sock.recv(plen - len(payload))
            if not chunk:
                break
            payload += chunk
        return hdr + payload
    except socket.timeout:
        return b""


def run_one_session(seq: int) -> None:
    """Open ONE connection and send a full auth sequence inside it.

    Sequence: PING (→ AUTH) → STATUS (observe state) → PROCESS (safe).
    This shape is what the fuzzer must learn and replay.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((TARGET_HOST, TARGET_PORT))

        # ── Step 1: PING → PONG (INIT → AUTHENTICATED) ───────────────
        ping_payload = f"SEQ{seq:05d}".encode("ascii")
        ping_pkt = build_ping_packet(ping_payload)
        logger.info(f"[seq={seq}] PING  {ping_pkt.hex()} "
                    f"(opcode=0x{ping_pkt[5]:02x}, len={ping_pkt[6]})")
        sock.sendall(ping_pkt)
        pong = _recv_response(sock)
        if pong:
            logger.info(f"[seq={seq}] PONG  {pong.hex()} "
                        f"(resp_opcode=0x{pong[5]:02x})")

        # ── Step 2: STATUS (observe AUTHENTICATED state — rich signal) ──
        status_pkt = build_packet(OPCODE_STATUS)
        sock.sendall(status_pkt)
        status_resp = _recv_response(sock)
        if status_resp:
            logger.info(f"[seq={seq}] STATUS {status_resp.hex()}")

        # ── Step 3: PROCESS_DATA (safe payload ≤ 64B) ────────────────
        data_size = 8 + (seq % 8)            # 8–15 bytes, safe
        process_payload = bytes(range(data_size))  # 0x00, 0x01, 0x02, ...
        process_pkt = build_process_packet(process_payload)
        logger.info(f"[seq={seq}] PROC  {process_pkt.hex()} "
                    f"(opcode=0x{process_pkt[5]:02x}, len={process_pkt[6]})")
        sock.sendall(process_pkt)
        ack = _recv_response(sock)
        if ack:
            logger.info(f"[seq={seq}] ACK   {ack.hex()} "
                        f"(resp_opcode=0x{ack[5]:02x})")

    except ConnectionRefusedError:
        logger.warning("Server not ready, retrying in 2s...")
        time.sleep(2)
        return
    except ConnectionResetError:
        logger.warning("Connection reset (server child may have crashed "
                       "under fuzzer mutation), retrying in 3s...")
        time.sleep(3)
        return
    except socket.timeout:
        logger.warning("Connection timed out, retrying...")
        return
    except Exception as e:
        logger.error(f"Error: {e}")
        return
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def main() -> None:
    """Connect to target and send periodic LIFA v2 sessions."""
    logger.info(
        f"LIFA Honest Client starting: "
        f"target={TARGET_HOST}:{TARGET_PORT}, "
        f"interval={SEND_INTERVAL_MS}ms"
    )
    logger.info("Protocol v2: MAGIC='LIFA', VERSION=0x01, "
                "opcodes=PING(0x01)/PROCESS(0x02)/STATUS(0x03)/RESET(0x04)")
    logger.info("Session shape: PING → STATUS → PROCESS (same connection)")

    seq = 0
    while True:
        run_one_session(seq)
        seq += 1
        time.sleep(SEND_INTERVAL_MS / 1000.0)


if __name__ == "__main__":
    main()
