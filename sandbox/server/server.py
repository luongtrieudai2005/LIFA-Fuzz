"""
sandbox/server/server.py
────────────────────────
Vulnerable mockup TCP server — placeholder for the actual proprietary target.

Has a KNOWN CRASH VULNERABILITY for testing the KILL_SERVER mutation rule:
    - Normal packets start with magic 0xDEADBEEF — these are processed normally.
    - Packets starting with magic 0x00000000 trigger a SIGSEGV (null pointer deref).
    - Packets starting with magic 0xCAFEBABE trigger a SIGABRT (abort).
    - Packets with length field > 4096 trigger a buffer overflow crash.

This mimics a real proprietary server with input validation bugs.
The Mutator's 1% KILL_SERVER rule sends these malicious magic bytes.
"""

import os
import sys
import struct
import logging
import socket
import threading

logger = logging.getLogger("target-server")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

MAGIC_OK = b"\xDE\xAD\xBE\xEF"
MAGIC_CRASH_NULL_DEREF = b"\x00\x00\x00\x00"
MAGIC_CRASH_ABORT = b"\xCA\xFE\xBA\xBE"
MAX_PAYLOAD_SIZE = 4096

CRASH_AFTER_N_PACKETS = int(os.environ.get("CRASH_AFTER_N_PACKETS", "0"))
_packet_counter = 0
_lock = threading.Lock()


def handle_connection(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Handle a single client connection.

    Protocol format:
        [4 bytes: magic] [2 bytes: length (uint16 LE)] [N bytes: payload]

    Crash triggers:
        - Magic == 0x00000000 → SIGSEGV (null pointer dereference simulation)
        - Magic == 0xCAFEBABE → SIGABRT (forced abort)
        - Payload length > 4096 → buffer overflow crash
    """
    global _packet_counter

    logger.info(f"Connection from {addr}")

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            with _lock:
                _packet_counter += 1
                count = _packet_counter

            hex_str = data.hex()
            logger.info(f"[{count}] Recv {len(data)} bytes: {hex_str}")

            # --- CRASH TRIGGERS (for fuzz testing) ---

            # Trigger 1: Null magic → SIGSEGV (simulates null pointer deref)
            if len(data) >= 4 and data[:4] == MAGIC_CRASH_NULL_DEREF:
                logger.error(f"[{count}] CRASH: null magic received → SIGSEGV")
                import ctypes
                ctypes.string_at(0)  # type: ignore[no-untyped-call]

            # Trigger 2: Abort magic → SIGABRT
            if len(data) >= 4 and data[:4] == MAGIC_CRASH_ABORT:
                logger.error(f"[{count}] CRASH: abort magic received → SIGABRT")
                import os as _os
                _os.abort()

            # Trigger 3: Read header length field
            if len(data) >= 6 and data[:4] == MAGIC_OK:
                payload_len = struct.unpack("<H", data[4:6])[0]

                # Trigger 4: Length overflow → SIGSEGV
                if payload_len > MAX_PAYLOAD_SIZE:
                    logger.error(
                        f"[{count}] CRASH: length overflow ({payload_len} > {MAX_PAYLOAD_SIZE}) → SIGSEGV"
                    )
                    # Simulate buffer overflow
                    overflow = bytearray(payload_len)
                    ctypes.memset(overflow, 0x41, payload_len)  # type: ignore[attr-defined]

                logger.info(f"[{count}] Valid packet: magic=OK, payload_len={payload_len}")

            # Counter-based crash trigger (for manual testing)
            if CRASH_AFTER_N_PACKETS > 0 and count >= CRASH_AFTER_N_PACKETS:
                logger.error(f"CRASH: packet count limit ({CRASH_AFTER_N_PACKETS}) reached")
                import ctypes
                ctypes.string_at(0)  # type: ignore[no-untyped-call]

            # Echo back
            conn.sendall(data)

    except ConnectionResetError:
        logger.warning(f"Connection reset by {addr}")
    except Exception as e:
        logger.error(f"Error handling {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"Connection closed: {addr}")


def main() -> None:
    """Start the vulnerable echo server."""
    host = "0.0.0.0"
    port = int(os.environ.get("SERVER_PORT", "9000"))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)
    server.settimeout(1.0)

    logger.info(f"Target server listening on {host}:{port}")
    logger.info(f"CRASH_AFTER_N_PACKETS = {CRASH_AFTER_N_PACKETS}")
    logger.info(f"Known vulnerabilities:")
    logger.info(f"  - Magic 00000000 → SIGSEGV (null deref)")
    logger.info(f"  - Magic CAFEBABE → SIGABRT")
    logger.info(f"  - Payload length > {MAX_PAYLOAD_SIZE} → buffer overflow")

    try:
        while True:
            try:
                conn, addr = server.accept()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        logger.info("Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
