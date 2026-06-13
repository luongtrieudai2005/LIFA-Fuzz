"""
sandbox/client/ftp_client.py
──────────────────────────────
FTP Honest Client — sends legitimate FTP protocol traffic for the
fuzzer to capture, mutate, and replay.

Protocol:
    FTP uses text-based commands terminated by CRLF (\\r\\n).
    Stateful handshake: USER → PASS → SYST → PORT → RETR/STOR/MKD → QUIT.
    Responses are 3-digit status codes (e.g., 220, 331, 230, 530).

FTP Token Dictionary (core commands the fuzzer should target):
    ["USER ", "PASS ", "SYST\\r\\n", "PORT ", "RETR ", "STOR ", "MKD ", "QUIT\\r\\n"]

Behavior:
    - Performs a full FTP login sequence (USER → PASS).
    - Sends SYST, then alternating data commands (LIST, RETR, MKD, etc.).
    - Each command is CRLF-terminated per RFC 959.
    - The fuzzer's Mutator will mutate these packets to trigger
      parser vulnerabilities in the LightFTP server.

Usage:
    python sandbox/client/ftp_client.py
    TARGET_HOST=172.16.0.2 TARGET_PORT=21 python sandbox/client/ftp_client.py
"""

from __future__ import annotations

import os
import sys
import time
import socket
import logging

logger = logging.getLogger("lifa-ftp-client")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

# ── Configuration (overridable via env vars) ─────────────────────
TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "21"))  # FTP default
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "200"))

# ── FTP Protocol Constants ────────────────────────────────────────────
# Core FTP token dictionary for the fuzzer
FTP_TOKENS: list[str] = [
    "USER ",
    "PASS ",
    "SYST\r\n",
    "PORT ",
    "RETR ",
    "STOR ",
    "MKD ",
    "QUIT\r\n",
]

# FTP status codes we track for response analysis
# Maps code → (description, auth_depth)
FTP_STATUS_CODES: dict[str, tuple[str, int]] = {
    "220": ("Service ready for new user.", 0),
    "331": ("User name okay, need password.", 1),
    "230": ("User logged in, proceed.", 2),       # deep auth state
    "530": ("Not logged in.", 0),
    "215": ("NAME system type.", 2),
    "257": ("\"PATHNAME\" created.", 2),
    "226": ("Closing data connection.", 2),
    "150": ("File status okay; about to open data connection.", 2),
    "221": ("Service closing control connection.", 0),
    "421": ("Service not available.", 0),
    "500": ("Syntax error, command unrecognized.", 0),
    "501": ("Syntax error in parameters or arguments.", 0),
    "502": ("Command not implemented.", 0),
    "530": ("Not logged in.", 0),
    "550": ("Requested action not taken.", 2),
}

CRLF = "\r\n"


def build_ftp_command(cmd: str, arg: str = "") -> bytes:
    """Build an FTP command with CRLF terminator.

    Args:
        cmd: FTP command keyword (e.g., "USER", "PASS").
        arg: Optional argument (e.g., username, password).

    Returns:
        Command bytes with CRLF line ending.
    """
    if arg:
        return f"{cmd} {arg}{CRLF}".encode("ascii")
    return f"{cmd}{CRLF}".encode("ascii")


def parse_ftp_response(data: bytes) -> tuple[str, str]:
    """Parse the first line of an FTP response.

    FTP responses follow the format: <3-digit-code><space><text><CRLF>
    Multi-line responses use: <3-digit-code>-<text> ... <3-digit-code><space><text>

    Args:
        data: Raw response bytes from the server.

    Returns:
        Tuple of (status_code, status_text).
    """
    try:
        text = data.decode("ascii", errors="replace").strip()
        if len(text) >= 3:
            code = text[:3]
            rest = text[3:].lstrip(" -")
            return code, rest
    except Exception:
        pass
    return "000", data.hex()


def main() -> None:
    """Connect to FTP server and send legitimate traffic sequences."""
    logger.info(
        f"LIFA FTP Honest Client starting: "
        f"target={TARGET_HOST}:{TARGET_PORT}, "
        f"interval={SEND_INTERVAL_MS}ms"
    )
    logger.info(f"FTP tokens: {FTP_TOKENS}")

    seq = 0
    username = "admin"
    password = "admin"

    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TARGET_HOST, TARGET_PORT))

            # ── Read banner (expect 220) ─────────────────────────────
            banner = sock.recv(4096)
            code, text = parse_ftp_response(banner)
            logger.info(
                f"[seq={seq}] Banner: {code} {text}"
            )

            # ── Phase 1: Authentication ──────────────────────────────
            # USER command
            pkt = build_ftp_command("USER", username)
            logger.info(f"[seq={seq}] Sending: {pkt.decode('ascii').strip()}")
            sock.sendall(pkt)

            resp = sock.recv(4096)
            code, text = parse_ftp_response(resp)
            logger.info(f"[seq={seq}] Response: {code} {text}")

            # PASS command
            pkt = build_ftp_command("PASS", password)
            logger.info(f"[seq={seq}] Sending: PASS ****")
            sock.sendall(pkt)

            resp = sock.recv(4096)
            code, text = parse_ftp_response(resp)
            logger.info(f"[seq={seq}] Response: {code} {text}")

            # ── Phase 2: Post-auth commands ──────────────────────────
            # Alternate between various FTP commands
            post_auth_cmds = [
                ("SYST", ""),
                ("PWD", ""),
                ("TYPE", "I"),
                ("MKD", f"testdir_{seq:05d}"),
                ("CWD", f"testdir_{seq:05d}"),
                ("DELE", f"testfile_{seq:05d}.txt"),
                ("RNFR", f"old_{seq:05d}.txt"),
                ("SIZE", f"testfile_{seq:05d}.txt"),
                ("NOOP", ""),
                ("FEAT", ""),
                ("LIST", ""),
                ("RETR", f"testfile_{seq % 5:05d}.txt"),
                ("STOR", f"upload_{seq:05d}.txt"),
            ]

            for cmd, arg in post_auth_cmds[:3 + (seq % 4)]:  # 3-6 cmds per session
                pkt = build_ftp_command(cmd, arg)
                logger.info(f"[seq={seq}] Sending: {pkt.decode('ascii').strip()}")
                sock.sendall(pkt)

                try:
                    resp = sock.recv(4096)
                    code, text = parse_ftp_response(resp)
                    logger.info(f"[seq={seq}] Response: {code} {text}")
                except socket.timeout:
                    logger.warning(f"[seq={seq}] Response timeout for {cmd}")

                time.sleep(0.05)  # Small delay between commands

            # ── Phase 3: QUIT ────────────────────────────────────────
            pkt = build_ftp_command("QUIT")
            logger.info(f"[seq={seq}] Sending: QUIT")
            sock.sendall(pkt)

            try:
                resp = sock.recv(4096)
                code, text = parse_ftp_response(resp)
                logger.info(f"[seq={seq}] Response: {code} {text}")
            except socket.timeout:
                pass

            seq += 1

        except ConnectionRefusedError:
            logger.warning("FTP server not ready, retrying in 2s...")
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
