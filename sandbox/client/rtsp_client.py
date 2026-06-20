"""
sandbox/client/rtsp_client.py
──────────────────────────────
RTSP Honest Client — sends legitimate RTSP protocol traffic for the
fuzzer to capture, mutate, and replay.

Protocol:
    RTSP is a text-based protocol similar to HTTP, used for streaming
    media control. Requests are CRLF-terminated with headers.
    Stateful sequence: OPTIONS → DESCRIBE → SETUP → PLAY → TEARDOWN.

RTSP Token Dictionary (core methods the fuzzer should target):
    ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
     "GET_PARAMETER", "SET_PARAMETER"]

Usage:
    TARGET_HOST=172.16.0.2 TARGET_PORT=8554 python sandbox/client/rtsp_client.py
"""

from __future__ import annotations

import os
import sys
import time
import socket
import logging

logger = logging.getLogger("lifa-rtsp-client")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_handler)

TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8554"))
SEND_INTERVAL_MS = int(os.environ.get("SEND_INTERVAL_MS", "200"))

CRLF = "\r\n"
SEQ = 0  # CSeq counter


def build_rtsp_request(method: str, url: str, headers: dict | None = None) -> bytes:
    """Build an RTSP request (HTTP-like text format)."""
    global SEQ
    SEQ += 1
    lines = [f"{method} {url} RTSP/1.0{CRLF}"]
    lines.append(f"CSeq: {SEQ}{CRLF}")
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}{CRLF}")
    lines.append(CRLF)  # empty line terminates headers
    return "".join(lines).encode("ascii")


def recv_response(sock: socket.socket) -> str:
    """Read RTSP response (until empty line or timeout)."""
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("ascii", errors="replace")
    except socket.timeout:
        return data.decode("ascii", errors="replace") if data else ""


def extract_header(resp: str, name: str) -> str:
    """Extract a header value from RTSP response."""
    for line in resp.split("\r\n"):
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def main() -> None:
    logger.info(f"LIFA RTSP Honest Client: target={TARGET_HOST}:{TARGET_PORT}")

    seq = 0

    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((TARGET_HOST, TARGET_PORT))

            url = f"rtsp://{TARGET_HOST}:{TARGET_PORT}/test.mkv"

            # Phase 1: OPTIONS
            pkt = build_rtsp_request("OPTIONS", url)
            logger.info(f"[seq={seq}] Sending OPTIONS")
            sock.sendall(pkt)
            resp = recv_response(sock)
            logger.info(f"[seq={seq}] OPTIONS response: {resp.split(CRLF)[0] if resp else 'timeout'}")

            # Phase 2: DESCRIBE
            pkt = build_rtsp_request("DESCRIBE", url, {"Accept": "application/sdp"})
            logger.info(f"[seq={seq}] Sending DESCRIBE")
            sock.sendall(pkt)
            resp = recv_response(sock)
            logger.info(f"[seq={seq}] DESCRIBE response: {resp.split(CRLF)[0] if resp else 'timeout'}")

            # Phase 3: SETUP (get Session ID)
            pkt = build_rtsp_request("SETUP", url + "/track1", {"Transport": "RTP/AVP;unicast;client_port=50000-50001"})
            logger.info(f"[seq={seq}] Sending SETUP")
            sock.sendall(pkt)
            resp = recv_response(sock)
            session = extract_header(resp, "Session")
            logger.info(f"[seq={seq}] SETUP response: {resp.split(CRLF)[0] if resp else 'timeout'} session={session[:16] if session else 'none'}")

            # Phase 4: PLAY (needs Session) — with RFC 2326 §3.4-3.6 Range formats.
            # Alternating formats across sessions so the math layer sees VARYING values
            # at the Range offset → HIGH_ENTROPY → PAYLOAD_EXTEND → overflow on clock=.
            range_formats = [
                "npt=0.001-",
                "clock=20%02d%02d%02dT%02d%02d%02d%02dZ-" % (
                    24 + (seq % 50), (seq % 12) + 1, (seq % 28) + 1,
                    seq % 24, (seq % 60), (seq * 7) % 60, (seq * 13) % 60),
                "smpte=0:%02d:%02d:%02d-" % (seq % 24, (seq * 7) % 60, (seq * 13) % 60),
            ]
            play_headers = {}
            if session:
                play_headers["Session"] = session
            play_headers["Range"] = range_formats[seq % len(range_formats)]
            pkt = build_rtsp_request("PLAY", url, play_headers)
            logger.info(f"[seq={seq}] Sending PLAY")
            sock.sendall(pkt)
            resp = recv_response(sock)
            logger.info(f"[seq={seq}] PLAY response: {resp.split(CRLF)[0] if resp else 'timeout'}")

            # Phase 5: TEARDOWN
            td_headers = {}
            if session:
                td_headers["Session"] = session
            pkt = build_rtsp_request("TEARDOWN", url, td_headers)
            logger.info(f"[seq={seq}] Sending TEARDOWN")
            sock.sendall(pkt)
            resp = recv_response(sock)
            logger.info(f"[seq={seq}] TEARDOWN response: {resp.split(CRLF)[0] if resp else 'timeout'}")

            # Extra commands for coverage
            extra_cmds = [
                ("PAUSE", url, {"Session": session} if session else {}),
                ("GET_PARAMETER", url, {"Session": session} if session else {}),
                ("SET_PARAMETER", url, {"Session": session} if session else {}),
            ]
            for method, m_url, hdrs in extra_cmds[:1 + (seq % 3)]:
                pkt = build_rtsp_request(method, m_url, hdrs)
                logger.info(f"[seq={seq}] Sending {method}")
                sock.sendall(pkt)
                resp = recv_response(sock)
                logger.info(f"[seq={seq}] {method} response: {resp.split(CRLF)[0] if resp else 'timeout'}")
                time.sleep(0.05)

            seq += 1

        except ConnectionRefusedError:
            logger.warning("RTSP server not ready, retrying in 2s...")
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
