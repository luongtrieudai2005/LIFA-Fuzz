#!/usr/bin/env python3
"""
Empirical test of the Firecracker gcov flush mechanism for LightFTP coverage.

Boots the COVERAGE rootfs (rootfs_lightftp_coverage.ext4), sends a few FTP
packets so fftp executes code, then stops the VM (stop() sends SendCtrlAltDel
→ guest SIGINT to PID 1 → gcov_flush handler → __gcov_dump). Then extracts
/opt/cov from the rootfs via debugfs and checks for .gcda.

PROVES (empirically, not by assumption): boot → traffic → CtrlAltDel → .gcda
written to the persistent rootfs at /opt/cov.

Usage: python3 scripts/test_coverage_flush.py
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

COVERAGE_ROOTFS = "sandbox/firecracker_env/rootfs_lightftp_coverage.ext4"


async def send_ftp_traffic(host: str, port: int) -> None:
    """Send a minimal FTP session so fftp runs enough code to register coverage."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        banner = await asyncio.wait_for(reader.read(256), timeout=5)
        print(f"  banner: {banner[:40]!r}")
        for cmd in [b"USER admin\r\n", b"PASS *\r\n", b"SYST\r\n", b"QUIT\r\n"]:
            writer.write(cmd)
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(256), timeout=2)
                print(f"  {cmd.strip().decode()} -> {resp[:30]!r}")
            except asyncio.TimeoutError:
                pass
        writer.close()
    except Exception as e:
        print(f"  (traffic send warning: {e})")


def debugfs_extract_gcda(rootfs: str) -> int:
    """Extract /opt/cov from rootfs via debugfs; return count of .gcda found."""
    if not shutil.which("debugfs"):
        print("  debugfs not found on host")
        return -1
    out = subprocess.run(
        ["debugfs", "-R", "ls -l /opt/cov", rootfs],
        capture_output=True, text=True, timeout=15,
    )
    print(f"  debugfs ls /opt/cov:\n{out.stdout.strip()}")
    # .gcda live under /opt/cov/tmp/LightFTP/Source/Release/ (GCOV_PREFIX + baked path)
    out2 = subprocess.run(
        ["debugfs", "-R", "ls -l /opt/cov/tmp/LightFTP/Source/Release", rootfs],
        capture_output=True, text=True, timeout=15,
    )
    print(f"  debugfs ls .../Release:\n{out2.stdout.strip()}")
    return out2.stdout.count(".gcda")


async def main() -> int:
    from sandbox.firecracker_driver import FirecrackerSandbox

    if not Path(COVERAGE_ROOTFS).exists():
        print(f"[err] {COVERAGE_ROOTFS} not built. Run build_rootfs_lightftp_coverage.sh")
        return 2

    print("=== boot coverage VM ===")
    # cov_duration=8 → /init watchdog SIGTERMs fftp after 8s → handler flushes.
    sb = FirecrackerSandbox(
        rootfs_path=COVERAGE_ROOTFS,
        target_name="lightftp",
        vm_ip="172.16.0.2",
        kernel_args=(
            "console=ttyS0 reboot=k panic=1 pci=off"
            " root=/dev/vda rw init=/init"
            " cov_duration=8"
            " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
        ),
    )
    try:
        await sb.start()
        print("  VM booted — sending FTP traffic...")
        await send_ftp_traffic("172.16.0.2", 21)
        # Wait for the /init watchdog (cov_duration=8s) to SIGTERM fftp →
        # gcov_flush + sync, then guest halt. Give margin for flush+sync.
        print("  waiting 15s for /init timer flush (default DUR=10) + sync...")
        await asyncio.sleep(15)
    finally:
        print("=== stop VM (guest should have self-halted after flush) ===")
        await sb.stop()

    print("\n=== extract /opt/cov from rootfs via debugfs ===")
    n = debugfs_extract_gcda(COVERAGE_ROOTFS)
    print(f"\n>>> .gcda count in /opt/cov: {n}")
    if n > 0:
        print(">>> FLUSH MECHANISM PROVEN ✓ — coverage extraction is viable.")
        return 0
    print(">>> NO .gcda — flush mechanism did NOT work. Investigate before FC2.")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
