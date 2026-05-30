#!/usr/bin/env python3
"""
smoke_test_firecracker.py
──────────────────────────
Real-world end-to-end smoke test for the Firecracker MicroVM sandbox driver.

Boots a REAL MicroVM, sends REAL TCP packets, takes a REAL snapshot,
crashes the target, measures the EXACT snapshot restore latency, and
verifies the target is alive again after restore.

Phases:
    1. Prerequisites    — verify KVM, binary, kernel, rootfs, sudoers
    2. Start            — boot the actual MicroVM (measure boot time)
    3. PING/PONG        — send a LIFA protocol PING, verify PONG
    4. Snapshot         — take a full VM memory snapshot
    5. Crash            — send a PROCESS_DATA overflow packet → SIGSEGV
    6. Restore          — reset_state() via snapshot (measure latency)
    7. Post-restore     — PING again to confirm target is alive
    8. Cleanup          — stop VM, destroy TAP, remove socket

Usage:
    python sandbox/smoke_test_firecracker.py
    python sandbox/smoke_test_firecracker.py --config config.yaml
    python sandbox/smoke_test_firecracker.py --skip-crash

Exit codes:
    0 — all phases passed
    1 — one or more phases failed
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

# ── ANSI Colors ──────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── LIFA Protocol Constants (from vulnerable_server.c) ──────────────────

LIFA_MAGIC = b"\x4C\x49\x46\x41"  # "LIFA"
OPCODE_PING = 0x01
OPCODE_PROCESS = 0x02
PROCESS_BUF_SIZE = 32  # Server's vulnerable buffer size


# =============================================================================
# Helpers
# =============================================================================


def banner(text: str) -> None:
    print(f"\n{BOLD}{'═' * 61}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'═' * 61}{RESET}\n")


def phase_header(num: int, title: str) -> None:
    print(f"\n{CYAN}{BOLD}Phase {num}: {title}{RESET}")
    print(f"{DIM}{'─' * 61}{RESET}")


def ok(msg: str, detail: str = "") -> None:
    suffix = f"  {DIM}({detail}){RESET}" if detail else ""
    print(f"  {GREEN}✓ PASS{RESET}  {msg}{suffix}")


def fail(msg: str, detail: str = "") -> None:
    suffix = f"  {RED}— {detail}{RESET}" if detail else ""
    print(f"  {RED}✗ FAIL{RESET}  {msg}{suffix}")


def warn(msg: str, detail: str = "") -> None:
    suffix = f"  {YELLOW}— {detail}{RESET}" if detail else ""
    print(f"  {YELLOW}⚠ WARN{RESET}  {msg}{suffix}")


def info(msg: str) -> None:
    print(f"  {DIM}→ {msg}{RESET}")


def make_ping_packet(payload: bytes = b"SMOKE") -> bytes:
    """Craft a LIFA PING packet: MAGIC + opcode(0x01) + length + payload."""
    return LIFA_MAGIC + bytes([OPCODE_PING, len(payload)]) + payload


def make_crash_packet() -> bytes:
    """Craft a LIFA PROCESS_DATA packet that overflows the 32-byte buffer.

    Payload is 40 bytes of 0x41 ('A') — 8 bytes past the 32-byte stack buffer.
    This triggers the vulnerable memcpy + NULL function pointer dereference → SIGSEGV.
    """
    payload = b"\x41" * (PROCESS_BUF_SIZE + 8)  # 40 bytes
    return LIFA_MAGIC + bytes([OPCODE_PROCESS, len(payload)]) + payload


async def send_and_receive(
    host: str, port: int, packet: bytes, timeout: float = 5.0
) -> bytes:
    """Send a LIFA packet and return the raw response."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    writer.write(packet)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    writer.close()
    await writer.wait_closed()
    return response


def load_config(config_path: str) -> dict[str, Any]:
    """Load config.yaml if present."""
    try:
        import yaml
        p = Path(config_path)
        if not p.exists():
            return {}
        with open(p, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        return {}


# =============================================================================
# Phase Results Tracker
# =============================================================================


class Results:
    """Track pass/fail for each phase."""

    def __init__(self) -> None:
        self._entries: list[tuple[str, str, str]] = []  # (name, status, detail)

    def passed(self, name: str, detail: str = "") -> None:
        self._entries.append((name, "PASS", detail))

    def failed(self, name: str, detail: str = "") -> None:
        self._entries.append((name, "FAIL", detail))

    def skipped(self, name: str, detail: str = "") -> None:
        self._entries.append((name, "SKIP", detail))

    def print_report(self) -> None:
        print(f"\n{BOLD}{'═' * 61}")
        print("  Firecracker Smoke Test Report")
        print(f"{'═' * 61}{RESET}")

        total = len(self._entries)
        passing = sum(1 for _, s, _ in self._entries if s == "PASS")

        for name, status, detail in self._entries:
            color = GREEN if status == "PASS" else (YELLOW if status == "SKIP" else RED)
            suffix = f"  {DIM}({detail}){RESET}" if detail else ""
            print(f"  {color}{status:<5}{RESET}  {name}{suffix}")

        print(f"\n{BOLD}{'═' * 61}{RESET}")

        if passing == total:
            print(f"  {GREEN}{BOLD}OVERALL: {passing}/{total} PASS{RESET}")
        else:
            print(f"  {RED}{BOLD}OVERALL: {passing}/{total} PASS ({total - passing} FAILED){RESET}")

        # Find restore latency if present
        for name, status, detail in self._entries:
            if "Restore" in name and status == "PASS":
                print(f"  {BOLD}RESTORE LATENCY: {GREEN}{detail}{RESET}")
                break

        print(f"{BOLD}{'═' * 61}{RESET}\n")

    @property
    def all_passed(self) -> bool:
        return all(s == "PASS" for _, s, _ in self._entries)


# =============================================================================
# Main Smoke Test
# =============================================================================


async def run_smoke_test(
    config_path: str = "config.yaml",
    skip_crash: bool = False,
) -> bool:
    """Execute the full smoke test. Returns True if all phases pass."""

    results = Results()
    sandbox: Optional[Any] = None
    interrupted = False

    def _sigint_handler(sig: int, frame: Any) -> None:
        nonlocal interrupted
        interrupted = True
        print(f"\n{YELLOW}Interrupted — cleaning up...{RESET}")

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        # ── Load config ──────────────────────────────────────────────
        config = load_config(config_path)
        fc_cfg = config.get("sandbox", {}).get("firecracker", {})

        binary_path = fc_cfg.get("binary_path", "sandbox/firecracker_env/firecracker")
        vmlinux_path = fc_cfg.get("vmlinux_path", "sandbox/firecracker_env/vmlinux")
        rootfs_path = fc_cfg.get("rootfs_path", "sandbox/firecracker_env/rootfs.ext4")
        snapshot_dir = fc_cfg.get("snapshot_dir", "sandbox/firecracker_env/snapshots")
        kernel_args = fc_cfg.get("kernel_args",
            "console=ttyS0 reboot=k panic=1 pci=off"
            " root=/dev/vda rw"
            " init=/bin/vulnerable_server"
            " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
        )
        mem_size_mb = fc_cfg.get("mem_size_mb", 256)
        vcpu_count = fc_cfg.get("vcpu_count", 2)
        tap_name = fc_cfg.get("tap_name", "tap-lifa0")
        host_ip = fc_cfg.get("host_ip", "172.16.0.1")
        vm_ip = fc_cfg.get("vm_ip", "172.16.0.2")
        target_port = config.get("sandbox", {}).get("upstream_port", 9000)
        socket_path = fc_cfg.get("socket_path", "/tmp/firecracker-lifa.sock")

        # ═══════════════════════════════════════════════════════════════
        # Phase 1: Prerequisites
        # ═══════════════════════════════════════════════════════════════

        phase_header(1, "Prerequisites")

        prereqs_ok = True

        # /dev/kvm
        if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK):
            ok("/dev/kvm accessible")
        else:
            fail("/dev/kvm", "Run: bash sandbox/configure_permissions.sh")
            prereqs_ok = False

        # Binary
        if Path(binary_path).is_file() and os.access(binary_path, os.X_OK):
            ok(f"firecracker binary ({binary_path})")
        else:
            fail("firecracker binary", f"Run: bash sandbox/setup_firecracker.sh")
            prereqs_ok = False

        # Kernel
        if Path(vmlinux_path).is_file():
            size = du_h(vmlinux_path)
            ok(f"vmlinux kernel ({size})")
        else:
            fail("vmlinux kernel", "Run: bash sandbox/firecracker_env/build_kernel.sh")
            prereqs_ok = False

        # RootFS
        if Path(rootfs_path).is_file():
            size = du_h(rootfs_path)
            ok(f"rootfs.ext4 image ({size})")
        else:
            fail("rootfs.ext4 image", "Run: bash sandbox/firecracker_env/build_rootfs.sh")
            prereqs_ok = False

        # Sudoers test (soft check — not a hard blocker)
        proc = await asyncio.create_subprocess_shell(
            "sudo -n ip link show lo",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode == 0:
            ok("passwordless sudo for ip commands")
        else:
            # Not fatal — driver tries bare 'ip' first, then falls back to sudo
            warn(
                "passwordless sudo for ip commands",
                "Driver will try bare 'ip' first — may need configure_permissions.sh",
            )

        if prereqs_ok:
            results.passed("Phase 1: Prerequisites")
        else:
            results.failed("Phase 1: Prerequisites")
            results.print_report()
            return False

        if interrupted:
            return False

        # ═══════════════════════════════════════════════════════════════
        # Phase 2: Start MicroVM
        # ═══════════════════════════════════════════════════════════════

        phase_header(2, "Start MicroVM")

        # Ensure project root is on sys.path for imports
        project_root = str(Path(__file__).resolve().parent.parent)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from sandbox.firecracker_driver import FirecrackerSandbox

        sandbox = FirecrackerSandbox(
            binary_path=binary_path,
            vmlinux_path=vmlinux_path,
            rootfs_path=rootfs_path,
            snapshot_dir=snapshot_dir,
            kernel_args=kernel_args,
            mem_size_mb=mem_size_mb,
            vcpu_count=vcpu_count,
            tap_name=tap_name,
            host_ip=host_ip,
            vm_ip=vm_ip,
            target_port=target_port,
            socket_path=socket_path,
        )

        try:
            t0 = time.perf_counter_ns()
            await sandbox.start()
            t1 = time.perf_counter_ns()
            boot_ms = (t1 - t0) / 1_000_000
            ok(f"VM booted successfully", f"boot: {boot_ms:.0f}ms")
            results.passed("Phase 2: VM Boot", f"{boot_ms:.0f}ms")
        except Exception as e:
            fail(f"VM boot failed: {e}")
            results.failed("Phase 2: VM Boot", str(e)[:80])
            results.print_report()
            return False

        if interrupted:
            return False

        # ═══════════════════════════════════════════════════════════════
        # Phase 3: PING/PONG Verification
        # ═══════════════════════════════════════════════════════════════

        phase_header(3, "PING/PONG Verification")

        try:
            ping_packet = make_ping_packet(b"SMOKE")
            info(f"Sending PING: {ping_packet.hex()}")

            pong = await send_and_receive(vm_ip, target_port, ping_packet)
            info(f"Received:     {pong.hex()}")

            # Verify response
            if (
                len(pong) >= 6
                and pong[:4] == LIFA_MAGIC
                and pong[4] == OPCODE_PING
                and pong[5] == len(b"SMOKE")
                and pong[6:] == b"SMOKE"
            ):
                ok("PONG verified — correct magic, opcode, payload")
                results.passed("Phase 3: PING/PONG")
            else:
                fail("PONG mismatch",
                    f"expected LIFA+0x01+5+SMOKE, got {pong.hex()}")
                results.failed("Phase 3: PING/PONG", "response mismatch")

        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            fail(f"TCP connection failed: {e}")
            results.failed("Phase 3: PING/PONG", str(e)[:80])

        if interrupted:
            return False

        # ═══════════════════════════════════════════════════════════════
        # Phase 4: Take Snapshot
        # ═══════════════════════════════════════════════════════════════

        phase_header(4, "Take Snapshot")

        snapshot_ok = False
        try:
            await sandbox._take_snapshot()

            mem_path = Path(snapshot_dir) / "vm.mem"
            vmstate_path = Path(snapshot_dir) / "vm.vmstate"

            if mem_path.is_file() and vmstate_path.is_file():
                mem_size = du_h(str(mem_path))
                vmstate_size = du_h(str(vmstate_path))
                ok(f"Snapshot created", f"mem: {mem_size}, vmstate: {vmstate_size}")
                results.passed("Phase 4: Snapshot", f"mem={mem_size}, vmstate={vmstate_size}")
                snapshot_ok = True
            else:
                fail("Snapshot files not found on disk")
                results.failed("Phase 4: Snapshot", "files missing")

        except Exception as e:
            fail(f"Snapshot failed: {e}")
            results.failed("Phase 4: Snapshot", str(e)[:80])

        if interrupted:
            return False

        # ═══════════════════════════════════════════════════════════════
        # Phase 5: Crash the Target
        # ═══════════════════════════════════════════════════════════════

        if skip_crash:
            phase_header(5, "Crash Test — SKIPPED (--skip-crash)")
            results.skipped("Phase 5: Crash Test", "--skip-crash")
            results.skipped("Phase 6: Snapshot Restore", "--skip-crash")
            results.skipped("Phase 7: Post-Restore PING", "--skip-crash")
        elif not snapshot_ok:
            phase_header(5, "Crash Test — SKIPPED (no snapshot)")
            info("Cannot test restore without a snapshot — skipping crash test")
            results.skipped("Phase 5: Crash Test", "no snapshot")
            results.skipped("Phase 6: Snapshot Restore", "no snapshot")
            results.skipped("Phase 7: Post-Restore PING", "no snapshot")
        else:
            phase_header(5, "Crash the Target")

            try:
                crash_packet = make_crash_packet()
                info(f"Sending overflow: {crash_packet[:10].hex()}... ({len(crash_packet)} bytes)")

                try:
                    # Send the crash packet — connection may reset
                    await send_and_receive(
                        vm_ip, target_port, crash_packet, timeout=3.0
                    )
                except (ConnectionResetError, asyncio.TimeoutError, BrokenPipeError):
                    pass  # Expected — server crashed

                # Wait for the VM process to exit
                await asyncio.sleep(0.5)

                alive = await sandbox.is_target_alive()
                info(f"is_target_alive() = {alive}")

                if not alive:
                    crash_info = await sandbox.get_last_crash_info()
                    if crash_info:
                        ok(
                            f"Target crashed — signal: {crash_info.signal}, "
                            f"exit_code: {crash_info.exit_code}",
                        )
                        results.passed(
                            "Phase 5: Crash Test",
                            f"signal={crash_info.signal}",
                        )
                    else:
                        ok("Target crashed (no crash info available)")
                        results.passed("Phase 5: Crash Test", "crashed")
                else:
                    fail("Target is still alive after crash packet",
                        "The crash may not have been fatal")
                    results.failed("Phase 5: Crash Test", "target still alive")

            except Exception as e:
                fail(f"Crash test error: {e}")
                results.failed("Phase 5: Crash Test", str(e)[:80])

            if interrupted:
                return False

            # ═══════════════════════════════════════════════════════════
            # Phase 6: Snapshot Restore (THE KEY METRIC)
            # ═══════════════════════════════════════════════════════════

            phase_header(6, "Snapshot Restore (key metric)")

            try:
                info("Calling reset_state()...")
                t0 = time.perf_counter_ns()
                await sandbox.reset_state()
                t1 = time.perf_counter_ns()

                restore_ns = t1 - t0
                restore_ms = restore_ns / 1_000_000

                target_str = "<10ms"
                if restore_ms < 10.0:
                    ok(
                        f"RESTORE LATENCY: {restore_ms:.2f}ms",
                        f"{GREEN}{BOLD}<<< {target_str} TARGET{RESET}",
                    )
                else:
                    fail(
                        f"RESTORE LATENCY: {restore_ms:.2f}ms",
                        f"{RED}EXCEEDS {target_str} TARGET{RESET}",
                    )

                results.passed(
                    "Phase 6: Snapshot Restore",
                    f"{restore_ms:.2f}ms",
                )

            except Exception as e:
                fail(f"Snapshot restore failed: {e}")
                results.failed("Phase 6: Snapshot Restore", str(e)[:80])

            if interrupted:
                return False

            # ═══════════════════════════════════════════════════════════
            # Phase 7: Post-Restore PING
            # ═══════════════════════════════════════════════════════════

            phase_header(7, "Post-Restore PING")

            try:
                ping_packet = make_ping_packet(b"ALIVE")
                info(f"Sending PING: {ping_packet.hex()}")

                pong = await send_and_receive(vm_ip, target_port, ping_packet)
                info(f"Received:     {pong.hex()}")

                if (
                    len(pong) >= 6
                    and pong[:4] == LIFA_MAGIC
                    and pong[4] == OPCODE_PING
                    and pong[5] == len(b"ALIVE")
                    and pong[6:] == b"ALIVE"
                ):
                    ok("PONG verified — target is alive after restore!")
                    results.passed("Phase 7: Post-Restore PING")
                else:
                    fail("PONG mismatch", f"got {pong.hex()}")
                    results.failed("Phase 7: Post-Restore PING", "response mismatch")

            except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
                fail(f"Post-restore connection failed: {e}")
                results.failed("Phase 7: Post-Restore PING", str(e)[:80])

        if interrupted:
            return False

        # ═══════════════════════════════════════════════════════════════
        # Phase 8: Cleanup
        # ═══════════════════════════════════════════════════════════════

        phase_header(8, "Cleanup")

        try:
            await sandbox.stop()
            ok("VM stopped, TAP destroyed, socket removed")
            results.passed("Phase 8: Cleanup")
        except Exception as e:
            fail(f"Cleanup error: {e}")
            results.failed("Phase 8: Cleanup", str(e)[:80])

        sandbox = None  # Prevent double-stop in finally

    except Exception as e:
        fail(f"Unexpected error: {e}")
        results.failed("Unexpected", str(e)[:80])

    finally:
        # Ensure cleanup even on error / interrupt
        if sandbox is not None:
            try:
                info("Emergency cleanup...")
                await sandbox.stop()
            except Exception:
                pass

    results.print_report()
    return results.all_passed


def du_h(path: str) -> str:
    """Get human-readable file size."""
    try:
        size = Path(path).stat().st_size
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.0f}{unit}"
            size /= 1024
        return f"{size:.0f}TB"
    except OSError:
        return "?"


# =============================================================================
# CLI Entry Point
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firecracker Sandbox Smoke Test — Real MicroVM Lifecycle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sandbox/smoke_test_firecracker.py
  python sandbox/smoke_test_firecracker.py --config config.yaml
  python sandbox/smoke_test_firecracker.py --skip-crash
        """,
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    parser.add_argument(
        "--skip-crash", action="store_true",
        help="Skip the crash/recovery test (only boot + PING + stop)",
    )
    args = parser.parse_args()

    banner("Firecracker MicroVM — Real-World Smoke Test")

    success = asyncio.run(run_smoke_test(
        config_path=args.config,
        skip_crash=args.skip_crash,
    ))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
