"""
tests/test_e2e_crash_detection.py
──────────────────────────────────
End-to-end integration test: crash detection with a real C server.

Starts the vulnerable_server subprocess, sends crash-triggering payloads,
and verifies that CrashMonitor + CrashManager correctly detect, record,
and recover from crashes.

Skip condition: requires gcc to compile the test server.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from fast_loop.crash_monitor import CrashMonitor
from shared.crash_manager import CrashManager, RecordResult
from shared.sandbox_abstraction import BaseSandbox, CrashInfo
from shared.schemas import CrashRecord

# ---------------------------------------------------------------------------
# Skip if no gcc
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    shutil.which("gcc") is None,
    reason="gcc not available — skipping E2E crash detection test",
)

# Path to the vulnerable server binary
DUMMY_DIR = Path(__file__).parent / "dummy_targets"
SERVER_BINARY = DUMMY_DIR / "vulnerable_server"
SERVER_SOURCE = DUMMY_DIR / "vulnerable_server.c"


# ---------------------------------------------------------------------------
# SubprocessSandbox — lightweight sandbox wrapping the C server
# ---------------------------------------------------------------------------

class SubprocessSandbox(BaseSandbox):
    """A minimal BaseSandbox that manages a subprocess-based TCP server.

    Used for E2E tests where Docker is not available.
    """

    def __init__(self, port: int = 19876) -> None:
        self._port = port
        self._process: Optional[subprocess.Popen] = None
        self._crash_exit_code: Optional[int] = None
        self._crash_time: float = 0.0
        self._reset_count: int = 0

    def _build(self) -> None:
        """Compile the vulnerable server if binary doesn't exist."""
        if not SERVER_BINARY.exists():
            result = subprocess.run(
                ["gcc", "-o", str(SERVER_BINARY), str(SERVER_SOURCE),
                 "-Wall", "-Wextra", "-O0", "-g", "-fno-stack-protector"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Compilation failed: {result.stderr}")

    async def start(self) -> None:
        self._build()
        # Kill any stale process occupying our port
        self._kill_port_user()
        self._process = subprocess.Popen(
            [str(SERVER_BINARY), str(self._port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Wait for server to start listening
        for _ in range(50):
            if self._is_port_open():
                return
            await asyncio.sleep(0.1)
        raise RuntimeError(f"Server did not start on port {self._port}")

    async def stop(self) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
            self._process = None

    async def reset_state(self) -> None:
        self._reset_count += 1
        await self.stop()
        self._crash_exit_code = None
        await self.start()

    async def get_target_info(self):
        from shared.sandbox_abstraction import ContainerInfo
        status = "running" if await self.is_target_alive() else "stopped"
        return ContainerInfo(
            name="vulnerable-server",
            host="127.0.0.1",
            port=self._port,
            internal_port=self._port,
            status=status,
        )

    async def is_target_alive(self) -> bool:
        """Check if the server process is still running (not crashed)."""
        if self._process is None:
            return False
        rc = self._process.poll()
        if rc is not None:
            # Python subprocess.poll() returns negative values when a
            # process is killed by signal (e.g., -11 for SIGSEGV).
            # Normalise to the Unix convention: 128 + signum.
            if rc < 0:
                rc = 128 + abs(rc)
            self._crash_exit_code = rc
            self._crash_time = time.time()
            return False
        return True

    async def get_last_crash_info(self) -> Optional[CrashInfo]:
        if self._crash_exit_code is None:
            return None
        # Signal map: Unix convention 128 + signum
        signal_map = {
            139: "SIGSEGV",  # 128 + 11
            134: "SIGABRT",  # 128 + 6
            136: "SIGFPE",   # 128 + 8
            137: "SIGKILL",  # 128 + 9
            135: "SIGBUS",   # 128 + 7
        }
        return CrashInfo(
            instance_name="vulnerable-server",
            exit_code=self._crash_exit_code,
            signal=signal_map.get(self._crash_exit_code),
            timestamp=self._crash_time,
        )

    async def get_network_config(self) -> dict:
        return {
            "network_name": "test-network",
            "subnet": "127.0.0.1/32",
            "target_host": "127.0.0.1",
            "target_port": self._port,
            "proxy_listen_port": self._port + 1,
            "sandbox_type": "subprocess",
        }

    def _kill_port_user(self) -> None:
        """Kill any stale process occupying our port from a previous test run."""
        try:
            result = subprocess.run(
                ["lsof", "-ti", f":{self._port}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    pid = int(pid_str.strip())
                    if pid != os.getpid():
                        try:
                            os.kill(pid, 9)
                        except (ProcessLookupError, PermissionError):
                            pass
                time.sleep(0.2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # lsof not available — best effort

    def _is_port_open(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("127.0.0.1", self._port))
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            return False

    @property
    def reset_count(self) -> int:
        return self._reset_count


# ---------------------------------------------------------------------------
# Helper: send raw bytes to the server
# ---------------------------------------------------------------------------

def _send_to_server(port: int, *payloads: bytes) -> list[bytes]:
    """Open TCP connection, send payloads sequentially, return responses.

    Each payload is sent individually with a response read in between
    to ensure the server processes them as separate protocol steps.
    """
    responses = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(("127.0.0.1", port))
        for payload in payloads:
            s.sendall(payload)
            # Wait briefly for the server to process before sending next
            time.sleep(0.05)
            try:
                resp = s.recv(4096)
                responses.append(resp)
            except (socket.timeout, ConnectionResetError, OSError):
                responses.append(b"")
    except (ConnectionRefusedError, OSError):
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return responses


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestE2ECrashDetection:
    @pytest.mark.asyncio
    async def test_crash_detection_and_recovery(self, tmp_path):
        """Full E2E: start server → crash it → detect → record → reset → alive."""
        port = 19876
        sandbox = SubprocessSandbox(port=port)

        try:
            # Start server
            await sandbox.start()
            assert await sandbox.is_target_alive()

            # Set up CrashMonitor with CrashManager
            crash_dir = tmp_path / "crashes"
            crash_dir.mkdir()
            crash_manager = CrashManager(crash_dir=str(crash_dir))

            monitor = CrashMonitor(
                sandbox=sandbox,
                crash_manager=crash_manager,
                auto_reset=False,  # We'll trigger on_crash manually
                crash_corpus_dir=str(crash_dir),
            )

            # Send normal handshake — should succeed
            resp = _send_to_server(port, b"HELLO\n", b"normal payload\n")
            assert len(resp) >= 1
            assert b"OK" in resp[0]

            # Send crash-triggering payload
            _send_to_server(port, b"HELLO\n", b"CRASH_ME\n")

            # Wait for crash to propagate
            await asyncio.sleep(0.3)

            # Verify server is dead
            alive = await sandbox.is_target_alive()
            assert not alive, "Server should be dead after CRASH_ME payload"

            # Get crash info — exit code varies by signal handling
            crash_info = await sandbox.get_last_crash_info()
            assert crash_info is not None
            # Exit code should indicate abnormal termination
            assert crash_info.exit_code != 0, (
                f"Expected non-zero exit code, got {crash_info.exit_code}"
            )

            # Trigger crash handler
            exit_code = crash_info.exit_code if crash_info else 139
            record = await monitor.on_crash(exit_code=exit_code)

            # Verify crash was recorded
            assert monitor.total_crashes == 1
            assert isinstance(record, CrashRecord)

            # Reset the target
            await sandbox.reset_state()

            # Verify target is alive again
            assert await sandbox.is_target_alive()

            # Send normal payload to verify recovery
            resp = _send_to_server(port, b"HELLO\n", b"back alive\n")
            assert len(resp) >= 1
            assert b"OK" in resp[0]
        finally:
            await sandbox.stop()

    @pytest.mark.asyncio
    async def test_overflow_triggers_crash(self, tmp_path):
        """Sending >1024 bytes should trigger SIGSEGV."""
        port = 19877
        sandbox = SubprocessSandbox(port=port)

        try:
            await sandbox.start()
            assert await sandbox.is_target_alive()

            # Send oversized payload (>1024 bytes)
            _send_to_server(port, b"HELLO\n", b"A" * 1025)

            await asyncio.sleep(0.3)

            alive = await sandbox.is_target_alive()
            assert not alive, "Server should crash on oversized payload"
        finally:
            await sandbox.stop()
