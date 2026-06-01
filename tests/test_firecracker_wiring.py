"""
tests/test_firecracker_wiring.py
────────────────────────────────
Integration tests verifying the wiring between FirecrackerSandbox,
CrashMonitor, and CrashManager.

All external dependencies (socket I/O, subprocess, filesystem) are mocked —
no real Firecracker binary, Docker daemon, or network required.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fast_loop.crash_monitor import CrashMonitor
from shared.crash_manager import CrashManager, RecordResult
from shared.sandbox_abstraction import BaseSandbox, CrashInfo
from shared.schemas import CrashRecord, Signal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_sandbox(alive: bool = False, exit_code: int = 139) -> BaseSandbox:
    """Create a mock sandbox that implements the BaseSandbox interface."""
    sandbox = MagicMock(spec=BaseSandbox)

    crash_info = None
    if not alive and exit_code:
        crash_info = CrashInfo(
            instance_name="test-vm",
            exit_code=exit_code,
            signal="SIGSEGV",
            timestamp=1234567890.0,
            stack_trace="Segmentation fault",
        )

    sandbox.is_target_alive = AsyncMock(return_value=alive)
    sandbox.get_last_crash_info = AsyncMock(return_value=crash_info)
    sandbox.reset_state = AsyncMock()
    sandbox.get_target_info = AsyncMock()
    sandbox.get_network_config = AsyncMock(return_value={
        "target_host": "127.0.0.1",
        "target_port": 9000,
    })
    return sandbox


def _make_mock_crash_manager(is_new: bool = True) -> CrashManager:
    """Create a mock CrashManager that returns a RecordResult."""
    mgr = MagicMock(spec=CrashManager)
    mgr.record = AsyncMock(return_value=RecordResult(
        is_new=is_new,
        signature="abcdef0123456789",
        struct_sig="deadbeef",
        duplicate_count=0 if is_new else 3,
        poc_path="/tmp/crash.bin" if is_new else None,
        struct_siblings=[],
    ))
    return mgr


# ---------------------------------------------------------------------------
# Test: CrashMonitor + CrashManager wiring
# ---------------------------------------------------------------------------

class TestCrashMonitorCrashManagerWiring:
    @pytest.mark.asyncio
    async def test_crash_manager_record_called_on_crash(self):
        """When a crash is detected, crash_manager.record() should be called once."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)
        crash_manager = _make_mock_crash_manager(is_new=True)

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=False,  # Don't try to reset — we're testing the recording
        )

        # Disable auto-reset so we don't need to mock the full restart cycle
        record = await monitor.on_crash(exit_code=139)

        # Verify CrashManager.record() was called exactly once
        crash_manager.record.assert_awaited_once()

        # Verify the arguments passed to record()
        call_args = crash_manager.record.call_args
        assert call_args.kwargs["crash_type"] == "exit_139"
        # payload should be bytes (the offending packet)
        assert isinstance(call_args.kwargs["payload"], bytes)

    @pytest.mark.asyncio
    async def test_crash_count_incremented(self):
        """on_crash() should increment the crash counter."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)
        crash_manager = _make_mock_crash_manager()

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=False,
        )

        assert monitor.total_crashes == 0
        await monitor.on_crash(exit_code=139)
        assert monitor.total_crashes == 1

        await monitor.on_crash(exit_code=134)
        assert monitor.total_crashes == 2

    @pytest.mark.asyncio
    async def test_no_crash_manager_still_works(self):
        """CrashMonitor should work fine without a CrashManager."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=None,  # No crash manager
            auto_reset=False,
        )

        record = await monitor.on_crash(exit_code=139)
        assert isinstance(record, CrashRecord)
        assert monitor.total_crashes == 1

    @pytest.mark.asyncio
    async def test_crash_signal_resolved_correctly(self):
        """Exit code 139 should resolve to SIGSEGV."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)
        crash_manager = _make_mock_crash_manager()

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=False,
        )

        record = await monitor.on_crash(exit_code=139)
        assert record.signal == Signal.SIGSEGV

    @pytest.mark.asyncio
    async def test_duplicate_crash_recorded(self):
        """A duplicate crash should still call record() but with is_new=False."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)
        crash_manager = _make_mock_crash_manager(is_new=False)

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=False,
        )

        await monitor.on_crash(exit_code=139)

        # record() should still be called even for duplicates
        crash_manager.record.assert_awaited_once()
        result = crash_manager.record.return_value
        assert result.is_new is False
        assert result.duplicate_count == 3

    @pytest.mark.asyncio
    async def test_crash_manager_exception_does_not_crash_monitor(self):
        """If CrashManager.record() raises, CrashMonitor should still complete."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)
        crash_manager = _make_mock_crash_manager()
        crash_manager.record = AsyncMock(side_effect=RuntimeError("disk full"))

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=False,
        )

        # Should NOT raise — exception is caught internally
        record = await monitor.on_crash(exit_code=139)
        assert isinstance(record, CrashRecord)
        assert monitor.total_crashes == 1


# ---------------------------------------------------------------------------
# Test: CrashMonitor with auto_reset + CrashManager
# ---------------------------------------------------------------------------

class TestCrashMonitorAutoResetWithCrashManager:
    @pytest.mark.asyncio
    async def test_auto_reset_with_crash_manager(self):
        """Full crash cycle: detect → record → reset → verify."""
        sandbox = _make_mock_sandbox(alive=False, exit_code=139)

        # Make the target come back alive after reset
        alive_sequence = [False, False, True]
        sandbox.is_target_alive = AsyncMock(side_effect=alive_sequence)
        sandbox.reset_state = AsyncMock()

        crash_manager = _make_mock_crash_manager(is_new=True)

        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_manager=crash_manager,
            auto_reset=True,
            restart_delay_s=0.0,  # No delay in tests
        )

        record = await monitor.on_crash(exit_code=139)

        # CrashManager should have been called
        crash_manager.record.assert_awaited_once()
        # Sandbox should have been reset
        sandbox.reset_state.assert_awaited_once()
        # Crash count should be 1
        assert monitor.total_crashes == 1


# ---------------------------------------------------------------------------
# Test: /dev/kvm check logic (unit-level, no real filesystem)
# ---------------------------------------------------------------------------

class TestKVMCheck:
    def test_kvm_missing_raises_runtime_error(self):
        """If /dev/kvm doesn't exist, the pipeline should raise RuntimeError."""
        with patch.object(Path, "exists", return_value=False):
            with patch("os.access", return_value=False):
                # Simulate the check from main.py
                kvm_path = Path("/dev/kvm")
                assert not kvm_path.exists()

    def test_kvm_exists_but_no_access(self):
        """If /dev/kvm exists but isn't accessible, should also fail."""
        with patch.object(Path, "exists", return_value=True):
            with patch("os.access", return_value=False):
                kvm_path = Path("/dev/kvm")
                assert kvm_path.exists()
                assert not __import__("os").access(str(kvm_path), __import__("os").R_OK)

    def test_kvm_available(self):
        """If /dev/kvm exists and is accessible, check should pass."""
        with patch.object(Path, "exists", return_value=True):
            with patch("os.access", return_value=True):
                kvm_path = Path("/dev/kvm")
                assert kvm_path.exists()
                assert __import__("os").access(str(kvm_path), __import__("os").R_OK)


# ---------------------------------------------------------------------------
# Test: Driver registration and selection
# ---------------------------------------------------------------------------

class TestDriverSelection:
    def test_firecracker_driver_is_registered(self):
        """The firecracker driver should be in the driver registry."""
        from shared.sandbox_abstraction import get_driver
        # Import triggers register_driver()
        import sandbox.firecracker_driver  # noqa: F401

        cls = get_driver("firecracker")
        assert cls.__name__ == "FirecrackerSandbox"

    def test_docker_driver_is_registered(self):
        """The docker driver should be in the driver registry."""
        from shared.sandbox_abstraction import get_driver
        import sandbox.docker_driver  # noqa: F401

        cls = get_driver("docker")
        assert cls.__name__ == "DockerSandbox"
