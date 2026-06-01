"""
tests/test_firecracker_driver.py
─────────────────────────────────
Tests for the Firecracker MicroVM sandbox driver.

Since Firecracker requires /dev/kvm, most tests use mocks to verify
the driver's logic without actually spawning a VM. A subset of tests
can be run in environments with KVM available (marked with @pytest.mark.kvm).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sandbox.firecracker_driver import (
    FirecrackerAPIClient,
    FirecrackerSandbox,
    TAPDeviceManager,
    UDSConnector,
)
from shared.sandbox_abstraction import (
    SandboxDriver,
    SandboxStartError,
    get_driver,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def fc_sandbox(tmp_path: Path) -> FirecrackerSandbox:
    """Create a FirecrackerSandbox with temp paths for isolation."""
    return FirecrackerSandbox(
        binary_path=str(tmp_path / "firecracker"),
        vmlinux_path=str(tmp_path / "vmlinux"),
        rootfs_path=str(tmp_path / "rootfs.ext4"),
        snapshot_dir=str(tmp_path / "snapshots"),
        socket_path=str(tmp_path / "fc.sock"),
        tap_name="tap-test0",
        host_ip="172.16.0.1",
        vm_ip="172.16.0.2",
        target_port=9000,
    )


@pytest.fixture
def fc_sandbox_with_files(tmp_path: Path) -> FirecrackerSandbox:
    """Create a FirecrackerSandbox with stub files present."""
    # Create stub binary
    binary = tmp_path / "firecracker"
    binary.write_text("#!/bin/sh\ntrue")
    binary.chmod(0o755)

    # Create stub kernel and rootfs
    (tmp_path / "vmlinux").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (tmp_path / "rootfs.ext4").write_bytes(b"\x00" * 1024)

    return FirecrackerSandbox(
        binary_path=str(binary),
        vmlinux_path=str(tmp_path / "vmlinux"),
        rootfs_path=str(tmp_path / "rootfs.ext4"),
        snapshot_dir=str(tmp_path / "snapshots"),
        socket_path=str(tmp_path / "fc.sock"),
        tap_name="tap-test0",
        host_ip="172.16.0.1",
        vm_ip="172.16.0.2",
        target_port=9000,
    )


# =============================================================================
# Driver Registration Tests
# =============================================================================


class TestDriverRegistration:
    """Verify the Firecracker driver is properly registered."""

    def test_driver_registered(self) -> None:
        """Firecracker driver should be discoverable via get_driver."""
        driver_cls = get_driver("firecracker")
        assert driver_cls is FirecrackerSandbox

    def test_driver_enum_value(self) -> None:
        """SandboxDriver.FIRECRACKER should have value 'firecracker'."""
        assert SandboxDriver.FIRECRACKER.value == "firecracker"


# =============================================================================
# Prerequisites Tests
# =============================================================================


class TestPrerequisites:
    """Test prerequisite checking logic."""

    def test_no_kvm_raises(self, fc_sandbox: FirecrackerSandbox) -> None:
        """Missing /dev/kvm should raise SandboxStartError."""
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(SandboxStartError, match="/dev/kvm"):
                fc_sandbox._check_prerequisites()

    def test_no_binary_raises(
        self, fc_sandbox_with_files: FirecrackerSandbox
    ) -> None:
        """Missing Firecracker binary should raise SandboxStartError."""
        # Delete the binary file
        Path(fc_sandbox_with_files.binary_path).unlink()

        with patch("sandbox.firecracker_driver.Path.exists", return_value=True), \
             patch("sandbox.firecracker_driver.Path.is_file", return_value=False), \
             patch("sandbox.firecracker_driver.os.access", return_value=True):
            with pytest.raises(SandboxStartError, match="binary"):
                fc_sandbox_with_files._check_prerequisites()

    def test_no_kernel_raises(
        self, fc_sandbox_with_files: FirecrackerSandbox
    ) -> None:
        """Missing kernel should raise SandboxStartError."""
        Path(fc_sandbox_with_files.vmlinux_path).unlink()

        def mock_is_file(self_path: Path) -> bool:
            # Binary and rootfs are files, kernel is not
            if str(self_path) == str(fc_sandbox_with_files.vmlinux_path):
                return False
            return True

        with patch("sandbox.firecracker_driver.Path.exists", return_value=True), \
             patch("sandbox.firecracker_driver.Path.is_file", mock_is_file), \
             patch("sandbox.firecracker_driver.os.access", return_value=True):
            with pytest.raises(SandboxStartError, match="kernel"):
                fc_sandbox_with_files._check_prerequisites()

    def test_no_rootfs_raises(
        self, fc_sandbox_with_files: FirecrackerSandbox
    ) -> None:
        """Missing rootfs should raise SandboxStartError."""
        Path(fc_sandbox_with_files.rootfs_path).unlink()

        def mock_is_file(self_path: Path) -> bool:
            # Binary and kernel are files, rootfs is not
            if str(self_path) == str(fc_sandbox_with_files.rootfs_path):
                return False
            return True

        with patch("sandbox.firecracker_driver.Path.exists", return_value=True), \
             patch("sandbox.firecracker_driver.Path.is_file", mock_is_file), \
             patch("sandbox.firecracker_driver.os.access", return_value=True):
            with pytest.raises(SandboxStartError, match="RootFS"):
                fc_sandbox_with_files._check_prerequisites()


# =============================================================================
# Lifecycle Tests (mocked)
# =============================================================================


class TestLifecycle:
    """Test start/stop/reset lifecycle with mocked Firecracker process."""

    @pytest.mark.asyncio
    async def test_is_target_alive_no_process(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """is_target_alive should return False when no process."""
        assert await fc_sandbox.is_target_alive() is False

    @pytest.mark.asyncio
    async def test_is_target_alive_process_running(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """is_target_alive should return True when process is running."""
        mock_proc = MagicMock()
        mock_proc.returncode = None  # Still running
        fc_sandbox._process = mock_proc

        assert await fc_sandbox.is_target_alive() is True

    @pytest.mark.asyncio
    async def test_is_target_alive_process_exited(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """is_target_alive should return False when process has exited."""
        mock_proc = MagicMock()
        mock_proc.returncode = 139  # SIGSEGV
        fc_sandbox._process = mock_proc

        assert await fc_sandbox.is_target_alive() is False
        assert fc_sandbox._last_exit_code == 139

    @pytest.mark.asyncio
    async def test_get_target_info_running(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """get_target_info should return correct info for running VM."""
        mock_proc = MagicMock()
        mock_proc.returncode = None
        fc_sandbox._process = mock_proc

        info = await fc_sandbox.get_target_info()
        assert info.host == "172.16.0.2"
        assert info.port == 9000
        assert info.status == "running"
        assert info.exit_code is None

    @pytest.mark.asyncio
    async def test_get_target_info_exited(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """get_target_info should return 'exited' status for crashed VM."""
        mock_proc = MagicMock()
        mock_proc.returncode = 139
        fc_sandbox._process = mock_proc

        info = await fc_sandbox.get_target_info()
        assert info.status == "exited"
        assert info.exit_code == 139

    @pytest.mark.asyncio
    async def test_get_network_config(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """get_network_config should return TAP-based network topology."""
        config = await fc_sandbox.get_network_config()
        assert config["target_host"] == "172.16.0.2"
        assert config["target_port"] == 9000
        assert config["sandbox_type"] == "firecracker"
        assert "tap-test0" in config["network_name"]

    @pytest.mark.asyncio
    async def test_get_last_crash_info_no_crash(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """get_last_crash_info should return None when VM is running."""
        mock_proc = MagicMock()
        mock_proc.returncode = None
        fc_sandbox._process = mock_proc

        result = await fc_sandbox.get_last_crash_info()
        assert result is None

    @pytest.mark.asyncio
    async def test_get_last_crash_info_with_crash(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """get_last_crash_info should return CrashInfo for SIGSEGV."""
        mock_proc = MagicMock()
        mock_proc.returncode = 139
        mock_proc.stdout = AsyncMock()
        mock_proc.stdout.read = AsyncMock(return_value=b"Kernel panic - not syncing")

        fc_sandbox._process = mock_proc
        fc_sandbox._last_exit_time = 12345.0

        crash = await fc_sandbox.get_last_crash_info()
        assert crash is not None
        assert crash.exit_code == 139
        assert crash.signal == "SIGSEGV"
        assert crash.timestamp == 12345.0


# =============================================================================
# Snapshot Tests
# =============================================================================


class TestSnapshot:
    """Test snapshot file existence checks."""

    def test_snapshot_files_not_exist(
        self, fc_sandbox: FirecrackerSandbox, tmp_path: Path
    ) -> None:
        """_snapshot_files_exist should return False when files missing."""
        fc_sandbox.snapshot_dir = tmp_path / "snapshots"
        assert fc_sandbox._snapshot_files_exist() is False

    def test_snapshot_files_exist(
        self, fc_sandbox: FirecrackerSandbox, tmp_path: Path
    ) -> None:
        """_snapshot_files_exist should return True when files present."""
        snap_dir = tmp_path / "snapshots"
        snap_dir.mkdir()
        (snap_dir / "vm.mem").write_bytes(b"\x00" * 100)
        (snap_dir / "vm.vmstate").write_bytes(b"\x00" * 100)
        fc_sandbox.snapshot_dir = snap_dir
        assert fc_sandbox._snapshot_files_exist() is True


# =============================================================================
# Sudo-Aware _run_ip() Tests
# =============================================================================


class TestRunIPSudo:
    """Test that _run_ip() prepends sudo when not running as root."""

    @pytest.mark.asyncio
    async def test_run_ip_uses_bare_ip_when_not_root_but_has_caps(self) -> None:
        """_run_ip should use bare 'ip' when not root but it succeeds (user has caps)."""
        with patch("sandbox.firecracker_driver.os.geteuid", return_value=1000):
            with patch(
                "sandbox.firecracker_driver.asyncio.create_subprocess_shell"
            ) as mock_shell:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
                mock_proc.returncode = 0
                mock_shell.return_value = mock_proc

                await TAPDeviceManager._run_ip("link set dev tap0 up")

                # Bare 'ip' succeeded — no sudo needed
                call_args = mock_shell.call_args[0][0]
                assert call_args == "ip link set dev tap0 up"
                # Only called once (bare ip, no sudo fallback)
                assert mock_shell.call_count == 1

    @pytest.mark.asyncio
    async def test_run_ip_falls_back_to_sudo_when_bare_ip_fails(self) -> None:
        """_run_ip should fall back to 'sudo -n /sbin/ip' when bare ip fails."""
        with patch("sandbox.firecracker_driver.os.geteuid", return_value=1000):
            with patch(
                "sandbox.firecracker_driver.asyncio.create_subprocess_shell"
            ) as mock_shell:
                # First call (bare ip) fails, second call (sudo) succeeds
                fail_proc = AsyncMock()
                fail_proc.communicate = AsyncMock(return_value=(b"", b"Operation not permitted"))
                fail_proc.returncode = 1

                ok_proc = AsyncMock()
                ok_proc.communicate = AsyncMock(return_value=(b"", b""))
                ok_proc.returncode = 0

                mock_shell.side_effect = [fail_proc, ok_proc]

                await TAPDeviceManager._run_ip("link set dev tap0 up")

                # Second call should use sudo
                sudo_call_args = mock_shell.call_args_list[1][0][0]
                assert "sudo -n /sbin/ip" in sudo_call_args
                assert "link set dev tap0 up" in sudo_call_args

    @pytest.mark.asyncio
    async def test_run_ip_no_sudo_when_root(self) -> None:
        """_run_ip should use bare 'ip' when euid == 0 (running as root)."""
        with patch("sandbox.firecracker_driver.os.geteuid", return_value=0):
            with patch(
                "sandbox.firecracker_driver.asyncio.create_subprocess_shell"
            ) as mock_shell:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
                mock_proc.returncode = 0
                mock_shell.return_value = mock_proc

                await TAPDeviceManager._run_ip("link set dev tap0 up")

                # Verify the command does NOT include sudo
                call_args = mock_shell.call_args[0][0]
                assert "sudo" not in call_args
                assert call_args.startswith("ip ")


# =============================================================================
# Signal Mapping Tests
# =============================================================================


class TestSignalMapping:
    """Test exit code to signal name mapping."""

    def test_sigsegv(self) -> None:
        assert FirecrackerSandbox._map_exit_code_to_signal(139) == "SIGSEGV"

    def test_sigabrt(self) -> None:
        assert FirecrackerSandbox._map_exit_code_to_signal(134) == "SIGABRT"

    def test_sigkill(self) -> None:
        assert FirecrackerSandbox._map_exit_code_to_signal(137) == "SIGKILL"

    def test_sigterm(self) -> None:
        assert FirecrackerSandbox._map_exit_code_to_signal(143) == "SIGTERM"

    def test_negative_signal(self) -> None:
        """Python subprocess returns negative values for signal kills."""
        import signal as sig
        result = FirecrackerSandbox._map_exit_code_to_signal(-sig.SIGSEGV)
        assert result == "SIGSEGV"

    def test_unknown_exit_code(self) -> None:
        """Unknown exit code should return None."""
        result = FirecrackerSandbox._map_exit_code_to_signal(42)
        assert result is None

    def test_clean_exit(self) -> None:
        """Exit code 0 (clean) should return None."""
        result = FirecrackerSandbox._map_exit_code_to_signal(0)
        assert result is None


# =============================================================================
# TAP Device Manager Tests
# =============================================================================


class TestTAPDeviceManager:
    """Test TAP device management."""

    def test_init_defaults(self) -> None:
        tap = TAPDeviceManager()
        assert tap.tap_name == "tap-lifa0"
        assert tap.host_ip == "172.16.0.1"
        assert tap.vm_ip == "172.16.0.2"
        assert tap._created is False

    @pytest.mark.asyncio
    async def test_create_already_exists(self) -> None:
        """create() should skip if device already exists."""
        tap = TAPDeviceManager(tap_name="lo")  # lo always exists

        with patch.object(tap, "_device_exists", return_value=True):
            await tap.create()
            assert tap._created is True


# =============================================================================
# Process Kill Tests
# =============================================================================


class TestProcessKill:
    """Test process management helpers."""

    @pytest.mark.asyncio
    async def test_kill_no_process(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """_kill_process should be safe when no process exists."""
        await fc_sandbox._kill_process()  # Should not raise

    @pytest.mark.asyncio
    async def test_kill_already_exited(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """_kill_process should handle already-exited processes."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        fc_sandbox._process = mock_proc

        await fc_sandbox._kill_process()
        assert fc_sandbox._process is None
        assert fc_sandbox._last_exit_code == 0

    @pytest.mark.asyncio
    async def test_kill_terminates_gracefully(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """_kill_process should SIGTERM first, then SIGKILL."""
        mock_proc = MagicMock()
        mock_proc.returncode = None
        # Simulate SIGTERM working
        mock_proc.wait = AsyncMock(return_value=None)

        fc_sandbox._process = mock_proc
        await fc_sandbox._kill_process()

        mock_proc.send_signal.assert_called_once()

    @pytest.mark.asyncio
    async def test_kill_force_on_timeout(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """_kill_process should SIGKILL if SIGTERM times out."""
        mock_proc = MagicMock()
        mock_proc.returncode = None

        # First wait (SIGTERM) times out, second wait (SIGKILL) succeeds
        call_count = 0

        async def mock_wait():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()

        mock_proc.wait = mock_wait
        fc_sandbox._process = mock_proc

        await fc_sandbox._kill_process()
        mock_proc.kill.assert_called_once()


# =============================================================================
# Reset State Tests
# =============================================================================


class TestResetState:
    """Test reset_state() logic."""

    @pytest.mark.asyncio
    async def test_reset_no_snapshot_falls_back(
        self, fc_sandbox: FirecrackerSandbox
    ) -> None:
        """reset_state() without snapshot should fall back to cold reset."""
        fc_sandbox._snapshot_taken = False

        # Mock stop and start to avoid actual VM operations
        with patch.object(fc_sandbox, "stop", new_callable=AsyncMock) as mock_stop, \
             patch.object(fc_sandbox, "start", new_callable=AsyncMock) as mock_start:
            await fc_sandbox.reset_state()
            mock_stop.assert_called_once()
            mock_start.assert_called_once()


# =============================================================================
# Constructor Tests
# =============================================================================


class TestConstructor:
    """Test FirecrackerSandbox constructor defaults."""

    def test_default_paths(self) -> None:
        sb = FirecrackerSandbox()
        assert sb.binary_path == Path("sandbox/firecracker_env/firecracker")
        assert sb.vmlinux_path == Path("sandbox/firecracker_env/vmlinux")
        assert sb.rootfs_path == Path("sandbox/firecracker_env/rootfs.ext4")
        assert sb.target_name == "vulnerable_server"
        assert "init=/bin/vulnerable_server" in sb.kernel_args
        assert sb.mem_size_mb == 256
        assert sb.vcpu_count == 2
        assert sb.vm_ip == "172.16.0.2"
        assert sb.target_port == 9000

    def test_lighttpd_target_defaults(self) -> None:
        """target_name='lighttpd' should select lighttpd rootfs + init=/init."""
        sb = FirecrackerSandbox(target_name="lighttpd")
        assert sb.rootfs_path == Path("sandbox/firecracker_env/rootfs_lighttpd.ext4")
        assert sb.kernel_args == (
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init"
        )
        assert sb.target_name == "lighttpd"

    def test_explicit_rootfs_overrides_target(self) -> None:
        """Explicit rootfs_path should not be overridden by target_name."""
        sb = FirecrackerSandbox(
            target_name="lighttpd",
            rootfs_path="/custom/rootfs.ext4",
        )
        assert sb.rootfs_path == Path("/custom/rootfs.ext4")

    def test_explicit_kernel_args_overrides_target(self) -> None:
        """Explicit kernel_args should not be overridden by target_name."""
        sb = FirecrackerSandbox(
            target_name="lighttpd",
            kernel_args="console=ttyS0 root=/dev/vda",
        )
        assert sb.kernel_args == "console=ttyS0 root=/dev/vda"

    def test_custom_paths(self, tmp_path: Path) -> None:
        sb = FirecrackerSandbox(
            binary_path=str(tmp_path / "fc"),
            vmlinux_path=str(tmp_path / "vmlinux"),
            rootfs_path=str(tmp_path / "rootfs.ext4"),
            mem_size_mb=512,
            vcpu_count=4,
        )
        assert sb.mem_size_mb == 512
        assert sb.vcpu_count == 4

    def test_initial_state(self) -> None:
        sb = FirecrackerSandbox()
        assert sb._process is None
        assert sb._api is None
        assert sb._tap is None
        assert sb._snapshot_taken is False
        assert sb._last_exit_code is None
