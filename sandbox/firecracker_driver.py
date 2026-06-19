"""
sandbox/firecracker_driver.py
──────────────────────────────
Firecracker MicroVM sandbox backend.

Implements ``BaseSandbox`` using the Firecracker MicroVM Manager API over
Unix Domain Sockets (UDS). Provides kernel-level isolation and snapshot/restore
capabilities for sub-10ms crash recovery.

Communication Pattern:
    The Firecracker process exposes a REST-like API over a Unix Domain Socket
    (e.g., ``/tmp/firecracker-lifa.sock``). Each PUT/GET call configures or
    queries the VM:

        ┌────────────────┐      UDS (HTTP)      ┌──────────────────┐
        │ firecracker_   │ ──── PUT /boot-source ───▶│  Firecracker     │
        │   driver.py    │ ──── PUT /machine-config ─▶│  MicroVM Process │
        │                │ ──── PUT /actions ─────────▶│                  │
        │  (this file)   │ ◀─── GET /vm/info ─────────│  (guest kernel)  │
        └────────────────┘                           └──────────────────┘

    After the VM boots and the target server reaches a ready state, a
    memory snapshot is taken. On crash, ``reset_state()`` restores from
    that snapshot in < 10ms — no reboot needed.

Prerequisites:
    - KVM enabled on the host (``/dev/kvm`` accessible).
    - Firecracker binary (``sandbox/firecracker_env/firecracker``).
    - vmlinux kernel and rootfs ext4 image for the guest VM.
    - Use ``sandbox/setup_firecracker.sh`` to download the binary.
    - Use ``sandbox/firecracker_env/build_kernel.sh`` to build the kernel.
    - Use ``sandbox/firecracker_env/build_rootfs.sh`` to build the rootfs.

Architecture:
    - Each MicroVM runs an isolated Linux kernel (kernel-level isolation).
    - Networking via TAP devices → host routing.
    - Snapshot/restore for sub-10ms state reset after crashes.

Performance Targets:
    - ``start()``:       ~125ms (cold boot).
    - ``reset_state()``: < 10ms  (snapshot restore).
    - ``stop()``:        < 50ms  (VM shutdown).

References:
    - Firecracker API docs:
      https://github.com/firecracker-microvm/firecracker/blob/main/docs/api.md
    - Snapshot/restore:
      https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting.md
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import time
from collections import deque
from pathlib import Path
from typing import Any, Optional

import aiohttp
import aiohttp.connector

from shared.logger import get_logger
from shared.sandbox_abstraction import (
    BaseSandbox,
    CrashInfo,
    ContainerInfo,
    register_driver,
    SandboxDriver,
    SandboxError,
    SandboxStartError,
    SandboxResetError,
)

logger = get_logger("sandbox.firecracker_driver")


# =============================================================================
# UDS HTTP Client for Firecracker API
# =============================================================================


class UDSConnector:
    """Placeholder — actual connector is aiohttp.UnixConnector created lazily.

    Kept for backward compatibility. The real work is done by
    ``aiohttp.UnixConnector`` which is created inside ``FirecrackerAPIClient``
    when the session is first opened.
    """

    def __init__(self, uds_path: str, **kwargs: Any) -> None:
        self.uds_path = uds_path


class FirecrackerAPIClient:
    """Async HTTP client for the Firecracker UDS API.

    Wraps aiohttp with a Unix Domain Socket connector for communicating
    with the Firecracker process.

    Args:
        socket_path: Path to the Firecracker UDS socket.
        timeout_s: Default request timeout in seconds.
    """

    def __init__(self, socket_path: str, timeout_s: float = 5.0) -> None:
        self.socket_path = socket_path
        self.timeout_s = timeout_s
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[UDSConnector] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session with UDS connector."""
        if self._session is None or self._session.closed:
            # Use aiohttp's built-in Unix domain socket connector
            self._connector = aiohttp.UnixConnector(path=self.socket_path)
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout_s),
            )
        return self._session

    async def put(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Send PUT request to the Firecracker API.

        Args:
            path: API endpoint path (e.g., "/boot-source").
            data: JSON payload.

        Returns:
            Response body as dict (may be empty for 204 No Content).

        Raises:
            SandboxError: On API error.
        """
        session = await self._get_session()
        url = f"http://localhost{path}"
        try:
            async with session.put(url, json=data) as resp:
                body = await resp.text()
                if resp.status not in (200, 204):
                    raise SandboxError(
                        f"Firecracker PUT {path} failed "
                        f"(HTTP {resp.status}): {body}",
                        driver="firecracker",
                    )
                if body:
                    return json.loads(body)
                return {}
        except aiohttp.ClientError as e:
            raise SandboxError(
                f"Firecracker PUT {path} connection error: {e}",
                driver="firecracker",
            ) from e

    async def patch(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Send PATCH request to the Firecracker API."""
        session = await self._get_session()
        url = f"http://localhost{path}"
        try:
            async with session.patch(url, json=data) as resp:
                body = await resp.text()
                if resp.status not in (200, 204):
                    raise SandboxError(
                        f"Firecracker PATCH {path} failed "
                        f"(HTTP {resp.status}): {body}",
                        driver="firecracker",
                    )
                if body:
                    return json.loads(body)
                return {}
        except aiohttp.ClientError as e:
            raise SandboxError(
                f"Firecracker PATCH {path} connection error: {e}",
                driver="firecracker",
            ) from e

    async def get(self, path: str) -> dict[str, Any]:
        """Send GET request to the Firecracker API.

        Args:
            path: API endpoint path (e.g., "/vm/info").

        Returns:
            Response body as dict.

        Raises:
            SandboxError: On API error.
        """
        session = await self._get_session()
        url = f"http://localhost{path}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise SandboxError(
                        f"Firecracker GET {path} failed "
                        f"(HTTP {resp.status}): {body}",
                        driver="firecracker",
                    )
                return await resp.json()
        except aiohttp.ClientError as e:
            raise SandboxError(
                f"Firecracker GET {path} connection error: {e}",
                driver="firecracker",
            ) from e

    async def close(self) -> None:
        """Close the HTTP session and connector."""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._connector = None


# =============================================================================
# TAP Device Manager
# =============================================================================


class TAPDeviceManager:
    """Manages TAP network devices for Firecracker VM networking.

    Creates a TAP device on the host that the VM's virtio-net connects to.
    The host can then route traffic to/from the VM via this TAP device.

    Network layout:
        Host (172.16.0.1) ←→ TAP device (tap-lifa0) ←→ VM (172.16.0.2:9000)
    """

    def __init__(
        self,
        tap_name: str = "tap-lifa0",
        host_ip: str = "172.16.0.1",
        vm_ip: str = "172.16.0.2",
        subnet: str = "24",
    ) -> None:
        self.tap_name = tap_name
        self.host_ip = host_ip
        self.vm_ip = vm_ip
        self.subnet = subnet
        self._created = False

    async def create(self) -> None:
        """Create and configure the TAP device.

        Requires root/sudo. Idempotent — skips if device already exists.
        """
        if await self._device_exists():
            logger.info(f"TAP device '{self.tap_name}' already exists — reusing")
            self._created = True
            return

        # Create TAP device
        await self._run_ip(f"tuntap add dev {self.tap_name} mode tap")
        # Bring it up
        await self._run_ip(f"link set dev {self.tap_name} up")
        # Assign host IP on the TAP interface
        await self._run_ip(
            f"addr add {self.host_ip}/{self.subnet} dev {self.tap_name}"
        )
        self._created = True
        logger.info(
            f"TAP device '{self.tap_name}' created: "
            f"host={self.host_ip}, vm={self.vm_ip}"
        )

    async def destroy(self) -> None:
        """Remove the TAP device."""
        if not self._created:
            return
        try:
            await self._run_ip(f"link del dev {self.tap_name}")
            logger.info(f"TAP device '{self.tap_name}' removed")
        except Exception as e:
            logger.warning(f"Failed to remove TAP device: {e}")
        finally:
            self._created = False

    async def _device_exists(self) -> bool:
        """Check if the TAP device already exists."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "link", "show", self.tap_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    async def _run_ip(args: str) -> None:
        """Run an iproute2 command. Requires privileges.

        Strategy (in order):
            1. If running as root → bare ``ip {args}``.
            2. Try bare ``ip {args}`` (works if user has CAP_NET_ADMIN or
               equivalent capabilities).
            3. Fall back to ``sudo -n /sbin/ip {args}`` (works if sudoers
               rule is installed by ``configure_permissions.sh``).

        Raises:
            SandboxError: If all strategies fail.
        """
        if os.geteuid() == 0:
            cmd = f"ip {args}"
        else:
            # Try bare ip first, fall back to sudo
            cmd = f"ip {args}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return  # Bare ip worked (user has capabilities)
            # Permission denied → try sudo
            cmd = f"sudo -n /sbin/ip {args}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise SandboxError(
                f"'{cmd}' failed (rc={proc.returncode}): {stderr.decode().strip()}",
                driver="firecracker",
            )


# =============================================================================
# FirecrackerSandbox
# =============================================================================


class FirecrackerSandbox(BaseSandbox):
    """Firecracker MicroVM sandbox backend.

    Manages the target as a Firecracker MicroVM with kernel-level isolation
    and sub-10ms snapshot/restore for crash recovery. The Client runs as a
    local subprocess on the host.

    All interaction with the Firecracker process happens via Unix Domain
    Socket HTTP requests. The socket path is unique per VM instance.

    Lifecycle:
        1. ``start()``       → spawn Firecracker process → configure VM via
                                UDS (boot-source, machine-config, network) →
                                boot → wait for ready → take initial snapshot.
        2. ``reset_state()`` → load snapshot via UDS (PUT /snapshot) →
                                resume → < 10ms total.
        3. ``stop()``        → send shutdown action → kill process →
                                clean TAP devices and UDS socket.

    Args:
        binary_path:      Path to the Firecracker binary.
        vmlinux_path:     Path to the vmlinux kernel binary.
        rootfs_path:      Path to the rootfs ext4 image.
        snapshot_dir:     Directory for VM memory snapshots.
        kernel_args:      Kernel boot arguments.
        mem_size_mb:      VM memory size in MB.
        vcpu_count:       Number of vCPUs per VM.
        tap_name:         Name of the TAP device for VM networking.
        host_ip:          IP address assigned to the host side of the TAP.
        vm_ip:            Static IP assigned to the VM.
        target_port:      Port the target server listens on inside the VM.
        socket_path:      Path for the Firecracker UDS socket.
    """

    # LightFTP is pre-baked into rootfs (all-in-one Docker build):
    #   /usr/local/bin/fftp  (ASAN-compiled, static-linked)
    #   /etc/fftp.conf       (bind 0.0.0.0:21)
    #   /init                (boots directly to fftp, no SSH)
    LIGHTFTP_BINARY = "/usr/local/bin/fftp"

    def __init__(
        self,
        binary_path: str = "sandbox/firecracker_env/firecracker",
        vmlinux_path: str = "sandbox/firecracker_env/vmlinux",
        rootfs_path: str = "",
        snapshot_dir: str = "sandbox/firecracker_env/snapshots",
        kernel_args: str = "",
        target_name: str = "vulnerable_server",
        mem_size_mb: int = 256,
        vcpu_count: int = 2,
        tap_name: str = "tap-lifa0",
        host_ip: str = "172.16.0.1",
        vm_ip: str = "172.16.0.2",
        target_port: int = 9000,
        socket_path: str = "/tmp/firecracker-lifa.sock",
    ) -> None:
        # Target-aware defaults for rootfs and kernel args
        fc_env = "sandbox/firecracker_env"
        if not rootfs_path:
            if target_name == "lightftp":
                rootfs_path = f"{fc_env}/rootfs_lightftp.ext4"
            elif target_name == "lighttpd":
                rootfs_path = f"{fc_env}/rootfs_lighttpd.ext4"
            elif target_name == "uftpd":
                rootfs_path = f"{fc_env}/rootfs_uftpd.ext4"
            else:
                rootfs_path = f"{fc_env}/rootfs.ext4"
        if not kernel_args:
            base_args = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw"
            if target_name in ("lighttpd", "lightftp", "uftpd"):
                kernel_args = f"{base_args} init=/init"
            else:
                kernel_args = (
                    f"{base_args} init=/bin/vulnerable_server"
                    " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
                )

        # LightFTP/uftpd listen on port 21 by default
        if target_name in ("lightftp", "uftpd") and target_port == 9000:
            target_port = 21

        self.binary_path = Path(binary_path)
        self.vmlinux_path = Path(vmlinux_path)
        self.rootfs_path = Path(rootfs_path)
        self.snapshot_dir = Path(snapshot_dir)
        self.kernel_args = kernel_args
        self.target_name = target_name
        self.mem_size_mb = mem_size_mb
        self.vcpu_count = vcpu_count
        self.tap_name = tap_name
        self.host_ip = host_ip
        self.vm_ip = vm_ip
        self.target_port = target_port
        self.socket_path = Path(socket_path)

        # Runtime state
        self._process: Optional[asyncio.subprocess.Process] = None
        self._api: Optional[FirecrackerAPIClient] = None
        self._tap: Optional[TAPDeviceManager] = None
        self._snapshot_taken: bool = False
        self._last_exit_code: Optional[int] = None
        self._last_exit_time: float = 0.0
        self._serial_output: str = ""
        # Continuous serial drain: keeps the Firecracker stdout pipe from
        # filling (which would block the VM → EPS stall) and retains serial
        # history (including ASAN reports) for get_last_crash_info.
        self._serial_buffer: deque = deque(maxlen=2000)  # ~64KB of text lines
        self._serial_task: Optional[asyncio.Task] = None

    def _apply_target_defaults(self) -> None:
        """Re-apply target-aware defaults after config overrides.

        Called by main.py after setting config attributes via setattr().
        Recomputes rootfs_path, kernel_args, and target_port based on
        the current target_name.
        """
        fc_env = "sandbox/firecracker_env"
        # Coerce to Path in case config override set a raw string
        self.rootfs_path = Path(self.rootfs_path)
        self.binary_path = Path(self.binary_path)
        self.vmlinux_path = Path(self.vmlinux_path)
        self.snapshot_dir = Path(self.snapshot_dir)
        self.socket_path = Path(self.socket_path)

        # Only update rootfs if it still points to the default
        default_rootfs = f"{fc_env}/rootfs.ext4"
        if str(self.rootfs_path) == default_rootfs or not self.rootfs_path.name:
            if self.target_name == "lightftp":
                self.rootfs_path = Path(f"{fc_env}/rootfs_lightftp.ext4")
            elif self.target_name == "lighttpd":
                self.rootfs_path = Path(f"{fc_env}/rootfs_lighttpd.ext4")
            elif self.target_name == "uftpd":
                self.rootfs_path = Path(f"{fc_env}/rootfs_uftpd.ext4")

        # Update kernel args for init-based targets
        if self.target_name in ("lighttpd", "lightftp", "uftpd"):
            base_args = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw"
            if "init=/init" not in self.kernel_args:
                self.kernel_args = f"{base_args} init=/init"

        # LightFTP/uftpd listen on port 21
        if self.target_name in ("lightftp", "uftpd") and self.target_port == 9000:
            self.target_port = 21

        logger.info(
            "Firecracker target defaults applied",
            extra={"context": {
                "target_name": self.target_name,
                "rootfs_path": str(self.rootfs_path),
                "target_port": self.target_port,
                "kernel_args": self.kernel_args,
            }},
        )

    # -----------------------------------------------------------------
    # Prerequisites Check
    # -----------------------------------------------------------------

    def _check_prerequisites(self) -> None:
        """Verify all prerequisites are available.

        Raises:
            SandboxStartError: If any prerequisite is missing.
        """
        # 1. KVM
        if not Path("/dev/kvm").exists():
            raise SandboxStartError(
                "/dev/kvm not found — KVM must be enabled on the host. "
                "Enable KVM: sudo modprobe kvm_intel (or kvm_amd)",
                driver="firecracker",
            )
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise SandboxStartError(
                "/dev/kvm not accessible — add user to kvm group: "
                "sudo usermod -aG kvm $USER",
                driver="firecracker",
            )

        # 2. Firecracker binary
        if not self.binary_path.is_file():
            raise SandboxStartError(
                f"Firecracker binary not found: {self.binary_path}. "
                f"Run: bash sandbox/setup_firecracker.sh",
                driver="firecracker",
            )
        if not os.access(str(self.binary_path), os.X_OK):
            raise SandboxStartError(
                f"Firecracker binary not executable: {self.binary_path}",
                driver="firecracker",
            )

        # 3. Kernel
        if not self.vmlinux_path.is_file():
            raise SandboxStartError(
                f"VM kernel not found: {self.vmlinux_path}. "
                f"Run: bash sandbox/firecracker_env/build_kernel.sh",
                driver="firecracker",
            )

        # 4. RootFS
        if not self.rootfs_path.is_file():
            raise SandboxStartError(
                f"RootFS image not found: {self.rootfs_path}. "
                f"Run: bash sandbox/firecracker_env/build_rootfs.sh",
                driver="firecracker",
            )

    # -----------------------------------------------------------------
    # BaseSandbox: start()
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Boot the target MicroVM.

        Steps:
            1. Verify prerequisites (KVM, binary, kernel, rootfs).
            2. Create TAP device for VM networking.
            3. Spawn Firecracker process with ``--api-sock <socket_path>``.
            4. Configure via UDS:
               - PUT /boot-source    (vmlinux + kernel args)
               - PUT /machine-config (vCPUs + memory)
               - PUT /network-interfaces (TAP device for virtio-net)
               - PUT /drives         (rootfs as read-write drive)
            5. PUT /actions (InstanceStart) to boot.
            6. Wait for target server to accept TCP connections.
            7. Take initial snapshot for fast ``reset_state()``.

        Raises:
            SandboxStartError: If the VM fails to start.
        """
        logger.info("Starting Firecracker sandbox...")
        self._check_prerequisites()

        # 1. Clean up stale socket
        if self.socket_path.exists():
            self.socket_path.unlink()
            logger.debug(f"Removed stale socket: {self.socket_path}")

        # 2. Create snapshot directory
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        # 3. Create TAP device
        self._tap = TAPDeviceManager(
            tap_name=self.tap_name,
            host_ip=self.host_ip,
            vm_ip=self.vm_ip,
        )
        await self._tap.create()

        # 4. Spawn Firecracker process
        logger.info(
            f"Spawning Firecracker: {self.binary_path} "
            f"--api-sock {self.socket_path}"
        )
        self._process = await asyncio.create_subprocess_exec(
            str(self.binary_path),
            "--api-sock", str(self.socket_path),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        # Give Firecracker a moment to create the socket
        await asyncio.sleep(0.1)
        if not self.socket_path.exists():
            raise SandboxStartError(
                "Firecracker did not create API socket",
                driver="firecracker",
            )

        # 5. Initialize API client
        self._api = FirecrackerAPIClient(str(self.socket_path), timeout_s=10.0)

        # 6. Configure VM via UDS
        try:
            # Boot source
            await self._api.put("/boot-source", {
                "kernel_image_path": str(self.vmlinux_path.resolve()),
                "boot_args": self.kernel_args,
            })
            logger.debug("Boot source configured")

            # Machine config
            await self._api.put("/machine-config", {
                "vcpu_count": self.vcpu_count,
                "mem_size_mib": self.mem_size_mb,
            })
            logger.debug(
                f"Machine config: {self.vcpu_count} vCPUs, "
                f"{self.mem_size_mb} MB RAM"
            )

            # Rootfs drive
            await self._api.put("/drives/rootfs", {
                "drive_id": "rootfs",
                "path_on_host": str(self.rootfs_path.resolve()),
                "is_root_device": True,
                "is_read_only": False,
            })
            logger.debug("RootFS drive configured")

            # Network interface
            await self._api.put("/network-interfaces/eth0", {
                "iface_id": "eth0",
                "guest_mac": "AA:FC:00:00:00:01",
                "host_dev_name": self.tap_name,
            })
            logger.debug(f"Network interface configured (TAP={self.tap_name})")

        except SandboxError as e:
            await self._kill_process()
            raise SandboxStartError(
                f"VM configuration failed: {e}",
                driver="firecracker",
            ) from e

        # 7. Boot the VM
        try:
            await self._api.put("/actions", {
                "action_type": "InstanceStart",
            })
            logger.info("VM boot initiated")
        except SandboxError as e:
            await self._kill_process()
            raise SandboxStartError(
                f"VM boot failed: {e}",
                driver="firecracker",
            ) from e

        # 8. Drain guest serial DURING boot — captures boot/panic/TSAN output so
        # we can diagnose a target that dies before listening, and keeps the
        # Firecracker stdout pipe from filling on a chatty guest.
        self._start_serial_drain()

        # 9. Wait for target server to be ready
        # LightFTP is pre-baked into rootfs (all-in-one Docker build),
        # no SSH provisioning needed — boots directly to fftp on port 21.
        boot_timeout = 15.0
        ready = await self._wait_for_target_tcp(timeout_s=boot_timeout)
        if not ready:
            if self._serial_buffer:
                logger.error(
                    "Guest serial console on boot failure:\n"
                    + "\n".join(self._serial_buffer)
                )
            await self._kill_process()
            raise SandboxStartError(
                f"Target server did not become ready within {boot_timeout}s",
                driver="firecracker",
            )
        logger.info(
            f"Target server ready at {self.vm_ip}:{self.target_port}"
        )

        # 9. Take initial snapshot for fast reset
        try:
            await self._take_snapshot()
            logger.info("Initial snapshot taken — ready for fast reset")
        except Exception as e:
            # Non-fatal — we can still do cold reset
            logger.warning(
                f"Failed to take initial snapshot (cold reset will be used): {e}"
            )

        logger.info("Firecracker sandbox started successfully")
        # Start continuous serial drain to prevent pipe-full stalls and
        # retain serial history (ASAN reports) for crash diagnostics.
        self._start_serial_drain()

    # -----------------------------------------------------------------
    # Serial drain — prevents pipe-full VM stalls + preserves ASAN trace
    # -----------------------------------------------------------------

    def _start_serial_drain(self) -> None:
        """Launch (or relaunch) the async serial drain task."""
        self._cancel_serial_drain()
        if self._process is not None and self._process.stdout is not None:
            self._serial_buffer.clear()
            self._serial_task = asyncio.create_task(
                self._drain_serial(), name="fc_serial_drain"
            )

    def _cancel_serial_drain(self) -> None:
        """Cancel the serial drain task if running."""
        if self._serial_task is not None and not self._serial_task.done():
            self._serial_task.cancel()
        self._serial_task = None

    async def _drain_serial(self) -> None:
        """Continuously read Firecracker stdout (VM serial console) into a
        rolling buffer.

        Without this, the stdout PIPE buffer (64KB on Linux) fills up with
        boot logs + connection logs → Firecracker blocks on write → VM
        stalls → EPS drops to 0. Additionally, the ASAN report (written at
        crash time) is the LAST thing flushed; if the pipe is already full,
        it never makes it through → ``get_last_crash_info`` reads stale/empty
        data → σ₃ dedup fails.

        This task drains the pipe line-by-line into ``_serial_buffer`` (deque,
        maxlen=2000 ≈ 64KB). The buffer is then the source for crash
        diagnostics.
        """
        try:
            while True:
                line = await self._process.stdout.readline()
                if not line:
                    break  # EOF — process exited
                self._serial_buffer.append(
                    line.decode("utf-8", errors="replace").rstrip("\n\r")
                )
        except asyncio.CancelledError:
            pass
        except Exception:
            pass  # Never crash the driver over serial drain

    # -----------------------------------------------------------------
    # BaseSandbox: stop()
    # -----------------------------------------------------------------

    async def stop(self) -> None:
        """Shut down and clean up the target MicroVM.

        Steps:
            1. Try graceful shutdown via API.
            2. Kill Firecracker process if it doesn't exit.
            3. Destroy TAP device.
            4. Clean up UDS socket and API session.
        """
        logger.info("Stopping Firecracker sandbox...")

        # Cancel serial drain before killing process
        self._cancel_serial_drain()

        # Try graceful shutdown via API
        if self._api is not None:
            try:
                await self._api.put("/actions", {
                    "action_type": "SendCtrlAltDel",
                })
                # Wait up to 2s for process to exit
                if self._process is not None:
                    try:
                        await asyncio.wait_for(self._process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass
            except Exception:
                pass
            finally:
                await self._api.close()
                self._api = None

        # Kill the process
        await self._kill_process()

        # Destroy TAP device
        if self._tap is not None:
            await self._tap.destroy()
            self._tap = None

        # Clean up socket
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass

        self._snapshot_taken = False
        logger.info("Firecracker sandbox stopped")

    # -----------------------------------------------------------------
    # BaseSandbox: reset_state()
    # -----------------------------------------------------------------

    async def reset_state(self) -> None:
        """Restore the target VM from snapshot (< 10ms).

        If a snapshot exists:
            1. Kill the crashed Firecracker process.
            2. Spawn a fresh Firecracker process.
            3. Load snapshot via API (PUT /snapshot).
            4. Resume VM execution.
            5. Wait for target server to be ready.

        If no snapshot:
            Fall back to cold boot (stop + start).

        Raises:
            SandboxResetError: If the reset fails.
        """
        t0 = time.monotonic()

        if not self._snapshot_taken or not self._snapshot_files_exist():
            logger.warning(
                "No snapshot available — performing cold reset (stop + start)"
            )
            await self.stop()
            await self.start()
            return

        try:
            # 1. Cancel serial drain + kill the crashed process
            self._cancel_serial_drain()
            await self._kill_process()
            await self._api.close() if self._api else None
            self._api = None

            # 2. Clean up stale socket
            if self.socket_path.exists():
                self.socket_path.unlink()

            # 3. Spawn fresh Firecracker process for snapshot restore
            self._process = await asyncio.create_subprocess_exec(
                str(self.binary_path),
                "--api-sock", str(self.socket_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await asyncio.sleep(0.05)  # Brief wait for socket creation

            # 4. Initialize new API client
            self._api = FirecrackerAPIClient(str(self.socket_path), timeout_s=10.0)

            # 5. Load snapshot
            mem_path = self.snapshot_dir / "vm.mem"
            vmstate_path = self.snapshot_dir / "vm.vmstate"

            await self._api.put("/snapshot/load", {
                "mem_file_path": str(mem_path.resolve()),
                "snapshot_path": str(vmstate_path.resolve()),
                "enable_diff_snapshots": False,
                "resume_vm": True,
            })

            elapsed = time.monotonic() - t0
            logger.info(
                f"VM snapshot restore complete ({elapsed * 1000:.1f}ms)"
            )

            # 6. Wait for target to be ready (much faster after restore)
            ready = await self._wait_for_target_tcp(timeout_s=5.0)
            if not ready:
                raise SandboxResetError(
                    "Target server not ready after snapshot restore",
                    driver="firecracker",
                )

            elapsed_total = time.monotonic() - t0
            logger.info(
                f"reset_state() complete ({elapsed_total * 1000:.1f}ms total, "
                f"target ready at {self.vm_ip}:{self.target_port})"
            )
            # Restart serial drain for the new process
            self._start_serial_drain()

        except SandboxResetError:
            raise
        except Exception as e:
            raise SandboxResetError(
                f"Snapshot restore failed: {e}",
                driver="firecracker",
            ) from e

    # -----------------------------------------------------------------
    # BaseSandbox: is_target_alive()
    # -----------------------------------------------------------------

    async def is_target_alive(self) -> bool:
        """Check if the target MicroVM is running.

        Checks:
            1. Firecracker process is still alive.
            2. (Optional) GET /vm/info confirms running state.

        Returns:
            True if the VM is running, False otherwise.
        """
        if self._process is None:
            return False

        # Check if process has exited
        if self._process.returncode is not None:
            self._last_exit_code = self._process.returncode
            self._last_exit_time = time.time()
            return False

        return True

    # -----------------------------------------------------------------
    # BaseSandbox: get_target_info()
    # -----------------------------------------------------------------

    async def get_target_info(self) -> ContainerInfo:
        """Return target VM connection info.

        Returns:
            ContainerInfo with VM IP and target port.
        """
        status = "running"
        exit_code = None

        if self._process is not None and self._process.returncode is not None:
            status = "exited"
            exit_code = self._process.returncode

        return ContainerInfo(
            name="lifa-firecracker-vm",
            host=self.vm_ip,
            port=self.target_port,
            internal_port=self.target_port,
            status=status,
            exit_code=exit_code,
        )

    # -----------------------------------------------------------------
    # Serial console accessor (for serial-ASAN detection on fork-per-conn
    # targets that survive per-connection crashes — e.g. uftpd, where an ASAN
    # abort kills the child but the daemon lives, so death-based crash
    # detection never fires. The crash monitor scans this for ASAN markers.)
    # -----------------------------------------------------------------

    def get_serial_output(self) -> str:
        """Return the current serial console buffer text (live + history)."""
        if not self._serial_buffer:
            return ""
        return "\n".join(self._serial_buffer)

    def clear_serial_buffer(self) -> None:
        """Clear the serial console buffer. Called after a serial-ASAN crash
        is recorded so the consumed ASAN report doesn't re-fire on the next
        poll — otherwise the stale report sits in the buffer and is re-detected
        every cycle until rotation, inflating the crash count 25:1 with phantom
        re-detections (the false-positive storm)."""
        self._serial_buffer.clear()

    # -----------------------------------------------------------------
    # BaseSandbox: get_last_crash_info()
    # -----------------------------------------------------------------

    async def get_last_crash_info(self) -> Optional[CrashInfo]:
        """Return crash details from the last VM exit.

        Parses the Firecracker process exit code to determine the crash
        signal and collects serial output as the stack trace.

        Returns:
            CrashInfo if a crash was detected, None if still running.
        """
        if self._process is None or self._process.returncode is None:
            return None

        exit_code = self._process.returncode
        crash_signal = self._map_exit_code_to_signal(exit_code)

        # Collect serial output from the continuous drain buffer. The drain
        # task reads Firecracker stdout line-by-line into ``_serial_buffer``
        # throughout the VM's lifetime, so the ASAN report flushed at crash
        # time IS captured (unlike the old approach which read the pipe only
        # AFTER exit — by then the pipe was often full/stale and the ASAN
        # report was lost, leaving σ₃ empty → over-counting).
        # Cancel the drain task FIRST to avoid a race where both the drain
        # task and this read() compete for the same pipe, splitting data.
        self._cancel_serial_drain()
        serial_output = "\n".join(self._serial_buffer)
        if self._process.stdout:
            try:
                remaining = await asyncio.wait_for(
                    self._process.stdout.read(), timeout=1.0
                )
                if remaining:
                    tail = remaining.decode("utf-8", errors="replace")
                    serial_output = serial_output + "\n" + tail if serial_output else tail
            except (asyncio.TimeoutError, Exception):
                pass

        self._serial_output = serial_output

        return CrashInfo(
            instance_name="lifa-firecracker-vm",
            exit_code=exit_code,
            signal=crash_signal,
            timestamp=self._last_exit_time or time.time(),
            stack_trace=serial_output[-8192:] if serial_output else None,
        )

    # -----------------------------------------------------------------
    # BaseSandbox: get_network_config()
    # -----------------------------------------------------------------

    async def get_network_config(self) -> dict[str, Any]:
        """Return MicroVM network topology.

        Returns:
            Dict with network_name, target_host, target_port,
            proxy_listen_port, sandbox_type.
        """
        return {
            "network_name": f"firecracker-tap-{self.tap_name}",
            "subnet": f"{self.host_ip}/24",
            "target_host": self.vm_ip,
            "target_port": self.target_port,
            "proxy_listen_port": 8001,
            "sandbox_type": "firecracker",
        }

    # -----------------------------------------------------------------
    # Snapshot Helpers
    # -----------------------------------------------------------------

    async def _take_snapshot(self) -> None:
        """Take a VM memory snapshot for fast reset.

        Creates:
            - vm.mem: VM memory state.
            - vm.vmstate: vCPU/device state.

        Must be called while the VM is running and the target is ready.
        The VM is paused before snapshot and resumed after.
        """
        if self._api is None:
            raise SandboxError("API client not initialized", driver="firecracker")

        mem_path = (self.snapshot_dir / "vm.mem").resolve()
        vmstate_path = (self.snapshot_dir / "vm.vmstate").resolve()

        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        # Firecracker requires the VM to be paused before snapshotting.
        await self._api.patch("/vm", {"state": "Paused"})
        logger.debug("VM paused for snapshot")

        try:
            await self._api.put("/snapshot/create", {
                "mem_file_path": str(mem_path),
                "snapshot_path": str(vmstate_path),
                "snapshot_type": "Full",
            })
        finally:
            # Always try to resume, even if snapshot failed.
            try:
                await self._api.patch("/vm", {"state": "Resumed"})
                logger.debug("VM resumed after snapshot")
            except Exception:
                pass

        self._snapshot_taken = True
        logger.info(
            f"Snapshot created: mem={mem_path}, vmstate={vmstate_path}"
        )

    def _snapshot_files_exist(self) -> bool:
        """Check if snapshot files exist on disk."""
        return (
            (self.snapshot_dir / "vm.mem").is_file()
            and (self.snapshot_dir / "vm.vmstate").is_file()
        )

    def _detect_fc_version(self) -> str:
        """Detect the Firecracker binary version for snapshot API compatibility.

        Runs ``firecracker --version`` and parses the output.
        Falls back to ``"0.0.0"`` if detection fails — Firecracker
        accepts any version string for full snapshots.

        Returns:
            Version string like ``"1.7.0"``.
        """
        try:
            import subprocess as _sp
            result = _sp.run(
                [str(self.binary_path), "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Firecracker outputs: "Firecracker v1.7.0"
            for part in result.stdout.strip().split():
                if part.startswith("v") and len(part) > 1:
                    return part[1:]  # Strip leading 'v'
            return result.stdout.strip().split()[-1]
        except Exception:
            return "0.0.0"

    # -----------------------------------------------------------------
    # Process Management
    # -----------------------------------------------------------------

    async def _kill_process(self) -> None:
        """Kill the Firecracker process and collect exit info."""
        if self._process is None:
            return

        proc = self._process
        self._process = None

        if proc.returncode is not None:
            # Already exited
            self._last_exit_code = proc.returncode
            return

        try:
            proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=1.0)
        except ProcessLookupError:
            pass

        self._last_exit_code = proc.returncode
        logger.debug(f"Firecracker process terminated (rc={proc.returncode})")

    # -----------------------------------------------------------------
    # Target Readiness
    # -----------------------------------------------------------------

    async def _wait_for_target_tcp(
        self, timeout_s: float = 15.0
    ) -> bool:
        """Wait until the target server accepts TCP connections.

        Polls with a non-blocking connect attempt at regular intervals.

        Args:
            timeout_s: Maximum wait time in seconds.

        Returns:
            True if the target is ready, False if timeout.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            # First check if the VM process is still alive
            if self._process is not None and self._process.returncode is not None:
                logger.error(
                    f"VM process exited during boot (rc={self._process.returncode})"
                )
                return False

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.vm_ip, self.target_port),
                    timeout=1.0,
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                await asyncio.sleep(0.1)

        return False

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _map_exit_code_to_signal(exit_code: int) -> Optional[str]:
        """Map a process exit code to a POSIX signal name.

        Firecracker exit codes:
            0  = clean shutdown
            1  = internal error
            Negative = signal (Python convention: -signal_number)
        """
        # Python subprocess returns negative for signal kills
        if exit_code < 0:
            sig = -exit_code
            return {
                signal.SIGSEGV: "SIGSEGV",
                signal.SIGABRT: "SIGABRT",
                signal.SIGBUS: "SIGBUS",
                signal.SIGFPE: "SIGFPE",
                signal.SIGILL: "SIGILL",
                signal.SIGTERM: "SIGTERM",
                signal.SIGKILL: "SIGKILL",
            }.get(sig, f"SIG{sig}")

        # Positive exit code: check if it's a signal+128
        return {
            134: "SIGABRT",
            135: "SIGBUS",
            136: "SIGFPE",
            137: "SIGKILL",
            139: "SIGSEGV",
            143: "SIGTERM",
        }.get(exit_code)


# =============================================================================
# Register this driver for discovery via get_driver("firecracker").
# =============================================================================

register_driver(SandboxDriver.FIRECRACKER.value, FirecrackerSandbox)
