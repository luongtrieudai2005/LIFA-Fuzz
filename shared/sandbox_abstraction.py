"""
shared/sandbox_abstraction.py
────────────────────────────
Abstract sandbox interface for LIFA-Fuzz Block 1.

Design Rationale:
    LIFA-Fuzz must support both Docker Containers (Phase 1 prototype)
    and MicroVMs / Firecracker (Phase 4 production) without modifying
    Block 2 or Block 3 code. This module defines the contract that
    ANY sandbox backend must fulfill.

    The Mutator, Interceptor, and Crash Monitor NEVER import Docker or
    Firecracker directly. They depend only on this abstract interface.

Architecture Decision:
    - Phase 1: ``DockerSandbox`` implements this via Docker Engine API.
    - Phase 4: ``FirecrackerSandbox`` implements this via Firecracker API.
      Snapshot/restore via VM memory snapshots (< 10ms restore).
    - The backend is selected at runtime via ``config.yaml``.

Swap Path:
    1. Create a new class implementing ``BaseSandbox`` (e.g., FirecrackerSandbox).
    2. Register it in ``SANDBOX_DRIVERS`` dict (bottom of this file).
    3. Set ``sandbox.driver: firecracker`` in ``config.yaml``.
    4. Zero changes to fast_loop/ or slow_loop/ code.

References:
    - NSFuzz paper: MicroVM-based network stack fuzzing with virtio-net.
    - Firecracker snapshot/restore: <10ms VM state restore.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


# =============================================================================
# Data Classes (Sandbox return types)
# =============================================================================


class SandboxDriver(str, Enum):
    """Available sandbox backend drivers."""

    DOCKER = "docker"
    FIRECRACKER = "firecracker"  # Phase 4


@dataclass(frozen=True)
class ContainerInfo:
    """Connection and status info for a single sandbox instance.

    Returned by the sandbox to tell Block 2 where to connect.

    Attributes:
        name:           Container/VM name (e.g., ``"lifa-target-server"``).
        host:           Reachable IP/hostname from the host network.
        port:           Exposed port for the main service.
        internal_port:  Port inside the container/VM.
        status:         Current status (``"running"``, ``"stopped"``, ``"crashed"``).
        exit_code:      Last exit code (0 if running, signal-based if crashed).
    """

    name: str
    host: str
    port: int
    internal_port: int
    status: str
    exit_code: Optional[int] = None


@dataclass(frozen=True)
class CrashInfo:
    """Detailed crash information from the sandbox.

    Attributes:
        instance_name:  Name of the crashed container/VM.
        exit_code:      Process exit code (e.g., 139 = SIGSEGV).
        signal:         Signal name if applicable (e.g., ``"SIGSEGV"``).
        timestamp:      Unix timestamp of the crash.
        stack_trace:    Captured stderr/stdout if available.
    """

    instance_name: str
    exit_code: int
    signal: Optional[str] = None
    timestamp: float = 0.0
    stack_trace: Optional[str] = None


# =============================================================================
# Abstract Base Class
# =============================================================================


class BaseSandbox(abc.ABC):
    """Abstract interface for sandbox backends.

    Every sandbox driver (Docker, Firecracker, QEMU) must implement
    these methods. Block 2 and Block 3 code depends ONLY on this interface.

    Contract:
        - ``start()`` must be called before any other method.
        - ``stop()`` must be called to release resources.
        - ``reset_state()`` must restore the target to a clean, known state.
        - All methods must be safe to call multiple times (idempotent where noted).

    Performance Targets:
        - ``reset_state()``: < 10ms for MicroVM (snapshot restore),
          acceptable ~200-500ms for Docker (container restart) in Phase 1.
        - ``start()``: < 2s for Docker, < 125ms for MicroVM (boot).
    """

    @abc.abstractmethod
    async def start(self) -> None:
        """Launch the sandbox environment.

        Brings up both the client and target server instances.
        Must wait until both are ready to accept connections.

        Raises:
            SandboxError: If the sandbox fails to start.
        """
        ...

    @abc.abstractmethod
    async def stop(self) -> None:
        """Shut down and destroy the sandbox environment.

        Cleans up all containers/VMs and releases network resources.
        Must be safe to call even if the sandbox is partially running.

        Raises:
            SandboxError: If cleanup fails (logged but not critical).
        """
        ...

    @abc.abstractmethod
    async def reset_state(self) -> None:
        """Restore the target server to a clean, known state.

        This is the critical hot-path for fuzzing throughput.
        Called by the Crash Monitor after every target crash.

        Implementation varies by backend:
            - Docker: Kill and restart the container (~200-500ms).
            - MicroVM: Restore from memory snapshot (< 10ms).

        MUST be safe to call while the target is running or crashed.
        MUST leave the target ready to accept new connections after return.

        Raises:
            SandboxError: If the reset fails after retries.
        """
        ...

    @abc.abstractmethod
    async def get_target_info(self) -> ContainerInfo:
        """Return connection details for the target server.

        Used by the Interceptor to know where to forward traffic.

        Returns:
            ContainerInfo with host, port, and status.
        """
        ...

    @abc.abstractmethod
    async def get_client_info(self) -> ContainerInfo:
        """Return connection details for the client instance.

        Used for diagnostics and traffic generation.

        Returns:
            ContainerInfo with host, port, and status.
        """
        ...

    @abc.abstractmethod
    async def is_target_alive(self) -> bool:
        """Check if the target server is running and healthy.

        Used by the Crash Monitor to detect crashes.

        Returns:
            True if the target is running, False otherwise.
        """
        ...

    @abc.abstractmethod
    async def get_last_crash_info(self) -> Optional[CrashInfo]:
        """Return crash details if the target has exited abnormally.

        Used by the Crash Monitor to create CrashRecord objects.

        Returns:
            CrashInfo if the target crashed, None if still running.
        """
        ...

    @abc.abstractmethod
    async def get_network_config(self) -> dict[str, Any]:
        """Return the sandbox network topology.

        Used by the Interceptor to configure its upstream connection.

        Returns:
            Dict with at minimum:
            ``{
                "network_name": str,
                "subnet": str,
                "target_host": str,
                "target_port": int,
                "proxy_listen_port": int,
            }``
        """
        ...

    # -----------------------------------------------------------------
    # Lifecycle utilities (optional override)
    # -----------------------------------------------------------------

    async def ensure_running(self) -> None:
        """Ensure the sandbox is running, start it if not.

        Convenience method — subclasses can override for smarter logic
        (e.g., reusing a warm MicroVM instead of cold boot).
        """
        if not await self.is_target_alive():
            await self.start()

    async def health_check(self) -> bool:
        """Full health check: target alive + network reachable.

        Default implementation checks target alive status.
        Subclasses may add network-level checks.
        """
        return await self.is_target_alive()


# =============================================================================
# Exceptions
# =============================================================================


class SandboxError(Exception):
    """Base exception for sandbox operations."""

    def __init__(self, message: str, driver: str = "") -> None:
        self.driver = driver
        super().__init__(f"[{driver}] {message}" if driver else message)


class SandboxStartError(SandboxError):
    """Failed to start the sandbox."""


class SandboxResetError(SandboxError):
    """Failed to reset sandbox state."""


class SandboxNetworkError(SandboxError):
    """Network configuration or connectivity issue."""


# =============================================================================
# Driver Registry
# =============================================================================

# Subclasses register themselves here. The orchestrator picks the driver
# based on ``config.yaml -> sandbox.driver``.
SANDBOX_DRIVERS: dict[str, type[BaseSandbox]] = {}


def register_driver(name: str, cls: type[BaseSandbox]) -> None:
    """Register a sandbox backend driver.

    Args:
        name: Driver identifier (e.g., ``"docker"``, ``"firecracker"``).
        cls:  Class implementing ``BaseSandbox``.
    """
    if name in SANDBOX_DRIVERS:
        raise ValueError(f"Sandbox driver '{name}' already registered by {SANDBOX_DRIVERS[name]}")
    SANDBOX_DRIVERS[name] = cls


def get_driver(name: str) -> type[BaseSandbox]:
    """Look up a registered sandbox driver by name.

    Args:
        name: Driver identifier from config.

    Returns:
        The sandbox driver class.

    Raises:
        KeyError: If no driver is registered under that name.
    """
    if name not in SANDBOX_DRIVERS:
        available = ", ".join(SANDBOX_DRIVERS.keys()) or "(none registered)"
        raise KeyError(
            f"Sandbox driver '{name}' not found. Available: {available}. "
            f"Did you import the driver module?"
        )
    return SANDBOX_DRIVERS[name]
