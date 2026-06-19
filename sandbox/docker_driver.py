"""
sandbox/docker_driver.py
───────────────────────
Docker-based sandbox backend — manages ONLY the Target Server container.

The Client runs as a lightweight local subprocess (see ``fast_loop/client_process.py``),
connecting to the Interceptor on the host. This eliminates unnecessary container
overhead since the Client is a trusted component that never crashes.

Implements ``BaseSandbox`` using the Docker Engine API.
For production fuzzing, swap to ``FirecrackerSandbox`` (Phase 4) for
kernel-level isolation and < 10ms snapshot/restore.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

import docker
from docker.errors import NotFound, APIError
from docker.models.containers import Container
from docker.models.networks import Network

from shared.logger import get_logger
from shared.sandbox_abstraction import (
    BaseSandbox,
    CrashInfo,
    ContainerInfo,
    SandboxDriver,
    SandboxError,
    SandboxResetError,
    SandboxStartError,
    register_driver,
)

logger = get_logger("sandbox.docker_driver")


class DockerSandbox(BaseSandbox):
    """Docker-based sandbox — manages the target container only.

    The Client runs as a local subprocess on the host, not inside Docker.

    Args:
        network_name:         Docker bridge network name.
        target_image_tag:     Tag for the target server image.
        target_container:     Container name for the target.
        target_internal_port: Port the server listens on inside the container.
        proxy_listen_port:    Port exposed on the host for the Interceptor.
        restart_delay_s:      Seconds to wait after reset_state().
        build_context:        Path to the directory containing the server Dockerfile.
    """

    def __init__(
        self,
        network_name: str = "lifa-network",
        target_image_tag: str = "lifa-target-server:latest",
        target_container: str = "lifa-target-server",
        target_internal_port: int = 9000,
        proxy_listen_port: int = 8001,
        restart_delay_s: float = 2.0,
        build_context: str = "sandbox/target",
    ) -> None:
        self.network_name = network_name
        self.target_image_tag = target_image_tag
        self.target_container = target_container
        self.target_internal_port = target_internal_port
        self.proxy_listen_port = proxy_listen_port
        self.restart_delay_s = restart_delay_s
        self.build_context = Path(build_context)

        self._docker_client: Optional[docker.DockerClient] = None
        self._target: Optional[Container] = None
        self._network: Optional[Network] = None

    # -----------------------------------------------------------------
    # Docker Client
    # -----------------------------------------------------------------

    def _docker(self) -> docker.DockerClient:
        if self._docker_client is None:
            self._docker_client = docker.from_env()
        return self._docker_client

    # -----------------------------------------------------------------
    # BaseSandbox Implementation
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Build target image, create network, and start target container."""
        client = self._docker()
        logger.info("Starting Docker sandbox (target only)...")

        try:
            # 1. Build target image — skip if already present (e.g. a pre-built
            #    coverage-instrumented image tagged lifa-fuzz-server:latest).
            build_path = str(self.build_context)
            if client.images.list(name=self.target_image_tag):
                logger.info(
                    f"Image '{self.target_image_tag}' already present — skipping build."
                )
            else:
                logger.info(f"Building target server image from {build_path}...")
                client.images.build(
                    path=build_path,
                    tag=self.target_image_tag,
                    rm=True,
                )

            # 2. Create network (idempotent)
            self._network = self._create_network()

            # 3. Start target server
            logger.info(f"Starting target container '{self.target_container}'...")
            self._target = client.containers.run(
                image=self.target_image_tag,
                name=self.target_container,
                network=self.network_name,
                detach=True,
                ports={f"{self.target_internal_port}/tcp": self.target_internal_port},
                # seccomp=unconfined lets TSAN targets disable ASLR per-process
                # via setarch -R (PIE shadow collision) without touching the host
                # sysctl. Harmless for non-sanitizer targets.
                security_opt=["seccomp=unconfined"],
            )

            # 4. Wait for target to be ready
            self._wait_for_running(self.target_container, timeout_s=15)
            logger.info("Target server is running.")
            logger.info("Docker sandbox started successfully.")

        except APIError as e:
            raise SandboxStartError(f"Failed to start Docker sandbox: {e}", driver="docker") from e

    async def stop(self) -> None:
        """Stop and remove the target container and network."""
        client = self._docker()

        try:
            container = client.containers.get(self.target_container)
            container.remove(force=True)
            logger.info(f"Removed container '{self.target_container}'")
        except NotFound:
            logger.debug(f"Container '{self.target_container}' not found (already removed)")

        try:
            network = client.networks.get(self.network_name)
            network.remove()
            logger.info(f"Removed network '{self.network_name}'")
        except NotFound:
            logger.debug(f"Network '{self.network_name}' not found (already removed)")

        self._target = None
        self._network = None

    async def reset_state(self) -> None:
        """Restart the target container (~200-500ms)."""
        if self._target is None:
            raise SandboxResetError("No target container to reset", driver="docker")

        logger.info(f"Resetting target '{self.target_container}'...")
        self._target.restart(timeout=10)

        # Wait for it to be running again
        self._wait_for_running(self.target_container, timeout_s=10)
        logger.info(f"Target '{self.target_container}' reset complete.")

    async def get_target_info(self) -> ContainerInfo:
        """Return target container connection info."""
        container = self._docker().containers.get(self.target_container)
        container.reload()

        return ContainerInfo(
            name=self.target_container,
            host=self.target_container,
            port=self.target_internal_port,
            internal_port=self.target_internal_port,
            status=container.status,
            exit_code=container.attrs["State"].get("ExitCode"),
        )

    async def is_target_alive(self) -> bool:
        """Check if the target container is running."""
        try:
            container = self._docker().containers.get(self.target_container)
            container.reload()
            return container.status == "running"
        except NotFound:
            return False

    async def get_last_crash_info(self) -> Optional[CrashInfo]:
        """Return crash details if the target exited abnormally."""
        try:
            container = self._docker().containers.get(self.target_container)
            container.reload()

            if container.status != "exited":
                return None

            exit_code = container.attrs["State"]["ExitCode"]
            signal = self._map_exit_code_to_signal(exit_code)

            return CrashInfo(
                instance_name=self.target_container,
                exit_code=exit_code,
                signal=signal,
                timestamp=time.time(),
            )
        except NotFound:
            return None

    async def get_network_config(self) -> dict[str, Any]:
        """Return the sandbox network topology.

        Resolves the host-accessible address for the target container.
        When running from the host (not inside Docker), the interceptor
        needs ``localhost:<mapped_port>`` rather than the Docker DNS name.
        """
        host_port = self.target_internal_port
        try:
            container = self._docker().containers.get(self.target_container)
            container.reload()
            port_bindings = container.attrs.get(
                "NetworkSettings", {}
            ).get("Ports", {})
            port_key = f"{self.target_internal_port}/tcp"
            if port_key in port_bindings and port_bindings[port_key]:
                host_port = int(port_bindings[port_key][0]["HostPort"])
        except Exception:
            pass

        return {
            "network_name": self.network_name,
            "target_host": "127.0.0.1",
            "target_port": host_port,
            "proxy_listen_port": self.proxy_listen_port,
            "sandbox_type": "docker",
        }

    # -----------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------

    def _create_network(self) -> Network:
        """Create the bridge network if it doesn't exist."""
        client = self._docker()
        try:
            network = client.networks.get(self.network_name)
            logger.debug(f"Network '{self.network_name}' already exists")
            return network
        except NotFound:
            network = client.networks.create(
                self.network_name, driver="bridge"
            )
            logger.info(f"Created network '{self.network_name}'")
            return network

    def _wait_for_running(self, name: str, timeout_s: float = 30) -> None:
        """Poll container until it's running or timeout."""
        client = self._docker()
        deadline = time.time() + timeout_s
        last_status = "unknown"

        while time.time() < deadline:
            try:
                container = client.containers.get(name)
                container.reload()
                last_status = container.status
                if container.status == "running":
                    return
            except NotFound:
                last_status = "not_found"
            time.sleep(0.2)

        # Collect diagnostics before failing
        diag = ""
        try:
            container = client.containers.get(name)
            logs = container.logs(tail=20).decode("utf-8", errors="replace")
            diag = f" status={container.status} logs={logs[:500]}"
        except Exception:
            pass

        raise SandboxStartError(
            f"Container '{name}' did not reach 'running' within {timeout_s}s "
            f"(last_status={last_status}).{diag}",
            driver="docker",
        )

    def _map_exit_code_to_signal(self, exit_code: int) -> Optional[str]:
        """Map Docker exit code to POSIX signal name."""
        return {
            134: "SIGABRT", 135: "SIGBUS", 136: "SIGFPE",
            137: "SIGKILL", 139: "SIGSEGV", 143: "SIGTERM",
            184: "SIGILL",
        }.get(exit_code)


# =============================================================================
# Register driver
# =============================================================================
register_driver(SandboxDriver.DOCKER.value, DockerSandbox)
