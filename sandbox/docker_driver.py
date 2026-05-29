"""
sandbox/docker_driver.py
───────────────────────
Docker-based sandbox backend — fully functional for local testing.

Implements ``BaseSandbox`` using the Docker Engine API.
This is the development/testing harness. For production fuzzing,
swap to ``FirecrackerSandbox`` (Phase 4) for kernel-level isolation
and < 10ms snapshot/restore.
"""

from __future__ import annotations

import asyncio
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
)

logger = get_logger("sandbox.docker_driver")


class DockerSandbox(BaseSandbox):
    """Docker-based sandbox — the local development backend.

    Manages two containers on an isolated bridge network.
    All operations go through the Docker Engine API (docker-py).

    Args:
        network_name:       Docker bridge network name.
        target_image_tag:   Tag for the target server image.
        client_image_tag:   Tag for the client image.
        target_container:   Container name for the target.
        client_container:   Container name for the client.
        target_internal_port: Port the server listens on inside the container.
        proxy_listen_port:   Port exposed on the host for the Interceptor.
        restart_delay_s:     Seconds to wait after reset_state().
        build_context:       Path to the directory containing Dockerfiles.
    """

    def __init__(
        self,
        network_name: str = "lifa-network",
        target_image_tag: str = "lifa-target-server:latest",
        client_image_tag: str = "lifa-client:latest",
        target_container: str = "lifa-target-server",
        client_container: str = "lifa-client",
        target_internal_port: int = 9000,
        proxy_listen_port: int = 8001,
        restart_delay_s: float = 2.0,
        build_context: str = ".",
    ) -> None:
        self.network_name = network_name
        self.target_image_tag = target_image_tag
        self.client_image_tag = client_image_tag
        self.target_container = target_container
        self.client_container = client_container
        self.target_internal_port = target_internal_port
        self.proxy_listen_port = proxy_listen_port
        self.restart_delay_s = restart_delay_s
        self.build_context = Path(build_context)

        self._client: Optional[docker.DockerClient] = None
        self._target: Optional[Container] = None
        self._client_container: Optional[Container] = None
        self._network: Optional[Network] = None

    # -----------------------------------------------------------------
    # Docker Client
    # -----------------------------------------------------------------

    def _docker(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # -----------------------------------------------------------------
    # BaseSandbox Implementation
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Build images, create network, and start both containers."""
        client = self._docker()
        logger.info("Starting Docker sandbox...")

        try:
            # 1. Build images
            logger.info("Building target server image...")
            client.images.build(
                path=str(self.build_context / "server"),
                tag=self.target_image_tag,
                rm=True,
            )

            logger.info("Building client image...")
            client.images.build(
                path=str(self.build_context / "client"),
                tag=self.client_image_tag,
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
                ports={f"{self.target_internal_port}/tcp": None},  # No host port needed (interceptor connects via network)
            )

            # 4. Wait for target to be ready
            self._wait_for_running(self.target_container, timeout_s=15)
            logger.info("Target server is running.")

            # 5. Start client
            logger.info(f"Starting client container '{self.client_container}'...")
            self._client_container = client.containers.run(
                image=self.client_image_tag,
                name=self.client_container,
                network=self.network_name,
                detach=True,
                environment={
                    "TARGET_HOST": self.target_container,
                    "TARGET_PORT": str(self.target_internal_port),
                    "SEND_INTERVAL_MS": "1000",
                },
            )
            logger.info("Client is running.")
            logger.info("Docker sandbox started successfully.")

        except APIError as e:
            raise SandboxStartError(f"Failed to start Docker sandbox: {e}", driver="docker") from e

    async def stop(self) -> None:
        """Stop and remove all containers and the network."""
        client = self._docker()

        for name in [self.client_container, self.target_container]:
            try:
                container = client.containers.get(name)
                container.remove(force=True)
                logger.info(f"Removed container '{name}'")
            except NotFound:
                logger.debug(f"Container '{name}' not found (already removed)")

        try:
            network = client.networks.get(self.network_name)
            network.remove()
            logger.info(f"Removed network '{self.network_name}'")
        except NotFound:
            logger.debug(f"Network '{self.network_name}' not found (already removed)")

        self._target = None
        self._client_container = None
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
            host=self.target_container,  # Docker DNS name inside the network
            port=self.target_internal_port,
            internal_port=self.target_internal_port,
            status=container.status,
            exit_code=container.attrs["State"].get("ExitCode"),
        )

    async def get_client_info(self) -> ContainerInfo:
        """Return client container connection info."""
        container = self._docker().containers.get(self.client_container)
        container.reload()

        return ContainerInfo(
            name=self.client_container,
            host=self.client_container,
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
        """Return the sandbox network topology."""
        return {
            "network_name": self.network_name,
            "target_host": self.target_container,
            "target_port": self.target_internal_port,
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

        while time.time() < deadline:
            try:
                container = client.containers.get(name)
                container.reload()
                if container.status == "running":
                    return
            except NotFound:
                pass
            time.sleep(0.2)

        raise SandboxStartError(
            f"Container '{name}' did not reach 'running' within {timeout_s}s",
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
