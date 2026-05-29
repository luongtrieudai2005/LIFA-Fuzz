"""
fast_loop/interceptor.py
─────────────────────────
Network Interceptor — async transparent TCP proxy with packet capture
and mutation injection.

Architecture:
    asyncio TCP proxy sitting between Client and Target Server.
    Each client connection spawns two relay tasks:
        - client -> server relay (captures + forwards)
        - server -> client relay (captures + forwards)

    A separate injection task reads from the mutation queue and sends
    mutated packets directly to the target.

Data flow:
        Client ──> [proxy:8001] ──> Interceptor ──> [target:9000] ──> Server
                              │                  │
                              ▼                  ▼
                        capture_packet     inject_mutation
                              │                  │
                              ▼                  ▼
                        traffic.log       traffic.log (is_mutated=True)
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Optional

from shared.logger import get_logger
from shared.schemas import Direction, TrafficRecord

logger = get_logger("fast_loop.interceptor")


class Interceptor:
    """Async TCP proxy with packet capture and mutation injection.

    Args:
        listen_host:      Host to bind the proxy to.
        listen_port:      Port for the proxy (client connects here).
        upstream_host:    Target server hostname/IP.
        upstream_port:    Target server port.
        traffic_log_path: Path to the JSONL traffic log file.
        max_connections:   Maximum concurrent proxied connections.
    """

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8001,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 9000,
        traffic_log_path: str = "/tmp/lifa_traffic.log",
        max_connections: int = 100,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.traffic_log_path = Path(traffic_log_path)
        self.max_connections = max_connections

        self._server: Optional[asyncio.Server] = None
        self._active_connections: int = 0
        self._running: bool = False
        self._log_lock = asyncio.Lock()
        self._total_captured: int = 0
        self._total_injected: int = 0

        # Mutation injection queue
        self._mutation_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Start the proxy server and the injection task."""
        self._running = True
        self._server = await asyncio.start_server(
            client_connected_cb=self._handle_connection,
            host=self.listen_host,
            port=self.listen_port,
        )
        logger.info(
            f"Interceptor listening on {self.listen_host}:{self.listen_port} "
            f"-> forwarding to {self.upstream_host}:{self.upstream_port}"
        )

        # Start injection task
        asyncio.create_task(self._injection_loop())

    async def serve_forever(self) -> None:
        """Run the proxy server until stopped."""
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def stop(self) -> None:
        """Gracefully shut down the proxy."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("Interceptor stopped.")

    # -----------------------------------------------------------------
    # Connection Handling
    # -----------------------------------------------------------------

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single proxied client connection."""
        if self._active_connections >= self.max_connections:
            logger.warning("Max connections reached, rejecting")
            client_writer.close()
            return

        self._active_connections += 1
        peer = client_writer.get_extra_info("peername")
        logger.info(f"New connection from {peer} (active: {self._active_connections})")

        try:
            server_reader, server_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=5.0,
            )
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            logger.error(f"Cannot connect upstream: {e}")
            client_writer.close()
            self._active_connections -= 1
            return

        # Two relay tasks
        c2s = asyncio.create_task(
            self._relay(client_reader, server_writer, Direction.CLIENT_TO_SERVER),
            name=f"relay-c2s-{peer}",
        )
        s2c = asyncio.create_task(
            self._relay(server_reader, client_writer, Direction.SERVER_TO_CLIENT),
            name=f"relay-s2c-{peer}",
        )

        # Wait for either direction to close
        done, pending = await asyncio.wait(
            [c2s, s2c], return_when=asyncio.FIRST_COMPLETED
        )

        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        server_writer.close()
        await server_writer.wait_closed()
        client_writer.close()
        await client_writer.wait_closed()
        self._active_connections -= 1
        logger.info(f"Connection from {peer} closed (active: {self._active_connections})")

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: Direction,
    ) -> None:
        """Relay data, capturing each chunk."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break

                await self.capture_packet(direction, data)
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # -----------------------------------------------------------------
    # Packet Capture
    # -----------------------------------------------------------------

    async def capture_packet(
        self,
        direction: Direction,
        raw_data: bytes,
        is_mutated: bool = False,
        mutation_id: Optional[str] = None,
    ) -> TrafficRecord:
        """Capture a packet and append to the traffic log."""
        record = TrafficRecord(
            direction=direction,
            raw_data=raw_data,
            is_mutated=is_mutated,
            mutation_id=mutation_id,
        )

        self._total_captured += 1

        # Append to JSONL log file
        async with self._log_lock:
            try:
                log_line = record.model_dump_json() + "\n"
                with open(self.traffic_log_path, "a") as f:
                    f.write(log_line)
            except OSError as e:
                logger.error(f"Failed to write traffic log: {e}")

        logger.debug(
            f"Captured {direction.value} {len(raw_data)} bytes "
            f"(total: {self._total_captured})"
        )
        return record

    # -----------------------------------------------------------------
    # Mutation Injection
    # -----------------------------------------------------------------

    async def _injection_loop(self) -> None:
        """Background task: read mutations from queue, inject toward target."""
        logger.info("Mutation injection loop started")
        while self._running:
            try:
                mutated_data = await asyncio.wait_for(
                    self._mutation_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.upstream_host, self.upstream_port),
                    timeout=3.0,
                )
                writer.write(mutated_data)
                await writer.drain()

                # Try to read response (optional, may timeout)
                try:
                    await asyncio.wait_for(reader.read(4096), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

                writer.close()
                await writer.wait_closed()

                self._total_injected += 1
                await self.capture_packet(
                    Direction.CLIENT_TO_SERVER,
                    mutated_data,
                    is_mutated=True,
                    mutation_id="injected",
                )
                logger.info(
                    f"Injected mutation #{self._total_injected} "
                    f"({len(mutated_data)} bytes)"
                )

            except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
                logger.warning(f"Injection failed (target may be down): {e}")
                await asyncio.sleep(1.0)

    async def inject_mutation(self, mutated_data: bytes) -> None:
        """Queue a mutated packet for injection (called by Mutation Engine)."""
        try:
            self._mutation_queue.put_nowait(mutated_data)
        except asyncio.QueueFull:
            logger.warning("Mutation queue full, dropping packet")

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def active_connections(self) -> int:
        return self._active_connections

    @property
    def total_captured(self) -> int:
        return self._total_captured

    @property
    def total_injected(self) -> int:
        return self._total_injected
