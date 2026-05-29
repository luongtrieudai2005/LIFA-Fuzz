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

    Pause/Resume:
        The CrashMonitor can call pause() to immediately stop all mutation
        injection and reject new client connections. resume() re-enables
        normal operation.  Uses asyncio.Event for zero-COST suspension.

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
        traffic_log_path: str = "shared/raw_traffic.jsonl",
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
        self._total_captured: int = 0
        self._total_injected: int = 0

        # ── Pause / Resume ───────────────────────────────────────────
        # asyncio.Event: set = paused, clear = running.
        # The injection loop awaits on this event, so paused mutations
        # queue up and are processed when resumed.
        self._pause_event: asyncio.Event = asyncio.Event()

        # Mutation injection queue
        self._mutation_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

        # Non-blocking write queue for traffic log.
        # capture_packet() pushes entries here; a background writer
        # flushes them to disk in batches. This ensures proxy
        # performance is never degraded by I/O.
        self._write_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=10000)
        self._write_buffer: list[str] = []
        self._buffer_flush_interval = 0.5  # seconds

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def start(self) -> None:
        """Start the proxy server, injection task, and log writer."""
        self._running = True
        self._pause_event.clear()  # Ensure we start in running state

        # Ensure log directory exists
        self.traffic_log_path.parent.mkdir(parents=True, exist_ok=True)

        self._server = await asyncio.start_server(
            client_connected_cb=self._handle_connection,
            host=self.listen_host,
            port=self.listen_port,
        )
        logger.info(
            f"Interceptor listening on {self.listen_host}:{self.listen_port} "
            f"-> forwarding to {self.upstream_host}:{self.upstream_port}"
        )
        logger.info(f"Traffic log: {self.traffic_log_path}")

        # Start background tasks
        asyncio.create_task(self._injection_loop(), name="injection_loop")
        asyncio.create_task(self._log_writer_loop(), name="log_writer_loop")

    async def serve_forever(self) -> None:
        """Run the proxy server until stopped."""
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def stop(self) -> None:
        """Gracefully shut down the proxy."""
        self._running = False
        self._pause_event.set()  # Unblock injection loop if waiting
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("Interceptor stopped.")

    # -----------------------------------------------------------------
    # Pause / Resume (called by CrashMonitor)
    # -----------------------------------------------------------------

    def pause(self) -> None:
        """Immediately pause mutation injection and reject new connections.

        Called by the CrashMonitor when a target crash is detected.
        Existing mutations in the queue are preserved and will be
        flushed on resume.
        """
        self._pause_event.set()
        logger.warning(
            "Interceptor PAUSED — injection stopped, new connections rejected"
        )

    def resume(self) -> None:
        """Resume mutation injection and accept new connections.

        Called by the CrashMonitor after the target server has been
        verified alive again following a crash reset.
        """
        self._pause_event.clear()
        logger.info("Interceptor RESUMED — injection and connections active")

    @property
    def is_paused(self) -> bool:
        """Whether the interceptor is currently paused."""
        return self._pause_event.is_set()

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

        # ── Pause check: reject new connections when paused ────────
        if self._pause_event.is_set():
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
        """Capture a packet and enqueue for non-blocking log write.

        Writes a simplified JSONL entry (LLM-optimized format):
            {"timestamp": float, "direction": str, "payload": hex_string, ...}
        """
        self._total_captured += 1

        # Write simplified JSONL entry
        entry = json.dumps({
            "timestamp": time.time(),
            "direction": direction.value,
            "payload": raw_data.hex(),
            "length": len(raw_data),
            "is_mutated": is_mutated,
            "mutation_id": mutation_id,
        })

        # Non-blocking: push to write queue, drops if full
        try:
            self._write_queue.put_nowait(entry)
        except asyncio.QueueFull:
            logger.warning("Traffic log write queue full, dropping entry")

        logger.debug(
            f"Captured {direction.value} {len(raw_data)} bytes "
            f"(total: {self._total_captured})"
        )
        return TrafficRecord(
            direction=direction,
            raw_data=raw_data,
            is_mutated=is_mutated,
            mutation_id=mutation_id,
        )

    async def _log_writer_loop(self) -> None:
        """Background task: flushes traffic log entries to disk in batches."""
        logger.debug("Traffic log writer started")
        while self._running:
            await asyncio.sleep(self._buffer_flush_interval)
            if not self._write_buffer:
                while not self._write_queue.empty():
                    try:
                        self._write_buffer.append(
                            self._write_queue.get_nowait()
                        )
                    except asyncio.QueueEmpty:
                        break

            if not self._write_buffer:
                continue

            try:
                with open(self.traffic_log_path, "a") as f:
                    for line in self._write_buffer:
                        f.write(line)
                        f.write("\n")
                flushed = len(self._write_buffer)
                self._write_buffer.clear()
                logger.debug(f"Flushed {flushed} entries to {self.traffic_log_path}")
            except OSError as e:
                logger.error(f"Failed to flush traffic log: {e}")

    # -----------------------------------------------------------------
    # Mutation Injection
    # -----------------------------------------------------------------

    async def _injection_loop(self) -> None:
        """Background task: read mutations from queue, inject toward target."""
        logger.info("Mutation injection loop started")
        while self._running:
            try:
                # ── Pause gate: wait until resumed ──────────────
                await self._pause_event.wait()

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
