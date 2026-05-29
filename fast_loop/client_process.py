"""
fast_loop/client_process.py
───────────────────────────
Manages the Client as a local asyncio subprocess on the host.

The Client generates baseline traffic by connecting to the Interceptor's
host port (default 8001). It runs outside Docker for simplicity and
performance — the Client is a trusted component that never crashes, so
there is no need for container-level isolation.

Lifecycle:
    - ``start()`` — launch via ``asyncio.create_subprocess_exec``
    - ``stop()``  — SIGTERM → wait 5s → SIGKILL
    - ``restart()`` — stop + start
    - ``watch()`` — watchdog task that auto-restarts if the subprocess dies

Crash Recovery:
    The client has built-in retry logic for ``ConnectionRefusedError``.
    When CrashMonitor pauses the Interceptor during crash recovery, the
    client gets connection refused, sleeps, and retries. When the
    Interceptor resumes, the client reconnects naturally. No explicit
    coordination needed.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

from shared.logger import get_logger

logger = get_logger("fast_loop.client_process")


class ClientSubprocess:
    """Manages the client script as an asyncio subprocess.

    Args:
        script_path:       Path to client.py.
        target_host:       Host the client connects to (Interceptor).
        target_port:       Port the client connects to (Interceptor).
        send_interval_ms:  Milliseconds between sends.
    """

    def __init__(
        self,
        script_path: str = "sandbox/client/client.py",
        target_host: str = "127.0.0.1",
        target_port: int = 8001,
        send_interval_ms: int = 1000,
    ) -> None:
        self.script_path = Path(script_path)
        self.target_host = target_host
        self.target_port = target_port
        self.send_interval_ms = send_interval_ms
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        """Launch the client subprocess."""
        if not self.script_path.exists():
            logger.warning(
                f"Client script not found: {self.script_path} "
                "— client subprocess will not run"
            )
            return

        env = {
            **os.environ,
            "TARGET_HOST": self.target_host,
            "TARGET_PORT": str(self.target_port),
            "SEND_INTERVAL_MS": str(self.send_interval_ms),
            "PYTHONUNBUFFERED": "1",
        }

        self._proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(self.script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        logger.info(
            f"Client subprocess started (PID={self._proc.pid}), "
            f"connecting to {self.target_host}:{self.target_port}"
        )

    async def stop(self) -> None:
        """Stop the client subprocess gracefully."""
        if self._proc is None or self._proc.returncode is not None:
            return
        logger.info(f"Stopping client subprocess (PID={self._proc.pid})...")
        self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Client did not exit in time — killing")
            self._proc.kill()
            await self._proc.wait()
        logger.info("Client subprocess stopped")

    async def restart(self) -> None:
        """Restart the client subprocess."""
        await self.stop()
        await self.start()

    @property
    def is_alive(self) -> bool:
        """Whether the client subprocess is still running."""
        return self._proc is not None and self._proc.returncode is None

    @property
    def pid(self) -> Optional[int]:
        """PID of the client subprocess, or None if not started."""
        return self._proc.pid if self._proc else None

    async def watch(self, check_interval: float = 5.0) -> None:
        """Watchdog loop: auto-restart the client if it dies.

        Runs as an asyncio task. Intended to be started via
        ``asyncio.create_task(client.watch())`` in main.py.

        Args:
            check_interval: Seconds between liveness checks.
        """
        while True:
            await asyncio.sleep(check_interval)
            if not self.is_alive:
                exit_code = self._proc.returncode if self._proc else "N/A"
                logger.warning(
                    f"Client subprocess died (exit={exit_code}), restarting..."
                )
                await self.restart()
