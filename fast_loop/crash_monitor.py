"""
fast_loop/crash_monitor.py
─────────────────────────
Crash Monitor — watches the Target Server for crash events.

Responsibilities:
    - Poll the sandbox backend for target liveness.
    - On crash: log the offending packet, timestamp, and exit code.
    - Notify the Interceptor to pause/resume mutation injection.
    - Maintain crash corpus (all packets that caused crashes).
    - Trigger sandbox state reset for continued fuzzing.

Architecture:
    Runs as an asyncio task in the Fast Loop's event loop. Polls the
    ``BaseSandbox`` abstraction at a configurable interval (default 500ms).
    When a crash is detected, it:
    1. Creates a CrashRecord with the last injected mutation.
    2. Saves the record to the crash corpus directory.
    3. Signals the Interceptor to pause.
    4. Calls ``sandbox.reset_state()`` to restore the target.
       - Docker: container restart (~200-500ms).
       - MicroVM: snapshot restore (< 10ms).
    5. Signals the Interceptor to resume.

Key Design:
    The Crash Monitor depends on ``BaseSandbox``, NOT on Docker directly.
    This allows swapping Docker for Firecracker in Phase 4 without
    modifying a single line of this file.

Configuration:
    All tunables are read from ``config.yaml`` under ``fast_loop.crash_monitor``.

TODO (Phase 2):
    - [ ] Implement sandbox polling via BaseSandbox.is_target_alive()
    - [ ] Implement crash detection logic
    - [ ] Implement crash corpus persistence (JSON files)
    - [ ] Implement auto-reset via sandbox.reset_state()
    - [ ] Implement Interceptor pause/resume signaling
    - [ ] Write tests/test_crash_monitor.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Optional

from shared.logger import get_logger
from shared.sandbox_abstraction import BaseSandbox
from shared.schemas import CrashRecord, Signal

logger = get_logger("fast_loop.crash_monitor")


# Map common exit codes to POSIX signals for human-readable crash reports.
EXIT_CODE_TO_SIGNAL: dict[int, Signal] = {
    134: Signal.SIGABRT,   # abort()
    135: Signal.SIGBUS,    # bus error
    136: Signal.SIGFPE,    # floating point exception
    137: Signal.SIGKILL,   # killed (OOM, manual)
    138: Signal.SIGUSR1,
    139: Signal.SIGSEGV,   # segmentation fault
    140: Signal.SIGUSR2,
    141: Signal.SIGPIPE,
    142: Signal.SIGALRM,
    143: Signal.SIGTERM,   # terminated
    184: Signal.SIGILL,    # illegal instruction
}


class CrashMonitor:
    """Watches the Target Server for crash events via the sandbox abstraction.

    Does NOT import Docker or Firecracker directly. All container/VM
    operations go through the ``BaseSandbox`` interface.

    Args:
        sandbox:            The sandbox backend (Docker, Firecracker, etc.).
        poll_interval_ms:   How often to check target status (milliseconds).
        crash_corpus_dir:   Directory to save crash artifacts (JSON + offending packet).
        auto_reset:         Whether to automatically reset the target after a crash.
        restart_delay_s:    Seconds to wait before resetting (Docker-specific).

    Example:
        >>> sandbox = DockerSandbox(target_container="lifa-target-server")
        >>> await sandbox.start()
        >>> monitor = CrashMonitor(sandbox=sandbox, auto_reset=True)
        >>> await monitor.watch()
    """

    def __init__(
        self,
        sandbox: BaseSandbox,
        poll_interval_ms: int = 500,
        crash_corpus_dir: str = "./crashes",
        auto_reset: bool = True,
        restart_delay_s: float = 2.0,
    ) -> None:
        self.sandbox = sandbox
        self.poll_interval_ms = poll_interval_ms
        self.crash_corpus_dir = Path(crash_corpus_dir)
        self.auto_reset = auto_reset
        self.restart_delay_s = restart_delay_s

        # Internal state
        self._running: bool = False
        self._crash_count: int = 0
        self._last_offending_packet: Optional[bytes] = None
        self._last_mutation_rule_id: Optional[str] = None

        # Callbacks (set by the Fast Loop orchestrator)
        self._on_crash_callback: Optional[Callable] = None

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def watch(self) -> None:
        """Continuously monitor the target container for crashes.

        Runs an infinite loop that polls the container status at the
        configured interval. On crash, delegates to ``on_crash()``.

        TODO (Phase 2): Implement.
        - Poll sandbox.is_target_alive() at configured interval
        - On False: call sandbox.get_last_crash_info() for details
        - Trigger on_crash() with the crash info
        - Handle sandbox backend errors gracefully
        """
        raise NotImplementedError("TODO: Implement container monitoring loop")

    async def stop(self) -> None:
        """Stop monitoring and clean up resources.

        TODO (Phase 2): Implement.
        """
        raise NotImplementedError("TODO: Implement stop")

    # -----------------------------------------------------------------
    # Crash Handling
    # -----------------------------------------------------------------

    async def on_crash(self, exit_code: int) -> CrashRecord:
        """Handle a crash event.

        1. Resolve the signal name from the exit code.
        2. Create a CrashRecord with the offending packet.
        3. Save the crash record to the corpus directory.
        4. Signal the Interceptor to pause (if callback is set).
        5. Optionally restart the container.

        Args:
            exit_code: Container exit code (e.g., 139 for SIGSEGV).

        Returns:
            The created CrashRecord.

        TODO (Phase 2): Implement.
        """
        raise NotImplementedError("TODO: Implement crash handling")

    def _resolve_signal(self, exit_code: int) -> Optional[Signal]:
        """Map a container exit code to a POSIX signal name.

        Args:
            exit_code: The numeric exit code from the container.

        Returns:
            The corresponding Signal enum value, or None if unrecognized.
        """
        return EXIT_CODE_TO_SIGNAL.get(exit_code)

    # -----------------------------------------------------------------
    # Corpus Management
    # -----------------------------------------------------------------

    def save_crash_record(self, record: CrashRecord) -> Path:
        """Persist a crash record to the corpus directory.

        Saves a JSON file named ``{crash_id}.json`` containing the
        crash metadata and offending packet hex.

        Args:
            record: The CrashRecord to save.

        Returns:
            Path to the saved file.

        TODO (Phase 2): Implement.
        - Ensure crash_corpus_dir exists
        - Write JSON with indent=2 for readability
        - Also save raw offending packet as .bin file for replay
        """
        raise NotImplementedError("TODO: Implement crash persistence")

    # -----------------------------------------------------------------
    # Container Control
    # -----------------------------------------------------------------

    async def restart_target(self) -> None:
        """Reset the crashed target via the sandbox abstraction.

        Delegates to ``sandbox.reset_state()``:
        - Docker: container restart (~200-500ms).
        - MicroVM: snapshot restore (< 10ms).

        TODO (Phase 2): Implement.
        - Call self.sandbox.reset_state()
        - Await health check via sandbox.is_target_alive()
        - Log the reset event with timing info
        """
        raise NotImplementedError("TODO: Implement target reset via sandbox")

    async def pause_interceptor(self) -> None:
        """Signal the Interceptor to pause mutation injection.

        Called after a crash to prevent flooding a potentially unstable
        target with mutations during restart.

        TODO (Phase 2): Implement.
        - Call registered _on_crash_callback or use asyncio.Event
        """
        raise NotImplementedError("TODO: Implement interceptor pause")

    async def resume_interceptor(self) -> None:
        """Signal the Interceptor to resume mutation injection.

        Called after the target container has successfully restarted.

        TODO (Phase 2): Implement.
        """
        raise NotImplementedError("TODO: Implement interceptor resume")

    # -----------------------------------------------------------------
    # Offending Packet Tracking
    # -----------------------------------------------------------------

    def register_offending_packet(
        self,
        packet: bytes,
        mutation_rule_id: Optional[str] = None,
    ) -> None:
        """Register the last mutation sent before a crash.

        Called by the Mutation Engine after each injection so the
        CrashMonitor knows which packet to blame.

        Args:
            packet:          The mutated packet bytes last sent.
            mutation_rule_id: ID of the rule that generated the mutation.
        """
        self._last_offending_packet = packet
        self._last_mutation_rule_id = mutation_rule_id

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Whether the monitor is currently watching."""
        return self._running

    @property
    def total_crashes(self) -> int:
        """Total number of crashes detected in this session."""
        return self._crash_count
