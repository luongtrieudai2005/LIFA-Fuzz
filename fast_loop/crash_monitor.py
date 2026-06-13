"""
fast_loop/crash_monitor.py
─────────────────────────
Crash Monitor — watches the Target Server for crash events.

Responsibilities:
    - Poll the sandbox backend for target liveness.
    - On crash: log the offending packet, timestamp, and exit code.
    - Pause the Interceptor and Mutation Engine immediately.
    - Save the offending packet as a PoC artifact (JSON + .bin) in /crashes/.
    - Record the crash through ``CrashManager`` for deduplication (if provided).
    - Call ``sandbox.reset_state()`` to restore the target.
    - Resume the Interceptor and Mutation Engine once the target is alive.

Architecture:
    Runs as an asyncio task in the Fast Loop's event loop. Polls the
    ``BaseSandbox`` abstraction at a configurable interval (default 500ms).
    When a crash is detected, it:
    1. Pauses the Interceptor and MutationEngine immediately.
    2. Creates a CrashRecord with the last injected mutation.
    3. Saves the record + raw packet to the crash corpus directory.
    4. Calls ``sandbox.reset_state()`` to restore the target.
    5. Waits for the target to become alive again.
    6. Resumes the Interceptor and MutationEngine.

Key Design:
    The Crash Monitor depends on ``BaseSandbox``, NOT on Docker directly.
    This allows swapping Docker for Firecracker in Phase 4 without
    modifying a single line of this file.

Configuration:
    All tunables are read from ``config.yaml`` under ``fast_loop.crash_monitor``.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from shared.logger import get_logger
from shared.sandbox_abstraction import BaseSandbox
from shared.schemas import CrashRecord, Signal

if TYPE_CHECKING:
    from shared.crash_manager import CrashManager

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
        interceptor:        The Interceptor instance (for pause/resume).
                            Can be None if pause/resume is managed externally.
        mutator:            The MutationEngine instance (for pause/resume
                            and last-injected-packet tracking).
                            Can be None if managed externally.
        crash_manager:      Optional CrashManager for crash deduplication.
                            When provided, every crash is recorded through it
                            so duplicate PoCs are filtered out automatically.
        poll_interval_ms:   How often to check target status (milliseconds).
        crash_corpus_dir:   Directory to save crash artifacts (JSON + .bin).
        auto_reset:         Whether to automatically reset the target after a crash.
        restart_delay_s:    Seconds to wait before resetting (Docker-specific).
    """

    def __init__(
        self,
        sandbox: BaseSandbox,
        interceptor: Any = None,
        mutator: Any = None,
        crash_manager: Optional[CrashManager] = None,
        poll_interval_ms: int = 500,
        crash_corpus_dir: str = "./crashes",
        auto_reset: bool = True,
        restart_delay_s: float = 2.0,
    ) -> None:
        self.sandbox = sandbox
        self.interceptor = interceptor
        self.mutator = mutator
        self.crash_manager = crash_manager
        self.poll_interval_ms = poll_interval_ms
        self.crash_corpus_dir = Path(crash_corpus_dir)
        self.auto_reset = auto_reset
        self.restart_delay_s = restart_delay_s

        # Internal state
        self._running: bool = False
        self._crash_count: int = 0
        self._last_offending_packet: bytes = b""
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
        """
        self._running = True
        was_alive = True  # Track state transitions

        logger.info(
            f"CrashMonitor started (poll={self.poll_interval_ms}ms, "
            f"auto_reset={self.auto_reset})"
        )

        while self._running:
            try:
                alive = await self.sandbox.is_target_alive()

                if was_alive and not alive:
                    # ── Verification step (Fix 1): confirm crash with retries ──
                    # Transient TCP failures (e.g., fork-based server overload)
                    # can cause a single is_target_alive() == False that resolves
                    # within seconds. Before declaring a crash, verify with a
                    # short retry loop to filter false positives.
                    verified = await self._verify_crash()

                    if not verified:
                        # False positive: target recovered on its own.
                        logger.info(
                            "CRASH VERIFICATION: target recovered — "
                            "false positive, skipping"
                        )
                        was_alive = True
                        await asyncio.sleep(self.poll_interval_ms / 1000.0)
                        continue

                    # State transition: running → crashed (VERIFIED)

                    # ── Collect crash diagnostics (Fix 2+3) ──
                    crash_info = await self.sandbox.get_last_crash_info()
                    exit_code = crash_info.exit_code if crash_info else 0
                    serial_output = ""
                    if crash_info and crash_info.stack_trace:
                        serial_output = crash_info.stack_trace

                    # ── Classify crash type (Fix 3) ──
                    crash_classification = self._classify_crash(
                        exit_code, serial_output
                    )

                    is_actionable = crash_classification.get("is_actionable", True)
                    if is_actionable:
                        logger.error("CRASH DETECTED — target server is down!")
                    else:
                        logger.info(
                            "Server exited normally (exit 0) — restarting..."
                        )
                    logger.warning(
                        f"Crash classified as: {crash_classification['type']} "
                        f"(confidence={crash_classification['confidence']})"
                    )

                    await self.on_crash(
                        exit_code,
                        classification=crash_classification,
                        serial_output=serial_output,
                    )
                    # After on_crash() → restart_target() → resume_interceptor(),
                    # the target may already be alive again.  Check and update
                    # was_alive so we don't miss a rapid re-crash:
                    #   was_alive=False + alive=False → missed crash.
                    try:
                        was_alive = await self.sandbox.is_target_alive()
                    except Exception:
                        was_alive = False

                elif not was_alive and alive:
                    # State transition: crashed → running (after reset)
                    logger.info("Target server is back up — resuming operations")
                    was_alive = True

            except Exception as e:
                logger.error(f"Error in crash monitor poll: {e}", exc_info=True)

            await asyncio.sleep(self.poll_interval_ms / 1000.0)

    async def stop(self) -> None:
        """Stop monitoring and clean up resources."""
        self._running = False
        logger.info("CrashMonitor stopped")

    # -----------------------------------------------------------------
    # Crash Handling
    # -----------------------------------------------------------------

    async def on_crash(
        self,
        exit_code: int,
        classification: Optional[dict] = None,
        serial_output: str = "",
    ) -> CrashRecord:
        """Handle a crash event.

        Full pipeline:
        1. Resolve the signal name from the exit code.
        2. Create a CrashRecord with the offending packet.
        3. Pause the Interceptor and MutationEngine immediately.
        4. Save the crash record to the corpus directory.
        5. Reset the target via sandbox.reset_state().
        6. Wait for the target to come back alive.
        7. Resume the Interceptor and MutationEngine.

        Args:
            exit_code: Container exit code (e.g., 139 for SIGSEGV).
            classification: Optional crash classification dict from
                ``_classify_crash()`` with keys: type, confidence, detail.
            serial_output: Optional serial console output from the VM
                (contains kernel panic / ASAN messages).

        Returns:
            The created CrashRecord.
        """
        self._crash_count += 1

        # 1. Resolve signal
        signal = self._resolve_signal(exit_code)
        signal_str = signal.value if signal else f"unknown (exit {exit_code})"
        logger.error(
            f"Crash #{self._crash_count}: {signal_str} "
            f"(exit_code={exit_code})"
        )

        # 2. Get offending packet from mutator's tracking
        # H5 fix: prefer the public API (register_offending_packet) first,
        # then fall back to the crash window, then to private fields.
        offending_packet = b""
        rule_id = None

        # Primary: data registered via register_offending_packet()
        if self._last_offending_packet:
            offending_packet = self._last_offending_packet
            rule_id = self._last_mutation_rule_id

        # Secondary: crash attribution window (H3 fix)
        if not offending_packet and self.mutator is not None:
            _get_window = getattr(self.mutator, "get_crash_window", None)
            if _get_window is not None:
                crash_window = _get_window()
                if crash_window:
                    _, offending_packet, rule_id = crash_window[-1]

        # Tertiary: backward-compat private field access
        if not offending_packet and self.mutator is not None:
            offending_packet = self.mutator._last_injected_packet
            rule_id = self.mutator._last_injected_rule_id

        # 3. Create CrashRecord
        record = CrashRecord(
            exit_code=exit_code,
            signal=signal,
            offending_packet=offending_packet,
            mutation_rule_id=rule_id,
            stack_trace=serial_output[-2000:] if serial_output else None,
        )
        logger.error(
            f"Crash artifact: packet={record.offending_packet_hex[:64]}, "
            f"rule_id={rule_id}"
        )

        # 3b. Attach classification metadata for downstream consumers
        is_actionable = True
        if classification:
            is_actionable = classification.get("is_actionable", True)
            logger.warning(
                f"Crash classification: {classification['type']} "
                f"(confidence={classification['confidence']:.0%}, "
                f"detail={classification.get('detail', '')})"
            )

        # 3c. Non-actionable exits (e.g., exit code 0): skip artifact
        #     saving and CrashManager recording — just restart the target.
        if not is_actionable:
            logger.info(
                "Normal server exit (not actionable) — "
                "skipping CrashManager recording and artifact saving"
            )
            if self.auto_reset:
                await self.restart_target()
            return record

        # 4. Pause traffic IMMEDIATELY
        await self.pause_interceptor()

        # 5. Save crash artifact to disk
        crash_path = self.save_crash_record(record)
        logger.error(f"Crash PoC saved to: {crash_path}")

        # 5b. Record through CrashManager for deduplication
        # Use classification type as crash_type for richer reporting
        crash_type_str = (
            classification["type"] if classification else f"exit_{exit_code}"
        )
        if self.crash_manager is not None:
            try:
                result = await self.crash_manager.record(
                    payload=record.offending_packet,
                    crash_type=crash_type_str,
                    rule_set_id=record.mutation_rule_id,
                    notes=classification.get("detail", "") if classification else "",
                )
                if result.is_new:
                    logger.info(
                        f"NEW unique crash recorded: sig={result.signature}"
                    )
                else:
                    logger.debug(
                        f"Duplicate crash #{result.duplicate_count} "
                        f"of sig={result.signature}"
                    )
            except Exception as e:
                logger.error(f"CrashManager.record() failed: {e}")

        # 6. Invoke external callback if registered
        if self._on_crash_callback:
            try:
                self._on_crash_callback(record)
            except Exception as e:
                logger.error(f"on_crash_callback error: {e}")

        # 7. Reset the target
        if self.auto_reset:
            await self.restart_target()
        else:
            logger.warning(
                "Auto-reset disabled — target left in crashed state. "
                "Manual intervention required."
            )

        return record

    def _resolve_signal(self, exit_code: int) -> Optional[Signal]:
        """Map a container exit code to a POSIX signal name."""
        return EXIT_CODE_TO_SIGNAL.get(exit_code)

    # -----------------------------------------------------------------
    # Crash Verification (Fix 1)
    # -----------------------------------------------------------------

    async def _verify_crash(
        self,
        retries: int = 3,
        delay_s: float = 0.5,
    ) -> bool:
        """Confirm that the target is truly crashed, not just a transient blip.

        After ``is_target_alive()`` returns False, this method waits briefly
        and retries to filter out false positives caused by:
        - Fork-based servers briefly refusing connections between child deaths
        - TCP backlog overflow causing momentary SYN drops
        - Scheduler starvation under high load

        However, if the sandbox process/container itself has exited (returncode
        is not None for Docker, Firecracker process has died), the crash is
        confirmed immediately without retries — there's no recovering from a
        dead process.

        Mock/test sandboxes that lack ``_process`` and ``target_container``
        are trusted outright — they don't have transient failures.

        Args:
            retries: Number of verification attempts (default 3).
            delay_s: Seconds between attempts (default 0.5s → total ~1.5s).

        Returns:
            True if the crash is confirmed (target still dead after all retries).
            False if the target recovered (false positive).
        """
        # Fast path 1: Firecracker — process exited → confirmed immediately.
        if hasattr(self.sandbox, "_process") and self.sandbox._process is not None:
            if self.sandbox._process.returncode is not None:
                return True  # Process exited → confirmed crash

        # Fast path 2: Docker — container not running → confirmed immediately.
        if hasattr(self.sandbox, "target_container"):
            client = None
            try:
                import docker
                client = docker.from_env()
                container = client.containers.get(self.sandbox.target_container)
                if container.status != "running":
                    return True  # Container stopped → confirmed crash
            except Exception:
                pass  # Can't check → fall through to retry logic
            finally:
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass

        # Fast path 3: Mock/test sandbox — no real process to go transient.
        # If the sandbox has neither _process nor target_container, it's a
        # test mock — trust its is_target_alive() result immediately.
        has_process = hasattr(self.sandbox, "_process") and self.sandbox._process is not None
        has_container = hasattr(self.sandbox, "target_container")
        if not has_process and not has_container:
            return True  # Mock sandbox: trust the driver, no transient failures

        # Slow path: retry to check for transient TCP/process failures
        for attempt in range(retries):
            await asyncio.sleep(delay_s)
            try:
                alive = await self.sandbox.is_target_alive()
                if alive:
                    return False  # Target recovered — false positive
            except Exception:
                pass  # Exception ≈ not alive, continue checking

        return True  # Still dead after all retries → confirmed crash

    # -----------------------------------------------------------------
    # Crash Classification (Fix 3)
    # -----------------------------------------------------------------

    def _classify_crash(
        self,
        exit_code: int,
        serial_output: str = "",
    ) -> dict:
        """Classify a crash by root cause using exit code + serial output.

        Categories:
            - ``asan_violation``  — AddressSanitizer detected a memory error.
                                   High-value: real memory corruption bug.
            - ``oom_kill``        — Linux OOM killer terminated the process.
                                   Denial-of-service via resource exhaustion.
            - ``signal_crash``    — Process killed by a fatal signal (SIGSEGV,
                                   SIGABRT, etc.) without ASAN context.
            - ``graceful_exit``   — Process called exit(0) or exit(1) cleanly.
                                   May indicate a logic bug or maxcmds limit.
            - ``kernel_panic``    — Guest kernel panicked (typically PID 1 death).
            - ``unknown``         — Cannot determine root cause.

        Returns:
            Dict with keys: type, confidence (0.0-1.0), detail (human-readable).
        """
        serial_lower = serial_output.lower() if serial_output else ""

        # ── Check for ASAN signature (highest priority) ────────────
        asan_markers = [
            "addresssanitizer",
            "==error:",
            "heap-buffer-overflow",
            "heap-use-after-free",
            "stack-buffer-overflow",
            "stack-use-after-free",
            "global-buffer-overflow",
            "use-after-poison",
            "container-overflow",
            "stack-overflow",
            "alloc-dealloc-mismatch",
            "memcpy-param-overlap",
            "new-delete-type-mismatch",
            "heap-allocated-memory",
            "freed here",
        ]
        for marker in asan_markers:
            if marker in serial_lower:
                # Try to extract the specific error type
                for specific in [
                    "heap-buffer-overflow",
                    "heap-use-after-free",
                    "stack-buffer-overflow",
                    "stack-use-after-free",
                    "global-buffer-overflow",
                    "stack-overflow",
                ]:
                    if specific in serial_lower:
                        return {
                            "type": "asan_violation",
                            "confidence": 0.95,
                            "detail": f"ASAN {specific}",
                            "is_actionable": True,
                        }
                return {
                    "type": "asan_violation",
                    "confidence": 0.90,
                    "detail": "ASAN memory error detected",
                    "is_actionable": True,
                }

        # ── Check for OOM killer ───────────────────────────────────
        oom_markers = [
            "out of memory",
            "oom-kill",
            "killed process",
            "oom_kill",
            "invoked oom-killer",
            "out_of_memory",
            "memory cgroup out of memory",
        ]
        for marker in oom_markers:
            if marker in serial_lower:
                return {
                    "type": "oom_kill",
                    "confidence": 0.85,
                    "detail": "OOM killer terminated process",
                    "is_actionable": True,
                }

        # ── Check for kernel panic ────────────────────────────────
        panic_markers = [
            "kernel panic",
            "attempted to kill init",
            "panic - not syncing",
        ]
        for marker in panic_markers:
            if marker in serial_lower:
                return {
                    "type": "kernel_panic",
                    "confidence": 0.80,
                    "detail": "Guest kernel panic (likely PID 1 death)",
                    "is_actionable": True,
                }

        # ── Check for known signal exit codes ──────────────────────
        signal = self._resolve_signal(exit_code)
        if signal is not None:
            return {
                "type": "signal_crash",
                "confidence": 0.90,
                "detail": f"Fatal signal: {signal.value}",
                "is_actionable": True,
            }

        # ── Check for negative exit code (signal via Python) ───────
        if exit_code < 0:
            sig_num = -exit_code
            return {
                "type": "signal_crash",
                "confidence": 0.90,
                "detail": f"Killed by signal {sig_num}",
                "is_actionable": True,
            }

        # ── Check for normal exit (exit code 0) ───────────────────
        # exit(0) = server shut down voluntarily — NOT a vulnerability.
        # For a long-running server this may indicate a DoS condition
        # (e.g., max-cmds limit reached), but it is NOT a memory
        # corruption bug.  We still restart the target but do NOT
        # record this as an actionable crash.
        if exit_code == 0:
            return {
                "type": "normal_exit",
                "confidence": 0.90,
                "detail": (
                    "Server exited(0) — normal shutdown, not a crash.  "
                    "Likely: connection limit, max-cmds, or clean close."
                ),
                "is_actionable": False,
            }

        # ── Non-zero exit without signal ───────────────────────────
        return {
            "type": "unknown",
            "confidence": 0.30,
            "detail": f"Process exited with code {exit_code}",
            "is_actionable": True,
        }

    # -----------------------------------------------------------------
    # Corpus Management
    # -----------------------------------------------------------------

    def save_crash_record(self, record: CrashRecord) -> Path:
        """Persist a crash record to the corpus directory.

        Saves:
        - ``/crashes/crash_<timestamp>_<crash_id>.json`` — metadata + hex.
        - ``/crashes/crash_<timestamp>_<crash_id>.bin`` — raw packet bytes for replay.

        Args:
            record: The CrashRecord to save.

        Returns:
            Path to the saved JSON file.
        """
        # Ensure crash directory exists
        self.crash_corpus_dir.mkdir(parents=True, exist_ok=True)

        timestamp_suffix = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"crash_{timestamp_suffix}_{record.crash_id}"
        json_path = self.crash_corpus_dir / f"{base_name}.json"
        bin_path = self.crash_corpus_dir / f"{base_name}.bin"

        # Save JSON metadata
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(
                    record.model_dump(mode="json"),
                    f,
                    indent=2,
                    default=str,
                )
            logger.info(f"Crash metadata saved: {json_path}")
        except OSError as e:
            logger.error(f"Failed to save crash JSON: {e}")

        # Save raw packet binary (for replay tools)
        if record.offending_packet:
            try:
                with open(bin_path, "wb") as f:
                    f.write(record.offending_packet)
                logger.info(f"Crash binary saved: {bin_path}")
            except OSError as e:
                logger.error(f"Failed to save crash binary: {e}")

        return json_path

    # -----------------------------------------------------------------
    # Container Control
    # -----------------------------------------------------------------

    async def restart_target(self) -> None:
        """Reset the crashed target via the sandbox abstraction.

        Delegates to ``sandbox.reset_state()``:
        - Docker: container restart (~200-500ms).
        - MicroVM: snapshot restore (< 10ms).

        After reset, waits for the target to become alive again.
        """
        logger.info(
            f"Resetting target server (waiting {self.restart_delay_s}s "
            f"before reset)..."
        )

        # Brief delay to let the crash settle (Docker daemon needs time)
        await asyncio.sleep(self.restart_delay_s)

        # Reset
        t0 = time.monotonic()
        try:
            await self.sandbox.reset_state()
        except Exception as e:
            logger.error(f"sandbox.reset_state() failed: {e}")
            # Still resume — otherwise the pipeline stays paused forever.
            await self.resume_interceptor()
            return

        # Verify target is alive again
        max_wait = 15.0  # seconds
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if await self.sandbox.is_target_alive():
                elapsed = time.monotonic() - t0
                logger.info(
                    f"Target server reset complete "
                    f"(took {elapsed:.2f}s, waited {max_wait - (deadline - time.monotonic()):.1f}s)"
                )
                # Resume operations
                await self.resume_interceptor()
                return
            await asyncio.sleep(0.5)

        logger.error(
            f"Target server did NOT come back alive after {max_wait}s. "
            f"Attempting one more reset..."
        )
        # Second attempt: reset + resume even if target isn't confirmed alive,
        # so the pipeline doesn't get stuck permanently.
        try:
            await self.sandbox.reset_state()
        except Exception:
            pass
        await asyncio.sleep(3.0)
        if await self.sandbox.is_target_alive():
            logger.info("Second reset succeeded — resuming operations")
        else:
            logger.error(
                "Second reset also failed — resuming pipeline anyway "
                "to avoid permanent stuck state. Crash monitor will "
                "re-detect if target is still down."
            )
        # Always resume after second attempt.  The crash monitor's watch()
        # loop will re-detect if the target is still dead and trigger a
        # fresh on_crash() cycle.
        await self.resume_interceptor()

    async def pause_interceptor(self) -> None:
        """Signal the Interceptor and MutationEngine to pause.

        Called after a crash to prevent flooding a potentially unstable
        target with mutations during restart.
        """
        if self.interceptor is not None:
            self.interceptor.pause()

        if self.mutator is not None:
            self.mutator.pause()

        logger.warning(
            "CrashMonitor: Interceptor + MutationEngine PAUSED "
            "(traffic stopped)"
        )

    async def resume_interceptor(self) -> None:
        """Signal the Interceptor and MutationEngine to resume.

        Called after the target container has successfully restarted
        and been verified alive.
        """
        if self.interceptor is not None:
            self.interceptor.resume()

        if self.mutator is not None:
            self.mutator.resume()

        logger.info(
            "CrashMonitor: Interceptor + MutationEngine RESUMED "
            "(traffic flowing)"
        )

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
