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
import re
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
        confirm_crashes: bool = False,
        serial_asan_detection: bool = False,
        serial_asan_reset_every: int = 0,
        serial_asan_reset_interval_s: float = 0.0,
    ) -> None:
        self.sandbox = sandbox
        self.interceptor = interceptor
        self.mutator = mutator
        self.crash_manager = crash_manager
        self.poll_interval_ms = poll_interval_ms
        self.crash_corpus_dir = Path(crash_corpus_dir)
        self.auto_reset = auto_reset
        self.restart_delay_s = restart_delay_s
        # Post-crash confirmation (Phase 1): when True, on_crash freezes the
        # mutator's attribution window and replays the candidate set on a
        # clean target to find the packet that actually reproduces the crash.
        # Opt-in (default False) so legacy tests/behaviour are unchanged.
        # See docs/crash_attribution_plan.md.
        self.confirm_crashes: bool = confirm_crashes
        # Serial-ASAN detection (fork-per-connection targets): when True, the
        # watch loop also scans the driver's serial console for ASAN markers
        # each cycle and fires on_crash(target_survived=True) on a NEW marker —
        # because the daemon survives per-connection ASAN aborts, so the normal
        # death-based detection never sees them.
        self.serial_asan_detection: bool = serial_asan_detection
        # Periodically snapshot-restore after this many per-connection ASAN
        # crashes to clear forked-child zombies before they clog a fork-per-
        # connection server (else PID/fd exhaustion → server stops accepting →
        # EPS collapse). 0 = never reset on survived crashes.
        self.serial_asan_reset_every: int = serial_asan_reset_every
        # Time-based periodic reset (independent of crash count). For fork-per-
        # connection targets, snapshot-restore every N seconds to clear zombie
        # children — without this, once-per-site crash counting starves the
        # crash-triggered resets above, zombies accumulate, the server stops
        # accepting, and EPS collapses to ~1. 0 = disabled.
        self.serial_asan_reset_interval_s: float = serial_asan_reset_interval_s
        self._last_reset_time: float = -1.0  # <0 = not started; set in watch()
        self._survived_since_reset: int = 0
        self._last_asan_sig: str = ""  # signature of the last ASAN block fired on
        # Once-per-site: a given ASAN crash-site signature fires at most ONCE.
        # This makes fires == unique (no re-counting of the same bug hit N
        # times). Combined with serial-confirmation, each unique crash is
        # confirmed (reproduced=True) on its first (and only) fire.
        self._fired_asan_sigs: set[str] = set()
        self._confirmed_asan_sigs: dict[str, bool] = {}  # sig → reproduced
        # Drain pause after pause_interceptor(): the mutator's run loop is
        # sequential, so at most ONE _send is in-flight when we pause. It
        # finishes within recv_timeout (≤0.5s). Sleeping this long before
        # confirmation ensures that in-flight send can't land on the target
        # during a candidate's liveness check and cause a false "reproduced".
        self.confirm_drain_s: float = 0.5

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
        # Initialize reset timer on first watch() call (BUG L1 fix)
        if self._last_reset_time < 0:
            import time as _t
            self._last_reset_time = _t.monotonic()

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

                # ── Serial-ASAN detection (fork-per-connection targets) ──
                # The daemon survives per-connection ASAN aborts (e.g. uftpd:
                # the forked child aborts, PID 1 lives), so the death transition
                # above never fires. Scan the live serial console for a NEW
                # ASAN marker and treat it as a crash (target survived).
                if self.serial_asan_detection and alive:
                    asan_block = self._scan_serial_for_new_asan()
                    if asan_block:
                        classification = self._classify_crash(134, asan_block)
                        await self.on_crash(
                            134,
                            classification=classification,
                            serial_output=asan_block,
                            target_survived=True,
                        )
                        try:
                            was_alive = await self.sandbox.is_target_alive()
                        except Exception:
                            pass

                # Time-based periodic reset (fork-per-conn): snapshot-restore
                # every N seconds to clear zombie children, INDEPENDENT of crash
                # count. Without this, once-per-site crash counting starves the
                # crash-triggered resets → zombies accumulate → server stops
                # accepting → "Cannot connect upstream" storm → EPS collapse.
                if (self.serial_asan_detection and alive
                        and self.serial_asan_reset_interval_s > 0):
                    now = time.monotonic()
                    if now - self._last_reset_time >= self.serial_asan_reset_interval_s:
                        self._last_reset_time = now
                        logger.info(
                            f"serial-ASAN: time-based reset "
                            f"({self.serial_asan_reset_interval_s:.0f}s) — "
                            f"clearing forked-child zombies"
                        )
                        await self.pause_interceptor()
                        try:
                            await self.restart_target(settle=False)
                        except Exception as _e:
                            logger.error(
                                f"serial-ASAN time-based reset failed: {_e}"
                            )

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
        target_survived: bool = False,
    ) -> CrashRecord:
        """Handle a target-down event (actionable crash OR normal exit).

        Actionability is decided by ``classification["is_actionable"]`` —
        for a normal exit (exit 0, e.g. a max-cmds / connection-limit
        shutdown) the classification carries ``is_actionable=False``.

        For a normal exit:
        1. Build the CrashRecord (returned to caller).
        2. Restart the target (if auto_reset).
        3. Return — NO counter increment, NO ERROR log, NO artifact,
           NO CrashManager recording.

        For an actionable crash:
        1. Resolve the signal name from the exit code.
        2. Increment the crash counter and log at ERROR.
        3. Pause the Interceptor and MutationEngine immediately.
        4. Save the crash record to the corpus directory.
        5. Record through CrashManager for deduplication.
        6. Reset the target via sandbox.reset_state().
        7. Resume the Interceptor and MutationEngine.

        Args:
            exit_code: Container exit code (e.g., 139 for SIGSEGV).
            classification: Optional crash classification dict from
                ``_classify_crash()`` with keys: type, confidence, detail,
                is_actionable.
            serial_output: Optional serial console output from the VM
                (contains kernel panic / ASAN messages).

        Returns:
            The created CrashRecord.
        """
        # 1. Determine actionability FIRST. A normal exit (exit 0 = clean
        #    shutdown, max-cmds limit, connection limit) is classified
        #    is_actionable=False. Such events must NOT increment the crash
        #    counter, must NOT log at ERROR, and must NOT save artifacts —
        #    they are target behaviour, not vulnerabilities. Previously this
        #    check ran AFTER _crash_count had been incremented and "Crash #N"
        #    / "Crash artifact" had been logged at ERROR, inflating the crash
        #    count and spamming logs with false crashes (e.g. every LightFTP
        #    max-cmds exit printed "Crash #6" at ERROR).
        is_actionable = True
        if classification:
            is_actionable = classification.get("is_actionable", True)

        # 2. Resolve signal + offending packet (needed for the returned record
        #    regardless of actionability).
        signal = self._resolve_signal(exit_code)

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
                    # PHASE 2: crash_window entries are 4-tuple (ts, payload,
                    # rule_id, prefix). Unpack robustly (handle both 3/4-tuple).
                    _entry = crash_window[-1]
                    offending_packet = _entry[1] if len(_entry) > 1 else b""
                    rule_id = _entry[2] if len(_entry) > 2 else None

        # Tertiary: backward-compat private field access (defensive — a
        # mutator stand-in or future implementation may not expose these).
        if not offending_packet and self.mutator is not None:
            offending_packet = getattr(self.mutator, "_last_injected_packet", b"") or b""
            rule_id = getattr(self.mutator, "_last_injected_rule_id", None)

        # 3. Create CrashRecord (returned to caller in every branch)
        record = CrashRecord(
            exit_code=exit_code,
            signal=signal,
            offending_packet=offending_packet,
            mutation_rule_id=rule_id,
            stack_trace=serial_output[-2000:] if serial_output else None,
        )

        # 4. Non-actionable exit: restart the target but do NOT treat it as a
        #    crash — no counter increment, no ERROR log, no artifact, no
        #    CrashManager recording.
        if not is_actionable:
            cls_type = classification["type"] if classification else "normal_exit"
            cls_detail = classification.get("detail", "") if classification else ""
            logger.info(
                f"Target exited normally (exit_code={exit_code}, "
                f"type={cls_type}) — not a crash; restarting target "
                f"without recording. ({cls_detail})"
            )
            if self.auto_reset:
                # Phase 3 / TASK 1: pause the Interceptor + MutationEngine
                # around the restart so the hot loop does NOT fire a barrage
                # of sends at the dead target. Without this, every send during
                # the restart stall got connection-refused → PacketStatus.CRASH
                # → spurious ONE_AT_A_TIME investigation (29x in the 8h run),
                # which burned budget on phantom crashes and collapsed EPS.
                # settle=False skips the 2s restart_delay_s (Firecracker snapshot
                # restore is <10ms; the settle is Docker-legacy and pure EPS
                # drag here). Real crashes still use settle=True (actionable
                # path below).
                await self.pause_interceptor()
                # Phase 3.1 / TASK 1: a graceful exit (exit 0) cannot itself be
                # a crash, so any ONE_AT_A_TIME investigation armed by
                # connection-refused sends that landed in the ~poll-interval
                # window BETWEEN target-down and pause() is phantom. Cancel it
                # so the engine reverts to normal mode on resume instead of
                # burning isolation budget on ghosts (~1.3/min in smoke #2).
                if self.mutator is not None:
                    cancel = getattr(self.mutator, "cancel_investigation", None)
                    if cancel is not None:
                        cancel()
                try:
                    await self.restart_target(settle=False)
                finally:
                    await self.resume_interceptor()
            return record

        # ── Actionable crash below ───────────────────────────────────
        self._crash_count += 1
        signal_str = signal.value if signal else f"unknown (exit {exit_code})"
        logger.error(
            f"Crash #{self._crash_count}: {signal_str} "
            f"(exit_code={exit_code})"
        )
        logger.error(
            f"Crash artifact: packet={record.offending_packet_hex[:64]}, "
            f"rule_id={rule_id}"
        )
        if classification:
            logger.warning(
                f"Crash classification: {classification['type']} "
                f"(confidence={classification['confidence']:.0%}, "
                f"detail={classification.get('detail', '')})"
            )

        # 5. Pause traffic IMMEDIATELY (skip for serial-ASAN: the daemon
        # survived the per-connection crash — keep fuzzing, no reset needed).
        if not target_survived:
            await self.pause_interceptor()

        # 5b. Post-crash confirmation (Phase 1, opt-in). The legacy
        #     attribution assumed crash_window[-1] was the culprit, but at
        #     ~400 EPS the real culprit (up to ~200 sends before detection)
        #     is usually evicted from the window and post-crash refused
        #     sends pollute it. Confirmation freezes the window and replays
        #     the candidate set on a clean target to find the packet that
        #     actually reproduces the crash. Runs while the mutator is
        #     paused, so the hot loop is unaffected; cost is paid only per
        #     crash. See docs/crash_attribution_plan.md.
        reproduced = False
        confirmation_method = "serial_asan" if target_survived else "window_last"
        # Confirmation runs whenever enabled + a mutator is present. It must
        # NOT be gated on `offending_packet`: that variable is exactly what
        # attribution produces, and when attribution already failed (empty
        # packet — the common real-world case for early/rapid crashes) is
        # precisely when confirmation is most needed. freeze() returns the
        # actual candidates; if the window is genuinely empty, _confirm_crash
        # returns (b"", None, False) and we fall through to the legacy record.
        if self.confirm_crashes and self.mutator is not None:
            # For target_survived (fork-per-conn), pause the mutator so back-
            # ground traffic doesn't produce ASAN that pollutes the serial-based
            # confirmation check. For death-based (target dies), the mutator is
            # already paused (step 5 above).
            if target_survived:
                await self.pause_interceptor()
            # Drain the (at most one) in-flight send so it cannot land on the
            # target during a candidate's check and cause a false "reproduced".
            await asyncio.sleep(self.confirm_drain_s)
            freeze = getattr(self.mutator, "freeze_crash_window", None)
            if freeze is not None:
                try:
                    candidates = freeze()
                    if candidates:
                        conf_payload, conf_rule, reproduced = (
                            await self._confirm_crash(
                                candidates, target_survived=target_survived
                            )
                        )
                        if reproduced and conf_payload:
                            offending_packet = conf_payload
                            rule_id = conf_rule
                            confirmation_method = "replay_confirmed"
                            record = CrashRecord(
                                exit_code=exit_code,
                                signal=signal,
                                offending_packet=offending_packet,
                                mutation_rule_id=rule_id,
                                stack_trace=(
                                    serial_output[-2000:]
                                    if serial_output else None
                                ),
                            )
                        else:
                            confirmation_method = "replay_unconfirmed"
                except Exception as exc:
                    logger.warning(
                        f"confirm: confirmation phase errored ({exc}); "
                        f"falling back to window[-1] attribution"
                    )
                    confirmation_method = "replay_error"
                finally:
                    unfreeze = getattr(self.mutator, "unfreeze_crash_window", None)
                    if unfreeze is not None:
                        try:
                            unfreeze()
                        except Exception:
                            pass
            # Resume the mutator if we paused it for serial-ASAN confirmation.
            if target_survived:
                await self.resume_interceptor()

        # 5c. Stamp the confirmation outcome onto the record so the
        # crash_monitor's own artifact (crashes/*.json via save_crash_record)
        # carries the same reproduced/confirmation_method as CrashManager.
        record.reproduced = reproduced
        record.confirmation_method = confirmation_method

        # 6. Save crash artifact to disk
        crash_path = self.save_crash_record(record)
        if reproduced:
            logger.error(f"Crash PoC saved (REPRODUCED) to: {crash_path}")
        elif self.confirm_crashes:
            logger.warning(
                f"Crash PoC saved (UNCONFIRMED — replay did not reproduce) "
                f"to: {crash_path}"
            )
        else:
            logger.error(f"Crash PoC saved to: {crash_path}")

        # 7. Record through CrashManager for deduplication
        # Use classification type as crash_type for richer reporting
        crash_type_str = (
            classification["type"] if classification else f"exit_{exit_code}"
        )
        # Record EVERY detected crash — do NOT withhold unconfirmed ones. A
        # crash detected by a fatal signal / ASAN marker is a real event even
        # when the replay confirmation fails (e.g. the blamed packet was a
        # misattributed later send, or the harness hit a transient error).
        # Withholding detected crashes to inflate the reproduced ratio would
        # be dishonest. Instead:
        #   - σ₃ (crash-location) dedup groups crashes by crash SITE, so a
        #     misattributed event whose serial still carries the real crash's
        #     ASAN trace dedups WITH it rather than inflating the unique count.
        #   - reproduced / confirmation_method are kept as transparent metadata
        #     on every record so the reader can judge confidence per crash.
        if self.crash_manager is not None:
            try:
                # σ₃: crash-LOCATION signature from the serial stack trace, so
                # distinct overflow payloads that abort at the same site dedup
                # to ONE vulnerability (standard crash-mode dedup). Computed
                # from the captured serial_output (ASAN report + backtrace).
                crash_location_sig = ""
                try:
                    from shared.crash_manager import compute_crash_location_sig
                    crash_location_sig = compute_crash_location_sig(
                        serial_output or ""
                    )
                except Exception:
                    crash_location_sig = ""
                result = await self.crash_manager.record(
                    payload=record.offending_packet,
                    crash_type=crash_type_str,
                    rule_set_id=record.mutation_rule_id,
                    notes=classification.get("detail", "") if classification else "",
                    reproduced=reproduced,
                    confirmation_method=confirmation_method,
                    crash_location_sig=crash_location_sig or None,
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

        # 7. Reset policy. Fork-per-connection targets (serial-ASAN) survive
        # each per-connection crash, so we DON'T reset per crash (keeps EPS
        # up) — but aborted children accumulate faster than they're reaped →
        # PID/fd exhaustion → server stops accepting → EPS collapse. So
        # periodically snapshot-restore to clear the zombies.
        if target_survived:
            self._survived_since_reset += 1
            if (self.serial_asan_reset_every > 0
                    and self._survived_since_reset >= self.serial_asan_reset_every):
                logger.info(
                    f"serial-ASAN: {self._survived_since_reset} per-connection "
                    f"crashes since last reset — snapshot restore to clear "
                    f"forked-child zombies (throughput recovery)."
                )
                self._survived_since_reset = 0
                await self.pause_interceptor()
                try:
                    await self.restart_target(settle=False)
                except Exception as e:
                    logger.error(f"serial-ASAN periodic reset failed: {e}")
            else:
                logger.info(
                    "Target survived per-connection crash (serial-ASAN) — "
                    "no reset; continuing to fuzz."
                )
        elif self.auto_reset:
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
                    "detail": "OOM killer terminated process "
                              "(infrastructure issue — VM ran out of memory, "
                              "not a target bug). Increase VM mem_size or "
                              "reduce maxusers/max_connections.",
                    "is_actionable": False,
                }

        # ── Check for kernel panic ────────────────────────────────
        panic_markers = [
            "kernel panic",
            "attempted to kill init",
            "panic - not syncing",
        ]
        for marker in panic_markers:
            if marker in serial_lower:
                # exit_code=0 = PID 1 exited NORMALLY (e.g. LightFTP QUIT →
                # clean shutdown, or maxcmds/maxusers limit reached). This is
                # NOT a crash — the kernel panics because init died, but the
                # death is benign. Only exit_code ≠ 0 (ASAN abort=134,
                # SIGSEGV=139) indicates a real crash.
                if exit_code == 0:
                    return {
                        "type": "normal_exit",
                        "confidence": 0.90,
                        "detail": (
                            "Server exited(0) — normal shutdown (QUIT, "
                            "maxcmds, or maxusers limit). Kernel panic "
                            "on PID-1 death is benign, NOT a crash."
                        ),
                        "is_actionable": False,
                    }
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
    # Serial-ASAN detection (fork-per-connection targets)
    # -----------------------------------------------------------------

    def _get_serial_text(self) -> str:
        """Live serial console text from the driver (defensive — only the
        Firecracker driver exposes get_serial_output())."""
        getter = getattr(self.sandbox, "get_serial_output", None)
        if getter is None:
            return ""
        try:
            return getter() or ""
        except Exception:
            return ""

    def _scan_serial_for_new_asan(self) -> str:
        """Scan the live serial console for an ASAN block not yet fired on.

        Dedups by crash-site signature so repeated same-site aborts (e.g.
        uftpd's handle_PORT) fire once, matching σ₃ unique-crash semantics.
        Returns the block text if a NEW one is found, else ''.
        """
        text = self._get_serial_text()
        if not text:
            return ""
        low = text.lower()
        if "addresssanitizer" not in low and "==error:" not in low:
            return ""
        block = self._extract_asan_block(text)
        if not block:
            return ""
        sig = self._asan_sig(block)
        if sig and sig in self._fired_asan_sigs:
            return ""  # once-per-site: this crash site already fired — no re-counting
        self._last_asan_sig = sig
        self._fired_asan_sigs.add(sig)
        # CONSUME the report: clear the serial buffer so this ASAN block
        # doesn't re-fire on the next poll. Without this the report sits in
        # the buffer and is re-detected every cycle → a 25:1 false-positive
        # storm (186 fires for 7 real sites). The next fire requires a NEW
        # ASAN report written AFTER this clear.
        clearer = getattr(self.sandbox, "clear_serial_buffer", None)
        if clearer is not None:
            try:
                clearer()
            except Exception:
                pass
        return block

    @staticmethod
    def _extract_asan_block(text: str) -> str:
        """Extract the most recent ASAN report: from the last '==ERROR:' line
        through the following 'ABORTING'/'SUMMARY:' (capped ~30 lines)."""
        lines = text.splitlines()
        start = -1
        for i in range(len(lines) - 1, -1, -1):
            ls = lines[i].lower()
            if "addresssanitizer" in ls or "==error:" in ls:
                start = i
                break
        if start < 0:
            return ""
        end = min(start + 30, len(lines))
        for j in range(start + 1, end):
            lj = lines[j].lower()
            if "aborting" in lj or "summary:" in lj:
                end = j + 1
                break
        return "\n".join(lines[start:end])

    @staticmethod
    def _asan_sig(block: str) -> str:
        """Crash-site signature: ASAN error type + the SUMMARY line (carries
        the binary offset, e.g. 'uftpd+0x605ac'). Same site → same sig."""
        low = block.lower()
        errtype = "asan"
        for spec in (
            "stack-buffer-overflow", "heap-buffer-overflow",
            "heap-use-after-free", "stack-use-after-free",
            "global-buffer-overflow", "stack-overflow",
        ):
            if spec in low:
                errtype = spec
                break
        summary = ""
        for line in block.splitlines():
            if "summary:" in line.lower():
                # Strip the per-process "==N==" PID prefix so the signature is
                # stable across crashes at the SAME site (each forked child has
                # a different PID, else every same-site abort looks "new").
                summary = re.sub(r"^==\d+==\s*", "", line.strip())
                break
        return f"{errtype}|{summary}"

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

    async def restart_target(self, settle: bool = True) -> None:
        """Reset the crashed target via the sandbox abstraction.

        Delegates to ``sandbox.reset_state()``:
        - Docker: container restart (~200-500ms).
        - MicroVM: snapshot restore (< 10ms).

        After reset, waits for the target to become alive again.

        Args:
            settle: When True, sleep ``restart_delay_s`` before resetting
                (lets a Docker crash settle so the daemon is ready). When
                False (e.g. a normal exit-code-0 restart on Firecracker),
                skip the delay — snapshot restore is sub-10ms and the 2s
                settle stall is pure EPS drag with no benefit.
        """
        if settle:
            logger.info(
                f"Resetting target server (waiting {self.restart_delay_s}s "
                f"before reset)..."
            )
            # Brief delay to let the crash settle (Docker daemon needs time)
            await asyncio.sleep(self.restart_delay_s)
        else:
            logger.info(
                "Resetting target server (fast path — no settle delay)..."
            )

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

    # -------------------------------------------------------------------
    # Post-Crash Confirmation (Phase 1)
    # -------------------------------------------------------------------

    async def _confirm_crash(
        self,
        candidates: list[tuple],
        target_survived: bool = False,
    ) -> tuple[bytes, Optional[str], bool]:
        """Replay candidate packets on a clean target to find the real culprit.

        Iterates the candidates most-recent-first (crashes usually come from
        a packet close to the moment of death), resetting the target before
        each replay so each attempt starts from a known-good state. Returns
        the first packet that reproduces the crash (``reproduced=True``).

        If no candidate reproduces (e.g. the crash needs a multi-packet
        prefix — Phase 2), falls back to the most-recent candidate flagged
        ``reproduced=False`` so the PoC is still recorded but clearly marked
        as unconfirmed.

        Failure isolation: any reset/replay error is logged and skipped —
        this never raises. A confirmation that can't run degrades to the
        legacy ``window[-1]`` attribution (``reproduced=False``).

        Args:
            candidates: ``[(ts, payload, rule_id, prefix), ...]`` oldest → newest,
                        from the frozen crash window. ``prefix`` is the verbatim
                        session-setup packets (e.g. USER+PASS) — replayed before
                        the target so stateful crashes reproduce (Phase 2).

        Returns:
            ``(payload, rule_id, reproduced)``.
        """
        if not candidates:
            return b"", None, False

        host = getattr(self.mutator, "target_host", None) if self.mutator else None
        port = getattr(self.mutator, "target_port", None) if self.mutator else None
        if not host or not port:
            _e = candidates[-1]
            return _e[1], _e[2], False

        # Bound the confirmation cost by WALL-CLOCK budget, not a fixed count.
        # We search candidates most-recent-first (the culprit is usually among
        # the latest sends) but a fixed count-cap would miss a culprit that
        # sits a little further back in the window — at high EPS the blamed
        # window[-1] and the real culprit can be many sends apart. A time
        # budget instead lets a cheap replay (e.g. a unit-test mock, or a
        # target that crashes fast) search the whole window, while a target
        # whose crash chain is slow (~3s liveness poll per candidate) is still
        # bounded so the hot loop is not paused for too long per crash.
        import time as _time
        _CONFIRM_BUDGET_S = 15.0
        _deadline = _time.monotonic() + _CONFIRM_BUDGET_S
        tried = 0
        for _entry in reversed(candidates):
            if _time.monotonic() > _deadline:
                logger.debug(
                    f"confirm: time budget ({_CONFIRM_BUDGET_S:.0f}s) reached "
                    f"after {tried} candidates; stopping search"
                )
                break
            payload = _entry[1]
            rule_id = _entry[2]
            # PHASE 2: the session prefix (verbatim setup packets e.g. USER+PASS).
            # A stateful crash only reproduces if the prefix is replayed first.
            prefix = _entry[3] if len(_entry) > 3 else []
            if not payload:
                continue
            tried += 1
            try:
                await self.sandbox.reset_state()
            except Exception as exc:
                logger.debug(f"confirm: reset failed before replay: {exc}")
                continue
            try:
                if not await self.sandbox.is_target_alive():
                    continue  # target didn't come back — can't test this one
            except Exception:
                continue
            reproduced = await self._replay_and_check(payload, host, port, prefix, check_serial=target_survived)
            if reproduced:
                logger.info(
                    f"confirm: REPRODUCED crash with replayed packet "
                    f"(len={len(payload)}, rule={rule_id}, "
                    f"prefix={len(prefix)}pkts, tried={tried})"
                )
                return payload, rule_id, True

        # No single packet reproduced — even with prefix. Genuinely unconfirmed.
        _e = candidates[-1]
        logger.warning(
            f"confirm: no candidate reproduced the crash "
            f"(tried {tried}/{len(candidates)}); flagging PoC as unconfirmed "
        )
        return _e[1], _e[2], False

    async def _replay_and_check(
        self, payload: bytes, host: str, port: int, prefix: list | None = None,
        check_serial: bool = False,
    ) -> bool:
        """Replay prefix (session setup) + payload on a fresh connection;
        return True if the target crashed afterward.

        PHASE 2 (stateful): for stateful protocols, the target packet alone
        won't reach the vulnerable code — the prefix (e.g. USER+PASS auth)
        must be replayed first on the SAME connection. Without this, every
        stateful crash is marked unconfirmed (target alone doesn't reproduce).
        The prefix is the verbatim setup captured from the real client.
        """
        prefix = prefix or []
        if check_serial:
            # Clear the serial buffer BEFORE replay so only ASAN from THIS
            # replay is detected (not stale or leftover reports).
            clearer = getattr(self.sandbox, "clear_serial_buffer", None)
            if clearer:
                try:
                    clearer()
                except Exception:
                    pass
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0
            )
        except Exception:
            return False  # can't connect → no reproduction signal
        try:
            # Drain the server greeting (e.g. FTP 220 banner) before any send.
            try:
                await asyncio.wait_for(reader.read(4096), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            # Replay the prefix packets verbatim, draining each response.
            for pkt in prefix:
                writer.write(pkt)
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(4096), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
            # Send the target payload + drain (ASAN fires during processing).
            writer.write(payload)
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(4096), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
        if check_serial:
            # Fork-per-connection: the daemon survives per-connection ASAN
            # aborts, so death-based check never fires. Poll the serial console
            # for a NEW ASAN marker (written after the buffer-clear above).
            # Poll every 0.3s for up to 3s — some crash chains (child abort →
            # serial drain → buffer update) take >1s; a single 1s check misses
            # them and marks REAL PoCs as unconfirmed.
            _SERIAL_DEADLINE_S = 3.0
            _SERIAL_POLL_S = 0.3
            _elapsed = 0.0
            while _elapsed < _SERIAL_DEADLINE_S:
                await asyncio.sleep(_SERIAL_POLL_S)
                _elapsed += _SERIAL_POLL_S
                _st = self._get_serial_text()
                _sl = _st.lower() if _st else ""
                if "addresssanitizer" in _sl or "==error:" in _sl:
                    return True
            return False

        # Grace period for the crash to manifest, then check liveness.
        # A single short sleep is insufficient for targets whose crash chain
        # is slow: e.g. a fork-per-connection server where the child aborts
        # (ASAN), the parent's SIGCHLD handler exits (CRASH_THRESHOLD), the
        # guest kernel panics on PID-1 death, and only then does the VMM
        # process register an exit code — that chain routinely takes ~1-2s.
        # A single 0.2s check reports the target as still alive and marks a
        # REAL PoC as "not reproduced" → every real crash ends up
        # "unconfirmed". Poll liveness for a few seconds instead so a slow
        # crash chain still registers. General for any target with a slow
        # crash-to-exit propagation.
        _CONFIRM_DEADLINE_S = 3.0
        _CONFIRM_POLL_S = 0.3
        _elapsed = 0.0
        while _elapsed < _CONFIRM_DEADLINE_S:
            await asyncio.sleep(_CONFIRM_POLL_S)
            _elapsed += _CONFIRM_POLL_S
            try:
                if not await self.sandbox.is_target_alive():
                    return True  # target died after the replay → reproduced
            except Exception:
                # Transient check error — keep polling rather than assume alive.
                continue
        return False  # stayed alive for the whole window → not reproduced

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
