"""
fast_loop/mutator.py
--------------------
Block 2 — Component D: Mutation Engine

CORE PROBLEM THIS SOLVES:
    Naïve fuzzing mutates ALL fields of a packet simultaneously.
    This is catastrophically bad for crash isolation: if a crash occurs,
    you cannot determine WHICH of the 6 mutated fields triggered it.
    You'd need to re-run thousands of tests to pinpoint the root cause.

TWO-MODE SCHEDULING ARCHITECTURE:
    ┌──────────────────────────────────────────────────────────────────┐
    │  Mode 1 — RANDOM_SUBSET  (default, normal fuzzing)              │
    │    Pick k=2 random mutable fields per packet.                   │
    │    High EPS. Broad coverage. Acceptable crash isolation.         │
    │                                                                  │
    │  Mode 2 — ONE_AT_A_TIME  (crash investigation, auto-triggered)  │
    │    Cycle through fields one-by-one. One field mutated per send.  │
    │    Lower EPS. Perfect crash isolation. Pinpoints exact field.    │
    └──────────────────────────────────────────────────────────────────┘

STATE MACHINE:
    [NORMAL / RANDOM_SUBSET]
           │
           │  crash detected (Health Monitor calls set_investigation_mode())
           ▼
    [INVESTIGATION / ONE_AT_A_TIME]
           │
           │  isolation_budget exhausted OR operator calls set_normal_mode()
           ▼
    [NORMAL / RANDOM_SUBSET]

ATOMIC RULE UPDATES:
    The Slow Loop (Block 3) can push a new SemanticRuleSet at any time.
    The hot loop MUST NOT be interrupted mid-packet construction.
    Solution: asyncio.Lock held only during the pointer swap (< 1 µs).

INTERFACES:
    CONSUMES: asyncio.Queue[PacketRecord] from Interceptor (C)
              SemanticRuleSet via update_rule_set() from Rule Generator (H)
    PRODUCES: mutated bytes → Target Server (B) via TCP
              PacketStatus  → Interceptor (C) via status_callback
              CrashReport   → CrashManager  via crash_callback
"""

from __future__ import annotations

import asyncio
import os
import random
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from shared.logger import get_logger
from shared.schemas import (
    FieldRule,
    MutationStrategy,
    PacketRecord,
    PacketStatus,
    SemanticRuleSet,
)

log = get_logger("fast_loop.mutator")


# ===========================================================================
# Mutation Mode
# ===========================================================================

class MutationMode(str, Enum):
    """
    Controls which fields are mutated per packet.

    RANDOM_SUBSET  → pick k random mutable fields (default, high EPS)
    ONE_AT_A_TIME  → one field per packet, cycling (crash isolation)
    ALL_FIELDS     → mutate every mutable field (max coverage, min isolation)
    DUMB           → no SemanticRules, random bit-flip fallback
    """
    RANDOM_SUBSET = "random_subset"
    ONE_AT_A_TIME = "one_at_a_time"
    ALL_FIELDS    = "all_fields"
    DUMB          = "dumb"


# ===========================================================================
# Schedulers
# ===========================================================================

class _BaseScheduler:
    """Abstract base: select which FieldRules to mutate for one packet."""

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        raise NotImplementedError

    def notify_crash(self) -> None:
        """Called when a crash is detected (for book-keeping in subclasses)."""
        pass

    def reset(self) -> None:
        """Reset internal state."""
        pass

    @property
    def description(self) -> str:
        raise NotImplementedError


class RandomSubsetScheduler(_BaseScheduler):
    """
    RANDOM_SUBSET: choose k fields at random per packet.

    Default k=2 balances two competing objectives:
      - Coverage:   low k → explore fewer fields per send → need more sends
      - Isolation:  high k → harder to pinpoint which field caused a crash
    k=2 is the empirically recommended starting point (see design notes).

    The fields are chosen WITHOUT replacement so the same field
    is never mutated twice in the same packet.

    Args:
        k: Number of fields to mutate per packet. Clamped to len(mutable_fields).
    """

    def __init__(self, k: int = 2) -> None:
        self.k = k

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        if not mutable_fields:
            return []
        k = min(self.k, len(mutable_fields))
        return random.sample(mutable_fields, k)

    @property
    def description(self) -> str:
        return f"RandomSubset(k={self.k})"


class OneAtATimeScheduler(_BaseScheduler):
    """
    ONE_AT_A_TIME: mutate exactly one field per packet, cycling deterministically.

    Each send targets a different field:
        send 0 → field 0
        send 1 → field 1
        send 2 → field 2
        send 3 → field 0  ← wraps around
        …

    This mode is used AUTOMATICALLY when a crash is detected, allowing the
    system to determine WHICH exact field triggered the vulnerability.

    Attributes:
        _cursor:         Index of the next field to mutate.
        budget_per_field: Max times each field is tested before moving on.
        isolation_budget: Total sends allowed before reverting to RANDOM_SUBSET.
    """

    def __init__(
        self,
        budget_per_field: int = 20,
        isolation_budget: int = 500,
    ) -> None:
        self.budget_per_field = budget_per_field
        self.isolation_budget = isolation_budget
        self._cursor:        int = 0
        self._field_hits:    dict[int, int] = {}
        self._sends_this_mode: int = 0

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        if not mutable_fields:
            return []
        idx = self._cursor % len(mutable_fields)
        chosen = mutable_fields[idx]

        # Advance cursor after budget_per_field hits on this field
        self._field_hits[idx] = self._field_hits.get(idx, 0) + 1
        if self._field_hits[idx] >= self.budget_per_field:
            self._cursor += 1
            self._field_hits[idx] = 0

        self._sends_this_mode += 1
        return [chosen]

    def is_budget_exhausted(self, num_fields: int) -> bool:
        """True when we have cycled through all fields enough times."""
        return self._sends_this_mode >= self.isolation_budget

    def get_current_field_index(self) -> int:
        """The 0-based index of the field currently under investigation."""
        return self._cursor

    def reset(self) -> None:
        self._cursor         = 0
        self._field_hits     = {}
        self._sends_this_mode = 0

    @property
    def description(self) -> str:
        return (
            f"OneAtATime(cursor={self._cursor}, "
            f"sends={self._sends_this_mode}/{self.isolation_budget})"
        )


class AllFieldsScheduler(_BaseScheduler):
    """
    ALL_FIELDS: mutate every mutable field per packet.
    Maximum coverage but zero crash isolation.
    Useful for initial quick reachability tests.
    """

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        return list(mutable_fields)

    @property
    def description(self) -> str:
        return "AllFields"


# ===========================================================================
# Runtime Statistics
# ===========================================================================

@dataclass
class MutatorStats:
    """Live statistics snapshot. Exposed via get_stats()."""
    mode:              str   = MutationMode.DUMB
    total_sent:        int   = 0
    total_accepted:    int   = 0
    total_rejected:    int   = 0
    total_timeout:     int   = 0
    total_crashes:     int   = 0
    current_eps:       float = 0.0
    rule_set_version:  int   = 0
    rule_set_id:       str   = "none"
    active_fields:     int   = 0
    investigation_mode: bool = False
    investigation_field: Optional[str] = None


# ===========================================================================
# Mutation Engine
# ===========================================================================

class MutationEngine:
    """
    High-speed, rule-aware, scheduling-driven packet mutation engine.

    Hot-loop lifecycle:
        1. Pop seed from queue (or pick from corpus via round-robin)
        2. Build base payload (from rule set's base_packet or seed)
        3. Scheduler selects k fields to mutate this round
        4. Apply per-field mutation strategies
        5. Send to Target Server
        6. Record status → feed back to Interceptor for stuck detection
        7. If CRASH → notify CrashManager + optionally enter investigation mode
        8. Repeat

    Mode transitions are ATOMIC — the scheduler object reference is
    swapped under asyncio.Lock. The hot loop sees either the old or
    the new scheduler, never a half-transitioned state.

    Args:
        target_host:        Hostname of Target Server (Block 1B).
        target_port:        Port of Target Server.
        seed_queue:         asyncio.Queue[PacketRecord] from Interceptor (C).
        k:                  Fields per packet in RANDOM_SUBSET mode.
        max_eps:            Throttle ceiling (0 = unlimited).
        connection_timeout: TCP connect timeout in seconds.
        recv_timeout:       Time to wait for a server response.
        auto_investigate:   If True, auto-switch to ONE_AT_A_TIME on crash.
        investigation_budget: Max sends in ONE_AT_A_TIME mode before reverting.
    """

    def __init__(
        self,
        target_host:          str,
        target_port:          int,
        seed_queue:           asyncio.Queue,
        k:                    int   = 2,
        max_eps:              int   = 1000,
        connection_timeout:   float = 1.0,
        recv_timeout:         float = 0.5,
        auto_investigate:     bool  = True,
        investigation_budget: int   = 500,
    ) -> None:
        self.target_host         = target_host
        self.target_port         = target_port
        self.seed_queue          = seed_queue
        self.k                   = k
        self.max_eps             = max_eps
        self.connection_timeout  = connection_timeout
        self.recv_timeout        = recv_timeout
        self.auto_investigate    = auto_investigate
        self.investigation_budget = investigation_budget

        # Active scheduler — swapped atomically on mode change
        self._scheduler:    _BaseScheduler    = RandomSubsetScheduler(k=k)
        self._mode:         MutationMode      = MutationMode.RANDOM_SUBSET
        self._sched_lock:   asyncio.Lock      = asyncio.Lock()

        # Active rule set — swapped atomically by Slow Loop (Block 3)
        self._rule_set:     Optional[SemanticRuleSet] = None
        self._rule_lock:    asyncio.Lock              = asyncio.Lock()

        # Seed corpus — populated incrementally from seed_queue
        self._corpus:       list[PacketRecord] = []
        self._rr_index:     int                = 0    # Round-robin cursor

        # EPS tracking (rolling window of send timestamps)
        self._eps_window:   deque[float]       = deque(maxlen=200)
        self._last_eps_log: float              = time.monotonic()

        # Callbacks (set by orchestrator / Health Monitor)
        # status_callback(packet_id: str, status: PacketStatus) → None
        self.status_callback: Optional[Callable[[str, PacketStatus], None]] = None
        # crash_callback(payload: bytes, crash_type: str) → None
        self.crash_callback:  Optional[Callable[[bytes, str], None]] = None

        # Control flags
        self._running: bool = False
        self._paused:  bool = False

        # Stats
        self._stats = MutatorStats()

        log.info(
            "MutationEngine initialized",
            extra={"context": {
                "target": f"{target_host}:{target_port}",
                "mode":   self._mode.value,
                "k":      k,
                "max_eps": max_eps,
            }},
        )

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main hot-loop. Run as a long-lived asyncio Task.

            task = asyncio.create_task(mutator.run())

        The loop:
            1. Drains any new seeds from the interceptor queue.
            2. Picks a seed from the corpus (round-robin).
            3. Builds + mutates a packet using the active scheduler.
            4. Sends the packet; records the status.
            5. Throttles to max_eps if configured.
            6. Repeats until stop() is called.

        TODO:
            - Persistent connection mode (pool of long-lived TCP connections).
            - Multi-target mode: fuzz multiple servers in parallel.
        """
        self._running = True
        log.info("MutationEngine hot-loop started", extra={"context": {
            "mode": self._mode.value,
            "target": f"{self.target_host}:{self.target_port}",
        }})

        # Initial seed drain — wait up to 5 s for the first seed
        for _ in range(50):
            await self._drain_seeds()
            if self._corpus:
                break
            await asyncio.sleep(0.1)

        if not self._corpus:
            log.warning("No seeds received after 5 s — entering dumb-fuzz mode")
            self._corpus.append(self._make_dummy_seed())

        while self._running:
            if self._paused:
                await asyncio.sleep(0.05)
                continue

            # Throttle
            if self.max_eps > 0:
                await asyncio.sleep(1.0 / self.max_eps)

            await self._drain_seeds()

            seed    = self._pick_seed()
            payload = await self._build_mutant(seed)
            status  = await self._send(payload, seed.packet_id)

            self._update_stats(status, payload)

            # Auto-switch to investigation mode after a crash
            if status == PacketStatus.CRASH and self.auto_investigate:
                await self.set_investigation_mode(
                    reason=f"crash detected on seed {seed.packet_id[:8]}"
                )

        log.info("MutationEngine hot-loop stopped", extra={"context": {
            "total_sent":  self._stats.total_sent,
            "crashes":     self._stats.total_crashes,
            "current_eps": self._stats.current_eps,
        }})

    async def stop(self) -> None:
        """Signal the hot-loop to stop cleanly after the current iteration."""
        self._running = False

    def pause(self) -> None:
        """Temporarily suspend fuzzing (e.g. while target server restarts)."""
        self._paused = True
        log.info("MutationEngine PAUSED")

    def resume(self) -> None:
        """Resume fuzzing after a pause."""
        self._paused = False
        log.info("MutationEngine RESUMED")

    # -----------------------------------------------------------------------
    # Mode Control  (hook for Health Monitor / orchestrator)
    # -----------------------------------------------------------------------

    async def set_investigation_mode(self, reason: str = "") -> None:
        """
        Switch to ONE_AT_A_TIME mode for precise crash isolation.

        Called automatically when auto_investigate=True and a crash fires.
        Can also be called manually by the Health Monitor (E).

        The scheduler cursor is reset so investigation starts from field 0.

        Args:
            reason: Free-text reason (logged for traceability).
        """
        async with self._sched_lock:
            if self._mode == MutationMode.ONE_AT_A_TIME:
                return   # Already investigating

            self._scheduler = OneAtATimeScheduler(
                isolation_budget=self.investigation_budget
            )
            self._mode = MutationMode.ONE_AT_A_TIME
            self._stats.mode               = self._mode.value
            self._stats.investigation_mode = True

        log.warning(
            "MODE → ONE_AT_A_TIME (crash isolation)",
            extra={"context": {
                "reason":  reason or "manual",
                "budget":  self.investigation_budget,
            }},
        )

    async def set_normal_mode(self) -> None:
        """
        Revert to RANDOM_SUBSET mode.

        Called after the investigation budget is exhausted,
        or manually by the operator once the crash has been reproduced.
        """
        async with self._sched_lock:
            self._scheduler = RandomSubsetScheduler(k=self.k)
            self._mode      = MutationMode.RANDOM_SUBSET
            self._stats.mode               = self._mode.value
            self._stats.investigation_mode = False
            self._stats.investigation_field = None

        log.info(
            "MODE → RANDOM_SUBSET (normal fuzzing resumed)",
            extra={"context": {"k": self.k}},
        )

    async def update_rule_set(self, new_rules: SemanticRuleSet) -> None:
        """
        Atomically replace the active SemanticRuleSet.

        Called by the Slow Loop (Block 3) Rule Generator (H) when fresh
        protocol inference is available. The swap completes in < 1 µs —
        the hot loop is never blocked for more than one lock acquisition.

        Args:
            new_rules: The new SemanticRuleSet from the LLM pipeline.
        """
        async with self._rule_lock:
            old_id = self._rule_set.rule_set_id[:8] if self._rule_set else "none"
            self._rule_set = new_rules
            self._stats.rule_set_version += 1
            self._stats.rule_set_id       = new_rules.rule_set_id[:8]
            self._stats.active_fields     = len(new_rules.get_mutable_fields())

        log.info(
            "Rule set updated (atomic swap)",
            extra={"context": {
                "old_id":     old_id,
                "new_id":     new_rules.rule_set_id[:8],
                "protocol":   new_rules.protocol_name,
                "mutable":    len(new_rules.get_mutable_fields()),
                "static":     len(new_rules.get_static_fields()),
                "confidence": f"{new_rules.overall_confidence:.0%}",
                "version":    self._stats.rule_set_version,
            }},
        )

    def get_stats(self) -> MutatorStats:
        """Return a snapshot of current runtime statistics."""
        return MutatorStats(
            mode               = self._mode.value,
            total_sent         = self._stats.total_sent,
            total_accepted     = self._stats.total_accepted,
            total_rejected     = self._stats.total_rejected,
            total_timeout      = self._stats.total_timeout,
            total_crashes      = self._stats.total_crashes,
            current_eps        = self._stats.current_eps,
            rule_set_version   = self._stats.rule_set_version,
            rule_set_id        = self._stats.rule_set_id,
            active_fields      = self._stats.active_fields,
            investigation_mode = self._stats.investigation_mode,
            investigation_field= self._stats.investigation_field,
        )

    # -----------------------------------------------------------------------
    # Seed Management
    # -----------------------------------------------------------------------

    async def _drain_seeds(self) -> None:
        """Non-blocking drain: move new PacketRecords from queue to corpus."""
        while not self.seed_queue.empty():
            try:
                record = self.seed_queue.get_nowait()
                self._corpus.append(record)
                self.seed_queue.task_done()
            except asyncio.QueueEmpty:
                break

    def _pick_seed(self) -> PacketRecord:
        """
        Round-robin seed selection from the corpus.

        Round-robin provides deterministic, full coverage of all captured
        seeds — every valid seed gets its turn as a mutation base.

        TODO:
            - Weighted selection: prefer seeds that produced
              previously-interesting responses (near-misses).
            - Diversity filter: detect and deprioritize near-duplicate seeds.
        """
        self._rr_index = self._rr_index % len(self._corpus)
        seed = self._corpus[self._rr_index]
        self._rr_index += 1
        return seed

    @staticmethod
    def _make_dummy_seed() -> PacketRecord:
        """Generate a minimal dummy seed when no real traffic is available."""
        dummy = b"\x00" * 16
        return PacketRecord(
            direction   = __import__("shared.schemas", fromlist=["Direction"]).Direction.CLIENT_TO_SERVER,
            hex_payload = dummy.hex(),
            byte_length = len(dummy),
        )

    # -----------------------------------------------------------------------
    # Packet Construction — THE CORE ALGORITHM
    # -----------------------------------------------------------------------

    async def _build_mutant(self, seed: PacketRecord) -> bytes:
        """
        Build one mutated packet using the active scheduler and rule set.

        Steps:
            1. Acquire rule set snapshot (lock-free after pointer copy)
            2. Determine base payload (rule set base_packet > seed)
            3. Ask scheduler WHICH fields to mutate this round
            4. Apply mutation strategy for each selected field
            5. Update investigation_field stat if in ONE_AT_A_TIME mode

        Returns:
            Mutated bytes ready to send to the target.
        """
        # Snapshot rule set — avoid holding lock during mutation
        async with self._rule_lock:
            rule_set = self._rule_set

        if rule_set is None:
            return self._dumb_mutate(bytearray(seed.raw_bytes))

        # Choose base payload
        base = bytearray(seed.raw_bytes)
        if rule_set.base_packet:
            try:
                base = bytearray(bytes.fromhex(rule_set.base_packet))
            except ValueError:
                pass   # Fallback to seed

        mutable = rule_set.get_mutable_fields()
        static  = rule_set.get_static_fields()

        # Apply STATIC fields first (always overwrite — preserve magic bytes)
        for f in static:
            base = _apply_field(base, f)

        # Ask scheduler which fields to mutate this round
        async with self._sched_lock:
            chosen = self._scheduler.select(mutable)
            # Track which field is under investigation
            if self._mode == MutationMode.ONE_AT_A_TIME and chosen:
                self._stats.investigation_field = chosen[0].field_name
            # Check if investigation budget exhausted
            if (
                self._mode == MutationMode.ONE_AT_A_TIME
                and isinstance(self._scheduler, OneAtATimeScheduler)
                and self._scheduler.is_budget_exhausted(len(mutable))
            ):
                asyncio.create_task(self.set_normal_mode())

        # Apply mutations for the chosen subset
        for f in chosen:
            base = _apply_field(base, f)

        return bytes(base)

    # -----------------------------------------------------------------------
    # Network Send
    # -----------------------------------------------------------------------

    async def _send(self, payload: bytes, seed_id: str) -> PacketStatus:
        """
        Open a fresh TCP connection and send one mutated payload.

        Fresh-connection-per-packet semantics ensure each test is
        independent. One rejected packet cannot poison the next.

        Returns:
            PacketStatus reflecting what the target server did.

        TODO:
            - Connection pooling for 10×+ EPS improvement.
            - UDP mode via raw socket.
            - Protocol-aware response validation (not just "got bytes?").
        """
        status = PacketStatus.TIMEOUT

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.connection_timeout,
            )
            writer.write(payload)
            await writer.drain()

            try:
                resp = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                status = PacketStatus.ACCEPTED if resp else PacketStatus.REJECTED
            except asyncio.TimeoutError:
                status = PacketStatus.TIMEOUT

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except ConnectionRefusedError:
            status = PacketStatus.CRASH
            log.error(
                "Target CRASH (connection refused)",
                extra={"context": {
                    "payload_hex": payload.hex()[:48],
                    "len":         len(payload),
                }},
            )
            if self.crash_callback:
                self.crash_callback(payload, "connection_refused")

        except asyncio.TimeoutError:
            status = PacketStatus.TIMEOUT

        except OSError as exc:
            log.warning("Send error", extra={"context": {"err": str(exc)[:80]}})
            status = PacketStatus.TIMEOUT

        # Feed result back to Interceptor for stuck detection
        if self.status_callback:
            self.status_callback(seed_id, status)

        return status

    # -----------------------------------------------------------------------
    # Dumb Fallback
    # -----------------------------------------------------------------------

    @staticmethod
    def _dumb_mutate(buf: bytearray) -> bytes:
        """
        Last-resort mutation: flip one random bit.
        Used when no SemanticRuleSet is loaded yet.
        """
        if not buf:
            return bytes(buf)
        i = random.randrange(len(buf))
        b = random.randrange(8)
        buf[i] ^= (1 << b)
        return bytes(buf)

    # -----------------------------------------------------------------------
    # Stats & EPS Tracking
    # -----------------------------------------------------------------------

    def _update_stats(self, status: PacketStatus, payload: bytes) -> None:
        """Update rolling counters and compute EPS every 5 seconds."""
        now = time.monotonic()
        self._eps_window.append(now)

        self._stats.total_sent += 1
        if status == PacketStatus.ACCEPTED:
            self._stats.total_accepted += 1
        elif status == PacketStatus.REJECTED:
            self._stats.total_rejected += 1
        elif status == PacketStatus.TIMEOUT:
            self._stats.total_timeout += 1
        elif status == PacketStatus.CRASH:
            self._stats.total_crashes += 1

        # Log EPS every 5 seconds
        if now - self._last_eps_log >= 5.0 and len(self._eps_window) > 1:
            window_s = self._eps_window[-1] - self._eps_window[0]
            eps = len(self._eps_window) / window_s if window_s > 0 else 0.0
            self._stats.current_eps = round(eps, 1)
            self._last_eps_log = now

            log.info(
                "Fuzzing heartbeat",
                extra={"context": {
                    "eps":      f"{eps:.1f}",
                    "mode":     self._mode.value,
                    "sent":     self._stats.total_sent,
                    "crashes":  self._stats.total_crashes,
                    "rejected": self._stats.total_rejected,
                    "rules_v":  self._stats.rule_set_version,
                    "fields":   self._stats.active_fields,
                }},
            )


# ===========================================================================
# Field Mutation — Pure Functions (no side effects, easily unit-tested)
# ===========================================================================

def _apply_field(buf: bytearray, rule: FieldRule) -> bytearray:
    """
    Apply a single FieldRule to a mutable bytearray.

    All mutation logic lives here, outside the MutationEngine class,
    so it can be unit-tested without any async machinery.

    Args:
        buf:  Mutable bytearray representing the full packet payload.
        rule: The FieldRule describing how to mutate one field.

    Returns:
        The same bytearray (modified in-place and returned for chaining).
    """
    start = rule.offset
    if start >= len(buf):
        return buf   # Offset out of bounds — skip silently

    length     = rule.length if rule.length != -1 else len(buf) - start
    end        = min(start + length, len(buf))
    actual_len = end - start
    if actual_len <= 0:
        return buf

    s = rule.mutation_strategy

    # ------------------------------------------------------------------
    if s == MutationStrategy.STATIC:
        # Overwrite with fixed value — NEVER deviate from this
        if rule.static_value:
            try:
                src = bytes.fromhex(rule.static_value)
                n   = min(len(src), actual_len)
                buf[start:start + n] = src[:n]
            except ValueError:
                log.warning(f"Bad static_value for field {rule.field_name!r}")

    # ------------------------------------------------------------------
    elif s == MutationStrategy.RANDOM_BYTES:
        buf[start:end] = os.urandom(actual_len)

    # ------------------------------------------------------------------
    elif s == MutationStrategy.BIT_FLIP:
        # Flip exactly one random bit within the field
        byte_i = random.randint(start, end - 1)
        bit_i  = random.randint(0, 7)
        buf[byte_i] ^= (1 << bit_i)

    # ------------------------------------------------------------------
    elif s == MutationStrategy.BOUNDARY_VALUES:
        """
        Classic boundary-value analysis for integer fields.
        Cycles through: 0x00…00, 0xFF…FF, 0x7F FF…FF, 0x80 00…00,
        and random ±1 around the current value.
        """
        candidates = [
            b"\x00" * actual_len,
            b"\xFF" * actual_len,
            b"\x7F" + b"\xFF" * (actual_len - 1),
            b"\x80" + b"\x00" * (actual_len - 1),
            b"\x00" * (actual_len - 1) + b"\x01",
        ]
        chosen = random.choice(candidates)[:actual_len]
        buf[start:start + len(chosen)] = chosen

    # ------------------------------------------------------------------
    elif s == MutationStrategy.INCREMENT:
        """
        Read as big-endian unsigned int, add 1, wrap at max.
        Used for sequence numbers.
        """
        current = int.from_bytes(buf[start:end], "big")
        max_val = (1 << (actual_len * 8)) - 1
        new_val = (current + 1) & max_val
        buf[start:end] = new_val.to_bytes(actual_len, "big")

    # ------------------------------------------------------------------
    elif s == MutationStrategy.CALCULATED:
        """
        Recalculate a derived field (typically: length = len(payload)).
        The 'payload' here means everything after this field.

        TODO:
            - Support CRC32 / checksum recalculation.
            - Support custom formulas from rule.calculation_source.
        """
        payload_start = start + actual_len
        payload_len   = max(0, len(buf) - payload_start)
        try:
            buf[start:end] = payload_len.to_bytes(actual_len, "big")
        except OverflowError:
            pass  # payload_len too large for field width — leave unchanged

    # ------------------------------------------------------------------
    elif s == MutationStrategy.DICTIONARY:
        """
        Pick a value from the LLM-provided dictionary of known-interesting
        values (e.g., command codes, type identifiers, version numbers).
        """
        if rule.dictionary_values:
            try:
                hex_val = random.choice(rule.dictionary_values)
                src     = bytes.fromhex(hex_val)[:actual_len]
                buf[start:start + len(src)] = src
            except (ValueError, IndexError):
                log.warning(f"Bad dictionary entry for field {rule.field_name!r}")

    # ------------------------------------------------------------------
    elif s == MutationStrategy.SKIP:
        pass   # Intentionally leave this field unchanged this round

    return buf