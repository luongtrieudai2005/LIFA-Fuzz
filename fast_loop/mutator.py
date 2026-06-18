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
    │  Mode 1 — RANDOM_SUBSET / WEIGHTED  (default, normal fuzzing)   │
    │    Pick k random mutable fields per packet.                      │
    │    High EPS. Broad coverage. Acceptable crash isolation.         │
    │                                                                  │
    │  Mode 2 — ONE_AT_A_TIME  (crash investigation, auto-triggered)  │
    │    Cycle through fields one-by-one. One field mutated per send.  │
    │    Lower EPS. Perfect crash isolation. Pinpoints exact field.    │
    │                                                                  │
    │  Warm-up — ALL_FIELDS  (first 30 s on new connection)           │
    │    Mutate every field per packet for initial reachability sweep. │
    │    Crashes logged but do NOT trigger investigation.              │
    └──────────────────────────────────────────────────────────────────┘

STATE MACHINE:
    [WARM-UP / ALL_FIELDS]  (first warmup_seconds)
           │
           │  warmup deadline reached
           ▼
    [NORMAL / RANDOM_SUBSET or WEIGHTED]
           │
           │  crash detected (Health Monitor calls set_investigation_mode())
           ▼
    [INVESTIGATION / ONE_AT_A_TIME]
           │
           │  isolation_budget exhausted → _revert_pending flag set
           │  (consumed deterministically in the hot loop)
           ▼
    [NORMAL / RANDOM_SUBSET or WEIGHTED]

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
import json
import math
import os
import random
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from shared.logger import get_logger

# BinaryMutator: 14-strategy AFL-class mutation engine for DUMB mode (Baseline A).
# When no SemanticRules are available, MutationEngine delegates to this instead
# of the old single-bit-flip _dumb_mutate(), ensuring Baseline A is a fair
# comparison against B (math-only) and C (full fusion).
from fast_loop.binary_mutator import BinaryMutator, BINARY_ONLY_STRATEGIES
from fast_loop.baseline_tracker import ResponseBaselineTracker

# StateTransitionGraph: Step 3 — State-Coverage Expansion.
# Tracks unique (prev_code, command, new_code) edges to reward the fuzzer
# for discovering new protocol state paths (STATE_NOVELTY seeds).
from fast_loop.state_transition_graph import StateTransitionGraph

from shared.schemas import (
    ActiveRuleSet,
    Direction,
    FieldRule,
    FieldType,
    FuzzTarget,
    MutationConstraints,
    MutationStrategy,
    PacketStatus,
    SeedSequence,
    TrafficRecord,
)

# P3-C: import operators at module level to avoid per-call import lookup
# in the hot path (_apply_field runs thousands of times per second).
from fast_loop.mutation_operators import (
    op_bit_flip,
    op_boundary_violation,
    op_buffer_overflow,
    op_format_string,
    op_integer_overflow,
    op_omission,
    op_random_byte_injection,
)

# Type aliases for clarity (these are the same as the underlying types)
SemanticRuleSet = ActiveRuleSet
PacketRecord = TrafficRecord

log = get_logger("fast_loop.mutator")


# ===========================================================================
# Known crash payloads (backward compat with tests and e2e)
# ===========================================================================

KILL_SERVER_PAYLOADS: list[bytes] = [
    b"\x00\x00\x00\x00",              # Null magic → SIGSEGV
    b"\xCA\xFE\xBA\xBE",             # Abort magic → SIGABRT
    b"\xDE\xAD\xBE\xEF\xFF\xFF",     # Length overflow → buffer overflow crash
]

# P3-B: Human-readable names for kill payloads (attribution)
_KILL_PAYLOAD_NAMES: list[str] = [
    "null_magic_crash",
    "abort_magic_crash",
    "length_overflow_crash",
]

# Phase 3.2 / BUG-2 fix: minimum gap between consecutive fast probes. A burst
# of refused sends reuses the last probe result within this window instead of
# re-opening up to 3 connections each — prevents self-amplifying overload on a
# thread/fork-per-connection target.
PROBE_COOLDOWN_S: float = 0.25


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
    k=2 is the empirically recommended starting point.

    P2-A: Supports adaptive k ≈ sqrt(num_fields) when adaptive=True.

    Args:
        k: Number of fields to mutate per packet. Clamped to len(mutable_fields).
        adaptive: If True, k = max(1, min(int(sqrt(n)), n//2 + 1)).
    """

    def __init__(self, k: int = 2, adaptive: bool = True) -> None:
        self.k = k
        self.adaptive = adaptive

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        if not mutable_fields:
            return []
        n = len(mutable_fields)
        if self.adaptive:
            k = max(1, min(int(math.isqrt(n)), n // 2 + 1))
        else:
            k = min(self.k, n)
        return random.sample(mutable_fields, k)

    @property
    def description(self) -> str:
        mode = "adaptive" if self.adaptive else f"static k={self.k}"
        return f"RandomSubset({mode})"


class OneAtATimeScheduler(_BaseScheduler):
    """
    ONE_AT_A_TIME: mutate exactly one field per packet, cycling deterministically.

    Each send targets a different field — tracked by **field name** (not index)
    so that rule set updates that reorder fields don't break crash isolation.

    This mode is used AUTOMATICALLY when a crash is detected, allowing the
    system to determine WHICH exact field triggered the vulnerability.
    """

    def __init__(
        self,
        budget_per_field: int = 20,
        isolation_budget: int = 500,
    ) -> None:
        self.budget_per_field = budget_per_field
        self.isolation_budget = isolation_budget
        # H1 fix: track by field name, not index — survives rule reorder.
        self._cursor_name: Optional[str] = None
        self._field_names: list[str] = []
        self._field_hits: dict[str, int] = {}
        self._sends_this_mode: int = 0

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        if not mutable_fields:
            return []

        # Build name→field lookup and ordered name list
        name_to_field: dict[str, FieldRule] = {
            f.field_name: f for f in mutable_fields
        }
        field_names = [f.field_name for f in mutable_fields]

        # First call or after reset — start at first field
        if self._cursor_name is None or self._cursor_name not in name_to_field:
            # If the current cursor field was removed, find the next one
            if self._cursor_name is not None and self._field_names:
                try:
                    old_idx = self._field_names.index(self._cursor_name)
                    # Try to find a field in the new list that comes after
                    for name in field_names:
                        if name not in self._field_names[:old_idx + 1]:
                            self._cursor_name = name
                            break
                    else:
                        self._cursor_name = field_names[0] if field_names else None
                except ValueError:
                    self._cursor_name = field_names[0] if field_names else None
            else:
                self._cursor_name = field_names[0] if field_names else None

            self._field_names = field_names

        if self._cursor_name is None or self._cursor_name not in name_to_field:
            return []

        chosen = name_to_field[self._cursor_name]

        # Advance cursor after budget_per_field hits on this field
        self._field_hits[self._cursor_name] = self._field_hits.get(
            self._cursor_name, 0
        ) + 1
        if self._field_hits[self._cursor_name] >= self.budget_per_field:
            # Move to next field in name order
            try:
                cur_idx = field_names.index(self._cursor_name)
                next_idx = (cur_idx + 1) % len(field_names)
                self._cursor_name = field_names[next_idx]
            except ValueError:
                self._cursor_name = field_names[0] if field_names else None
            # Reset hits for the new field
            if self._cursor_name:
                self._field_hits[self._cursor_name] = 0

        self._field_names = field_names
        self._sends_this_mode += 1
        return [chosen]

    def is_budget_exhausted(self, num_fields: int) -> bool:
        """True when we have cycled through all fields enough times."""
        return self._sends_this_mode >= self.isolation_budget

    def get_current_field_index(self) -> int:
        """The 0-based index of the field currently under investigation."""
        if self._cursor_name and self._field_names:
            try:
                return self._field_names.index(self._cursor_name)
            except ValueError:
                return 0
        return 0

    @property
    def cursor_name(self) -> Optional[str]:
        """The name of the field currently under investigation."""
        return self._cursor_name

    def reset(self) -> None:
        self._cursor_name = None
        self._field_names = []
        self._field_hits = {}
        self._sends_this_mode = 0

    @property
    def description(self) -> str:
        return (
            f"OneAtATime(cursor={self._cursor_name}, "
            f"sends={self._sends_this_mode}/{self.isolation_budget})"
        )


class AllFieldsScheduler(_BaseScheduler):
    """
    ALL_FIELDS: mutate every mutable field per packet.
    Maximum coverage but zero crash isolation.
    Useful for initial quick reachability tests and warm-up phase.
    """

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        return list(mutable_fields)

    @property
    def description(self) -> str:
        return "AllFields"


# ===========================================================================
# P2-B: Weighted Scheduler — strategy-priority field selection
# ===========================================================================

# Strategy weights: higher = more likely to be selected for mutation.
# Based on empirical security research — length fields and opcodes produce
# the majority of exploitable crashes.
_STRATEGY_WEIGHTS: dict[MutationStrategy, float] = {
    MutationStrategy.BOUNDARY_VALUES: 4.0,   # length fields: #1 bug source
    MutationStrategy.DICTIONARY:      3.0,   # opcodes: triggers different code paths
    MutationStrategy.PAYLOAD_EXTEND:  3.5,   # variable-length payloads: overflow class
    MutationStrategy.INCREMENT:       2.5,   # sequence numbers: state confusion
    MutationStrategy.BIT_FLIP:        1.5,   # flags/enums: subtle state bugs
    MutationStrategy.CALCULATED:      2.0,   # derived fields: recalculation bugs
    MutationStrategy.RANDOM_BYTES:    1.0,   # payload: baseline
    MutationStrategy.FORMAT_STRING:   2.0,   # format string: memory corruption
    MutationStrategy.TRUNCATE:        1.5,   # truncation: edge cases
    MutationStrategy.STATIC:          0.0,   # excluded from selection
    MutationStrategy.SKIP:            0.0,   # excluded from selection
}


class WeightedScheduler(_BaseScheduler):
    """
    WEIGHTED: select k fields using strategy-priority weights.

    Fields with BOUNDARY_VALUES strategy are ~4x more likely to be selected
    than RANDOM_BYTES. Confidence from the LLM further scales the weight
    (low-confidence fields are penalized).

    Args:
        k: Base number of fields to select (used when adaptive=False).
        adaptive: If True, k scales with sqrt(num_fields).
    """

    def __init__(self, k: int = 2, adaptive: bool = True) -> None:
        self.k = k
        self.adaptive = adaptive

    def select(self, mutable_fields: list[FieldRule]) -> list[FieldRule]:
        if not mutable_fields:
            return []

        n = len(mutable_fields)
        if self.adaptive:
            k = max(1, min(int(math.isqrt(n)), n // 2 + 1))
        else:
            k = min(self.k, n)

        # Compute weights: strategy_weight * confidence
        weights = []
        for f in mutable_fields:
            sw = _STRATEGY_WEIGHTS.get(f.mutation_strategy, 1.0)
            weights.append(sw * max(0.1, f.confidence))

        total = sum(weights)
        if total == 0:
            # All fields are SKIP/STATIC — fall back to uniform
            return random.sample(mutable_fields, min(k, n))

        # Weighted selection without replacement
        chosen_indices: set[int] = set()
        max_attempts = k * 10  # prevent infinite loop
        attempts = 0
        while len(chosen_indices) < k and attempts < max_attempts:
            idx = random.choices(range(n), weights=weights, k=1)[0]
            chosen_indices.add(idx)
            attempts += 1

        # If we couldn't get k unique indices, fill with remaining
        if len(chosen_indices) < k:
            remaining = [i for i in range(n) if i not in chosen_indices]
            random.shuffle(remaining)
            chosen_indices.update(remaining[: k - len(chosen_indices)])

        return [mutable_fields[i] for i in chosen_indices]

    @property
    def description(self) -> str:
        return (
            f"Weighted(bv=4.0, dict=3.0, inc=2.5, "
            f"calc=2.0, bf=1.5, rb=1.0)"
        )


# ===========================================================================
# Runtime Statistics
# ===========================================================================

@dataclass
class MutatorStats:
    """Live statistics snapshot. Exposed via get_stats()."""
    mode:                       str                        = MutationMode.DUMB
    total_sent:                 int                        = 0
    total_accepted:             int                        = 0
    total_rejected:             int                        = 0
    total_timeout:              int                        = 0
    total_crashes:              int                        = 0
    current_eps:                float                      = 0.0
    rule_set_version:           int                        = 0
    rule_set_id:                str                        = "none"
    active_fields:              int                        = 0
    investigation_mode:         bool                       = False
    investigation_field:        Optional[str]              = None
    # P2-A: k used this round (for heartbeat logging)
    k_this_round:               int                        = 0
    # P1-A: revert pending flag
    revert_pending:             bool                       = False
    # P2-C: last investigation summary
    last_investigation_summary: dict                       = field(default_factory=dict)
    # EWMA Adaptive Controller telemetry
    current_k:                 int                        = 200
    recv_sample_rate:          float                      = 0.0
    ewma_lambda_c:             float                      = 0.0
    # Rule count for dashboard / telemetry
    active_rule_count:         int                        = 0
    ewma_regime:               str                        = "sparse"
    # SemFuzz-style semantic-violation oracle telemetry (potential semantic
    # bugs, NOT crashes). Reported as raw counts — precision is bounded by the
    # inferred (no-RFC) expected response; the paper itself reports 62.5%.
    semantic_oracle_checks:    int                        = 0
    semantic_violations_detected: int                      = 0


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

    Args:
        target_host:        Hostname of Target Server (Block 1B).
        target_port:        Port of Target Server.
        seed_queue:         asyncio.Queue[PacketRecord] from Interceptor (C).
        k:                  Fields per packet in RANDOM_SUBSET mode (minimum k).
        max_eps:            Throttle ceiling (0 = unlimited).
        connection_timeout: TCP connect timeout in seconds.
        recv_timeout:       Time to wait for a server response.
        auto_investigate:   If True, auto-switch to ONE_AT_A_TIME on crash.
        investigation_budget: Max sends in ONE_AT_A_TIME mode before reverting.
        connection_mode:    "fresh" (new conn per send) or "stateful" (setup sequence).
        no_recv:            If True, fire-and-forget mode.
        adaptive_k:         P2-A: If True, k scales with sqrt(num_fields).
        use_weighted:       P2-B: If True, use WeightedScheduler in normal mode.
        budget_per_field:   P2-D: Hits per field in investigation (0 = adaptive).
        warmup_seconds:     P3-A: Duration of ALL_FIELDS warm-up (0 = disabled).
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
        connection_mode:      str   = "fresh",
        no_recv:              bool  = False,
        # P2-A: adaptive k scaling
        adaptive_k:           bool  = True,
        # P2-B: weighted field selection
        use_weighted:         bool  = True,
        # P2-D: configurable investigation budget per field
        budget_per_field:     int   = 0,
        # P3-A: warm-up phase
        warmup_seconds:       float = 30.0,
        # Phase 3.1 / TASK 1: post-resume grace window. After the CrashMonitor
        # restarts the target (snapshot restore) and resumes the engine, the
        # freshly-restored server may refuse connections for a few hundred ms
        # while it re-arms its accept loop. Connection-refused during this
        # window is a transient restart artifact, NOT a crash. See
        # _in_restart_grace() / _classify_conn_refused.
        restart_grace_s:      float = 0.5,
        # ProtocolModule: "null" (default, pure black-box core) or a registered
        # case-study module name (e.g. "ftp"). Resolved via shared registry —
        # the core never hardcodes a protocol.
        protocol_module:      str   = "null",
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
        self.no_recv             = no_recv
        self.connection_mode     = connection_mode
        # P2-A / P2-B / P2-D / P3-A
        self.adaptive_k          = adaptive_k
        self.use_weighted        = use_weighted
        self.budget_per_field    = budget_per_field
        self.warmup_seconds      = warmup_seconds
        # Phase 3.1 / TASK 1: post-resume grace window length (seconds).
        self.restart_grace_s     = restart_grace_s

        # Active scheduler — swapped atomically on mode change
        self._scheduler:    _BaseScheduler    = self._make_normal_scheduler()
        self._mode:         MutationMode      = MutationMode.RANDOM_SUBSET
        self._sched_lock:   asyncio.Lock      = asyncio.Lock()

        # Bugfix: sync stats.mode with actual initial mode
        self._stats = MutatorStats()
        self._stats.mode = self._mode.value

        # Active rule set — swapped atomically by Slow Loop (Block 3)
        self._rule_set:     Optional[SemanticRuleSet] = None

        # Cached setup packets from ActiveRuleSet (for stateful mode)
        self._setup_packets: list[bytes] = []
        self._rule_lock:    asyncio.Lock              = asyncio.Lock()

        # Seed corpus — populated incrementally from seed_queue
        # Each entry is a SeedSequence (1+ packets from one TCP session).
        self._corpus:       list[SeedSequence] = []

        # IFPS: Inverse-Frequency Power Schedule seed selection
        # Tracks how many times each sequence has been used → rare sequences
        # get higher Energy = 1/(freq+1) → more fuzzing cycles.
        self._seed_freq:    dict[str, int]     = {}

        # EPS tracking (rolling window of send timestamps)
        self._eps_window:   deque[float]       = deque(maxlen=200)
        self._last_eps_log: float              = time.monotonic()

        # Callbacks (set by orchestrator / Health Monitor)
        self.status_callback: Optional[Callable[[str, PacketStatus], None]] = None
        self.crash_callback:  Optional[Callable[[bytes, str], None]] = None

        # Control flags
        self._running: bool = False
        self._paused:  bool = False

        # BinaryMutator for DUMB mode (Baseline A — AFL-class random fuzzing).
        # Uses 14+4 strategies (bit_flip, interesting values, arithmetic, block
        # operations, plus FTP-aware token injection) instead of the old
        # single-bit-flip _dumb_mutate().
        # No seed → non-deterministic, matching standard fuzzing practice.
        self._binary_mutator: BinaryMutator = BinaryMutator()

        # Step 3: State Transition Graph — tracks unique protocol state edges.
        # Lock-free: only accessed from the single asyncio hot loop.
        # NOTE: kept for backward-compat property access; the active tracker is
        # now module-owned (self._module.state_tracker()). NullModule ⇒ None.
        self._stg: StateTransitionGraph = StateTransitionGraph()

        # ProtocolModule seam (replaces the old `_is_ftp_target = port==21`
        # hardcode). Default NullModule = pure black-box (no protocol
        # knowledge). A case-study target passes protocol_module="ftp" (config)
        # → FTPModule adds FTP status-code/CRLF/STG/token-injection knowledge
        # as a DISCLOSED extension. The core never assumes a protocol.
        from shared.protocol_module import get_protocol_module
        self._module = get_protocol_module(protocol_module)
        self._state_tracker = self._module.state_tracker()  # None for Null
        # Backward-compat: crash_monitor/tests may read self._is_ftp_target.
        self._is_ftp_target: bool = (self._module.name == "ftp")

        # P1-A: revert pending flag — deterministic mode revert
        self._revert_pending: bool = False

        # P3-A: warm-up state
        self._warmup_done: bool = False

        # Backward compat — accessed by crash_monitor.py
        self._last_injected_packet: bytes = b""
        self._last_injected_rule_id: Optional[str] = None

        # H3/H5 fix: crash attribution window — stores last N sends so the
        # crash monitor can see recent history, not just the last packet.
        # Bumped 100→200 (H5): at sustained high EPS the detection lag
        # (poll_interval + confirm_drain) can exceed 100 sends, evicting the
        # real culprit before Phase 2 confirmation can replay it. 200 keeps
        # ~2-4s of history at typical EPS; memory ~200KB worst case.
        self._crash_window: deque = deque(maxlen=200)

        # Post-crash confirmation (Phase 1): when frozen, _send() stops
        # appending to the crash_window. crash_monitor freezes it on crash
        # detection so the candidate set isn't polluted by post-crash
        # connection-refused sends, then replays the frozen set to find the
        # packet that actually reproduces the crash. See
        # docs/crash_attribution_plan.md. Hot-loop cost: one bool branch.
        self._window_frozen: bool = False

        # Phase 3 / TASK 1: set True while the CrashMonitor is restarting the
        # target (pause() sets it, resume() clears it). Any in-flight send that
        # hits a refused/reset connection during this window is classified
        # TIMEOUT, not CRASH — a transient side-effect of the target being
        # briefly down, not an actionable vulnerability. Without this guard the
        # restart stall produced a storm of false CRASH statuses that armed
        # ONE_AT_A_TIME investigation on every send. See _classify_conn_refused.
        self._target_restarting: bool = False

        # Phase 3.1 / TASK 1: post-resume grace deadline. resume() stamps
        # ``now + restart_grace_s`` here; _in_restart_grace() treats the engine
        # as still in restart-grace until this deadline even though
        # ``_target_restarting`` has cleared. This closes the gap between the
        # target being back alive (is_target_alive() True) and actually
        # accepting connections (accept loop re-armed) — the ~1.3/min phantom
        # ONE_AT_A_TIME investigations in smoke #2 came from sends in that gap.
        self._restart_grace_until: float = 0.0

        # Phase 3.2 / BUG-2 fix: probe rate-limit state. Without a cooldown, a
        # burst of refused sends (up to 5 before the hot-loop back-pressure
        # kicks in) could each fire 3 fresh probe connections → 15 extra
        # connections on a thread/fork-per-connection target, self-amplifying
        # the very overload that caused the refusals. Reuse the last probe
        # result within PROBE_COOLDOWN_S.
        self._last_probe_monotonic: float = 0.0
        self._last_probe_alive: bool = True

        # Stats (initialized above with correct mode)
        self._mutation_signatures: set[str] = set()
        self._current_rule_type: Optional[str] = None  # for _track_rule_response
        # SemFuzz-style semantic-violation oracle: when the current send is a
        # structural violation, this holds the EXPECTED response category
        # ("normal"/"error"). ``_classify_response`` compares it to the actual
        # category and records a divergence as a potential semantic bug.
        self._pending_violation_expected: Optional[str] = None
        # Differential-baseline oracle (Phase 3): normal response signatures
        # per (command, state), built from accepted non-violation traffic.
        self._baseline = ResponseBaselineTracker()
        # Last server state code observed (for the baseline key). Updated by
        # the send path after state-tracker record_edge.
        self._last_state_code: str = ""

        # Rule file poller — bridges Slow Loop / Math-Only → Fast Loop
        rule_cfg = self._load_rules_path_from_config()
        self._rules_file: str = rule_cfg
        self._last_rules_mtime: float = 0.0

        # EWMA Adaptive Controller state — file-based IPC with Slow Loop
        self._current_k: int = 200          # Sampling interval (K_max default)
        self._packet_counter: int = 0       # Monotonic — never reset
        self._recv_count: int = 0           # Number of recv() calls (for telemetry)
        self._seq_log_counter: int = 0      # Samples _execute_sequence chain logs
        self._consecutive_failures: int = 0 # Back-pressure: consecutive CRASH/TIMEOUT
        self._MAX_CONSECUTIVE_FAILURES = 5  # Back off after this many failures
        self._rule_response_stats: dict[str, dict[str, int]] = {}  # Per rule-type stats
        self._ipc_read_interval: int = 50   # Read adaptive_k.json every N packets
        self._adaptive_k_path: str = "shared/adaptive_k.json"
        self._response_buf_path: str = "shared/response_buffer.jsonl"
        self._adaptive_k_mtime: float = 0.0
        # Load adaptive config from config.yaml (if present)
        self._load_adaptive_config_into_self()

        log.info(
            "MutationEngine initialized",
            extra={"context": {
                "target": f"{target_host}:{target_port}",
                "mode":   self._mode.value,
                "k":      k,
                "max_eps": max_eps,
                "adaptive_k": adaptive_k,
                "use_weighted": use_weighted,
                "warmup_seconds": warmup_seconds,
            }},
        )

    # -------------------------------------------------------------------
    # Scheduler factory
    # -------------------------------------------------------------------

    def _make_normal_scheduler(self) -> _BaseScheduler:
        """Create the appropriate normal-mode scheduler based on config."""
        if self.use_weighted:
            return WeightedScheduler(k=self.k, adaptive=self.adaptive_k)
        else:
            return RandomSubsetScheduler(k=self.k, adaptive=self.adaptive_k)

    # -------------------------------------------------------------------
    # Backward Compatibility
    # -------------------------------------------------------------------

    @property
    def coverage_summary(self) -> dict:
        """Backward-compatible property for telemetry and callers.

        Step 3: Extended with STG metrics for CSV telemetry and dashboard.
        """
        s = self._stats
        # State metrics come from the module's tracker (FTPModule → FTP STG;
        # NullModule → None → all zeros, i.e. no protocol-state concept).
        stg = self._state_tracker.stats if self._state_tracker is not None else {
            "unique_states": 0, "unique_edges": 0, "unique_paths": 0,
            "total_edge_records": 0, "novel_seed_count": 0,
        }
        return {
            "total_mutations": s.total_sent,
            "total_packets": s.total_sent,
            "total_kills": s.total_crashes,
            "unique_offsets_fuzzed": len(self._mutation_signatures),
            "active_rules": s.rule_set_version,
            "current_eps": s.current_eps,
            "mode": s.mode,
            "investigation_mode": s.investigation_mode,
            "current_k": self._current_k,
            "recv_sample_rate": self._recv_count / max(1, s.total_sent),
            # Step 3: State Transition Graph metrics
            "unique_states": stg["unique_states"],
            "unique_state_edges": stg["unique_edges"],
            "unique_state_paths": stg["unique_paths"],
            "novel_seed_count": stg["novel_seed_count"],
        }

    # -------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------

    async def run(self) -> None:
        """Main hot-loop. Run as a long-lived asyncio Task."""
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

        # P3-A: ALL_FIELDS warm-up phase
        warmup_deadline: float = 0.0
        if self.warmup_seconds > 0 and not self._warmup_done:
            log.info(
                f"Starting ALL_FIELDS warm-up ({self.warmup_seconds}s)",
                extra={"context": {"warmup_seconds": self.warmup_seconds}},
            )
            async with self._sched_lock:
                self._scheduler = AllFieldsScheduler()
                self._mode = MutationMode.ALL_FIELDS
                self._stats.mode = self._mode.value
            warmup_deadline = time.monotonic() + self.warmup_seconds

        while self._running:
            if self._paused:
                await asyncio.sleep(0.05)
                continue

            # Poll for rule updates from Slow Loop / Math-Only
            await self._poll_rules_file()

            # EWMA Adaptive Controller: refresh k from Slow Loop every N packets
            if self._packet_counter % self._ipc_read_interval == 0:
                self._poll_adaptive_k()

            # Throttle
            if self.max_eps > 0:
                await asyncio.sleep(1.0 / self.max_eps)

            await self._drain_seeds()

            # ── Sequence-Aware Fuzzing ──────────────────────────────
            seed   = self._pick_seed()       # returns SeedSequence

            # Skip empty sequences (shouldn't happen, but defensive)
            if not seed.packets:
                continue

            target = self._split_sequence(seed)   # FuzzTarget
            payload = await self._build_mutant(target.target_seed)

            # IFPS: track sequence frequency for energy-based selection
            self._seed_freq[seed.sequence_id] = (
                self._seed_freq.get(seed.sequence_id, 0) + 1
            )

            # Dispatch: multi-packet sequence vs single-packet legacy path
            if target.prefix or target.suffix:
                # Multi-packet sequence: use ⟨Prefix, Target, Suffix⟩
                status = await self._execute_sequence(target, payload)
            elif self.connection_mode == "stateful" and self._setup_packets:
                # Single packet with static setup packets from config
                status = await self._send_stateful(payload, seed.sequence_id)
            else:
                # Single packet: fresh connection per send (legacy)
                status = await self._send(payload, seed.sequence_id)

            self._update_stats(status, payload)

            # Back-pressure: if too many consecutive failures, back off
            # to let the server recover instead of flooding a dead socket.
            if status in (PacketStatus.CRASH, PacketStatus.TIMEOUT):
                self._consecutive_failures += 1
            else:
                self._consecutive_failures = 0

            if self._consecutive_failures >= self._MAX_CONSECUTIVE_FAILURES:
                log.warning(
                    f"{self._consecutive_failures} consecutive failures — "
                    f"backing off 2s for server recovery"
                )
                await asyncio.sleep(2.0)
                self._consecutive_failures = 0

            # Track per-rule-type response stats for LLM feedback
            self._track_rule_response(status)

            # IFPS: periodic cap to prevent unbounded growth.
            # Cap rather than delete — deleting would cause .get(_, 0) to
            # return 0, giving the seed maximum Energy (inverting IFPS).
            if self._stats.total_sent % 10_000 == 0 and self._seed_freq:
                cap = 999
                self._seed_freq = {
                    k: min(v, cap) for k, v in self._seed_freq.items()
                }

            # Cap mutation signatures to prevent OOM on long fuzzing runs.
            # FIX: instead of .clear() (which drops coverage to 0, breaking
            # monotonic coverage plots), keep the latest 80k signatures.
            if len(self._mutation_signatures) > 100_000:
                # Discard oldest 20k, keep most recent 80k
                excess = list(self._mutation_signatures)[:20000]
                for sig in excess:
                    self._mutation_signatures.discard(sig)

            # P3-A: warm-up deadline check
            if warmup_deadline > 0 and time.monotonic() >= warmup_deadline:
                self._warmup_done = True
                await self.set_normal_mode()
                warmup_deadline = 0.0
                log.info("Warm-up complete — switching to normal mode")

            # P1-A: deterministic revert from ONE_AT_A_TIME → normal
            if self._revert_pending:
                self._revert_pending = False
                self._stats.revert_pending = False
                await self.set_normal_mode()

            # Auto-switch to investigation mode after a crash
            # P3-A: skip investigation during warm-up
            if (
                status == PacketStatus.CRASH
                and self.auto_investigate
                and not (self._mode == MutationMode.ALL_FIELDS and not self._warmup_done)
            ):
                await self.set_investigation_mode(
                    reason=f"crash detected on seed {seed.sequence_id[:8]}"
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
        # Phase 3 / TASK 1: mark the target as restarting so any in-flight
        # send that hits a refused/reset connection is classified TIMEOUT,
        # not CRASH (prevents spurious ONE_AT_A_TIME investigation).
        self._target_restarting = True
        log.info("MutationEngine PAUSED")

    def resume(self) -> None:
        """Resume fuzzing after a pause."""
        self._paused = False
        self._target_restarting = False
        # Phase 3.1 / TASK 1: arm the post-resume grace window. The target is
        # back alive (is_target_alive() True) but its accept loop may not be
        # ready for a few hundred ms; sends landing in that gap get
        # connection-refused and would otherwise be classified CRASH, arming a
        # phantom ONE_AT_A_TIME investigation (~1.3/min in smoke #2).
        # _in_restart_grace() / _classify_conn_refused treat those as TIMEOUT.
        self._restart_grace_until = time.monotonic() + self.restart_grace_s
        log.info("MutationEngine RESUMED")

    def _in_restart_grace(self) -> bool:
        """True while connection-refused is a transient restart artifact.

        Covers two windows where a refused/reset connection is NOT a crash:
        1. ``_target_restarting`` is set — the CrashMonitor paused us to
           restart the target (it is briefly down).
        2. The post-resume grace window — the target is back up but may not
           have re-armed its accept loop yet.
        """
        if self._target_restarting:
            return True
        return time.monotonic() < self._restart_grace_until

    def cancel_investigation(self) -> None:
        """Cancel a spurious ONE_AT_A_TIME investigation.

        Called by the CrashMonitor on a *non-actionable* (exit 0) restart: a
        graceful shutdown cannot itself be a crash, so any ONE_AT_A_TIME
        investigation armed by connection-refused sends that landed in the
        ~poll-interval window between target-down and pause() is phantom. We
        stage a revert via ``_revert_pending``; the hot loop is paused, so the
        revert lands at the top of the first iteration after resume (line ~835).
        A no-op if we are not in investigation mode, so it is always safe to
        call.
        """
        if self._mode == MutationMode.ONE_AT_A_TIME:
            self._revert_pending = True
            self._stats.revert_pending = True
            log.info(
                "Cancelling phantom ONE_AT_A_TIME investigation "
                "(armed by pre-pause connection-refused race)"
            )

    # -------------------------------------------------------------------
    # Mode Control  (hook for Health Monitor / orchestrator)
    # -------------------------------------------------------------------

    async def set_investigation_mode(self, reason: str = "") -> None:
        """Switch to ONE_AT_A_TIME mode for precise crash isolation.

        P1-A fix: If already in ONE_AT_A_TIME, reset the scheduler
        instead of silently dropping the crash trigger.
        """
        async with self._sched_lock:
            # BUG-1 fix: a freshly-armed real-crash investigation must supersede
            # any _revert_pending staged by cancel_investigation() during a
            # prior normal-exit (phantom pre-pause race). Without this, a stale
            # cancel from the previous cycle would revert THIS real-crash
            # investigation on the next hot-loop iteration, silently dropping
            # crash isolation. Clear unconditionally — if no cancel was pending
            # this is a no-op.
            self._revert_pending = False
            self._stats.revert_pending = False

            if self._mode == MutationMode.ONE_AT_A_TIME:
                # P1-A: restart investigation from field 0 with fresh budget
                if isinstance(self._scheduler, OneAtATimeScheduler):
                    self._scheduler.reset()
                    log.warning(
                        "Crash during investigation — restarting field scan from field 0",
                        extra={"context": {"reason": reason}},
                    )
                return

            # P2-D: adaptive budget_per_field
            if self.budget_per_field > 0:
                bpf = self.budget_per_field  # explicit override
            else:
                # Adaptive: target ~5s per field at current EPS
                eps = self._stats.current_eps or 10.0
                bpf = max(20, min(200, int(5.0 * eps)))

            self._scheduler = OneAtATimeScheduler(
                budget_per_field=bpf,
                isolation_budget=self.investigation_budget,
            )
            self._mode = MutationMode.ONE_AT_A_TIME
            self._stats.mode               = self._mode.value
            self._stats.investigation_mode = True

        log.warning(
            "MODE → ONE_AT_A_TIME (crash isolation)",
            extra={"context": {
                "reason":  reason or "manual",
                "budget":  self.investigation_budget,
                "budget_per_field": bpf,
            }},
        )

    async def set_normal_mode(self) -> None:
        """Revert to normal mode (WEIGHTED or RANDOM_SUBSET).

        P2-C: Captures investigation summary before discarding scheduler.
        """
        async with self._sched_lock:
            # P2-C: capture investigation summary before replacing scheduler
            if isinstance(self._scheduler, OneAtATimeScheduler):
                self._stats.last_investigation_summary = {
                    "field_index_at_revert": self._scheduler.get_current_field_index(),
                    "total_sends": self._scheduler._sends_this_mode,
                    "field_hits": dict(self._scheduler._field_hits),
                    "reverted_at": time.monotonic(),
                    "reason": "budget_exhausted",
                }
                log.warning(
                    "Investigation complete — summary",
                    extra={"context": self._stats.last_investigation_summary},
                )

            self._scheduler = self._make_normal_scheduler()
            self._mode      = MutationMode.RANDOM_SUBSET
            self._stats.mode               = self._mode.value
            self._stats.investigation_mode = False
            self._stats.investigation_field = None

        log.info(
            "MODE → RANDOM_SUBSET (normal fuzzing resumed)",
            extra={"context": {
                "k": self.k,
                "weighted": self.use_weighted,
                "adaptive_k": self.adaptive_k,
            }},
        )

    async def update_rule_set(self, new_rules: SemanticRuleSet) -> None:
        """Atomically replace the active SemanticRuleSet.

        P1-B: Auto-transition from DUMB to normal mode when rules arrive.
        """
        async with self._rule_lock:
            old_id = self._rule_set.rule_set_id[:8] if self._rule_set else "none"
            self._rule_set = new_rules
            self._stats.rule_set_version += 1
            self._stats.rule_set_id       = new_rules.rule_set_id[:8]
            self._stats.active_fields     = len(new_rules.get_mutable_fields())

            # Cache decoded setup packets for stateful mode
            self._setup_packets = [
                bytes.fromhex(hp) for hp in new_rules.setup_packets if hp
            ]

        # P1-B: auto-transition from DUMB → normal when rules arrive
        if self._mode == MutationMode.DUMB:
            async with self._sched_lock:
                self._scheduler = self._make_normal_scheduler()
                self._mode = MutationMode.RANDOM_SUBSET
                self._stats.mode = self._mode.value
                self._stats.investigation_field = None
            log.info("Rules arrived — transitioning from DUMB to RANDOM_SUBSET")

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
        total = max(1, self._stats.total_sent)
        return MutatorStats(
            mode                       = self._mode.value,
            total_sent                 = self._stats.total_sent,
            total_accepted             = self._stats.total_accepted,
            total_rejected             = self._stats.total_rejected,
            total_timeout              = self._stats.total_timeout,
            total_crashes              = self._stats.total_crashes,
            current_eps                = self._stats.current_eps,
            rule_set_version           = self._stats.rule_set_version,
            rule_set_id                = self._stats.rule_set_id,
            active_fields              = self._stats.active_fields,
            investigation_mode         = self._stats.investigation_mode,
            investigation_field        = self._stats.investigation_field,
            k_this_round               = self._stats.k_this_round,
            revert_pending             = self._stats.revert_pending,
            last_investigation_summary = dict(self._stats.last_investigation_summary),
            current_k                  = self._current_k,
            recv_sample_rate           = self._recv_count / total,
            active_rule_count          = len(self._rule_set.rules) if self._rule_set is not None else 0,
        )

    def get_crash_window(self) -> list[tuple]:
        """H3 fix: return recent send history for crash attribution.

        Returns a list of ``(timestamp, payload_bytes, rule_id)`` tuples
        representing the last N sends.  The CrashMonitor uses this to
        attribute crashes to the correct packet, not just the most recent.
        """
        return list(self._crash_window)

    def freeze_crash_window(self) -> list[tuple]:
        """Freeze the crash attribution window and snapshot its contents.

        Post-crash confirmation (Phase 1): when the crash monitor detects a
        down target, it freezes the window so subsequent connection-refused
        sends don't pollute the candidate set, then replays the snapshot to
        find the packet that actually reproduces the crash. Returns the
        frozen candidate set (oldest → newest) as a list of
        ``(timestamp, payload_bytes, rule_id)`` tuples. Idempotent: a second
        freeze returns the same (already frozen) window.
        """
        self._window_frozen = True
        return list(self._crash_window)

    def unfreeze_crash_window(self) -> None:
        """Resume appending to the crash attribution window after confirmation."""
        self._window_frozen = False

    @property
    def window_frozen(self) -> bool:
        """Whether the crash window is currently frozen (post-crash confirmation)."""
        return self._window_frozen

    # -------------------------------------------------------------------
    # P2-C: Investigation Summary
    # -------------------------------------------------------------------

    def get_last_investigation_summary(self) -> dict:
        """Return summary from last completed investigation phase."""
        return dict(self._stats.last_investigation_summary)

    # -------------------------------------------------------------------
    # Sequence Splitter — M = ⟨Prefix, Target, Suffix⟩
    # -------------------------------------------------------------------

    def _split_sequence(self, seq: SeedSequence) -> FuzzTarget:
        """Split a SeedSequence into ⟨Prefix, Target, Suffix⟩.

        Target index selection uses quadratic weighting:
            P(i) ∝ (i + 1)²
        so later packets (deeper protocol states) are selected more often.
        For a 3-packet FTP session (USER, PASS, LIST), this means:
            P(index=0) = 1/14, P(index=1) = 4/14, P(index=2) = 9/14
        """
        n = len(seq.packets)
        if n == 0:
            raise IndexError("Sequence has no packets")
        if n == 1:
            return FuzzTarget(
                prefix=[],
                target_seed=seq.packets[0],
                target_index=0,
                suffix=[],
                sequence_id=seq.sequence_id,
            )

        # Quadratic weighting: later packets = deeper states = more interesting
        weights = [(i + 1) ** 2 for i in range(n)]
        total = sum(weights)
        r = random.random() * total
        cumulative = 0.0
        target_idx = n - 1  # default to last packet
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                target_idx = i
                break

        return FuzzTarget(
            prefix=[p.raw_bytes for p in seq.packets[:target_idx]],
            target_seed=seq.packets[target_idx],
            target_index=target_idx,
            suffix=[p.raw_bytes for p in seq.packets[target_idx + 1:]],
            sequence_id=seq.sequence_id,
        )

    # -------------------------------------------------------------------
    # EWMA Adaptive Controller — helpers
    # -------------------------------------------------------------------

    def _should_recv(self) -> bool:
        """EWMA Adaptive Controller: decide whether this packet should call recv().

        Returns True every current_k-th packet.
        When no_recv=True, always returns False (fire-and-forget mode).
        Thread-safe: _packet_counter is only written from the single asyncio hot loop.
        """
        if self.no_recv:
            return False
        self._packet_counter += 1
        return (self._packet_counter % max(1, self._current_k)) == 0

    def _record_response_sample(self, response: bytes) -> None:
        """EWMA Adaptive Controller: append sampled response to shared buffer.

        Fast path: skip if file already large (>80KB ≈ 1000 lines).
        Non-blocking: write failure is silently ignored (never crash the hot loop).

        FTP-aware: when the response looks like an FTP status code (3 ASCII
        digits followed by space/hyphen), extracts and logs the status code
        alongside the hex_prefix so the EWMA controller can reward deep
        authentication states with higher recv() intensity.
        """
        try:
            path = self._response_buf_path
            # Fast size check before open (os.stat is ~200ns)
            try:
                if os.stat(path).st_size > 80_000:
                    return
            except FileNotFoundError:
                pass
            hex_prefix = response[:8].hex() if len(response) >= 8 else response.hex()

            entry: dict = {
                "hex_prefix": hex_prefix,
                "length": len(response),
                "ts": round(time.time(), 3),
            }

            # Protocol-specific extras (e.g. FTP status code) → sub-dict
            # ``_extra`` so they don't leak into the top-level keys the EWMA
            # core reads. NullModule ⇒ empty dict ⇒ key omitted (pure black-box).
            extra = self._module.response_sample_extra(response)
            if extra:
                entry["_extra"] = extra

            line = json.dumps(entry) + "\n"
            with open(path, "a") as f:
                f.write(line)
        except Exception:
            pass  # Never crash hot loop for IPC write failure

    def _classify_response(self, resp: bytes, payload: bytes) -> PacketStatus:
        """Classify server response by protocol-specific status codes.

        For FTP (via FTPModule): uses 3-digit status codes (RFC 959).
        For the black-box core (NullModule): any non-empty reply ⇒ ACCEPTED.

        Args:
            resp:    Raw response bytes from the server.
            payload: The original payload sent (for context).

        Returns:
            Appropriate PacketStatus enum value.

        BUG-4 fix: a protocol module's ``classify`` runs on arbitrary (often
        mutated, malformed) bytes in the hot loop. If it ever raises, the
        exception would propagate out of ``_send``/``_execute_sequence`` past
        their connection-error-only handlers and kill the hot-loop task. Fall
        back to ACCEPTED (we got non-empty bytes back = the server processed
        something) and log once; never let a classifier crash take the engine
        down.
        """
        try:
            status = self._module.classify(resp, payload)
        except Exception as exc:
            log.warning(
                "protocol module classify() raised — falling back to ACCEPTED",
                extra={"context": {"err": str(exc)[:120],
                                   "resp_len": len(resp),
                                   "payload_len": len(payload)}},
            )
            status = PacketStatus.ACCEPTED

        # Track the latest server state code (for the baseline key) from the
        # response we just classified.
        try:
            self._last_state_code = self._module.extract_state_code(resp) or ""
        except Exception:
            pass

        # ── Differential-baseline oracle (Phase 3) ─────────────────────────
        # Replaces the Phase-1/2 inferred "expected error" oracle, which had
        # ~0% precision (server tolerance was indistinguishable from bugs).
        # The baseline is BEHAVIOURAL: the response signatures a command
        # normally gets, recorded from accepted non-violation sends. A
        # structural violation whose response signature MATCHES the baseline
        # is one the server did not react to ⇒ a potential semantic bug.
        #
        # No RFC/ground-truth: only observed behaviour. On a strict, correct
        # target (LIFA v2) every violation yields a distinct ERROR signature,
        # so nothing matches the ACK baseline ⇒ 0 false positives. That
        # zero-FP result is the oracle's precision proof.
        is_violation = self._current_rule_type == "semantic_violation"
        try:
            bkey = self._baseline.make_key(self._module, payload, self._last_state_code)
        except Exception:
            bkey = None
        # A response's category: only "normal" (success-class) replies form the
        # baseline. An error reply (e.g. FTP 501) IS the server reacting to a
        # bad input, so it must never be recorded as "normal" nor flag a match.
        try:
            rcat = self._module.response_category(resp, payload)
        except Exception:
            rcat = "normal" if resp else "error"

        if is_violation:
            self._pending_violation_expected = None
            if self._baseline.has_baseline(bkey):
                self._stats.semantic_oracle_checks += 1
                # Only a NORMAL reply that matches the baseline is suspicious —
                # the server treated the violation as a valid message. An error
                # reply means the server reacted correctly ⇒ never flagged.
                if rcat == "normal":
                    vsig = self._baseline.signature(self._module, resp, payload)
                    if self._baseline.is_baseline(bkey, vsig):
                        self._stats.semantic_violations_detected += 1
                        _resp_snip = resp[:80].decode("ascii", "replace").replace("\r", "\\r").replace("\n", "\\n")
                        _pay_snip = payload[:40].decode("ascii", "replace").replace("\r", "\\r").replace("\n", "\\n")
                        log.warning(
                            "Differential oracle: violation got a NORMAL "
                            f"baseline reply (sig={vsig!r}) — server accepted "
                            "the violation; potential semantic bug",
                            extra={"context": {"sig": vsig, "resp_len": len(resp),
                                               "resp": _resp_snip, "payload": _pay_snip}},
                        )
        elif status == PacketStatus.ACCEPTED and rcat == "normal":
            # Build the baseline from NORMAL accepted traffic only (not errors).
            self._baseline.record(
                bkey, self._baseline.signature(self._module, resp, payload)
            )
        return status

    def _track_rule_response(self, status: PacketStatus) -> None:
        """Track per-rule-type response stats for LLM feedback.

        Records accepted/rejected/timeout/crash counts grouped by the
        mutation strategy that produced the current packet. Exposed via
        the ``rule_response_stats`` property for the RulesOrchestrator
        to build LLM response feedback.
        """
        rule_type = self._current_rule_type or "unknown"
        if rule_type not in self._rule_response_stats:
            self._rule_response_stats[rule_type] = {
                "accepted": 0, "rejected": 0, "timeout": 0, "crash": 0,
            }
        key = status.value  # "accepted", "rejected", "timeout", "crash"
        if key in self._rule_response_stats[rule_type]:
            self._rule_response_stats[rule_type][key] += 1

    @property
    def rule_response_stats(self) -> dict[str, dict[str, int]]:
        """Snapshot of per-rule-type response stats (for LLM feedback)."""
        return dict(self._rule_response_stats)

    def _write_rule_response_stats(self) -> None:
        """Write per-rule-type response stats to shared JSON file.

        Called every heartbeat (~5s) so the RulesOrchestrator can read
        it and build LLM response feedback. Uses atomic write.
        """
        if not self._rule_response_stats:
            return
        try:
            path = Path("shared/rule_response_stats.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._rule_response_stats, f)
            tmp.rename(path)
        except Exception:
            pass  # Must not crash the hot loop

    def _poll_adaptive_k(self) -> None:
        """Poll shared/adaptive_k.json for EWMA controller updates.

        Reuses the exact same mtime-check pattern as _poll_rules_file().
        Non-blocking: if file missing or malformed, keep existing _current_k.
        """
        try:
            path = self._adaptive_k_path
            if not os.path.exists(path):
                return
            mtime = os.path.getmtime(path)
            if mtime <= self._adaptive_k_mtime:
                return
            with open(path) as f:
                data = json.load(f)

            if isinstance(data, dict) and "current_k" in data:
                k = int(data["current_k"])
                self._current_k = max(1, min(k, self._ewma_k_max))  # clamp [1, K_max]
                self._stats.current_k = self._current_k
                self._stats.ewma_lambda_c = data.get("lambda_c", 0.0)
                self._stats.ewma_regime = data.get("regime", "sparse")
                self._adaptive_k_mtime = mtime
        except (ValueError, KeyError, TypeError, OSError):
            pass  # Keep existing _current_k on any parse error

    @staticmethod
    def _load_adaptive_config() -> dict:
        """Read adaptive_sampling + ewma_controller config from config.yaml, return with defaults."""
        defaults = {
            "ipc_read_interval": 50,
            "k_default": 200,
            "adaptive_k_path": "shared/adaptive_k.json",
            "response_buf_path": "shared/response_buffer.jsonl",
            "ewma_k_max": 200,
        }
        try:
            import yaml
            cfg = Path("config.yaml")
            if cfg.exists():
                with open(cfg) as f:
                    data = yaml.safe_load(f) or {}
                # Fast Loop side (adaptive_sampling)
                section = (data.get("fast_loop") or {}).get("adaptive_sampling") or {}
                for key, default in defaults.items():
                    if key in section:
                        defaults[key] = section[key]
                # Slow Loop side (ewma_controller) — K_max is defined here
                ewma = (data.get("slow_loop") or {}).get("ewma_controller") or {}
                if "K_max" in ewma:
                    defaults["ewma_k_max"] = ewma["K_max"]
        except Exception:
            pass
        return defaults

    def _load_adaptive_config_into_self(self) -> None:
        """Load adaptive config into instance variables."""
        cfg = self._load_adaptive_config()
        self._ipc_read_interval = cfg["ipc_read_interval"]
        self._current_k = cfg["k_default"]
        self._adaptive_k_path = cfg["adaptive_k_path"]
        self._response_buf_path = cfg["response_buf_path"]
        self._ewma_k_max: int = cfg["ewma_k_max"]

    # -------------------------------------------------------------------
    # Seed Management
    # -------------------------------------------------------------------

    async def _drain_seeds(self) -> None:
        """Non-blocking drain: move SeedSequence objects from queue to corpus.

        Backward compatible: bare TrafficRecord objects are automatically
        wrapped in a single-packet SeedSequence.

        Evicts highest-frequency (least interesting) sequences when corpus
        exceeds MAX_CORPUS to prevent unbounded memory growth.
        """
        MAX_CORPUS = 5000

        while not self.seed_queue.empty():
            try:
                item = self.seed_queue.get_nowait()
                # Backward compat: wrap bare TrafficRecord from legacy callers
                if isinstance(item, TrafficRecord) and not isinstance(item, SeedSequence):
                    item = SeedSequence(packets=[item])
                self._corpus.append(item)
                self.seed_queue.task_done()
            except asyncio.QueueEmpty:
                break

        # Evict least-interesting sequences when corpus exceeds cap.
        # Highest-frequency = most over-fuzzed = least interesting for IFPS.
        if len(self._corpus) > MAX_CORPUS:
            scored = [
                (i, self._seed_freq.get(s.sequence_id, 0))
                for i, s in enumerate(self._corpus)
            ]
            scored.sort(key=lambda x: x[1], reverse=True)
            # Remove top 20% most-frequent seeds
            to_remove = set(i for i, _ in scored[: len(scored) // 5])
            self._corpus = [
                s for i, s in enumerate(self._corpus) if i not in to_remove
            ]

    def _pick_seed(self) -> SeedSequence:
        """Inverse-Frequency Power Schedule (IFPS) seed selection.

        Operates at sequence level: each SeedSequence is one unit.
        Rarely-used sequences get higher energy and are chosen more often.

        Step 3 — STATE_NOVELTY boost: seeds that discovered new protocol
        state edges receive a 5× energy multiplier, making them far more
        likely to be selected. This drives deep-state exploration, similar
        to AFL rewarding new code-branch discoveries.

        Uses acceptance-rejection sampling — O(1) expected time per
        selection regardless of corpus size.
        """
        n = len(self._corpus)
        if n == 0:
            raise IndexError("Corpus is empty")
        if n == 1:
            return self._corpus[0]

        # Max energy is 1.0 (freq=0).  Acceptance-rejection:
        for _ in range(n + 10):  # bounded retries, fallback to uniform
            idx = random.randint(0, n - 1)
            seq = self._corpus[idx]
            freq = self._seed_freq.get(seq.sequence_id, 0)
            energy = 1.0 / (freq + 1)
            # STATE_NOVELTY boost: 5× acceptance for seeds that found new edges
            # (module-owned tracker; NullModule has no tracker → no boost).
            if self._state_tracker is not None and self._state_tracker.is_novel_seed(seq.sequence_id):
                energy *= StateTransitionGraph.NOVELTY_ENERGY_MULTIPLIER
            if random.random() < min(energy, 1.0):
                return seq

        # Fallback: uniform random (extremely unlikely to reach here)
        return self._corpus[random.randint(0, n - 1)]

    @staticmethod
    def _make_dummy_seed() -> SeedSequence:
        """Generate a minimal dummy seed when no real traffic is available."""
        dummy = b"\x00" * 16
        return SeedSequence(
            packets=[TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=dummy,
            )],
        )

    # -------------------------------------------------------------------
    # Rule File Poller — bridges Slow Loop / Math-Only → Fast Loop
    # -------------------------------------------------------------------

    @staticmethod
    def _load_rules_path_from_config() -> str:
        """Read rule_output_file from config.yaml, fallback to shared/active_rules.json."""
        try:
            import yaml as _yaml
            _cfg = Path("config.yaml")
            if _cfg.exists():
                with open(_cfg) as _f:
                    data = _yaml.safe_load(_f) or {}
                # Try rule_generator.rule_output_file first (slow loop path)
                rg = (data.get("slow_loop") or {}).get("rule_generator") or {}
                path = rg.get("rule_output_file")
                if path:
                    return path
                # Try fast_loop.rule_watcher.rules_file
                rw = (data.get("fast_loop") or {}).get("rule_watcher") or {}
                path = rw.get("rules_file")
                if path:
                    return path
        except Exception:
            pass
        return "shared/active_rules.json"

    async def _poll_rules_file(self) -> None:
        """Poll shared/active_rules.json for new rules from Slow Loop."""
        path = self._rules_file
        try:
            if not os.path.exists(path):
                return
            mtime = os.path.getmtime(path)
            if mtime <= self._last_rules_mtime:
                return
            with open(path) as _f:
                raw = json.loads(_f.read())

            # C4 fix: update mtime BEFORE update_rule_set so that a
            # failed update doesn't cause infinite retries on same file.
            self._last_rules_mtime = mtime

            if isinstance(raw, dict):
                params = dict(raw)
                params.setdefault("protocol_name", "inferred")
                # C4 fix: overall_confidence and protocol_name are now
                # included in the payload by push_rules() — ActiveRuleSet
                # will pick them up via **params automatically.
                rule_set = ActiveRuleSet(**params)
            elif isinstance(raw, list):
                rule_set = ActiveRuleSet(
                    protocol_name="inferred",
                    rules=raw,
                )
            else:
                return

            await self.update_rule_set(rule_set)

        except json.JSONDecodeError as e:
            log.warning(f"Corrupt rules file {path}: {e}")
            # Still advance mtime so we don't retry the same corrupt file
            try:
                self._last_rules_mtime = os.path.getmtime(path)
            except OSError:
                pass
        except Exception as e:
            log.warning(f"Error polling rules file: {e}")

    # -------------------------------------------------------------------
    # Packet Construction — THE CORE ALGORITHM
    # -------------------------------------------------------------------

    async def _build_mutant(self, seed: PacketRecord) -> bytes:
        """Build one mutated packet using the active scheduler and rule set.

        Implements ε-greedy exploration (Task 3):
            ε = 0.2 — with 20% probability, bypass LLM rules and apply
            purely random havoc mutation via BinaryMutator to maintain
            wide state-space coverage and prevent mode collapse.
        """
        # ── Phase 3 / TASK 3: exploitation payloads ────────────────────
        # With ~50% probability on FTP targets (the confirmed vuln is in
        # argument handling), bypass every other path and inject a known
        # "magic value" payload (buffer overflow / format string / path
        # traversal) directly into the argument region. RANDOM_BYTES almost
        # never synthesizes these, so this is what actually detonates the
        # known memory-handling bug. The remaining ~50% keep the ε-greedy
        # exploration + LLM-guided exploitation paths intact.
        _MAGIC_PROB = 0.2 if getattr(self, "_is_ftp_target", False) else 0.0
        if _MAGIC_PROB and random.random() < _MAGIC_PROB:
            buf = bytearray(seed.raw_bytes)
            self._binary_mutator.mutate_with(buf, "magic_values")
            result = bytes(buf)
            self._last_injected_rule_id = "magic_values"
            self._current_rule_type = "magic_values"
            self._mutation_signatures.add(f"magic:len:{len(result)}")
            return result

        # ── ε-greedy: exploration vs exploitation ──────────────────────
        # Operators = generic 15 + module-supplied (FTPModule adds 4 FTP
        # strategies; NullModule adds none → pure black-box havoc, no FTP leak).
        _exploration_ops = BINARY_ONLY_STRATEGIES + self._module.binary_operators()
        _EPSILON = 0.2
        if random.random() < _EPSILON:
            # EXPLORATION: bypass LLM rules, pure random/havoc mutation
            buf = bytearray(seed.raw_bytes)
            self._binary_mutator.mutate(buf, strategies=_exploration_ops)
            result = bytes(buf)
            self._last_injected_rule_id = "epsilon_explore"
            self._current_rule_type = "epsilon_explore"
            # Track mutation signatures for coverage proxy
            if buf and len(buf) == len(seed.raw_bytes):
                for i in range(len(buf)):
                    if buf[i] != seed.raw_bytes[i]:
                        self._mutation_signatures.add(f"explore:{i}:{buf[i]:02x}")
            elif buf:
                self._mutation_signatures.add(f"explore:len:{len(buf)}")
            return result

        # ── EXPLOITATION: structured LLM-guided mutation ───────────────
        # Snapshot rule set — avoid holding lock during mutation
        async with self._rule_lock:
            rule_set = self._rule_set

        if rule_set is None:
            # P1-B: properly transition to DUMB mode
            if self._mode != MutationMode.DUMB:
                self._mode = MutationMode.DUMB
                self._stats.mode = "dumb"
                self._stats.investigation_field = None
                log.info("No rule set — entering DUMB mode (BinaryMutator)")

            buf = bytearray(seed.raw_bytes)
            # BinaryMutator: generic 15 strategies + module operators (FTP for
            # the case study; none for the black-box NullModule). AFL-class
            # random fuzzing — Baseline A baseline against B and C.
            self._binary_mutator.mutate(buf, strategies=_exploration_ops)
            result = bytes(buf)
            # Clear rule attribution — no rule produced this mutation
            self._last_injected_rule_id = None
            self._current_rule_type = "dumb"
            # Track mutation signatures for coverage proxy.
            # BinaryMutator may change length (block_dup/del/truncate),
            # so only track same-length mutations for offset coverage.
            if buf and len(buf) == len(seed.raw_bytes):
                for i in range(len(buf)):
                    if buf[i] != seed.raw_bytes[i]:
                        self._mutation_signatures.add(f"dumb:{i}:{buf[i]:02x}")
            elif buf:
                # Length-changing mutation — track by total length as proxy
                self._mutation_signatures.add(f"dumb:len:{len(buf)}")
            return result

        # Choose base payload
        base = bytearray(seed.raw_bytes)
        if rule_set.base_packet:
            try:
                base = bytearray(bytes.fromhex(rule_set.base_packet))
            except ValueError:
                pass

        mutable = rule_set.get_mutable_fields()
        static  = rule_set.get_static_fields()

        # ── Semantic-violation path (SemFuzz-style, paper-faithful) ──────────
        # Apply a disclosed structural violation (add/remove/update) from the
        # active ProtocolModule's case-study set (e.g. FTP CRLF removal). The
        # deterministic engine recomputes the length field so the packet stays
        # syntactically valid — a valid violation reaches deep parser logic
        # (paper §3.5.2). The expected response category is stashed for the
        # oracle in _classify_response. No protocol-specific logic in core:
        # strategies come entirely from the module.
        _VIOLATION_PROB = 0.08
        # Collect violation strategies from TWO sources (paper §3.4 mutation
        # strategies + disclosed case-study):
        #   (a) grammar-targeted: SemanticRule.violation_strategies attached
        #       by the rule generator (target real inferred fields).
        #   (b) case-study: module.violation_strategies() (e.g. FTP CRLF).
        try:
            _vstrats = list(self._module.violation_strategies()) if self._module else []
        except Exception:
            _vstrats = []
        for _r in rule_set.rules:
            try:
                if _r.violation_strategies:
                    _vstrats.extend(_r.violation_strategies)
            except Exception:
                pass
        if _vstrats and random.random() < _VIOLATION_PROB:
            try:
                from fast_loop.violation_mutator import FlatFieldViolationMutator
                strat = random.choice(_vstrats)
                fields = list(mutable) + list(static)
                vbuf = FlatFieldViolationMutator(fields).execute(
                    bytearray(seed.raw_bytes), strat
                )
                result = bytes(vbuf)
                self._last_injected_rule_id = f"violation:{strat.action.value}"
                self._current_rule_type = "semantic_violation"
                self._pending_violation_expected = strat.expected_category.value
                self._mutation_signatures.add(
                    f"violation:{strat.action.value}:off{strat.target_offset}"
                )
                return result
            except Exception as exc:
                log.debug(f"violation mutation failed: {exc}")

        # Apply STATIC fields first (always overwrite — preserve magic bytes)
        for f in static:
            base = _apply_field(base, f)

        # ── Size-escalation mode (AFL-style growth bias) ───────────────
        # Variable-length payloads are where buffer overflows live, and a
        # length-clamping server can only be overflowed by GROWING the actual
        # bytes — not by rewriting the length field. With multiple fields the
        # scheduler must keep mutations length-preserving, so payload growth
        # is only reachable when the variable field is mutated alone. Sample
        # that single-field growth path explicitly and periodically so the
        # fuzzer does not starve the overflow bug class. This is GENERAL: it
        # keys off the PAYLOAD_EXTEND strategy the analyzer assigns to ANY
        # variable-length tail field, not any protocol-specific offset.
        _PAYLOAD_GROW_PROB = 0.25
        if random.random() < _PAYLOAD_GROW_PROB:
            grow_fields = [
                f for f in mutable
                if f.mutation_strategy == MutationStrategy.PAYLOAD_EXTEND
            ]
            if grow_fields:
                f = random.choice(grow_fields)
                grown = _apply_field(base, f, preserve_length=False)
                # Length-aware growth: a grown payload with a stale declared
                # length is clamped by the server (min(declared, actual)) and
                # the overflow is masked. Rewrite the length field to the new
                # payload size so the packet stays valid and reaches the copy.
                grown = _recompute_length_fields(
                    grown, list(mutable) + list(static)
                )
                self._last_injected_rule_id = f"payload_extend:{f.field_name}"
                self._current_rule_type = "payload_extend"
                start = f.offset
                length = f.length if f.length != -1 else len(grown) - start
                for off in range(start, min(start + length, len(grown))):
                    self._mutation_signatures.add(
                        f"rule:{f.field_name}:payload_extend:{off}"
                    )
                self._mutation_signatures.add(
                    f"grow:{f.field_name}:len:{len(grown)}"
                )
                # Text-protocol delimiter preservation: if the original seed
                # ended with a CRLF (FTP/HTTP/SMTP/POP3/IMAP) and the growth
                # destroyed it (op_buffer_overflow replaces [start:end] which
                # overlaps the trailing CRLF), re-append it. Without this the
                # server never sees a complete command → timeout → no crash.
                # GENERAL: checks for \r\n on the original seed, not any
                # protocol name or field label.
                if seed.raw_bytes.endswith(b"\r\n") and not grown.endswith(b"\r\n"):
                    grown += b"\r\n"
                return bytes(grown)

        # Ask scheduler which fields to mutate this round
        async with self._sched_lock:
            chosen = self._scheduler.select(mutable)
            if self._mode == MutationMode.ONE_AT_A_TIME and chosen:
                self._stats.investigation_field = chosen[0].field_name
            # P2-A: track k used this round
            self._stats.k_this_round = len(chosen)
            if (
                self._mode == MutationMode.ONE_AT_A_TIME
                and isinstance(self._scheduler, OneAtATimeScheduler)
                and self._scheduler.is_budget_exhausted(len(mutable))
            ):
                # P1-A: set flag instead of fire-and-forget
                self._revert_pending = True
                self._stats.revert_pending = True

        # Apply mutations for the chosen subset
        # Bugfix: when k>1, force length-preserving mutations so that
        # an operator that inserts/deletes bytes doesn't corrupt the
        # offsets of subsequent fields.
        multi = len(chosen) > 1
        for f in chosen:
            base = _apply_field(base, f, preserve_length=multi)
            # Track mutation signature per field+strategy+offset
            start = f.offset
            length = f.length if f.length != -1 else len(base) - start
            for off in range(start, min(start + length, len(base))):
                self._mutation_signatures.add(
                    f"rule:{f.field_name}:{f.mutation_strategy}:{off}"
                )

        # Track which rules were applied for crash attribution
        if chosen:
            self._last_injected_rule_id = ",".join(f.field_name for f in chosen)
            self._current_rule_type = chosen[0].mutation_strategy.value
        else:
            self._last_injected_rule_id = None
            self._current_rule_type = None

        # Length-aware fixup: if a single-field mutation (multi=False) grew or
        # shrank the packet, the declared length field is now stale and the
        # server would clamp it — masking any overflow. Recompute the length
        # field to the current payload size. Only when size changed (multi-field
        # mode is length-preserving, so no fixup needed there).
        if not multi and len(base) != len(seed.raw_bytes):
            base = _recompute_length_fields(base, list(mutable) + list(static))
            # Text-protocol CRLF preservation (same rationale as size-escalation
            # path above): if the seed ended with \r\n and growth destroyed it,
            # re-append so the server sees a complete command.
            if seed.raw_bytes.endswith(b"\r\n") and not base.endswith(b"\r\n"):
                base += b"\r\n"

        return bytes(base)

    # -------------------------------------------------------------------
    # FTP Protocol Enforcement
    # -------------------------------------------------------------------

    def _ensure_ftp_crlf(self, payload: bytes) -> bytes:
        """Apply protocol framing via the ProtocolModule.

        Kept as a thin wrapper for the many call sites; the actual framing
        (CRLF for FTP, identity for the black-box NullModule) lives in
        ``self._module.ensure_framing()``.
        """
        return self._module.ensure_framing(payload)

    # -------------------------------------------------------------------
    # FTP connection-terminating command blacklist (Phase 3 / TASK 2)
    # -------------------------------------------------------------------

    def _is_ftp_quit_command(self, payload: bytes) -> bool:
        """Return True if *payload* is an FTP connection-terminating command.

        QUIT/BYE/EXIT make LightFTP shut down the session (and, on some
        control paths, the process exits cleanly with exit_code=0). Sending
        them wastes a ~2s VM restart and — before Phase 3 — every such
        normal exit was treated as a crash, arming ONE_AT_A_TIME
        investigation on phantom crashes. TASK 2 drops these commands
        before they hit the wire.

        Match is on the leading command token (case-insensitive), terminated
        by a space / CR / LF / end-of-payload — so e.g. ``QUITX`` is NOT
        matched, but ``QUIT\\r\\n`` / ``QUIT admin`` are.
        """
        if not payload or not getattr(self, "_is_ftp_target", False):
            return False
        try:
            text = payload[:8].decode("ascii", errors="ignore").upper()
        except Exception:
            return False
        for verb in ("QUIT", "BYE", "EXIT"):
            if text.startswith(verb):
                terminator = text[len(verb):len(verb) + 1]
                if terminator in ("", " ", "\r", "\n"):
                    return True
        return False

    def _drop_if_ftp_quit(self, payload: bytes, seed_id: str) -> bool:
        """If *payload* is an FTP QUIT/BYE/EXIT, log ``[Drop]`` and return True.

        Caller returns ``PacketStatus.REJECTED`` immediately (no socket send).
        ``status_callback`` is notified REJECTED so the seed is neither
        re-tried nor counted as a crash. Returns False for non-QUIT payloads
        (caller continues normally).
        """
        if not self._is_ftp_quit_command(payload):
            return False
        log.info(
            "[Drop] FTP QUIT/BYE/EXIT — skipping send to avoid target shutdown",
            extra={"context": {
                "payload_hex": payload.hex()[:48],
                "len":         len(payload),
                "seed":        (seed_id or "")[:8],
            }},
        )
        if self.status_callback:
            try:
                self.status_callback(seed_id, PacketStatus.REJECTED)
            except Exception:
                pass
        return True

    # -------------------------------------------------------------------
    # Network Send
    # -------------------------------------------------------------------

    async def _probe_target_alive(self) -> bool:
        """Fast black-box probe: is the target accepting TCP connections now?

        Three quick connect attempts, 50 ms apart, 0.2 s timeout each. If any
        succeeds the target is up — a refused send that reached this probe was
        a transient restart/overload artifact (phantom), NOT a real crash.

        Pure black-box: a TCP connect is exactly the same observable the
        fuzzer already uses to send; no source/protocol knowledge. Worst-case
        cost ~150-200 ms, paid ONLY on a refused send that already passed the
        restart-grace filter (rare), so the hot-path EPS is unaffected.

        BUG-2 fix: rate-limited via PROBE_COOLDOWN_S. A burst of refused sends
        would otherwise each open up to 3 connections, self-amplifying overload
        on a thread/fork-per-connection target. Within the cooldown we reuse
        the last result — the target's liveness does not meaningfully change
        in 250 ms, and a fresh probe then just re-opens connections we are
        about to close.
        """
        now = time.monotonic()
        if now - self._last_probe_monotonic < PROBE_COOLDOWN_S:
            return self._last_probe_alive

        alive = False
        for attempt in range(3):
            writer = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    timeout=0.2,
                )
                alive = True  # connect succeeded → target is up
                break
            except (asyncio.TimeoutError, ConnectionRefusedError,
                    ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                    except Exception:
                        pass
            if attempt < 2:
                await asyncio.sleep(0.05)

        self._last_probe_monotonic = now
        self._last_probe_alive = alive
        return alive

    async def _classify_conn_refused(
        self,
        payload: bytes,
        label: str,
        extra: dict | None = None,
    ) -> PacketStatus:
        """Classify a refused/reset/broken-pipe connection.

        Three filters, cheapest first (Phase 3 / 3.1 / 3.2):

        1. **restart-grace** (``_in_restart_grace()``): the target is known to
           be restarting (paused) OR within the post-resume grace window.
           A refusal here is a transient restart artifact → TIMEOUT.

        2. **Fast target probe** (Phase 3.2): a refusal that slipped past
           restart-grace may still be transient — the target is up but a single
           accept/overload hiccup dropped us. Probe with 3 quick connect
           attempts; if ANY succeeds, the target is alive → phantom → TIMEOUT.
           No investigation, EPS preserved.

        3. **Real crash**: only if both filters fail (target genuinely silent
           across 3 probes) do we classify CRASH and let the hot loop arm the
           ONE_AT_A_TIME investigation. ASAN aborts (exit 134) are caught
           earlier by the CrashMonitor via the sandbox, not here.
        """
        # Filter 1: restart-grace.
        if self._in_restart_grace():
            log.debug(
                f"Target unreachable during restart-grace ({label}) — "
                f"classified TIMEOUT, not crash"
            )
            return PacketStatus.TIMEOUT

        # Filter 2: fast probe — is the target actually up right now?
        if await self._probe_target_alive():
            log.debug(
                f"Target reachable on probe after refused ({label}) — "
                f"transient artifact, classified TIMEOUT, not crash"
            )
            return PacketStatus.TIMEOUT

        # Filter 3: target genuinely down across 3 probes → real crash.
        ctx = {
            "payload_hex": payload.hex()[:48],
            "len":         len(payload),
        }
        if extra:
            ctx.update(extra)
        log.error(f"Target CRASH ({label}) — confirmed down across 3 probes",
                  extra={"context": ctx})
        if self.crash_callback:
            self.crash_callback(payload, "connection_refused")
        return PacketStatus.CRASH

    async def _send(self, payload: bytes, seed_id: str) -> PacketStatus:
        """Open a fresh TCP connection and send one mutated payload."""
        # FTP CRLF enforcement: ensure packet ends with \r\n
        payload = self._ensure_ftp_crlf(payload)

        # Phase 3 / TASK 2: drop connection-terminating commands (QUIT/BYE/EXIT)
        # before they hit the wire — they make the target exit(0) and waste a
        # restart. Return REJECTED (never CRASH) without opening a socket.
        if self._drop_if_ftp_quit(payload, seed_id):
            return PacketStatus.REJECTED

        status = PacketStatus.TIMEOUT
        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.connection_timeout,
            )

            # Drain server greeting (e.g. FTP 220 banner) before sending.
            # Without this, the first read returns the greeting, not the
            # response to our packet — off-by-one (same bug as _execute_sequence).
            try:
                await asyncio.wait_for(reader.read(4096), timeout=self.recv_timeout)
            except asyncio.TimeoutError:
                pass

            writer.write(payload)
            await writer.drain()

            # Always read response — classify as accepted/rejected/timeout
            self._recv_count += 1
            try:
                resp = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                if resp:
                    status = self._classify_response(resp, payload)
                    self._record_response_sample(resp)
                    # State-transition tracking — pass RAW RESPONSE BYTES so
                    # both FTPStateTracker (extracts code from bytes[:3]) and
                    # InferredStateTracker (label_packet on full bytes) work.
                    # Previously passed new_code (module-extracted) which was ""
                    # for NullModule → label_packet("") → None → tracker DEAD.
                    if self._state_tracker is not None:
                        cmd = self._module.extract_command(payload)
                        self._state_tracker.record_edge("220", cmd, resp, seed_id)
                else:
                    status = PacketStatus.REJECTED
            except asyncio.TimeoutError:
                status = PacketStatus.TIMEOUT

        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
            status = await self._classify_conn_refused(payload, "connection refused/reset")

        except asyncio.TimeoutError:
            status = PacketStatus.TIMEOUT

        except OSError as exc:
            # Other OS errors (e.g. network unreachable) — not crashes
            log.warning("Send error", extra={"context": {"err": str(exc)[:80]}})
            status = PacketStatus.TIMEOUT

        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

        # Backward compat — crash_monitor reads these
        self._last_injected_packet = payload
        # H3 fix: append to crash attribution window
        if not self._window_frozen:
            self._crash_window.append((time.monotonic(), payload, self._last_injected_rule_id, []))  # [] prefix = single-packet, no session

        # Feed result back to Interceptor for stuck detection
        if self.status_callback:
            self.status_callback(seed_id, status)

        return status

    # -------------------------------------------------------------------
    # Stateful Send (multi-step handshake on one connection)
    # -------------------------------------------------------------------

    async def _send_stateful(
        self, payload: bytes, seed_id: str
    ) -> PacketStatus:
        """Send setup packets + mutated payload on ONE TCP connection."""
        # FTP CRLF enforcement
        payload = self._ensure_ftp_crlf(payload)

        # Phase 3 / TASK 2: drop QUIT/BYE/EXIT before sending.
        if self._drop_if_ftp_quit(payload, seed_id):
            return PacketStatus.REJECTED

        status = PacketStatus.TIMEOUT
        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.connection_timeout,
            )

            # 1. Send setup packets sequentially
            for setup_pkt in self._setup_packets:
                writer.write(setup_pkt)
                await writer.drain()
                try:
                    await asyncio.wait_for(
                        reader.read(4096), timeout=self.recv_timeout
                    )
                except (asyncio.TimeoutError, Exception):
                    pass

            # 2. Send the mutated payload
            writer.write(payload)
            await writer.drain()

            # 3. Read final response — always read and classify
            self._recv_count += 1
            try:
                resp = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                if resp:
                    status = self._classify_response(resp, payload)
                    self._record_response_sample(resp)
                else:
                    status = PacketStatus.REJECTED
            except asyncio.TimeoutError:
                status = PacketStatus.TIMEOUT

        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
            status = await self._classify_conn_refused(
                payload, "stateful, connection refused/reset"
            )

        except asyncio.TimeoutError:
            status = PacketStatus.TIMEOUT

        except OSError as exc:
            log.warning("Stateful send error", extra={"context": {"err": str(exc)[:80]}})
            status = PacketStatus.TIMEOUT

        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

        # Backward compat — crash_monitor reads these
        self._last_injected_packet = payload
        # H3 fix: append to crash attribution window
        if not self._window_frozen:
            self._crash_window.append((time.monotonic(), payload, self._last_injected_rule_id, []))  # [] prefix = single-packet, no session

        # Feed result back to Interceptor for stuck detection
        if self.status_callback:
            self.status_callback(seed_id, status)

        return status

    # -------------------------------------------------------------------
    # Sequence Send (Prefix → Mutated Target → Suffix on one connection)
    # -------------------------------------------------------------------

    async def _execute_sequence(
        self, target: FuzzTarget, mutated_payload: bytes
    ) -> PacketStatus:
        """Send ⟨Prefix, Mutated_Target, Suffix⟩ on ONE TCP connection.

        This implements the SOTA M = ⟨Prefix, Mutated_Target, Suffix⟩ paradigm
        for stateful protocol fuzzing:
          Step A: Open one TCP connection
          Step B: Send prefix packets verbatim (drive server into deep state)
          Step C: Send mutated target packet (the fuzzing payload)
          Step D: Send suffix packets verbatim (optional structural integrity)
          Step E: Close connection

        The returned PacketStatus reflects the server's response to the
        mutated target ONLY — prefix/suffix responses are drained but ignored.

        Step 3 — STG Tracking:
          Prefix responses are already read (then discarded). We capture them
          for the StateTransitionGraph at zero extra cost. For the mutated
          target, STG piggybacks on the existing _should_recv() gate.
        """
        # FTP CRLF enforcement on the mutated target
        mutated_payload = self._ensure_ftp_crlf(mutated_payload)

        # Phase 3 / TASK 2: drop QUIT/BYE/EXIT target commands before sending —
        # they would terminate the session/target and waste a restart.
        if self._drop_if_ftp_quit(mutated_payload, target.sequence_id):
            return PacketStatus.REJECTED

        status = PacketStatus.TIMEOUT
        writer = None

        # Step 3: STG tracking — initial state for FTP is always 220 (banner).
        # Track prev_code across the entire sequence to chain edges.
        prev_code = "220"

        # Collect the full response chain for diagnostics: [greeting, *prefix, target].
        # Task B — exposes whether auth (e.g. FTP 230) completes before the target.
        chain: list[str] = []

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=self.connection_timeout,
            )

            # Step A: drain the server's initial greeting (e.g. FTP "220 ready"
            # banner) BEFORE sending our first packet. GENERIC — we do not
            # inspect content, just consume whatever the server sends on connect
            # so the first prefix read returns the prefix's own response, not the
            # greeting. Without this, every read is off-by-one (a classic FTP
            # client bug) → state mis-tracked, auth slips, target response misread.
            # Protocols with no greeting: the read times out (≤ recv_timeout) and
            # we proceed. reader.read returns as soon as data is available, so a
            # real greeting costs ~nothing.
            try:
                greeting = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                if greeting and self._module is not None:
                    g_code = self._module.extract_state_code(greeting)
                    chain.append(g_code)
                    if g_code:
                        prev_code = g_code  # initial state for edge chaining
            except (asyncio.TimeoutError, Exception):
                pass  # no greeting on connect — fine

            # Step B: Send prefix packets VERBATIM (never mutated) — these
            # establish protocol state (e.g. USER→PASS auth). Only the target is
            # fuzzed (Task C). Drain each response so the next read aligns.
            for pkt_bytes in target.prefix:
                writer.write(pkt_bytes)
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(
                        reader.read(4096), timeout=self.recv_timeout
                    )
                    if resp:
                        new_code = (
                            self._module.extract_state_code(resp)
                            if self._module is not None else ""
                        )
                        chain.append(new_code)  # diagnostic
                        # State-transition tracking — pass RAW RESPONSE BYTES.
                        if self._state_tracker is not None:
                            cmd = self._module.extract_command(pkt_bytes)
                            self._state_tracker.record_edge(
                                prev_code, cmd, resp, target.sequence_id
                            )
                            prev_code = new_code
                    else:
                        chain.append("")  # empty reply
                except (asyncio.TimeoutError, Exception):
                    chain.append("timeout")  # prefix got no response

            # Step C: Send mutated target — always read and classify response
            writer.write(mutated_payload)
            await writer.drain()

            self._recv_count += 1
            try:
                resp = await asyncio.wait_for(
                    reader.read(4096), timeout=self.recv_timeout
                )
                if resp:
                    status = self._classify_response(resp, mutated_payload)
                    self._record_response_sample(resp)
                    t_code = (
                        self._module.extract_state_code(resp)
                        if self._module is not None else ""
                    )
                    chain.append(t_code)  # diagnostic: target's response code
                    # State-transition tracking — pass RAW RESPONSE BYTES.
                    if self._state_tracker is not None:
                        cmd = self._module.extract_command(
                            mutated_payload
                        )
                        is_novel = self._state_tracker.record_edge(
                            prev_code, cmd, resp, target.sequence_id
                        )
                        if is_novel:
                            log.info(
                                f"STATE_NOVELTY: new edge "
                                f"({prev_code},{cmd},{t_code}) "
                                f"seed={target.sequence_id[:8]}",
                            )
                else:
                    chain.append("")
                    status = PacketStatus.REJECTED
            except asyncio.TimeoutError:
                chain.append("timeout")
                status = PacketStatus.TIMEOUT

            # Step D: Send suffix packets verbatim
            for pkt_bytes in target.suffix:
                writer.write(pkt_bytes)
                await writer.drain()
                try:
                    await asyncio.wait_for(
                        reader.read(4096), timeout=self.recv_timeout
                    )
                except (ConnectionResetError, BrokenPipeError):
                    # Server crashed during suffix — the mutated target caused it.
                    # In no_recv mode, status is still ACCEPTED — override to CRASH.
                    if status != PacketStatus.CRASH:
                        status = PacketStatus.CRASH
                    # FIX: fire crash_callback so CrashManager sees this crash
                    if self.crash_callback:
                        self.crash_callback(mutated_payload, "suffix_crash")
                    break
                except (asyncio.TimeoutError, Exception):
                    pass

        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
            status = await self._classify_conn_refused(
                mutated_payload,
                "sequence, connection refused/reset",
                extra={"target_idx": target.target_index},
            )

        except asyncio.TimeoutError:
            status = PacketStatus.TIMEOUT

        except OSError as exc:
            log.warning(
                "Sequence send error",
                extra={"context": {"err": str(exc)[:80]}},
            )
            status = PacketStatus.TIMEOUT

        finally:
            # Step E: Close — always, even on error
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            # Task B: log the full response chain — [greeting, *prefix, target].
            # Reveals whether auth (e.g. FTP 230) completes BEFORE the mutated
            # target, i.e. whether the target is fuzzed post-auth. Diagnoses the
            # "stuck at 220" class of bugs; sample-logged to avoid spam.
            if self._seq_log_counter % 50 == 0:  # log ~2% of sequences
                log.info(
                    f"SEQ {target.sequence_id[:8]} chain={chain} "
                    f"target_idx={target.target_index} status={status.value}"
                )
            self._seq_log_counter += 1

        # Backward compat — crash_monitor reads this (only mutated target)
        self._last_injected_packet = mutated_payload
        # H3 fix: append to crash attribution window. PHASE 2: include the
        # session PREFIX so confirm_crashes can replay prefix+target (a target
        # alone won't reproduce a stateful crash — needs USER+PASS auth first).
        if not self._window_frozen:
            self._crash_window.append((
                time.monotonic(), mutated_payload,
                self._last_injected_rule_id, list(target.prefix),
            ))

        if self.status_callback:
            self.status_callback(target.sequence_id, status)

        return status

    # -------------------------------------------------------------------
    # Dumb Fallback
    # -------------------------------------------------------------------

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

    # -------------------------------------------------------------------
    # Stats & EPS Tracking
    # -------------------------------------------------------------------

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
                    "k":        self._stats.k_this_round,
                    "sent":     self._stats.total_sent,
                    "crashes":  self._stats.total_crashes,
                    "rejected": self._stats.total_rejected,
                    "rules_v":  self._stats.rule_set_version,
                    "fields":   self._stats.active_fields,
                    "ewma_k":   self._current_k,
                    "recv_rate": f"{self._recv_count / max(1, self._stats.total_sent):.1%}",
                }},
            )

            # Write rule response stats to shared file for LLM feedback
            self._write_rule_response_stats()


# ===========================================================================
# P3-B: Kill Payload Dispatch
# ===========================================================================

async def send_kill_payloads(engine: MutationEngine) -> list[dict]:
    """Send all KILL_SERVER_PAYLOADS with proper attribution.

    P3-B: Each kill payload is sent with a named rule_id and
    does NOT trigger investigation mode. Returns a list of
    result dicts with payload name and status.

    This function should be called by the orchestrator or test harness,
    NOT from the hot loop.
    """
    results: list[dict] = []
    for idx, payload in enumerate(KILL_SERVER_PAYLOADS):
        name = _KILL_PAYLOAD_NAMES[idx] if idx < len(_KILL_PAYLOAD_NAMES) else f"kill_{idx}"
        rule_id = f"kill_payload:{name}"

        # Set attribution before send
        engine._last_injected_rule_id = rule_id
        engine._last_injected_packet = payload

        status = await engine._send(payload, f"kill_{idx}")
        crash_type = f"kill_payload:{name}" if status == PacketStatus.CRASH else None

        if status == PacketStatus.CRASH:
            log.critical(
                f"Kill payload confirmed crash: {name}",
                extra={"context": {
                    "payload_name": name,
                    "rule_id": rule_id,
                }},
            )
            # Fire crash callback with proper attribution
            if engine.crash_callback:
                engine.crash_callback(payload, crash_type or "kill_payload")

        results.append({
            "name": name,
            "rule_id": rule_id,
            "status": status.value,
            "crash": status == PacketStatus.CRASH,
        })

    return results


# ===========================================================================
# Field Mutation — Pure Functions (no side effects, easily unit-tested)
# P3-C: Integrated with mutation_operators.py for sophisticated mutations
# ===========================================================================


def _endian_for_type(field_type: FieldType) -> str:
    """Return ``"little"`` or ``"big"`` byte order for a FieldType.

    Any FieldType whose value contains ``"_le"`` is little-endian;
    everything else defaults to big-endian.
    """
    if "_le" in field_type.value:
        return "little"
    return "big"


def _recompute_length_fields(buf: bytearray, fields: list) -> bytearray:
    """Recompute length field(s) so the packet stays length-consistent after a
    payload grew or shrank.

    A length-delimited server computes the copy size as ``min(declared_len,
    actual_bytes)``. If a mutation grows the actual payload but leaves the
    declared length field at its old (small) value, the server clamps to the
    old value and the overflow is masked — the fuzzer would only ever crash by
    accident (e.g. an A-flood overwriting the length bytes). Recomputing the
    length field to the current payload size makes the grown packet VALID, so
    the server trusts the declared length and reaches the vulnerable copy.

    Length fields are identified STRUCTURALLY, not by LLM semantic label, so
    this works for any length-delimited protocol and does not depend on the
    LLM happenning to name a field "length":
      - primary: a field marked ``calculation_source == "payload"`` (the math
        analyzer sets this on the length field it detects);
      - fallback: a numeric (uint*) field that immediately precedes the
        variable-length payload (``offset + length == payload_offset``).

    Args:
        buf:    the mutated packet buffer (may have grown/shrunk).
        fields: the field rules (mutable + static) for the active grammar.

    Returns:
        The same ``buf`` with length field(s) rewritten to the current
        payload byte count.
    """
    if not fields:
        return buf

    # The payload field is the variable-length tail (length == -1), or — if
    # none is marked variable — the highest-offset field (the trailing region).
    payload_field = None
    for f in fields:
        if getattr(f, "length", 0) == -1:
            payload_field = f
            break
    if payload_field is None:
        payload_field = max(fields, key=lambda f: getattr(f, "offset", 0))
    payload_start = getattr(payload_field, "offset", 0)
    if payload_start >= len(buf):
        return buf  # payload starts past the buffer — nothing to recompute

    # Identify length field(s) to recompute. Two strategies:
    #   (a) declared: a field marked calculation_source == "payload" (the math
    #       analyzer sets this); OR
    #   (b) structural fallback: the numeric (uint*) field with the largest
    #       offset that still precedes the payload — i.e. the closest numeric
    #       field before the payload. This tolerates static padding/reserved
    #       fields sitting between the length field and the payload (a common
    #       LLM-grammar artifact), so recompute still fires when the grammar is
    #       not perfectly tight. It does NOT key off any protocol-specific
    #       offset or label.
    length_targets: list = []
    declared = [
        f for f in fields
        if getattr(f, "calculation_source", None) == "payload"
        and getattr(f, "length", 0) > 0
        and getattr(f, "offset", 0) < payload_start
    ]
    if declared:
        length_targets = declared
    else:
        numeric_before = [
            f for f in fields
            if getattr(f, "length", 0) > 0
            and getattr(f, "offset", 0) < payload_start
            and getattr(f, "data_type", None) is not None
            and "uint" in getattr(f.data_type, "value", "")
        ]
        if numeric_before:
            # closest numeric field before the payload (max offset)
            length_targets = [
                max(numeric_before, key=lambda f: getattr(f, "offset", 0))
            ]

    for f in length_targets:
        flen = getattr(f, "length", 0)
        foff = getattr(f, "offset", 0)
        data_type = getattr(f, "data_type", None)
        start = foff
        end = foff + flen
        if end > len(buf):
            continue
        payload_len = max(0, len(buf) - payload_start)
        field_type = data_type or FieldType.UINT16_LE
        byte_order = _endian_for_type(field_type)
        try:
            buf[start:end] = payload_len.to_bytes(flen, byte_order)
        except (OverflowError, ValueError):
            pass  # payload too large for the length field width — leave as-is
    return buf


def _apply_field(
    buf: bytearray,
    rule: FieldRule,
    preserve_length: bool = False,
) -> bytearray:
    """
    Apply a single FieldRule to a mutable bytearray.

    All mutation logic lives here, outside the MutationEngine class,
    so it can be unit-tested without any async machinery.

    P3-C: Dispatches to mutation_operators.py for BOUNDARY_VALUES,
    RANDOM_BYTES, BIT_FLIP, FORMAT_STRING, and TRUNCATE strategies.
    Falls back to inline logic for DICTIONARY, CALCULATED, INCREMENT,
    STATIC, and SKIP.

    Bugfix (preserve_length): When multiple fields are mutated in one
    packet (k > 1), an operator that inserts or deletes bytes shifts
    all subsequent field offsets — silently corrupting the packet.
    When preserve_length=True, all mutations are constrained to be
    in-place (same buffer length before and after).

    Args:
        buf:             Mutable bytearray representing the full packet payload.
        rule:            The FieldRule describing how to mutate one field.
        preserve_length: If True, only use length-preserving mutations.
                         Set True when k > 1 fields are mutated per packet.

    Returns:
        The same bytearray (modified in-place and returned for chaining).
    """
    start = rule.offset
    if start >= len(buf):
        return buf

    length     = rule.length if rule.length != -1 else len(buf) - start
    end        = min(start + length, len(buf))
    actual_len = end - start
    if actual_len <= 0:
        return buf

    s = rule.mutation_strategy
    constraints = MutationConstraints()  # default: no constraints
    # Type-aware dispatch: use explicit data_type from rule if available,
    # otherwise infer from byte length (defaults to big-endian).
    field_type = rule.data_type if rule.data_type else _infer_field_type(actual_len)

    if s == MutationStrategy.STATIC:
        if rule.static_value:
            try:
                src = bytes.fromhex(rule.static_value)
                n   = min(len(src), actual_len)
                buf[start:start + n] = src[:n]
            except ValueError:
                pass

    elif s == MutationStrategy.BOUNDARY_VALUES:
        # P3-C: dispatch to operators — 70% integer overflow, 30% boundary violation
        # Both operators are length-preserving (replace in-place).
        if random.random() < 0.7:
            buf = op_integer_overflow(buf, start, end, field_type, constraints)
        else:
            buf = op_boundary_violation(buf, start, end, field_type, constraints)

    elif s == MutationStrategy.RANDOM_BYTES:
        if preserve_length:
            # Multi-field safe: pure in-place replace, zero length change.
            buf[start:end] = os.urandom(actual_len)
        else:
            # Single-field: full operator with inject/overflow modes.
            if random.random() < 0.7 or rule.length != -1:
                buf = op_random_byte_injection(buf, start, end, field_type, constraints)
            else:
                # Buffer overflow only for variable-length fields
                if len(buf) <= 65536:
                    buf = op_buffer_overflow(buf, start, end, field_type, constraints)
                else:
                    buf[start:end] = os.urandom(actual_len)

    elif s == MutationStrategy.PAYLOAD_EXTEND:
        # Grow a variable-length payload field with extra bytes (overflow
        # class). Only the single-field path (preserve_length=False) actually
        # grows — growing inside a multi-field mutation would corrupt the
        # offsets of subsequent fields. In multi-field mode we fall back to an
        # in-place rewrite so the field is still exercised this round; the
        # dedicated size-escalation path in _build_mutant guarantees that
        # single-field growth happens periodically.
        if preserve_length:
            buf[start:end] = os.urandom(actual_len)
        else:
            if len(buf) <= 65536:
                buf = op_buffer_overflow(buf, start, end, field_type, constraints)
            else:
                buf = op_random_byte_injection(buf, start, end, field_type, constraints)

    elif s == MutationStrategy.BIT_FLIP:
        # Always length-preserving — safe for multi-field.
        buf = op_bit_flip(buf, start, end, field_type, constraints)

    elif s == MutationStrategy.FORMAT_STRING:
        if preserve_length:
            # Multi-field safe: truncate/truncate payload to fit field exactly.
            payload = random.choice(_FORMAT_STRING_PAYLOADS_SLICE)
            payload = payload[:actual_len]
            # Pad if shorter
            if len(payload) < actual_len:
                payload = payload + b"\x00" * (actual_len - len(payload))
            buf[start:start + actual_len] = payload
        else:
            buf = op_format_string(buf, start, end, field_type, constraints)

    elif s == MutationStrategy.TRUNCATE:
        if preserve_length:
            # Multi-field safe: can't truncate — use random bytes instead
            # to still mutate the field without destroying subsequent fields.
            buf[start:end] = os.urandom(actual_len)
        else:
            buf = op_omission(buf, start, end, field_type, constraints)

    elif s == MutationStrategy.INCREMENT:
        byte_order = _endian_for_type(field_type)
        current = int.from_bytes(buf[start:end], byte_order)
        max_val = (1 << (actual_len * 8)) - 1
        new_val = (current + 1) & max_val
        buf[start:end] = new_val.to_bytes(actual_len, byte_order)

    elif s == MutationStrategy.CALCULATED:
        payload_start = start + actual_len
        payload_len   = max(0, len(buf) - payload_start)
        byte_order = _endian_for_type(field_type)
        try:
            buf[start:end] = payload_len.to_bytes(actual_len, byte_order)
        except OverflowError:
            pass

    elif s == MutationStrategy.DICTIONARY:
        if rule.dictionary_values:
            try:
                hex_val = random.choice(rule.dictionary_values)
                src = bytes.fromhex(hex_val)
                # H2 fix: when preserve_length=True (multi-field mode),
                # pad or truncate to exactly actual_len so buffer length
                # doesn't change and subsequent field offsets stay valid.
                if preserve_length:
                    if len(src) < actual_len:
                        src = src + b"\x00" * (actual_len - len(src))
                    else:
                        src = src[:actual_len]
                else:
                    src = src[:actual_len]
                buf[start:start + len(src)] = src
            except (ValueError, IndexError):
                pass

    elif s == MutationStrategy.SKIP:
        pass

    # Post-mutation: null-terminate STRING fields.
    # Applied only when:
    #   1. field_type is STRING and field has room (actual_len > 1)
    #   2. Strategy produces string-like output (not numeric strategies
    #      like INCREMENT/CALCULATED — nulling would corrupt the integer)
    #   3. Buffer wasn't resized (preserve_length=True or in-place strategy)
    #   4. Null position is still within bounds (guards TRUNCATE shrinking buf)
    _STRING_SAFE_STRATEGIES = {
        MutationStrategy.RANDOM_BYTES,
        MutationStrategy.STATIC,
        MutationStrategy.BIT_FLIP,
        MutationStrategy.FORMAT_STRING,
        MutationStrategy.DICTIONARY,
    }
    if (
        field_type == FieldType.STRING
        and s in _STRING_SAFE_STRATEGIES
        and preserve_length  # buffer wasn't resized
        and actual_len > 1
        and start + actual_len - 1 < len(buf)  # bounds guard
    ):
        buf[start + actual_len - 1] = 0x00

    return buf


def _infer_field_type(byte_len: int) -> FieldType:
    """Infer FieldType from byte length for operator dispatch."""
    _LEN_TO_TYPE: dict[int, FieldType] = {
        1: FieldType.UINT8,
        2: FieldType.UINT16_BE,
        4: FieldType.UINT32_BE,
    }
    return _LEN_TO_TYPE.get(byte_len, FieldType.BYTES)


# Pre-sliced format-string payloads for preserve_length mode
# (avoids importing the full list from mutation_operators each call)
_FORMAT_STRING_PAYLOADS_SLICE: list[bytes] = [
    b"%s%s%s%s%n",
    b"%x%x%x%x%x",
    b"%p%p%p%p",
    b"%n%d%s%p",
    b"%s" * 50,
    b"AAAA%p%p%p%p%p%p%p%p%p%p",
    b"%08x.%08x.%08x.%08x",
    b"%%%dc%%%d$s%%%d$n",
    b"%n" * 20,
]
