"""
slow_loop/rules_orchestrator.py
─────────────────────────────────
Rules Orchestrator — manages the Slow Loop inference pipeline with
intelligent packet selection, deduplication, and token budget enforcement.

Sits between the daemon loop and the individual components:
    TrafficParser → RulesOrchestrator → LLMAgent → RuleGenerator

Responsibilities:
    - De-duplicate packets before sending to the LLM (avoid redundant tokens).
    - Implement a sliding window to only send the last N diverse packets.
    - Estimate and enforce token budgets per inference cycle.
    - Wrap the Parser → LLM → RuleGen pipeline with graceful error handling.
    - Surface errors to the Dashboard via the shared inference log.

De-duplication Strategy:
    Each packet gets a "signature" based on:
      - First N bytes (prefix) — identifies the protocol message type
      - Total packet length — differentiates same-type packets of different sizes
    Packets with identical signatures are de-duplicated; only the most recent
    representative is kept. This prevents sending 100 nearly-identical heartbeat
    packets while preserving genuinely diverse traffic.

Sliding Window:
    The orchestrator maintains a buffer of the last ``window_size`` unique
    packets. When a new inference cycle runs, it selects up to
    ``max_packets_per_inference`` diverse packets from this buffer.
    The selection favors diversity: it picks representatives from each
    signature group in round-robin order.

Token Budget:
    The orchestrator estimates the token cost of the LLM prompt before
    sending. If the estimate exceeds the remaining budget, the inference
    is skipped and a warning is logged. This prevents runaway API costs.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from typing import Any, Optional

from shared.logger import get_logger
from shared.runtime_state import read_runtime_state
from shared.schemas import FieldRule, MutationStrategy, ProtocolGrammar, RuleType, SemanticRule
from slow_loop.llm_agent import LLMAgent, estimate_tokens
from slow_loop.parser import InteractionSession, TrafficParser
from slow_loop.rule_generator import RuleGenerator
from slow_loop.differential_analyzer import (
    DifferentialAnalyzer,
    HeatmapResult,
    generate_text_heatmap,
)
from slow_loop.ewma_controller import EWMAController

logger = get_logger("slow_loop.rules_orchestrator")


# =============================================================================
# Packet Signature & Dedup
# =============================================================================


def packet_signature(
    packet_hex: str, prefix_bytes: int = 4
) -> str:
    """Create a dedup signature from a packet's hex payload.

    The signature is ``<first-N-bytes-hex>:<total-length>:<content-hash>``.
    The content hash is a lightweight fingerprint of the *middle* portion
    of the packet (after the prefix, before the last 4 bytes). This makes
    dedup less aggressive for text protocols like HTTP where many packets
    share the same method prefix (``GET ``, ``POST``) but have different
    content (paths, headers, query parameters).

    For binary protocols, the content hash still provides good dedup because
    structurally identical messages will produce the same hash.

    Examples:
        >>> packet_signature("deadbeef00050041", prefix_bytes=4)
        'deadbeef:8:deadbeef'  # short packets use full content

    Args:
        packet_hex:   Hex-encoded packet payload.
        prefix_bytes: Number of leading bytes to include in the signature.

    Returns:
        A string signature like ``"deadbeef:8:a3f2c1"``.
    """
    prefix = packet_hex[: prefix_bytes * 2]
    length = len(packet_hex) // 2

    # Content fingerprint: hash the middle portion of the packet.
    # This distinguishes packets with same prefix+length but different
    # content (e.g., "GET /path1" vs "GET /path2" in HTTP traffic).
    # Use a simple rolling XOR over 8-byte chunks — fast, no imports needed.
    body_start = prefix_bytes * 2
    body_end = max(body_start, len(packet_hex) - 8)  # exclude last 4 bytes
    body = packet_hex[body_start:body_end]

    if len(body) >= 8:
        fingerprint = 0
        for i in range(0, len(body) - 7, 8):
            chunk = body[i:i + 8]
            # XOR-fold 8 hex chars into a 32-bit value
            fingerprint ^= int(chunk, 16) if len(chunk) == 8 else int(chunk, 16)
        content_hash = f"{fingerprint:08x}"[-6:]  # last 6 hex digits
    else:
        # Short body — use full packet hex as content_hash to avoid
        # empty-string collisions that over-deduplicate short packets
        # (e.g., ACKs, status bytes, single-byte protocol messages).
        content_hash = packet_hex if not body else body

    return f"{prefix}:{length}:{content_hash}"


# =============================================================================
# Sliding Window Buffer
# =============================================================================


class SlidingWindow:
    """A fixed-capacity buffer that de-duplicates packets by signature.

    Uses an OrderedDict as an LRU-like structure: when a duplicate arrives,
    it moves to the end (most recent). When the buffer exceeds capacity,
    the oldest entry is evicted.

    Args:
        max_entries: Maximum number of unique packets to keep.
        prefix_bytes: Bytes used for dedup signature.
    """

    def __init__(
        self, max_entries: int = 200, prefix_bytes: int = 4
    ) -> None:
        self.max_entries = max_entries
        self.prefix_bytes = prefix_bytes
        # OrderedDict preserves insertion order; we use it as LRU
        self._buffer: OrderedDict[str, dict[str, Any]] = OrderedDict()
        # Incremental inference: tracks which packet signatures have been
        # sent to the LLM.  Prevents re-sending the same packets across
        # cycles, reducing token consumption from O(N) to O(ΔN).
        self._inferred_sigs: set[str] = set()

    def add(self, packet: dict[str, Any]) -> bool:
        """Add a packet to the buffer. Returns True if it was new.

        Args:
            packet: A parsed packet dict with at least a 'payload' key.

        Returns:
            True if the packet was previously unseen, False if duplicate.
        """
        hex_data = packet.get("payload", "")
        sig = packet_signature(hex_data, self.prefix_bytes)

        is_new = sig not in self._buffer

        # Move to end (most recently seen)
        if sig in self._buffer:
            self._buffer.move_to_end(sig)
        self._buffer[sig] = packet

        # Evict oldest if over capacity; also prune their inferred status
        while len(self._buffer) > self.max_entries:
            evicted_sig, _ = self._buffer.popitem(last=False)
            self._inferred_sigs.discard(evicted_sig)

        return is_new

    def add_all(self, packets: list[dict[str, Any]]) -> int:
        """Add multiple packets. Returns count of new (non-duplicate) packets.

        Args:
            packets: List of parsed packet dicts.

        Returns:
            Number of packets that were not duplicates.
        """
        new_count = 0
        for pkt in packets:
            if self.add(pkt):
                new_count += 1
        return new_count

    def get_diverse_sample(self, n: int) -> list[dict[str, Any]]:
        """Select up to N diverse packets from the buffer.

        Diversity strategy:
        1. Group packets by their prefix (first N bytes).
        2. Pick representatives from each group in round-robin order.
        3. This ensures we get variety across message types, not just
           the most recent packets.

        Args:
            n: Maximum number of packets to return.

        Returns:
            List of up to N diverse packet dicts.
        """
        if len(self._buffer) <= n:
            return list(self._buffer.values())

        # Group by prefix (message type)
        groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        for sig, pkt in self._buffer.items():
            prefix = sig.split(":")[0]
            if prefix not in groups:
                groups[prefix] = []
            groups[prefix].append(pkt)

        # Round-robin pick from each group
        result: list[dict[str, Any]] = []
        group_keys = list(groups.keys())

        while len(result) < n and group_keys:
            exhausted: list[str] = []
            for key in group_keys:
                if groups[key]:
                    result.append(groups[key].pop(0))
                if not groups[key]:
                    exhausted.append(key)
                if len(result) >= n:
                    break
            for key in exhausted:
                if key in group_keys:
                    group_keys.remove(key)
            if not group_keys:
                break

        return result[:n]

    # -----------------------------------------------------------------
    # Incremental Inference: Unseen Packet Tracking
    # -----------------------------------------------------------------

    def mark_inferred(self, sigs: set[str]) -> None:
        """Mark packet signatures as having been sent to the LLM.

        Called by RulesOrchestrator after a successful LLM inference.
        Future ``get_unseen_samples()`` calls will skip these signatures,
        ensuring the LLM only receives genuinely new traffic data.

        Args:
            sigs: Set of packet signatures that were included in the
                  LLM prompt for this cycle.
        """
        self._inferred_sigs.update(sigs)

    def get_unseen_samples(self, n: int) -> list[dict[str, Any]]:
        """Select up to N diverse packets NOT yet sent to the LLM.

        Uses the same round-robin diversity strategy as
        ``get_diverse_sample()``, but restricted to the subset of the
        buffer whose signatures are not in ``_inferred_sigs``.

        This is the core of the incremental inference optimisation:
        instead of re-sending the full window every cycle, only truly
        new packets are forwarded to the LLM.

        Args:
            n: Maximum number of unseen packets to return.

        Returns:
            List of up to N diverse unseen packet dicts.
        """
        # Filter buffer to only unseen entries
        unseen: OrderedDict[str, dict[str, Any]] = OrderedDict(
            (sig, pkt)
            for sig, pkt in self._buffer.items()
            if sig not in self._inferred_sigs
        )

        if len(unseen) <= n:
            return list(unseen.values())

        # Same round-robin diversity selection, restricted to unseen
        groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        for sig, pkt in unseen.items():
            prefix = sig.split(":")[0]
            if prefix not in groups:
                groups[prefix] = []
            groups[prefix].append(pkt)

        result: list[dict[str, Any]] = []
        group_keys = list(groups.keys())

        while len(result) < n and group_keys:
            exhausted: list[str] = []
            for key in group_keys:
                if groups[key]:
                    result.append(groups[key].pop(0))
                if not groups[key]:
                    exhausted.append(key)
                if len(result) >= n:
                    break
            for key in exhausted:
                if key in group_keys:
                    group_keys.remove(key)
            if not group_keys:
                break

        return result[:n]

    @property
    def unseen_count(self) -> int:
        """Number of packets in the window that have NOT been sent to the LLM."""
        return sum(1 for sig in self._buffer if sig not in self._inferred_sigs)

    def reset_inferred(self) -> None:
        """Clear all inferred markers — forces a full re-inference on next cycle.

        Called when ``re_infer_interval_s`` triggers a scheduled full
        re-analysis of the entire sliding window.
        """
        self._inferred_sigs.clear()

    @property
    def size(self) -> int:
        """Current number of unique packets in the buffer."""
        return len(self._buffer)

    @property
    def unique_prefixes(self) -> int:
        """Number of distinct message types (by prefix) in the buffer."""
        return len({sig.split(":")[0] for sig in self._buffer})


# =============================================================================
# Rules Orchestrator
# =============================================================================


class RulesOrchestrator:
    """Orchestrates the Slow Loop pipeline with dedup and budget management.

    Wraps: TrafficParser → (dedup) → LLMAgent → RuleGenerator

    Args:
        parser:                  TrafficParser instance for reading traffic log.
        agent:                   LLMAgent instance for LLM inference.
        rule_gen:                RuleGenerator for converting grammar to rules.
        max_packets_per_inference: Max packets to send per LLM call.
        window_size:             Sliding window capacity (unique packets to track).
        max_prompt_tokens:       Maximum estimated tokens per LLM prompt.
                                   0 = unlimited (no budget enforcement).
        min_packets_before_infer: Minimum new unique packets before invoking LLM.
    """

    def __init__(
        self,
        parser: TrafficParser,
        agent: LLMAgent,
        rule_gen: RuleGenerator,
        max_packets_per_inference: int = 20,
        window_size: int = 200,
        max_prompt_tokens: int = 0,
        min_packets_before_infer: int = 2,
        crash_manager: Any = None,
        ab_mode: str = "llm",
        ewma_controller: Optional[EWMAController] = None,
        re_infer_interval_s: float = 600.0,
        force_inference_time_s: float = 600.0,
        force_inference_mutations: int = 20000,
    ) -> None:
        self.parser = parser
        self.agent = agent
        self.rule_gen = rule_gen
        self.max_packets_per_inference = max_packets_per_inference
        self.max_prompt_tokens = max_prompt_tokens
        self.min_packets_before_infer = min_packets_before_infer
        self.crash_manager = crash_manager
        self.ab_mode: str = ab_mode

        # EWMA Adaptive Controller — coordinates Fast Loop recv() sampling
        self._ewma: Optional[EWMAController] = ewma_controller
        self._ewma_epoch_start: float = time.monotonic()

        # Time-based re-inference: force a new inference cycle even when
        # no new unique packets arrive, as long as enough time has passed.
        # Set HIGH (default 600s) because the grammar is stable after 1-2
        # inferences. Frequent re-inference wastes tokens and blocks the
        # fuzzing pipeline (~40s per LLM call).
        self._re_infer_interval_s: float = re_infer_interval_s
        self._last_inference_time: float = time.monotonic()

        # Phase 3 / TASK 4: force-inference cadence. Even when the packet-based
        # trigger starves (few new unique packets), force an LLM inference when
        # EITHER enough time has passed OR enough mutations have run. This broke
        # the 14-inferences/4h starvation seen in the 8h campaign. The mutation
        # count is read cross-process from shared/runtime_state.json (the Fast
        # Loop writes it; the Slow Loop is a separate process and cannot import
        # the live MutationEngine).
        self._force_inference_time_s: float = force_inference_time_s
        self._force_inference_mutations: int = force_inference_mutations
        self._mutations_at_last_inference: int = self._read_total_mutations()

        # Sliding window for dedup
        self._window = SlidingWindow(max_entries=window_size)

        # Differential analysis (mathematical pre-processing)
        self._analyzer = DifferentialAnalyzer()
        self._last_heatmap: Optional[HeatmapResult] = None

        # Crash isolation: when True, fuzzer uses k=1 (single-field) mode
        self._precision_mode: bool = False

        # Runtime stats
        self._total_cycles: int = 0
        self._total_inferences: int = 0
        self._total_rules_pushed: int = 0
        self._skipped_budget: int = 0
        self._skipped_insufficient_data: int = 0
        self._errors: int = 0
        self._bootstrap_count: int = 0
        self._last_error: str = ""
        self._last_cycle_time: float = 0.0

        # C3 fix: Guard to prevent bootstrap rules from overwriting
        # good LLM-generated rules on budget exhaustion or error fallback.
        self._llm_rules_active: bool = False

        # A/B mode tracking
        self._ab_cycle_counter: int = 0
        self._ab_results_log: list[dict] = []

        # Incremental inference: stores a condensed summary of the last
        # successful LLM grammar so the next cycle can UPDATE rather
        # than re-derive from scratch.  Set to None on first cycle or
        # after a forced full re-inference.
        self._previous_grammar_summary: Optional[dict[str, Any]] = None

    # -----------------------------------------------------------------
    # Main Pipeline
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # Phase 3 / TASK 4 — force-inference cadence helpers
    # -----------------------------------------------------------------

    def _read_total_mutations(self) -> int:
        """Read the Fast Loop's cumulative mutation count cross-process.

        The Slow Loop is a separate process, so it cannot import the live
        MutationEngine. It reads ``mutator.total_sent`` from
        ``shared/runtime_state.json`` (written by the Fast Loop). Returns 0
        on any failure (missing file, malformed JSON, schema drift) — fail
        safe so the time-based trigger still works.
        """
        try:
            state = read_runtime_state()
            if state is None:
                return 0
            mutator = getattr(state, "mutator", None)
            if mutator is None:
                return 0
            return int(getattr(mutator, "total_sent", 0)) or 0
        except Exception:
            return 0

    def _force_inference_due(self) -> bool:
        """Return True if a forced LLM inference is due (Phase 3 / TASK 4).

        Force when EITHER:
          * ``> force_inference_time_s`` seconds elapsed since the last
            inference, OR
          * ``> force_inference_mutations`` new mutations ran since the last
            inference.
        Independent of new-unique-packet count — breaks starvation.
        """
        time_since_last = time.monotonic() - self._last_inference_time
        if time_since_last > self._force_inference_time_s:
            return True
        mutations_since = (
            self._read_total_mutations() - self._mutations_at_last_inference
        )
        if mutations_since > self._force_inference_mutations:
            return True
        return False

    def _mark_inference_time(self) -> None:
        """Record that an inference attempt just completed (success or error).

        Resets both the time-based and mutation-based force-inference counters
        so neither re-arms until another threshold elapses.
        """
        self._last_inference_time = time.monotonic()
        self._mutations_at_last_inference = self._read_total_mutations()

    async def run_cycle(self) -> Optional[dict[str, Any]]:
        """Execute one inference cycle: read → dedup → math → LLM → rules.

        The Neural-Mathematical Fusion Loop:
            1. Read traffic and deduplicate packets (sliding window).
            2. Select diverse samples.
            3. Run DifferentialAnalyzer on raw client bytes → HeatmapResult.
            4. Inject heatmap hint into LLM prompt.
            5. If LLM fails, fall back to bootstrap rules from heatmap.
            6. Convert grammar → SemanticRules and push.
            7. Check crash_manager for precision mode.

        Returns:
            A dict with cycle results, or None if the cycle was skipped.
        """
        t0 = time.monotonic()
        self._total_cycles += 1

        # EWMA epoch timer: do NOT reset here.
        # _ewma_epoch_start tracks the time of the LAST SUCCESSFUL EWMA update.
        # Removing the reset fixes Baseline B (Math-Only) where fast cycles
        # (<5s) never triggered EWMA, leaving adaptive sampling stuck at K_max.
        # Skipped cycles naturally accumulate epoch time, which correctly
        # reduces the coverage rate (delta_C / wall_time) when no new
        # protocol structure is being discovered.

        try:
            # ── 1. Read traffic log ─────────────────────────────────
            sessions = await self.parser.read_log()
            # Phase 3 / TASK 4: do NOT bail when there are no new sessions if a
            # force-inference trigger is due — proceed using the buffered window
            # packets instead. Returning early here (before the time/mutation
            # triggers were ever checked) was the actual LLM-starvation cause.
            if not sessions and not self._force_inference_due():
                return None

            # Flatten all packets from all sessions
            all_packets: list[dict[str, Any]] = []
            for session in sessions:
                all_packets.extend(session.packets)

            # ── 2. Add to sliding window (dedup) ────────────────────
            new_count = self._window.add_all(all_packets)

            logger.info(
                f"Cycle #{self._total_cycles}: "
                f"{len(all_packets)} packets read, "
                f"{new_count} new unique, "
                f"window={self._window.size}, "
                f"types={self._window.unique_prefixes}"
            )

            # ── 3. Check minimum threshold ──────────────────────────
            time_since_last = time.monotonic() - self._last_inference_time
            re_infer_due = time_since_last >= self._re_infer_interval_s
            # Phase 3 / TASK 4: force trigger (time OR mutations) — independent
            # of new-unique-packet count, breaks LLM starvation.
            force_due = self._force_inference_due()

            if (
                new_count < self.min_packets_before_infer
                and not re_infer_due
                and not force_due
            ):
                self._skipped_insufficient_data += 1
                logger.debug(
                    f"Not enough new unique packets ({new_count} < "
                    f"{self.min_packets_before_infer}) — accumulating"
                )
                # NOTE: Do NOT call _update_ewma() here — no new metrics
                # are available on skipped cycles. Calling it would cause
                # lambda_c to decay proportionally to call frequency rather
                # than elapsed time (wrong drift toward sparse mode).
                return {
                    "status": "skipped",
                    "reason": (
                        f"Insufficient new unique packets: {new_count} < "
                        f"{self.min_packets_before_infer}"
                    ),
                    "packets_available": self._window.size,
                }

            # Forced re-inference trigger: even if new_count is below
            # threshold, force inference when the time/mutation timer fires.
            # This ensures the LLM keeps running on protocols with few message
            # types (Phase 3 / TASK 4: time-based OR mutation-based).
            if new_count < self.min_packets_before_infer and (re_infer_due or force_due):
                muts_since = max(
                    0, self._read_total_mutations() - self._mutations_at_last_inference
                )
                logger.info(
                    f"Forced re-inference triggered "
                    f"(time_since_last={time_since_last:.0f}s, "
                    f"new_unique={new_count}, "
                    f"mutations_since_last={muts_since}). "
                    f"Forcing cycle with {self._window.size} buffered packets."
                )

            # ── 4a. Select FULL diverse samples (for math analysis) ──
            # The DifferentialAnalyzer needs MANY samples for reliable
            # statistics (entropy, variance, Pearson). With only 20 packets,
            # byte-level variance is too noisy → 1 collapsed field group
            # → no PAYLOAD_EXTEND → no overflow discovery. Use 100 samples
            # for the math path; the LLM still gets max_packets_per_inference
            # (token-efficient) from full_selected below.
            _MATH_SAMPLE_SIZE = max(100, self.max_packets_per_inference * 5)
            full_selected = self._window.get_diverse_sample(
                _MATH_SAMPLE_SIZE
            )

            if not full_selected:
                return {
                    "status": "skipped",
                    "reason": "No diverse samples available",
                    "packets_available": 0,
                }

            # ── 4b. Select UNSEEN diverse samples (for LLM) ─────────
            # Incremental inference: only send new packets to the LLM,
            # along with a summary of the previous grammar so the LLM
            # can UPDATE rather than re-derive from scratch.
            # On scheduled re-inference, reset inferred markers so ALL
            # buffer packets become eligible again (periodic full sweep),
            # then use the full diverse sample.
            # Skip full re-inference if ALL packets have already been
            # sent to the LLM (grammar is stable — no new info to learn).
            if re_infer_due:
                if self._window.unseen_count == 0:
                    logger.debug(
                        f"  Re-inference skipped: no unseen packets "
                        f"(window={self._window.size})"
                    )
                    llm_selected = []
                else:
                    self._window.reset_inferred()
                    llm_selected = full_selected
            else:
                llm_selected = self._window.get_unseen_samples(
                    self.max_packets_per_inference
                )

            # ── 5. Differential Analysis (Math Layer) ───────────────
            # Math runs on the FULL diverse sample for accurate statistics,
            # even if only a subset (the unseen packets) goes to the LLM.
            math_hint: Optional[str] = None
            raw_packets = self._extract_raw_bytes(full_selected)
            if len(raw_packets) >= self._analyzer.min_packets:
                try:
                    heatmap = self._analyzer.analyze(raw_packets)
                    self._last_heatmap = heatmap
                    math_hint = heatmap.to_llm_hint()
                    logger.info(
                        f"  Differential analysis: {len(heatmap.field_groups)} "
                        f"field groups from {heatmap.packet_count} packets, "
                        f"depth={heatmap.analysis_depth}B"
                    )
                except ValueError:
                    # Not enough packets for analysis — proceed without hint
                    logger.debug("  Differential analysis skipped (insufficient data)")

            # ── 5b. Text Protocol Token-Level Analysis ────────────────
            # Runs alongside the byte-level analyzer. For text/line protocols,
            # the byte-level analyzer sees everything as HIGH_ENTROPY (worthless).
            # This token-frequency analysis identifies likely STATIC keywords
            # (commands, header-names) from MUTABLE data (paths, values).
            if raw_packets:
                try:
                    text_hint = generate_text_heatmap(raw_packets)
                    if text_hint:
                        if math_hint:
                            math_hint += "\n\n" + text_hint
                        else:
                            math_hint = text_hint
                        logger.info("  Text protocol analysis: token-level hint generated")
                except Exception:
                    logger.debug("  Text protocol analysis skipped")

            # ── 5a. State Machine Inference (Tầng 3 — Veritas-inspired) ──
            # Generic state machine from traffic: no hardcoded FTP. Produces
            # P-PSM → shared/state_machine.json → Fast Loop InferredStateTracker.
            # CRITICAL: feed BOTH directions (C2S + S2C). Server responses
            # (220, 331, 230) are the actual STATE messages — without them
            # the P-PSM only clusters client commands, missing real states.
            # raw_packets (C2S only) is for DifferentialAnalyzer; the P-PSM
            # needs its own all-direction packet list.
            try:
                from slow_loop.state_machine_inferer import StateMachineInferer
                import json as _json
                from pathlib import Path as _Path

                if not hasattr(self, "_state_inferer"):
                    self._state_inferer = StateMachineInferer(min_packets=10)
                # Extract REAL (non-mutated) packets for P-PSM inference.
                # Mutated packets have corrupted headers → wrong format messages
                # → garbage clustering → wrong state machine. State inference
                # must reflect REAL protocol behavior, not fuzzer's mutations.
                real_pkts = [p for p in full_selected
                             if p.get("payload", p.get("raw_hex", ""))
                             and not p.get("is_mutated", False)]
                all_packets = [
                    bytes.fromhex(p.get("payload", p.get("raw_hex", "")))
                    for p in real_pkts
                ]
                if len(all_packets) >= self._state_inferer.min_packets:
                    # Build sessions from REAL packets only (group by session_id).
                    from collections import defaultdict as _dd
                    sess_map: dict = _dd(list)
                    for p in real_pkts:
                        ph = p.get("payload", p.get("raw_hex", ""))
                        sid = p.get("session_id", "")
                        sess_map[sid].append(bytes.fromhex(ph))
                    sessions = list(sess_map.values())
                    psm = self._state_inferer.infer(all_packets, sessions)
                    if psm.n_states >= 2:
                        sm_path = _Path("shared/state_machine.json")
                        sm_path.write_text(_json.dumps(psm.to_dict()))
                        logger.info(
                            f"  State machine inference: {psm.n_states} states, "
                            f"{len(psm.transitions)} transitions → {sm_path}"
                        )
                        state_hint = psm.to_hint()
                        if state_hint and math_hint:
                            math_hint += "\n\n" + state_hint
                        elif state_hint:
                            math_hint = state_hint
            except Exception as e:
                logger.debug(f"  State machine inference skipped: {e}")

            # ── 5b. Skip LLM if no unseen packets ───────────────────
            # Incremental optimisation: if all diverse samples have already
            # been sent to the LLM, there is nothing new to learn.
            # Still update EWMA with the latest math analysis.
            if not llm_selected and not re_infer_due:
                self._update_ewma()
                return {
                    "status": "skipped",
                    "reason": (
                        f"No unseen packets for incremental inference "
                        f"(window={self._window.size}, "
                        f"unseen={self._window.unseen_count})"
                    ),
                    "packets_available": self._window.size,
                    "unseen": self._window.unseen_count,
                }

            # ── 6. Build LLM payload (from unseen samples) ──────────
            fake_session = InteractionSession(session_id=0)
            for pkt in llm_selected:
                fake_session.add_packet(pkt)

            payload = self.parser.format_for_llm([fake_session])

            # ── 7. Token budget check ───────────────────────────────
            payload_str = json.dumps(payload, ensure_ascii=False)
            estimated_tokens = estimate_tokens(payload_str)
            # Also count tokens from injected prompt components that the
            # LLM agent will add (math_hint, previous_grammar, response_feedback).
            if math_hint:
                estimated_tokens += estimate_tokens(math_hint)
            if self._previous_grammar_summary:
                estimated_tokens += estimate_tokens(
                    json.dumps(self._previous_grammar_summary, ensure_ascii=False)
                )
            # Build response feedback early so we can count its tokens.
            response_feedback = self._build_response_feedback()
            if response_feedback:
                estimated_tokens += estimate_tokens(response_feedback)

            if self.max_prompt_tokens > 0 and estimated_tokens > self.max_prompt_tokens:
                self._skipped_budget += 1
                msg = (
                    f"Estimated tokens ({estimated_tokens}) exceeds budget "
                    f"({self.max_prompt_tokens}). Skipping inference."
                )
                logger.warning(msg)
                self._last_error = msg

                # Budget exhausted → push bootstrap rules ONLY if no LLM
                # rules have been pushed yet (C3 fix: don't overwrite good
                # LLM rules with stale heatmap bootstrap rules).
                if self._last_heatmap and not self._llm_rules_active:
                    await self._push_bootstrap(
                        "  Budget exhausted — pushed {n} bootstrap rules "
                        "from heatmap"
                    )
                elif self._llm_rules_active:
                    logger.debug(
                        "  Budget exhausted but LLM rules already active — "
                        "skipping bootstrap overwrite"
                    )

                # Update EWMA even on budget skip to prevent epoch accumulation
                # that would cause a mode shock when budget is restored.
                self._update_ewma()

                return {
                    "status": "skipped",
                    "reason": msg,
                    "packets_available": self._window.size,
                }

            # ── 8. A/B mode decision ────────────────────────────────
            use_llm = True
            if self.ab_mode == "random":
                use_llm = False
            elif self.ab_mode == "alternating":
                use_llm = (self._ab_cycle_counter % 2 == 0)
            self._ab_cycle_counter += 1

            # H6 fix: A/B "random" mode must NEVER call the LLM.
            # When use_llm=False and no heatmap exists yet, return early
            # instead of falling through to the LLM call.
            if not use_llm:
                if self._last_heatmap:
                    bootstrap = self._convert_field_rules(
                        self._last_heatmap.to_field_rules()
                    )
                    if bootstrap:
                        await self.rule_gen.push_rules(
                            bootstrap,
                            overall_confidence=0.6,
                            protocol_name="bootstrap",
                        )
                        self._total_rules_pushed += len(bootstrap)
                        self._bootstrap_count += 1
                    elapsed = time.monotonic() - t0
                    self._last_cycle_time = elapsed
                    self._ab_results_log.append({
                        "cycle": self._total_cycles,
                        "mode": "heatmap",
                        "ab_mode_setting": self.ab_mode,
                    })
                    logger.info(
                        f"Cycle #{self._total_cycles}: A/B mode={self.ab_mode}, "
                        f"use_llm=False → {len(bootstrap)} heatmap rules pushed"
                    )
                    return {
                        "status": "bootstrap",
                        "reason": f"A/B mode: {self.ab_mode} (use_llm=False)",
                        "rules": bootstrap,
                        "heatmap_groups": len(self._last_heatmap.field_groups),
                        "packets_available": self._window.size,
                    }
                else:
                    # No heatmap yet — can't produce rules, but must NOT
                    # fall through to LLM in "random" A/B mode.
                    logger.debug(
                        f"Cycle #{self._total_cycles}: A/B mode={self.ab_mode}, "
                        f"use_llm=False but no heatmap yet — waiting"
                    )
                    return {
                        "status": "skipped_no_heatmap",
                        "reason": f"A/B mode: {self.ab_mode}, no heatmap available",
                        "packets_available": self._window.size,
                    }

            # ── 9. Crash isolation check (before LLM call) ──────────
            # Must run regardless of LLM success/failure — crashes occur
            # independently of grammar inference.
            if self.crash_manager:
                await self._check_crash_isolation()

            # ── 10. Call LLM with math hint + response feedback ──────
            # response_feedback was already built at step 7 for token budget.
            try:
                grammar = await self.agent.infer_protocol(
                    payload,
                    math_hint=math_hint,
                    previous_grammar_summary=self._previous_grammar_summary,
                    response_feedback=response_feedback,
                )
                self._total_inferences += 1
                self._mark_inference_time()  # Reset timer
            except (RuntimeError, ValueError) as llm_err:
                # LLM failed → fall back to bootstrap rules from heatmap
                self._errors += 1
                self._last_error = str(llm_err)
                # BUG 4 fix: reset inference timer so re_infer_due won't
                # fire again immediately, causing an infinite full-buffer
                # retransmit loop during LLM outages.
                self._mark_inference_time()
                # BUG 3 fix: allow bootstrap fallback to activate again
                # on next cycle so the fuzzer can recover from stale rules.
                self._llm_rules_active = False
                logger.warning(
                    f"  LLM inference failed: {llm_err}"
                )

                if self._last_heatmap and not self._llm_rules_active:
                    bootstrap = await self._push_bootstrap(
                        "  BOOTSTRAP FALLBACK: pushed {n} rules from "
                        "DifferentialAnalyzer (LLM was unavailable)",
                        level="warning",
                    )
                    if bootstrap:
                        elapsed = time.monotonic() - t0
                        self._last_cycle_time = elapsed
                        return {
                            "status": "bootstrap",
                            "reason": f"LLM failed: {llm_err}",
                            "rules": bootstrap,
                            "heatmap_groups": len(
                                self._last_heatmap.field_groups
                            ),
                            "packets_available": self._window.size,
                        }
                elif self._llm_rules_active:
                    logger.debug(
                        "  LLM failed but existing rules still active — "
                        "skipping bootstrap overwrite"
                    )

                raise  # Re-raise if no heatmap available

            # ── 9. Generate and push rules ──────────────────────────
            rules: list[SemanticRule] = []
            if grammar.fields:
                rules = self.rule_gen.grammar_to_rules(
                    grammar, heatmap=self._last_heatmap
                )
                if rules:
                    await self.rule_gen.push_rules(
                        rules,
                        overall_confidence=grammar.confidence,
                        protocol_name=grammar.protocol_name,
                    )
                    self._total_rules_pushed += len(rules)
                    # C3 fix: mark that LLM rules have been pushed so
                    # bootstrap fallback won't overwrite them.
                    self._llm_rules_active = True
                elif not self._llm_rules_active:
                    # LLM SUCCEEDED but grammar_to_rules yielded 0 placeable
                    # fields — e.g. a text/line protocol whose fields carry no
                    # fixed byte offsets (the LLM returns offsets as [0,0) or
                    # -1, which rule_generator drops). Without this fallback a
                    # successful inference leaves the engine starving at 0
                    # rules for the whole campaign. Feed bootstrap rules from
                    # the math heatmap so fuzzing continues. We deliberately do
                    # NOT set _llm_rules_active (these are not LLM rules), so a
                    # future grammar with placeable fields can still replace
                    # them.
                    pushed = await self._push_bootstrap(
                        ("  LLM yielded 0 placeable fields (fields="
                         f"{len(grammar.fields)}, likely text/line protocol "
                         "with no fixed offsets) — pushed {n} bootstrap "
                         "rules from DifferentialAnalyzer"),
                        level="warning",
                    )
                    if pushed:
                        rules = pushed

            # ── 9b. Incremental: mark inferred + store grammar ───────
            # Track which packets have been sent to the LLM so future
            # cycles can skip them (incremental inference).
            llm_sigs = {
                packet_signature(
                    pkt.get("payload", ""),
                    self._window.prefix_bytes,
                )
                for pkt in llm_selected
                if pkt.get("payload")
            }
            self._window.mark_inferred(llm_sigs)
            self._previous_grammar_summary = self._condense_grammar(grammar)
            logger.info(
                f"  Incremental: {len(llm_sigs)} packets inferred "
                f"(unseen_remaining={self._window.unseen_count}, "
                f"window={self._window.size})"
            )

            # ── 11. EWMA Adaptive Controller update ──────────────────
            self._update_ewma()

            # ── 12. Return result ───────────────────────────────────
            elapsed = time.monotonic() - t0
            self._last_cycle_time = elapsed

            logger.info(
                f"Cycle #{self._total_cycles} complete: "
                f"protocol='{grammar.protocol_name}', "
                f"fields={len(grammar.fields)}, "
                f"rules={len(rules)}, "
                f"math_hint={'yes' if math_hint else 'no'}, "
                f"took={elapsed:.2f}s"
            )

            self._ab_results_log.append({
                "cycle": self._total_cycles,
                "mode": "llm",
                "ab_mode_setting": self.ab_mode,
            })

            return {
                "status": "success",
                "grammar": grammar,
                "rules": rules,
                "packets_sent": len(llm_selected),
                "packets_available": self._window.size,
                "unique_types": self._window.unique_prefixes,
                "heatmap_groups": (
                    len(self._last_heatmap.field_groups)
                    if self._last_heatmap
                    else 0
                ),
            }

        except ValueError as e:
            # LLM parse errors — non-fatal, try bootstrap fallback
            self._errors += 1
            self._last_error = str(e)
            self._mark_inference_time()
            self._llm_rules_active = False
            logger.error(f"LLM parse error in cycle #{self._total_cycles}: {e}")

            # EWMA: update even on error so k stays current
            self._update_ewma()

            if self._last_heatmap and not self._llm_rules_active:
                bootstrap = await self._push_bootstrap(
                    "  BOOTSTRAP FALLBACK (parse error): pushed {n} rules "
                    "from DifferentialAnalyzer",
                    level="warning",
                )
                if bootstrap:
                    return {
                        "status": "bootstrap",
                        "reason": f"Parse error, heatmap fallback: {e}",
                        "rules": bootstrap,
                        "heatmap_groups": len(
                            self._last_heatmap.field_groups
                        ),
                        "packets_available": self._window.size,
                    }

            return {
                "status": "error",
                "reason": f"Parse error: {e}",
                "packets_available": self._window.size,
            }

        except RuntimeError as e:
            # LLM API errors — non-fatal, try bootstrap fallback
            self._errors += 1
            self._last_error = str(e)
            self._mark_inference_time()
            self._llm_rules_active = False
            logger.error(f"LLM API error in cycle #{self._total_cycles}: {e}")

            # EWMA: update even on error so k stays current
            self._update_ewma()

            if self._last_heatmap and not self._llm_rules_active:
                bootstrap = await self._push_bootstrap(
                    "  BOOTSTRAP FALLBACK (API error): pushed {n} rules "
                    "from DifferentialAnalyzer",
                    level="warning",
                )
                if bootstrap:
                    return {
                        "status": "bootstrap",
                        "reason": f"API error, heatmap fallback: {e}",
                        "rules": bootstrap,
                        "heatmap_groups": len(
                            self._last_heatmap.field_groups
                        ),
                        "packets_available": self._window.size,
                    }

            return {
                "status": "error",
                "reason": f"API error: {e}",
                "packets_available": self._window.size,
            }

        except Exception as e:
            # Unexpected errors — log and continue
            self._errors += 1
            self._last_error = str(e)
            self._mark_inference_time()
            self._llm_rules_active = False
            logger.error(
                f"Unexpected error in cycle #{self._total_cycles}: {e}",
                exc_info=True,
            )

            # EWMA: update even on unexpected error so k stays current
            self._update_ewma()

            return {
                "status": "error",
                "reason": f"Unexpected: {e}",
                "packets_available": self._window.size,
            }

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        """Return orchestrator statistics."""
        return {
            "total_cycles": self._total_cycles,
            "total_inferences": self._total_inferences,
            "total_rules_pushed": self._total_rules_pushed,
            "window_size": self._window.size,
            "unique_types": self._window.unique_prefixes,
            "skipped_budget": self._skipped_budget,
            "skipped_insufficient_data": self._skipped_insufficient_data,
            "errors": self._errors,
            "bootstrap_count": self._bootstrap_count,
            "unseen_packets": self._window.unseen_count,
            "has_previous_grammar": self._previous_grammar_summary is not None,
            "ab_mode": self.ab_mode,
            "ab_cycle_counter": self._ab_cycle_counter,
            "precision_mode": self._precision_mode,
            "last_error": self._last_error,
            "last_cycle_time_s": round(self._last_cycle_time, 2),
        }

    @property
    def window(self) -> SlidingWindow:
        """Access the underlying sliding window for testing."""
        return self._window

    @property
    def precision_mode(self) -> bool:
        """Whether the orchestrator is in precision (k=1) crash isolation mode."""
        return self._precision_mode

    @property
    def last_heatmap(self) -> Optional[HeatmapResult]:
        """Access the last DifferentialAnalyzer result for testing."""
        return self._last_heatmap

    # -----------------------------------------------------------------
    # Fusion Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _extract_raw_bytes(
        packets: list[dict[str, Any]],
    ) -> list[bytes]:
        """Extract raw bytes from client-to-server packets.

        Only includes packets whose direction is ``client_to_server``,
        since server responses are not useful for protocol structure
        analysis of the attack surface.

        Args:
            packets: List of parsed packet dicts with 'payload' and
                     'direction' keys.

        Returns:
            List of raw bytes objects, one per client packet.
        """
        raw: list[bytes] = []
        for pkt in packets:
            direction = pkt.get("direction", "")
            payload_hex = pkt.get("payload", "")
            if direction == "client_to_server" and payload_hex:
                try:
                    raw.append(bytes.fromhex(payload_hex))
                except ValueError:
                    continue
        return raw

    def _build_response_feedback(self) -> Optional[str]:
        """Build response feedback as structured JSON for the LLM.

        Collects per-rule-type accepted/rejected/timeout/crash counts and
        formats them as JSON. This creates a closed-loop feedback cycle: the
        LLM sees how its rules performed and can adjust offsets, types, and
        strategies accordingly.

        CRITICAL: the output is prefixed with a ``## RESPONSE FEEDBACK`` header
        because ``LLMAgent.call_llm()`` checks ``"RESPONSE FEEDBACK" in prompt``
        (uppercase + space) to decide whether to append
        ``SYSTEM_PROMPT_FEEDBACK_APPEND`` (the guidance instructions). Plain JSON
        with a ``"response_feedback"`` key would NOT match that marker, silently
        disabling the guidance. The header keeps the marker working while the
        body is now compact JSON instead of a wide text table.

        Returns:
            ``"## RESPONSE FEEDBACK\\n\\n<json>"``, or None if no data available.
        """
        # Read response stats from shared file written by mutator
        try:
            from pathlib import Path as _Path
            stats_path = _Path("shared/rule_response_stats.json")
            if not stats_path.exists():
                return None
            import json as _json
            data = _json.loads(stats_path.read_text(encoding="utf-8"))
            if not data:
                return None
        except Exception:
            return None

        # Check if we have previous grammar to reference
        has_previous = self._previous_grammar_summary is not None
        total_rules = len(self._previous_grammar_summary.get("fields", [])) if has_previous else 0

        field_stats = []
        grand_total = 0
        grand_accepted = 0
        for strategy, counts in data.items():
            accepted = counts.get("accepted", 0)
            rejected = counts.get("rejected", 0)
            timeout = counts.get("timeout", 0)
            crash = counts.get("crash", 0)
            total = accepted + rejected + timeout + crash
            if total == 0:
                continue
            grand_total += total
            grand_accepted += accepted
            field_stats.append({
                "strategy": strategy,
                "accepted": accepted,
                "rejected": rejected,
                "timeout": timeout,
                "crash": crash,
                "total": total,
                "accept_rate": round(accepted / total, 3) if total > 0 else 0.0,
            })

        if grand_total == 0:
            return None

        feedback = {
            "type": "response_feedback",
            "version": 2,
            "total_rules": total_rules if has_previous else None,
            "field_stats": field_stats,
            "overall": {
                "total_sends": grand_total,
                "accepted": grand_accepted,
                "acceptance_rate": round(grand_accepted / grand_total, 3),
            },
            "guidance_rules": [
                "High rejection (>70%) on a field → offset or type likely WRONG",
                "High acceptance on BOUNDARY_VALUES → grammar is accurate",
                "High timeout (>30%) → server may be crashing",
            ],
        }
        # Marker header (see docstring) + compact JSON body.
        return "## RESPONSE FEEDBACK\n\n" + _json.dumps(feedback, indent=2)

    async def _push_bootstrap(
        self, log_msg: str, *, level: str = "info"
    ) -> list[SemanticRule]:
        """Convert the last DifferentialAnalyzer heatmap into rules and push
        them as bootstrap rules — the math-layer fallback that keeps the
        engine fed when the LLM yields no usable rules.

        Returns the pushed rules (possibly empty: no heatmap yet, or the
        heatmap produced nothing). Only bumps ``_total_rules_pushed`` /
        ``_bootstrap_count`` when rules are actually pushed.

        The caller owns the ``_llm_rules_active`` guard — do not overwrite
        good LLM rules with stale heatmap bootstrap rules (C3 fix, see the
        budget-exhausted / LLM-failure call sites).

        ``log_msg`` is a plain string that may contain the literal token
        ``{n}``, replaced with the number of rules pushed.
        """
        if not self._last_heatmap:
            return []
        bootstrap = self._convert_field_rules(
            self._last_heatmap.to_field_rules()
        )
        if not bootstrap:
            return []
        await self.rule_gen.push_rules(
            bootstrap,
            overall_confidence=0.6,
            protocol_name="bootstrap",
        )
        self._total_rules_pushed += len(bootstrap)
        self._bootstrap_count += 1
        _log = {
            "info": logger.info,
            "warning": logger.warning,
            "error": logger.error,
        }.get(level, logger.info)
        _log(log_msg.replace("{n}", str(len(bootstrap))))
        return bootstrap

    @staticmethod
    def _convert_field_rules(
        field_rules: list[FieldRule]
    ) -> list[SemanticRule]:
        """Convert lightweight FieldRule objects into full SemanticRules.

        This is the bootstrap fallback path — when the LLM is unavailable,
        the math layer's FieldRules are converted directly so the fuzzer
        never starves for rules.

        These rules are OFFSET-based (the math layer has no text tokenizer).
        On line-oriented text protocols they mutate byte offsets, not tokens
        — by design: this path isolates the math layer (Baseline B). A
        text-aware variant should be a new named baseline reusing
        shared/text_tokenizer, not a change here.

        Pure function: uses no instance state (only the two staticmethod
        helpers below). C2 fix — previously called via a fragile
        ``RulesOrchestrator.__new__()`` hack in evaluation_runner that would
        silently AttributeError if this method ever touched ``self``. Keeping
        it static makes that contract explicit and lets callers invoke it
        without constructing an orchestrator.

        Args:
            field_rules: FieldRule list from ``HeatmapResult.to_field_rules()``.

        Returns:
            List of SemanticRule objects ready for push_rules().
        """
        rules: list[SemanticRule] = []
        for fr in field_rules:
            # H4 fix: SKIP fields must not become active mutation rules
            if fr.mutation_strategy == MutationStrategy.SKIP:
                continue
            end = fr.offset + fr.length if fr.length > 0 else 65535

            # STATIC fields: exclude from mutation via mutation_strategy_override
            # (get_mutable_fields() skips STATIC). preserve_bytes is ONLY set
            # for the offset-0 STATIC field (the magic header), because
            # ActiveRuleSet.get_static_fields() treats preserve_bytes as a
            # packet prefix anchored at offset 0 — the same contract that
            # rule_generator uses when it carries grammar.magic_bytes on every
            # rule. Setting preserve_bytes for a non-zero STATIC field violates
            # that contract: get_static_fields() would either drop it silently,
            # or — if it is longer than the real magic — overwrite the magic at
            # offset 0 (corrupting the header every mutated packet sends).
            # Non-zero STATIC fields are already protected from mutation and
            # pass through the seed unchanged, so they need no preserve_bytes.
            preserve = b""
            strategy_override = None
            if fr.mutation_strategy == MutationStrategy.STATIC:
                strategy_override = MutationStrategy.STATIC
                if fr.offset == 0 and fr.static_value:
                    try:
                        preserve = bytes.fromhex(fr.static_value)
                    except ValueError:
                        pass
            elif fr.mutation_strategy == MutationStrategy.PAYLOAD_EXTEND:
                # Variable-length tail field: carry PAYLOAD_EXTEND across the
                # FieldRule→SemanticRule bridge so _apply_field() reaches the
                # grow branch (op_buffer_overflow). Without this override the
                # SemanticRule defaults to RANDOM_BYTES and the payload is
                # only ever rewritten in place, never grown — so a server
                # that length-clamps to bytes-received is never overflowed.
                strategy_override = MutationStrategy.PAYLOAD_EXTEND

            rule = SemanticRule(
                rule_type=RulesOrchestrator._strategy_to_rule_type(fr.mutation_strategy),
                target_field_name=fr.field_name,
                mutation_type=RulesOrchestrator._strategy_to_rule_type(fr.mutation_strategy),
                offset_start=fr.offset,
                offset_end=end,
                field_type=RulesOrchestrator._infer_field_type(fr),
                preserve_bytes=preserve,
                priority=fr.confidence,
                description=fr.notes or f"Bootstrap rule from DifferentialAnalyzer",
                dictionary_values=fr.dictionary_values if fr.dictionary_values else [],
                mutation_strategy_override=strategy_override,
            )
            rules.append(rule)
        return rules

    @staticmethod
    def _condense_grammar(grammar: ProtocolGrammar) -> dict[str, Any]:
        """Create a token-efficient summary of a ProtocolGrammar.

        The summary includes field names, offsets, types, and strategies —
        enough context for the LLM to UPDATE its understanding without
        re-deriving from scratch on the next cycle.

        Args:
            grammar: The ProtocolGrammar from a successful LLM inference.

        Returns:
            A dict suitable for ``_format_previous_grammar()`` in LLMAgent.
        """
        return {
            "protocol_name": grammar.protocol_name,
            "magic_bytes": grammar.magic_bytes,
            "total_header_size": grammar.total_header_size,
            "min_packet_size": grammar.min_packet_size,
            "max_packet_size": grammar.max_packet_size,
            "confidence": grammar.confidence,
            "reasoning": grammar.reasoning,
            "fields": [
                {
                    "name": f.name,
                    "offset_start": f.offset_start,
                    "offset_end": f.offset_end,
                    "field_type": f.field_type.value,
                    "mutation_strategy": f.mutation_strategy.value,
                    "is_constant": f.is_constant,
                    "possible_values": f.possible_values,
                    "description": f.description,
                }
                for f in grammar.fields
            ],
        }

    @staticmethod
    def _strategy_to_rule_type(strategy: Any) -> RuleType:
        """Map a MutationStrategy to the closest RuleType."""
        from shared.schemas import MutationStrategy

        mapping = {
            MutationStrategy.STATIC: RuleType.STRUCTURAL,
            MutationStrategy.BOUNDARY_VALUES: RuleType.BOUNDARY,
            MutationStrategy.BIT_FLIP: RuleType.BIT_FLIP,
            MutationStrategy.RANDOM_BYTES: RuleType.STRUCTURAL,
            MutationStrategy.INCREMENT: RuleType.STRUCTURAL,
            MutationStrategy.CALCULATED: RuleType.BOUNDARY,
            MutationStrategy.DICTIONARY: RuleType.STRUCTURAL,
            MutationStrategy.FORMAT_STRING: RuleType.STRUCTURAL,
            MutationStrategy.PAYLOAD_EXTEND: RuleType.STRUCTURAL,
            MutationStrategy.TRUNCATE: RuleType.STRUCTURAL,
            MutationStrategy.SKIP: RuleType.BIT_FLIP,
        }
        return mapping.get(strategy, RuleType.BIT_FLIP)

    @staticmethod
    def _infer_field_type(fr: FieldRule) -> Any:
        """Guess a FieldType from a FieldRule's properties.

        H8 fix: if the DifferentialAnalyzer already detected the correct
        endianness and stored it in ``fr.data_type``, use that directly
        instead of hardcoding little-endian.
        """
        from shared.schemas import FieldType

        # H8: respect explicitly-detected data_type (includes endianness)
        if fr.data_type is not None:
            return fr.data_type

        length = fr.length if fr.length > 0 else 0
        if fr.calculation_source:
            if length == 2:
                return FieldType.UINT16_LE
            if length == 4:
                return FieldType.UINT32_LE
            if length == 1:
                return FieldType.UINT8
        if fr.static_value:
            if length == 4:
                return FieldType.UINT32_LE
            if length == 2:
                return FieldType.UINT16_LE
        return FieldType.BYTES

    async def _check_crash_isolation(self) -> None:
        """Check crash stats and enable precision mode if crashes detected.

        When the CrashManager reports unique crashes, the orchestrator
        enters precision mode (k=1), signalling the Fast Loop to reduce
        mutation breadth for precise crash isolation.
        """
        if not self.crash_manager:
            return
        try:
            crash_stats = await self.crash_manager.get_statistics()
            if crash_stats.unique_crashes > 0 and not self._precision_mode:
                self._precision_mode = True
                logger.warning(
                    f"CRASH DETECTED — entering precision mode (k=1). "
                    f"Unique crashes: {crash_stats.unique_crashes}, "
                    f"Total hits: {crash_stats.total_hits}. "
                    f"Reducing mutation breadth for crash isolation."
                )
        except Exception as e:
            logger.debug(f"Crash stats check failed: {e}")

    def _update_ewma(self) -> None:
        """Update EWMA controller with current coverage metrics.

        Called from success and error exit paths in run_cycle().
        Skipped when insufficient time has elapsed since the last update
        to avoid spurious lambda_c decay from high-frequency calls with
        no new metrics (e.g. rapid LLM retries).
        """
        if not self._ewma:
            return
        epoch_s = time.monotonic() - self._ewma_epoch_start
        # Minimum epoch duration guard: avoid calling EWMA when the epoch
        # is too short to carry meaningful new metrics. Without this, rapid
        # error-retry cycles (e.g. LLM API errors with backoff) cause lambda_c
        # to decay proportionally to call frequency rather than elapsed time.
        if epoch_s < 5.0:
            return
        fg = (
            len(self._last_heatmap.field_groups)
            if self._last_heatmap
            else 0
        )
        self._ewma.update(
            field_groups_count=fg,
            epoch_duration_s=epoch_s,
        )
        self._ewma_epoch_start = time.monotonic()
