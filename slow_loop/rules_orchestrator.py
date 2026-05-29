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
from shared.schemas import FieldRule, ProtocolGrammar, RuleType, SemanticRule
from slow_loop.llm_agent import LLMAgent, estimate_tokens
from slow_loop.parser import InteractionSession, TrafficParser
from slow_loop.rule_generator import RuleGenerator
from slow_loop.differential_analyzer import DifferentialAnalyzer, HeatmapResult

logger = get_logger("slow_loop.rules_orchestrator")


# =============================================================================
# Packet Signature & Dedup
# =============================================================================


def packet_signature(
    packet_hex: str, prefix_bytes: int = 4
) -> str:
    """Create a dedup signature from a packet's hex payload.

    The signature is ``<first-N-bytes-hex>:<total-length>``.
    Packets with the same prefix and length are considered duplicates.

    Examples:
        >>> packet_signature("deadbeef00050041", prefix_bytes=4)
        'deadbeef:8'
        >>> packet_signature("deadbeef00050042", prefix_bytes=4)
        'deadbeef:8'  # same type, same length → duplicate

    Args:
        packet_hex:   Hex-encoded packet payload.
        prefix_bytes: Number of leading bytes to include in the signature.

    Returns:
        A string signature like ``"deadbeef:8"``.
    """
    prefix = packet_hex[: prefix_bytes * 2]
    length = len(packet_hex) // 2
    return f"{prefix}:{length}"


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

        # Evict oldest if over capacity
        while len(self._buffer) > self.max_entries:
            self._buffer.popitem(last=False)

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
        min_packets_before_infer: int = 5,
        crash_manager: Any = None,
    ) -> None:
        self.parser = parser
        self.agent = agent
        self.rule_gen = rule_gen
        self.max_packets_per_inference = max_packets_per_inference
        self.max_prompt_tokens = max_prompt_tokens
        self.min_packets_before_infer = min_packets_before_infer
        self.crash_manager = crash_manager

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

    # -----------------------------------------------------------------
    # Main Pipeline
    # -----------------------------------------------------------------

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

        try:
            # ── 1. Read traffic log ─────────────────────────────────
            sessions = await self.parser.read_log()
            if not sessions:
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
            if new_count < self.min_packets_before_infer:
                self._skipped_insufficient_data += 1
                logger.debug(
                    f"Not enough new unique packets ({new_count} < "
                    f"{self.min_packets_before_infer}) — accumulating"
                )
                return {
                    "status": "skipped",
                    "reason": (
                        f"Insufficient new unique packets: {new_count} < "
                        f"{self.min_packets_before_infer}"
                    ),
                    "packets_available": self._window.size,
                }

            # ── 4. Select diverse samples ───────────────────────────
            selected = self._window.get_diverse_sample(
                self.max_packets_per_inference
            )

            if not selected:
                return {
                    "status": "skipped",
                    "reason": "No diverse samples available",
                    "packets_available": 0,
                }

            # ── 5. Differential Analysis (Math Layer) ───────────────
            math_hint: Optional[str] = None
            raw_packets = self._extract_raw_bytes(selected)
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
            else:
                logger.debug(
                    f"  Differential analysis skipped "
                    f"(need {self._analyzer.min_packets}, have {len(raw_packets)})"
                )

            # ── 6. Build LLM payload ───────────────────────────────
            fake_session = InteractionSession(session_id=0)
            for pkt in selected:
                fake_session.add_packet(pkt)

            payload = self.parser.format_for_llm([fake_session])

            # ── 7. Token budget check ───────────────────────────────
            payload_str = json.dumps(payload, ensure_ascii=False)
            estimated_tokens = estimate_tokens(payload_str)

            if self.max_prompt_tokens > 0 and estimated_tokens > self.max_prompt_tokens:
                self._skipped_budget += 1
                msg = (
                    f"Estimated tokens ({estimated_tokens}) exceeds budget "
                    f"({self.max_prompt_tokens}). Skipping inference."
                )
                logger.warning(msg)
                self._last_error = msg

                # Budget exhausted → push bootstrap rules if available
                if self._last_heatmap:
                    bootstrap = self._convert_field_rules(
                        self._last_heatmap.to_field_rules()
                    )
                    if bootstrap:
                        await self.rule_gen.push_rules(bootstrap)
                        self._total_rules_pushed += len(bootstrap)
                        self._bootstrap_count += 1
                        logger.info(
                            f"  Budget exhausted — pushed {len(bootstrap)} "
                            f"bootstrap rules from heatmap"
                        )

                return {
                    "status": "skipped",
                    "reason": msg,
                    "packets_available": self._window.size,
                }

            # ── 8. Call LLM with math hint ──────────────────────────
            try:
                grammar = await self.agent.infer_protocol(
                    payload, math_hint=math_hint
                )
                self._total_inferences += 1
            except (RuntimeError, ValueError) as llm_err:
                # LLM failed → fall back to bootstrap rules from heatmap
                self._errors += 1
                self._last_error = str(llm_err)
                logger.warning(
                    f"  LLM inference failed: {llm_err}"
                )

                if self._last_heatmap:
                    bootstrap = self._convert_field_rules(
                        self._last_heatmap.to_field_rules()
                    )
                    if bootstrap:
                        await self.rule_gen.push_rules(bootstrap)
                        self._total_rules_pushed += len(bootstrap)
                        self._bootstrap_count += 1
                        logger.warning(
                            f"  BOOTSTRAP FALLBACK: pushed {len(bootstrap)} "
                            f"rules from DifferentialAnalyzer "
                            f"(LLM was unavailable)"
                        )
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

                raise  # Re-raise if no heatmap available

            # ── 9. Generate and push rules ──────────────────────────
            rules: list[SemanticRule] = []
            if grammar.fields:
                rules = self.rule_gen.grammar_to_rules(grammar)
                if rules:
                    await self.rule_gen.push_rules(rules)
                    self._total_rules_pushed += len(rules)

            # ── 10. Crash isolation check ───────────────────────────
            if self.crash_manager:
                await self._check_crash_isolation()

            # ── 11. Return result ───────────────────────────────────
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

            return {
                "status": "success",
                "grammar": grammar,
                "rules": rules,
                "packets_sent": len(selected),
                "packets_available": self._window.size,
                "unique_types": self._window.unique_prefixes,
                "heatmap_groups": (
                    len(self._last_heatmap.field_groups)
                    if self._last_heatmap
                    else 0
                ),
            }

        except ValueError as e:
            # LLM parse errors — non-fatal
            self._errors += 1
            self._last_error = str(e)
            logger.error(f"LLM parse error in cycle #{self._total_cycles}: {e}")
            return {
                "status": "error",
                "reason": f"Parse error: {e}",
                "packets_available": self._window.size,
            }

        except RuntimeError as e:
            # LLM API errors — non-fatal
            self._errors += 1
            self._last_error = str(e)
            logger.error(f"LLM API error in cycle #{self._total_cycles}: {e}")
            return {
                "status": "error",
                "reason": f"API error: {e}",
                "packets_available": self._window.size,
            }

        except Exception as e:
            # Unexpected errors — log and continue
            self._errors += 1
            self._last_error = str(e)
            logger.error(
                f"Unexpected error in cycle #{self._total_cycles}: {e}",
                exc_info=True,
            )
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

    def _convert_field_rules(
        self, field_rules: list[FieldRule]
    ) -> list[SemanticRule]:
        """Convert lightweight FieldRule objects into full SemanticRules.

        This is the bootstrap fallback path — when the LLM is unavailable,
        the math layer's FieldRules are converted directly so the fuzzer
        never starves for rules.

        Args:
            field_rules: FieldRule list from ``HeatmapResult.to_field_rules()``.

        Returns:
            List of SemanticRule objects ready for push_rules().
        """
        rules: list[SemanticRule] = []
        for fr in field_rules:
            end = fr.offset + fr.length if fr.length > 0 else 65535
            rule = SemanticRule(
                rule_type=self._strategy_to_rule_type(fr.mutation_strategy),
                target_field_name=fr.field_name,
                mutation_type=self._strategy_to_rule_type(fr.mutation_strategy),
                offset_start=fr.offset,
                offset_end=end,
                field_type=self._infer_field_type(fr),
                priority=fr.confidence,
                description=fr.notes or f"Bootstrap rule from DifferentialAnalyzer",
            )
            rules.append(rule)
        return rules

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
            MutationStrategy.SKIP: RuleType.BIT_FLIP,
        }
        return mapping.get(strategy, RuleType.BIT_FLIP)

    @staticmethod
    def _infer_field_type(fr: FieldRule) -> Any:
        """Guess a FieldType from a FieldRule's properties."""
        from shared.schemas import FieldType

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
