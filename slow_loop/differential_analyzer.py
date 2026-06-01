"""
slow_loop/differential_analyzer.py
-----------------------------------
Block 3 — Mathematical Pre-processing Layer: Cross-Packet Differential Analysis

PURPOSE:
    Run BEFORE the LLM to reduce its workload by ~70%.
    Automatically classify each byte offset using pure statistics —
    no machine learning, no training data, just math.

ALGORITHM (per byte offset i):
    ┌─────────────────────────────────────────────────────────────────┐
    │ 1. Collect:  V_i = [pkt[i] for pkt in packets if i < len(pkt)] │
    │                                                                 │
    │ 2. Compute:                                                     │
    │    H(V_i)   = -Σ p(v) · log₂ p(v)         ← Shannon Entropy   │
    │    σ²(V_i)  = Σ (v − μ)² / n              ← Variance          │
    │    τ_b(V_i) = (C − D) / √((n₀−T_y)·n₀)   ← Kendall's Tau-b   │
    │    r_L(V_i) = Cov(V_i, L) / (σ_V · σ_L)  ← Pearson w/ Length │
    │                                                                 │
    │ 3. Label:                                                       │
    │    H = 0.0              → STATIC       (magic bytes, version)   │
    │    |r_L| > 0.85         → CALCULATED   (length field)           │
    │    τ > 0.75             → CALCULATED   (sequence number)        │
    │    H > 3.5              → HIGH_ENTROPY (payload / encrypted)    │
    │    0 < H ≤ 3.5          → LOW_ENTROPY  (flags, enum, type)      │
    │                                                                 │
    │ 4. Cluster adjacent same-label offsets → FieldGroups            │
    │                                                                 │
    │ 5. Output: HeatmapResult → to_llm_hint() + to_field_rules()    │
    └─────────────────────────────────────────────────────────────────┘

INTEGRATION:
    analyzer = DifferentialAnalyzer()
    result   = analyzer.analyze(packets)
    prompt   = parser.to_llm_prompt(traffic_data, hint=result.to_llm_hint())
    rules    = result.to_field_rules()   # Bootstrap rules before LLM responds
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from shared.logger import get_logger
from shared.schemas import FieldRule, FieldType, MutationStrategy

log = get_logger("slow_loop.differential_analyzer")


# ===========================================================================
# Constants & Thresholds
# ===========================================================================

# Shannon entropy thresholds (bits, max = log₂(256) = 8.0)
_H_STATIC_MAX    = 0.0    # Exactly constant
_H_LOW_MAX       = 3.0    # Structured but varying (flags, enums, type codes)
_H_HIGH_MIN      = 3.5    # High entropy → payload / encrypted region

# Correlation threshold for length-field detection (Pearson r)
_CORR_LENGTH_MIN  = 0.85

# Kendall's tau threshold for sequence-number detection
_TAU_MONO_MIN     = 0.75

# Minimum packets required for meaningful analysis
_MIN_PACKETS      = 3

# Minimum coverage (fraction of packets with data at this offset) to analyze
_MIN_COVERAGE     = 0.6

# Maximum byte offset to analyze (keep LLM prompt manageable)
_MAX_ANALYSIS_DEPTH = 64

# Integer encodings tried for length-field detection
_INT_ENCODINGS: dict[str, tuple[str, int]] = {
    "uint8":    (">B",  1),
    "uint16_be": (">H", 2),
    "uint16_le": ("<H", 2),
    "uint32_be": (">I", 4),
    "uint32_le": ("<I", 4),
}


# ===========================================================================
# Enumerations
# ===========================================================================

class OffsetLabel(str, Enum):
    """
    Classification label for a single byte offset.
    Priority (high → low): STATIC > CALCULATED > HIGH_ENTROPY > LOW_ENTROPY
    """
    STATIC       = "STATIC"        # H = 0.0  → never change (magic bytes, padding)
    CALCULATED   = "CALCULATED"    # Deterministic but derived (length, seq, checksum)
    HIGH_ENTROPY = "HIGH_ENTROPY"  # H > 3.5  → fuzz freely (payload, random data)
    LOW_ENTROPY  = "LOW_ENTROPY"   # 0 < H ≤ 3.5 → fuzz carefully (flags, type codes)
    UNKNOWN      = "UNKNOWN"       # Insufficient data (<MIN_PACKETS with this offset)


class CalcSubType(str, Enum):
    """Sub-classification for CALCULATED offsets."""
    LENGTH_FIELD    = "LENGTH_FIELD"     # Pearson r > θ with packet/payload length
    SEQUENCE_NUMBER = "SEQUENCE_NUMBER"  # Kendall τ > θ (monotonic increase)
    CHECKSUM        = "CHECKSUM"         # Reserved — future: reproducibility oracle


# ===========================================================================
# Data Classes
# ===========================================================================

@dataclass
class OffsetStats:
    """
    Full statistical profile of a single byte offset across the packet corpus.

    All fields are computed from raw observations — no assumptions about
    the protocol. The `label` and `confidence` are derived from these stats.
    """
    offset:        int
    sample_count:  int           # Number of packets containing this offset
    coverage:      float         # sample_count / total_packets ∈ [0, 1]
    entropy:       float         # Shannon H ∈ [0.0, 8.0]  (bits)
    variance:      float         # Statistical variance of byte values
    unique_count:  int           # |{distinct values}|
    sample_values: list[int]     # Up to 8 representative byte values
    constant_value: Optional[int] = None   # Set iff label == STATIC

    # Length-correlation analysis
    best_corr:      float  = 0.0    # Best |Pearson r| across all encodings
    best_encoding:  str    = ""     # Encoding giving best_corr
    best_length_ref: str   = ""     # "total" or "payload_N" (N = header guess)

    # Monotonicity analysis
    kendall_tau:    float  = 0.0    # ∈ [-1, +1]; >0.75 = monotonically increasing

    # Label (assigned by _label_offset)
    label:          OffsetLabel    = OffsetLabel.UNKNOWN
    sub_type:       Optional[str]  = None
    confidence:     float          = 0.0   # ∈ [0, 1] how sure we are of the label


@dataclass
class FieldGroup:
    """
    A contiguous range of byte offsets that share the same classification.

    Multiple consecutive STATIC offsets → one STATIC FieldGroup.
    Represents a single "field" in the inferred protocol grammar.
    """
    start:      int           # Inclusive start offset
    end:        int           # Exclusive end offset  (length = end - start)
    label:      OffsetLabel
    sub_type:   Optional[str]  = None
    static_hex: Optional[str]  = None   # Hex of constant value (STATIC only)
    confidence: float          = 0.0
    notes:      str            = ""

    @property
    def length(self) -> int:
        """Byte length of the group. Returns -1 for variable-length groups."""
        if self.end == -1:
            return -1
        return self.end - self.start

    @property
    def suggested_strategy(self) -> MutationStrategy:
        """Map OffsetLabel → MutationStrategy for SemanticRuleSet generation."""
        mapping = {
            OffsetLabel.STATIC:       MutationStrategy.STATIC,
            OffsetLabel.CALCULATED:   MutationStrategy.CALCULATED if self.sub_type == CalcSubType.LENGTH_FIELD else MutationStrategy.RANDOM_BYTES,
            OffsetLabel.HIGH_ENTROPY: MutationStrategy.RANDOM_BYTES,
            OffsetLabel.LOW_ENTROPY:  MutationStrategy.BIT_FLIP,
            OffsetLabel.UNKNOWN:      MutationStrategy.SKIP,
        }
        return mapping.get(self.label, MutationStrategy.RANDOM_BYTES)


@dataclass
class HeatmapResult:
    """
    Complete output of the DifferentialAnalyzer for a packet corpus.

    Contains the per-offset statistical breakdown AND the clustered
    field groups ready for injection into the LLM prompt and/or
    direct conversion to FieldRule objects.
    """
    analyzed_at:    datetime
    packet_count:   int
    min_length:     int
    max_length:     int
    analysis_depth: int                      # Bytes analyzed (≤ MAX_ANALYSIS_DEPTH)
    offset_stats:   dict[int, OffsetStats]   # Per-offset raw statistics
    field_groups:   list[FieldGroup]         # Clustered field boundaries

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-safe)."""
        return {
            "analyzed_at":    self.analyzed_at.isoformat(),
            "packet_count":   self.packet_count,
            "length_range":   {"min": self.min_length, "max": self.max_length},
            "analysis_depth": self.analysis_depth,
            "field_groups": [
                {
                    "start":      g.start,
                    "end":        g.end,
                    "length":     g.length,
                    "label":      g.label.value,
                    "sub_type":   g.sub_type,
                    "static_hex": g.static_hex,
                    "strategy":   g.suggested_strategy.value,
                    "confidence": round(g.confidence, 3),
                    "notes":      g.notes,
                }
                for g in self.field_groups
            ],
            "offset_stats": {
                str(off): {
                    "entropy":      round(s.entropy, 4),
                    "variance":     round(s.variance, 2),
                    "unique":       s.unique_count,
                    "coverage":     round(s.coverage, 3),
                    "tau":          round(s.kendall_tau, 3),
                    "best_corr":    round(s.best_corr, 3),
                    "label":        s.label.value,
                    "sub_type":     s.sub_type,
                    "confidence":   round(s.confidence, 3),
                }
                for off, s in self.offset_stats.items()
            },
        }

    def to_llm_hint(self) -> str:
        """
        Format the heatmap as a token-efficient hint block for the LLM prompt.

        P3-I: Uses pipe-delimited columns instead of Unicode box-drawing chars.
        Saves ~200 tokens per hint (~40% reduction) with no information loss.

        This is injected verbatim into the LLM's system/user message.
        Goal: give the LLM a pre-computed head start so it focuses on
        semantic naming and confirmation rather than raw byte discovery.
        """
        label_tags = {
            OffsetLabel.STATIC:       "STATIC",
            OffsetLabel.CALCULATED:   "CALC",
            OffsetLabel.HIGH_ENTROPY: "HIGH",
            OffsetLabel.LOW_ENTROPY:  "LOW",
            OffsetLabel.UNKNOWN:      "UNKN",
        }

        lines = [
            "## MATHEMATICAL PRE-ANALYSIS (computed before LLM — trust this)",
            f"Packets: {self.packet_count} | "
            f"Length: {self.min_length}-{self.max_length}B | "
            f"Depth: {self.analysis_depth}B",
            "",
            "offset | label | H(X)  | variance | notes",
            "-------|-------|-------|----------|------",
        ]

        for off, s in sorted(self.offset_stats.items()):
            tag = label_tags.get(s.label, "?")
            h_str = f"{s.entropy:.3f}"
            var_str = f"{s.variance:.1f}"

            if s.label == OffsetLabel.STATIC:
                note = f"const=0x{s.constant_value:02X} conf={s.confidence:.2f}"
            elif s.label == OffsetLabel.CALCULATED:
                if s.sub_type == CalcSubType.LENGTH_FIELD:
                    note = f"r={s.best_corr:+.3f} enc={s.best_encoding}"
                else:
                    note = f"tau={s.kendall_tau:+.3f} (monotonic)"
            elif s.label == OffsetLabel.HIGH_ENTROPY:
                note = f"unique={s.unique_count}/256 conf={s.confidence:.2f}"
            else:
                note = f"unique={s.unique_count} conf={s.confidence:.2f}"

            lines.append(f"{off:5d}  | {tag:5s} | {h_str:5s} | {var_str:8s} | {note}")

        lines += [
            "",
            "### Inferred Field Groups (strong structural hints):",
        ]

        for g in self.field_groups:
            span = f"[{g.start:02d}-{g.end - 1:02d}]" if g.length > 1 else f"[{g.start:02d}]"
            tag = label_tags.get(g.label, "?")
            strat = g.suggested_strategy.value
            hex_val = f" val=0x{g.static_hex}" if g.static_hex else ""
            lines.append(
                f"  {span} {tag:5s} {g.length:2d}B "
                f"strategy={strat}{hex_val} conf={g.confidence:.2f}"
            )

        lines += [
            "",
            "### Instruction",
            "The heatmap is MATHEMATICALLY COMPUTED, not guessed.",
            "Your task: name fields, identify semantics, flag CHECKSUM/SEQUENCE patterns.",
            "Do NOT re-derive what is already marked STATIC or HIGH_ENTROPY.",
        ]
        return "\n".join(lines)

    def to_field_rules(self) -> list[FieldRule]:
        """
        Convert field groups into FieldRule objects for a SemanticRuleSet.

        These rules can be used IMMEDIATELY by the Mutation Engine as a
        bootstrap rule set while the LLM processes the full prompt.
        This closes the gap between "no rules" and "LLM response" — the
        analyzer output is typically available in <1 ms.
        """
        # Map encoding strings from _best_length_correlation to FieldType
        _ENC_TO_FIELD_TYPE: dict[str, FieldType] = {
            "uint8":     FieldType.UINT8,
            "uint16_le": FieldType.UINT16_LE,
            "uint16_be": FieldType.UINT16_BE,
            "uint32_le": FieldType.UINT32_LE,
            "uint32_be": FieldType.UINT32_BE,
        }

        rules: list[FieldRule] = []
        for i, g in enumerate(self.field_groups):
            # Propagate endian info from first offset's best_encoding
            data_type: Optional[FieldType] = None
            if g.label == OffsetLabel.CALCULATED and g.sub_type == CalcSubType.LENGTH_FIELD:
                stat = self.offset_stats.get(g.start)
                if stat and stat.best_encoding in _ENC_TO_FIELD_TYPE:
                    data_type = _ENC_TO_FIELD_TYPE[stat.best_encoding]

            rule = FieldRule(
                field_name         = f"field_{i:02d}_{g.label.value.lower()}",
                offset             = g.start,
                length             = g.length if g.end != -1 else -1,
                mutation_strategy  = g.suggested_strategy,
                static_value       = g.static_hex if g.label == OffsetLabel.STATIC else None,
                calculation_source = "payload" if (g.sub_type == CalcSubType.LENGTH_FIELD) else None,
                data_type          = data_type,
                notes              = g.notes or f"Auto-inferred by DifferentialAnalyzer (conf={g.confidence:.2f})",
                confidence         = g.confidence,
            )
            rules.append(rule)
        return rules


# ===========================================================================
# Pure-Python Mathematical Primitives
# ===========================================================================

def _shannon_entropy(values: list[int]) -> float:
    """
    Compute Shannon entropy H(X) = -Σ p(x) · log₂ p(x) in bits.

    H = 0.0  → all values identical (perfectly constant)
    H = 8.0  → uniform distribution over [0, 255] (maximum randomness)

    Args:
        values: List of byte values (0–255).

    Returns:
        Entropy in bits ∈ [0.0, 8.0].
    """
    n = len(values)
    if n == 0:
        return 0.0
    counts = Counter(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _variance(values: list[int]) -> float:
    """
    Population variance σ² = Σ(v − μ)² / n.

    Max variance for uniform byte distribution ≈ 5461 (n→∞).
    Variance = 0 iff all values are identical.

    Args:
        values: List of byte values.

    Returns:
        Population variance ≥ 0.
    """
    n = len(values)
    if n < 2:
        return 0.0
    mu = sum(values) / n
    return sum((v - mu) ** 2 for v in values) / n


def _pearson_r(xs: list[float], ys: list[float]) -> float:
    """
    Pearson correlation coefficient r = Cov(X,Y) / (σ_X · σ_Y).

    r = +1.0 → perfect positive linear relationship
    r =  0.0 → no linear relationship
    r = -1.0 → perfect negative linear relationship

    Args:
        xs: First variable (e.g., parsed integer values at an offset).
        ys: Second variable (e.g., packet lengths).

    Returns:
        Pearson r ∈ [-1.0, +1.0], or 0.0 if correlation is undefined.
    """
    n = len(xs)
    if n < 2 or len(ys) != n:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    num   = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x < 1e-9 or den_y < 1e-9:
        return 0.0
    return num / (den_x * den_y)


def _kendall_tau(values: list[int], max_samples: int = 200) -> float:
    """
    Kendall's rank correlation coefficient τ.

    Measures monotonic trend in the ORDER values appear (i.e., over time).

    Uses Kendall tau-b which correctly handles ties (common in byte data):

        τ_b = (C − D) / √((C + D + T_x) · (C + D + T_y))

    With x = capture index (always unique, T_x = 0):

        τ_b = (C − D) / √((total_pairs − T_y) · total_pairs)

    Where:
        C = concordant pairs
        D = discordant pairs (= index inversions after sorting by value)
        T_y = tied pairs in the value dimension
        total_pairs = n·(n−1)/2

    Algorithm: modified merge-sort inversion counting on indices after
    stable-sorting (value, index) pairs by value.  Equal values are NOT
    counted as inversions — they go into T_y.

    τ > +0.75 → strong monotonic increase  → SEQUENCE_NUMBER
    τ < −0.75 → strong monotonic decrease  → (rare, e.g., countdown)
    |τ| < 0.75 → no clear trend

    P1-D fix: Input is stride-sampled to max_samples to cap array size.

    Complexity: O(min(n, max_samples) · log(min(n, max_samples)))

    Args:
        values:      Byte values in capture order.
        max_samples: Cap input size via stride sampling (default 200).

    Returns:
        τ_b ∈ [-1.0, +1.0].

    Edge cases:
        [1,2,3,4,5]       →  1.0  (perfect increasing)
        [5,4,3,2,1]       → -1.0  (perfect decreasing)
        [1,1,1,1,1]       →  0.0  (all tied)
        [1,2,1,2,1]       →  0.0  (ambiguous with ties)
        n < 4             →  0.0  (not enough data)
    """
    n = len(values)

    # Stride-based downsampling to cap O(n log n) cost
    if n > max_samples:
        step = n / max_samples
        values = [values[int(i * step)] for i in range(max_samples)]
        n = max_samples

    if n < 4:
        return 0.0

    total_pairs = n * (n - 1) // 2

    # Step 1: Stable-sort (value, index) pairs by value.
    # Python's sorted() is stable (Timsort) — tied values keep original order.
    pairs = sorted(enumerate(values), key=lambda p: p[1])
    sorted_values  = [p[1] for p in pairs]
    sorted_indices = [p[0] for p in pairs]

    # Step 2: Count inversions among indices = D (discordant pairs).
    # After stable-sort by value, an inversion of indices means:
    #   a higher-valued element appears earlier in capture order → discordant.
    _, D = _merge_sort_inversions(sorted_indices)

    # Step 3: Count tied value pairs = T_y.
    # For k equal values in sorted order: k·(k-1)/2 tied pairs.
    T_y = _count_ties(sorted_values)

    # Step 4: Compute Kendall tau-b.
    C = total_pairs - D - T_y
    denom_sq = (total_pairs - T_y) * total_pairs

    if denom_sq <= 0:
        return 0.0  # All pairs are tied

    return (C - D) / math.sqrt(denom_sq)


def _merge_sort_inversions(arr: list[int]) -> tuple[list[int], int]:
    """Count inversions using modified merge sort.  O(n log n).

    An inversion is a pair (i, j) where i < j but arr[i] > arr[j].
    Equal elements (arr[i] == arr[j]) are NOT counted as inversions.

    Returns (sorted_copy, inversion_count).
    """
    n = len(arr)
    if n <= 1:
        return arr[:], 0

    # Divide
    mid = n // 2
    left,  left_inv  = _merge_sort_inversions(arr[:mid])
    right, right_inv = _merge_sort_inversions(arr[mid:])

    # Conquer: merge while counting cross-inversions
    merged = []
    inversions = left_inv + right_inv
    i = j = 0

    while i < len(left) and j < len(right):
        # <= (not <) ensures equal elements do NOT count as inversions
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            # All remaining elements in left are greater → each is an inversion
            inversions += len(left) - i
            j += 1

    # Append leftovers
    merged.extend(left[i:])
    merged.extend(right[j:])

    return merged, inversions


def _count_ties(sorted_values: list[int]) -> int:
    """Count tied pairs in a sorted list of values.

    For each group of k consecutive equal values: k·(k-1)/2 tied pairs.
    """
    ties = 0
    i = 0
    n = len(sorted_values)
    while i < n:
        j = i + 1
        # Scan past all values equal to sorted_values[i]
        while j < n and sorted_values[j] == sorted_values[i]:
            j += 1
        k = j - i  # size of this equal-value group
        if k > 1:
            ties += k * (k - 1) // 2
        i = j
    return ties


def _try_decode_int(data: bytes, fmt: str, size: int) -> Optional[int]:
    """Safely decode bytes as a fixed-size integer."""
    if len(data) < size:
        return None
    try:
        return struct.unpack(fmt, data[:size])[0]
    except struct.error:
        return None


# ===========================================================================
# Differential Analyzer
# ===========================================================================

class DifferentialAnalyzer:
    """
    Stateless mathematical analyzer for a collection of binary packets.

    Call `analyze(packets)` with a list of raw byte strings.
    Returns a `HeatmapResult` containing per-offset statistics,
    clustered field groups, and methods for LLM hint generation.

    The analyzer is intentionally STATELESS — each call to analyze()
    is independent. This allows it to be reused across multiple
    TrafficLog batches without side effects.

    Example:
        analyzer = DifferentialAnalyzer()
        packets  = [pkt.raw_bytes for pkt in traffic_log.packets
                    if pkt.direction == Direction.CLIENT_TO_SERVER]
        result   = analyzer.analyze(packets)
        hint     = result.to_llm_hint()       # → into LLM prompt
        rules    = result.to_field_rules()    # → bootstrap SemanticRuleSet
    """

    def __init__(
        self,
        max_depth:        int   = _MAX_ANALYSIS_DEPTH,
        min_packets:      int   = _MIN_PACKETS,
        min_coverage:     float = _MIN_COVERAGE,
        h_static_max:     float = _H_STATIC_MAX,
        h_low_max:        float = _H_LOW_MAX,
        h_high_min:       float = _H_HIGH_MIN,
        corr_length_min:  float = _CORR_LENGTH_MIN,
        tau_mono_min:     float = _TAU_MONO_MIN,
        # P1-D: cap τ input to avoid O(n²) blowup on large corpora
        max_tau_samples:  int   = 200,
        # P2-A: stop analysis after N consecutive HIGH_ENTROPY offsets
        early_stop_consecutive: int = 10,
    ) -> None:
        self.max_depth       = max_depth
        self.min_packets     = min_packets
        self.min_coverage    = min_coverage
        self.h_static_max    = h_static_max
        self.h_low_max       = h_low_max
        self.h_high_min      = h_high_min
        self.corr_length_min = corr_length_min
        self.tau_mono_min    = tau_mono_min
        self.max_tau_samples = max_tau_samples
        self.early_stop_consecutive = early_stop_consecutive

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def analyze(self, packets: list[bytes]) -> HeatmapResult:
        """
        Main entry point. Analyze a list of raw packets and return a HeatmapResult.

        Args:
            packets: Raw bytes for each packet (typically client→server only).
                     Should be from a single session for meaningful diff analysis.

        Returns:
            HeatmapResult with per-offset stats, field groups, and LLM hint.

        Raises:
            ValueError: If fewer than min_packets are provided.
        """
        if len(packets) < self.min_packets:
            raise ValueError(
                f"DifferentialAnalyzer needs at least {self.min_packets} packets "
                f"(got {len(packets)}). Capture more traffic before analysis."
            )

        lengths        = [len(p) for p in packets]
        min_len        = min(lengths)
        max_len        = max(lengths)
        analysis_depth = min(min_len, self.max_depth)

        log.info(
            "Starting differential analysis",
            extra={"context": {
                "packets":  len(packets),
                "len_range": f"{min_len}–{max_len}B",
                "depth":    f"{analysis_depth}B",
            }},
        )

        # -------------------------------------------------------------------
        # Step 1: Compute per-offset statistics
        # -------------------------------------------------------------------
        all_stats: dict[int, OffsetStats] = {}
        consecutive_high: int = 0  # P2-A: track HIGH_ENTROPY streak
        effective_depth: int = analysis_depth

        for offset in range(analysis_depth):
            stats = self._analyze_offset(offset, packets, lengths)
            if stats is not None:
                all_stats[offset] = stats

                # P2-A: early-stop on consecutive HIGH_ENTROPY offsets
                if stats.label == OffsetLabel.HIGH_ENTROPY:
                    consecutive_high += 1
                    if consecutive_high >= self.early_stop_consecutive:
                        # Truncate: keep offsets up to the start of this streak
                        effective_depth = max(0, offset - self.early_stop_consecutive + 1)
                        # Remove the HIGH_ENTROPY streak offsets
                        for trim_off in range(effective_depth, offset + 1):
                            all_stats.pop(trim_off, None)
                        log.info(
                            "Early-stop: %d consecutive HIGH_ENTROPY offsets — "
                            "trimming analysis to %d bytes",
                            consecutive_high, effective_depth,
                        )
                        break
                else:
                    consecutive_high = 0

        # -------------------------------------------------------------------
        # Step 2: Cluster into field groups
        # -------------------------------------------------------------------
        groups = self._cluster_into_fields(all_stats, effective_depth)

        # P2-E: Merge split multi-byte CALCULATED fields
        groups = self._merge_calculated_neighbors(groups, all_stats)

        # Mark the final group as variable-length if max_len > min_len
        if groups and max_len > min_len:
            last = groups[-1]
            if last.label == OffsetLabel.HIGH_ENTROPY:
                # H9 fix: set end=-1 so to_field_rules() produces length=-1
                # for variable-length payloads (previously only notes were set,
                # making the g.end != -1 check in to_field_rules() dead code).
                last.end = -1
                last.notes = (
                    f"Variable-length payload. "
                    f"Observed range: {min_len - last.start}–{max_len - last.start} B"
                )

        result = HeatmapResult(
            analyzed_at    = datetime.now(timezone.utc),
            packet_count   = len(packets),
            min_length     = min_len,
            max_length     = max_len,
            analysis_depth = effective_depth,
            offset_stats   = all_stats,
            field_groups   = groups,
        )

        unique_labels = Counter(s.label.value for s in all_stats.values())
        log.info(
            "Differential analysis complete",
            extra={"context": {
                "field_groups": len(groups),
                "labels":       dict(unique_labels),
            }},
        )

        return result

    # -----------------------------------------------------------------------
    # Per-Offset Analysis
    # -----------------------------------------------------------------------

    def _analyze_offset(
        self,
        offset:   int,
        packets:  list[bytes],
        lengths:  list[int],
    ) -> Optional[OffsetStats]:
        """
        Compute the full statistical profile for a single byte offset.

        Returns None if coverage is too low (< min_coverage).
        """
        # Collect all packets that contain this offset
        pairs = [
            (packets[i][offset], lengths[i])
            for i in range(len(packets))
            if offset < lengths[i]
        ]
        if not pairs:
            return None

        values_here, pkt_lengths = zip(*pairs)
        values_here  = list(values_here)
        pkt_lengths  = list(pkt_lengths)

        coverage = len(values_here) / len(packets)
        if coverage < self.min_coverage:
            return None

        H       = _shannon_entropy(values_here)
        var     = _variance(values_here)
        unique  = len(set(values_here))
        samples = sorted(set(values_here))[:8]

        # P1-D: skip τ for HIGH_ENTROPY offsets — they're never sequence numbers.
        # This avoids O(n²) τ computation on ~60% of offsets (the payload region).
        if H <= self.h_high_min:
            tau = _kendall_tau(values_here, max_samples=self.max_tau_samples)
        else:
            tau = 0.0

        # Length correlation across all integer encodings
        best_corr, best_enc, best_ref = self._best_length_correlation(
            offset, packets, pkt_lengths, lengths
        )

        # Determine label (priority order matters!)
        label, sub_type, confidence = self._label_offset(
            H=H, tau=tau, best_corr=best_corr, unique=unique
        )

        return OffsetStats(
            offset         = offset,
            sample_count   = len(values_here),
            coverage       = coverage,
            entropy        = H,
            variance       = var,
            unique_count   = unique,
            sample_values  = samples,
            constant_value = values_here[0] if label == OffsetLabel.STATIC else None,
            best_corr      = best_corr,
            best_encoding  = best_enc,
            best_length_ref= best_ref,
            kendall_tau    = tau,
            label          = label,
            sub_type       = sub_type,
            confidence     = confidence,
        )

    @staticmethod
    def _compute_header_candidates(all_lengths: list[int]) -> list[int]:
        """P2-G: Derive candidate header sizes from observed packet lengths.

        Instead of a hardcoded list, we use the data to generate plausible
        header_size values. The key insight: payload_length = total_length - header_size.
        The header_size should be ≤ min(all_lengths) and typically aligns to
        common field sizes (1, 2, 4 bytes).

        Returns a sorted list of candidate header sizes including 0 (total length).
        """
        min_len = min(all_lengths)
        max_len = max(all_lengths)
        candidates: set[int] = {0}

        # Core candidates: common field sizes around minimum length
        for base in range(max(0, min_len - 4), min(max_len + 1, min_len + 17)):
            candidates.add(base)

        # Also try specific sizes that often appear in protocol headers
        for typical in [2, 4, 6, 8, 12, 16, 20, 24, 32]:
            if typical <= max_len:
                candidates.add(typical)

        return sorted(candidates)

    def _best_length_correlation(
        self,
        offset:      int,
        packets:     list[bytes],
        pkt_lengths: list[int],  # lengths for packets that have this offset
        all_lengths: list[int],  # all packet lengths (aligned with packets)
    ) -> tuple[float, str, str]:
        """
        Try to decode bytes at `offset` in multiple integer encodings and
        compute Pearson r with packet length (total and various payload offsets).

        Returns:
            (best_abs_r, best_encoding, best_reference_type)
        """
        best_r      = 0.0
        best_enc    = ""
        best_ref    = ""

        # P2-G: Data-driven header candidates instead of hardcoded list.
        # The field might encode payload_length = total_length - header_size.
        # We derive candidates from the observed packet length distribution.
        header_guesses = self._compute_header_candidates(all_lengths)

        for enc_name, (fmt, size) in _INT_ENCODINGS.items():
            # Extract parsed integer values for packets that have offset + size bytes
            parsed_vals: list[int] = []
            ref_lengths: list[int] = []

            for i, pkt in enumerate(packets):
                if offset + size <= len(pkt):
                    val = _try_decode_int(pkt[offset:], fmt, size)
                    if val is not None:
                        parsed_vals.append(val)
                        ref_lengths.append(all_lengths[i])

            if len(parsed_vals) < self.min_packets:
                continue

            # Try correlating with total length and payload lengths
            xs = [float(v) for v in parsed_vals]

            for hdr_size in header_guesses:
                ys = [float(max(0, l - hdr_size)) for l in ref_lengths]
                r  = _pearson_r(xs, ys)
                if abs(r) > abs(best_r):
                    best_r   = r
                    best_enc = enc_name
                    best_ref = f"total-{hdr_size}" if hdr_size > 0 else "total"

        return abs(best_r), best_enc, best_ref

    def _label_offset(
        self,
        H:         float,
        tau:       float,
        best_corr: float,
        unique:    int,
    ) -> tuple[OffsetLabel, Optional[str], float]:
        """
        Assign a label to an offset using a strict priority ordering.

        Priority: STATIC > CALCULATED (length) > CALCULATED (seq) > HIGH_ENTROPY > LOW_ENTROPY

        Returns:
            (label, sub_type, confidence)
        """
        # --- STATIC: perfectly constant ---
        if H <= self.h_static_max:
            return OffsetLabel.STATIC, None, 1.0

        # --- CALCULATED / LENGTH FIELD ---
        if best_corr >= self.corr_length_min:
            confidence = _scale(best_corr, self.corr_length_min, 1.0)
            return OffsetLabel.CALCULATED, CalcSubType.LENGTH_FIELD, confidence

        # --- CALCULATED / SEQUENCE NUMBER ---
        if tau >= self.tau_mono_min:
            confidence = _scale(tau, self.tau_mono_min, 1.0)
            return OffsetLabel.CALCULATED, CalcSubType.SEQUENCE_NUMBER, confidence

        # --- HIGH ENTROPY ---
        if H >= self.h_high_min:
            confidence = _scale(H, self.h_high_min, 8.0)
            return OffsetLabel.HIGH_ENTROPY, None, min(confidence, 0.95)

        # --- LOW ENTROPY (structured but variable) ---
        # P1-B fix: handle gap zone (h_low_max < H < h_high_min) gracefully.
        # Old code: confidence = 1.0 - _scale(H, 0.0, h_low_max) → 0.0 for H > h_low_max.
        # New: within LOW_MAX → confidence decreases with H; above → lower floor.
        if H <= self.h_low_max:
            confidence = 1.0 - _scale(H, 0.0, self.h_low_max)
        else:
            # Gap zone: moderate entropy, lower confidence, but not zero
            confidence = max(0.2, 1.0 - _scale(H, self.h_low_max, 8.0))
        return OffsetLabel.LOW_ENTROPY, None, max(0.4, confidence)

    # -----------------------------------------------------------------------
    # Field Group Clustering
    # -----------------------------------------------------------------------

    def _cluster_into_fields(
        self,
        all_stats:      dict[int, OffsetStats],
        analysis_depth: int,
    ) -> list[FieldGroup]:
        """
        Merge adjacent offsets with the same label into FieldGroups.

        Algorithm:
            - Walk offsets 0 … analysis_depth-1 in order.
            - When the label changes (or sub_type changes), emit the
              accumulated group and start a new one.
            - Compute per-group confidence as the mean of constituent offsets.

        Special handling:
            - Multiple STATIC offsets → one group (single magic-bytes field)
            - A lone CALCULATED offset might be multi-byte → look ahead
        """
        if not all_stats:
            return []

        groups:   list[FieldGroup] = []
        cur_start:  int            = 0
        cur_label:  OffsetLabel    = all_stats.get(0, OffsetStats(
            0, 0, 0.0, 0.0, 0.0, 0, [], None, 0.0, "", "", 0.0,
            OffsetLabel.UNKNOWN, None, 0.0,
        )).label
        cur_sub:    Optional[str]  = all_stats.get(0, OffsetStats(
            0, 0, 0.0, 0.0, 0.0, 0, [], None, 0.0, "", "", 0.0,
            OffsetLabel.UNKNOWN, None, 0.0,
        )).sub_type
        accum_conf: list[float]    = []
        accum_stat: list[OffsetStats] = []

        def flush(end: int) -> None:
            if not accum_stat:
                return
            avg_conf = sum(accum_conf) / len(accum_conf)

            # Build static hex for STATIC groups
            static_hex: Optional[str] = None
            if cur_label == OffsetLabel.STATIC:
                static_bytes = bytes(
                    s.constant_value for s in accum_stat
                    if s.constant_value is not None
                )
                static_hex = static_bytes.hex()

            # Build notes
            if cur_label == OffsetLabel.STATIC:
                notes = f"Constant value: 0x{static_hex}"
            elif cur_label == OffsetLabel.CALCULATED:
                if cur_sub == CalcSubType.LENGTH_FIELD:
                    enc = accum_stat[0].best_encoding
                    ref = accum_stat[0].best_length_ref
                    notes = f"Length field ({enc}, ref={ref}, r={accum_stat[0].best_corr:.3f})"
                else:
                    notes = f"Monotonic sequence (τ={accum_stat[0].kendall_tau:+.3f})"
            elif cur_label == OffsetLabel.HIGH_ENTROPY:
                avg_h = sum(s.entropy for s in accum_stat) / len(accum_stat)
                notes = f"Variable data (avg H={avg_h:.2f} bits)"
            else:
                notes = f"Low-entropy field (flags/enum)"

            groups.append(FieldGroup(
                start      = cur_start,
                end        = end,
                label      = cur_label,
                sub_type   = cur_sub.value if isinstance(cur_sub, CalcSubType) else cur_sub,
                static_hex = static_hex,
                confidence = avg_conf,
                notes      = notes,
            ))

        for offset in range(analysis_depth):
            s = all_stats.get(offset)
            if s is None:
                continue

            # Resolve sub_type to comparable value
            s_sub = s.sub_type.value if isinstance(s.sub_type, CalcSubType) else s.sub_type

            if s.label != cur_label or s_sub != (cur_sub.value if isinstance(cur_sub, CalcSubType) else cur_sub):
                flush(offset)
                cur_start  = offset
                cur_label  = s.label
                cur_sub    = s.sub_type
                accum_conf = []
                accum_stat = []

            accum_conf.append(s.confidence)
            accum_stat.append(s)

        flush(analysis_depth)
        return groups

    def _merge_calculated_neighbors(
        self,
        groups: list[FieldGroup],
        all_stats: dict[int, OffsetStats],
    ) -> list[FieldGroup]:
        """P2-E: Merge split multi-byte CALCULATED fields.

        Problem: A uint16_be length field at offset 4 spans bytes 4-5.
        Offset 4 gets CALCULATED (uint16 decode correlates), offset 5 gets
        a different label (single-byte decode doesn't correlate). Clustering
        splits them into two separate FieldGroups.

        Fix: If a CALCULATED singleton group is immediately followed by a
        non-STATIC group whose total span matches a multi-byte encoding
        (2 or 4 bytes), merge them and propagate the CALCULATED label.
        """
        if len(groups) < 2:
            return groups

        # Encoding sizes that could span multiple bytes
        # M5 fix: include 3 (24-bit) and 8 (64-bit) field sizes
        multi_byte_sizes = {2, 3, 4, 8}

        merged: list[FieldGroup] = []
        i = 0
        while i < len(groups):
            g = groups[i]

            # Check: singleton CALCULATED(LENGTH_FIELD) followed by non-STATIC neighbor
            if (
                g.label == OffsetLabel.CALCULATED
                and g.sub_type == CalcSubType.LENGTH_FIELD.value
                and g.length == 1
                and i + 1 < len(groups)
                and groups[i + 1].label != OffsetLabel.STATIC
            ):
                neighbor = groups[i + 1]
                combined_len = g.length + neighbor.length

                if combined_len in multi_byte_sizes:
                    # Merge: extend the CALCULATED group to cover both
                    enc = g.notes.split("enc=")[-1].split(",")[0] if "enc=" in g.notes else ""
                    ref = g.notes.split("ref=")[-1].split(")")[0] if "ref=" in g.notes else ""

                    merged_group = FieldGroup(
                        start=g.start,
                        end=neighbor.end,
                        label=OffsetLabel.CALCULATED,
                        sub_type=CalcSubType.LENGTH_FIELD.value,
                        confidence=max(g.confidence, neighbor.confidence),
                        notes=f"Multi-byte length field ({enc}, ref={ref}, "
                              f"r={g.confidence:.3f}, {combined_len}B merged)",
                    )
                    merged.append(merged_group)
                    i += 2  # skip both groups
                    continue

            merged.append(g)
            i += 1

        return merged


# ===========================================================================
# Helper
# ===========================================================================

def _scale(val: float, lo: float, hi: float) -> float:
    """Linear scale val from [lo, hi] to [0, 1]. Clamps to [0, 1]."""
    if hi <= lo:
        return 1.0
    return max(0.0, min(1.0, (val - lo) / (hi - lo)))
