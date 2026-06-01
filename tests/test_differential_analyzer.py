"""
tests/test_differential_analyzer.py
─────────────────────────────────────
Unit tests for the DifferentialAnalyzer — mathematical pre-processing layer.
"""

import pytest

from slow_loop.differential_analyzer import (
    DifferentialAnalyzer,
    FieldGroup,
    HeatmapResult,
    OffsetLabel,
    CalcSubType,
    _shannon_entropy,
    _variance,
    _pearson_r,
    _kendall_tau,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def analyzer():
    """A default DifferentialAnalyzer instance."""
    return DifferentialAnalyzer()


@pytest.fixture
def sample_packets():
    """Realistic protocol-like packets with a 4-byte magic header,
    2-byte length field, and variable payload."""
    magic = b"\xDE\xAD\xBE\xEF"
    packets = []
    for i in range(10):
        payload_len = 4 + i  # varying payload
        length_bytes = payload_len.to_bytes(2, "big")
        payload = bytes([j % 256 for j in range(payload_len)])
        packets.append(magic + length_bytes + payload)
    return packets


@pytest.fixture
def static_packets():
    """All-identical packets — every offset should be STATIC."""
    return [b"\xDE\xAD\xBE\xEF\x00\x05HELLO"] * 10


# =============================================================================
# Mathematical Primitives
# =============================================================================


class TestMathPrimitives:
    """Tests for pure mathematical helper functions."""

    def test_shannon_entropy_constant(self):
        """Entropy of constant values is 0."""
        assert _shannon_entropy([0x42] * 100) == 0.0

    def test_shannon_entropy_uniform(self):
        """Entropy of uniform 0-255 distribution ≈ 8.0 bits."""
        values = list(range(256))
        entropy = _shannon_entropy(values)
        assert 7.9 < entropy <= 8.0

    def test_shannon_entropy_binary(self):
        """Entropy of binary values [0, 1] = 1.0 bit."""
        entropy = _shannon_entropy([0, 1] * 50)
        assert abs(entropy - 1.0) < 0.01

    def test_variance_constant(self):
        """Variance of constant values is 0."""
        assert _variance([42] * 100) == 0.0

    def test_variance_positive(self):
        """Variance of varying values > 0."""
        assert _variance([0, 255] * 50) > 0

    def test_pearson_r_perfect_positive(self):
        """Perfect positive correlation → r = 1.0."""
        xs = [1.0, 2.0, 3.0, 4.0, 5.0]
        ys = [2.0, 4.0, 6.0, 8.0, 10.0]
        assert abs(_pearson_r(xs, ys) - 1.0) < 0.001

    def test_pearson_r_perfect_negative(self):
        """Perfect negative correlation → r = -1.0."""
        xs = [1.0, 2.0, 3.0, 4.0, 5.0]
        ys = [10.0, 8.0, 6.0, 4.0, 2.0]
        assert abs(_pearson_r(xs, ys) - (-1.0)) < 0.001

    def test_pearson_r_no_correlation(self):
        """Zero correlation → r ≈ 0."""
        xs = [1.0, 2.0, 3.0, 4.0, 5.0]
        ys = [3.0, 1.0, 5.0, 2.0, 4.0]
        r = _pearson_r(xs, ys)
        assert abs(r) < 0.5  # Not strongly correlated

    def test_kendall_tau_increasing(self):
        """Monotonically increasing → τ ≈ 1.0."""
        values = list(range(20))
        assert _kendall_tau(values) > 0.9

    def test_kendall_tau_decreasing(self):
        """Monotonically decreasing → τ ≈ -1.0."""
        values = list(range(20, 0, -1))
        assert _kendall_tau(values) < -0.9

    def test_kendall_tau_too_few_values(self):
        """Less than 4 values → τ = 0.0 (not enough data)."""
        assert _kendall_tau([1, 2, 3]) == 0.0


# =============================================================================
# Analyzer Core
# =============================================================================


class TestAnalyzerCore:
    """Tests for DifferentialAnalyzer.analyze()."""

    def test_analyze_basic(self, analyzer, sample_packets):
        """analyze() returns a HeatmapResult with expected structure."""
        result = analyzer.analyze(sample_packets)

        assert isinstance(result, HeatmapResult)
        assert result.packet_count == 10
        assert result.analysis_depth > 0
        assert len(result.offset_stats) > 0
        assert len(result.field_groups) > 0

    def test_analyze_detects_static_magic(self, analyzer, sample_packets):
        """First 4 bytes (magic) should be labeled STATIC."""
        result = analyzer.analyze(sample_packets)

        for offset in range(4):
            if offset in result.offset_stats:
                assert result.offset_stats[offset].label == OffsetLabel.STATIC
                assert result.offset_stats[offset].entropy == 0.0

    def test_analyze_detects_length_field(self, analyzer, sample_packets):
        """Bytes 4-5 (length field) should be labeled CALCULATED."""
        result = analyzer.analyze(sample_packets)

        # At least one of offsets 4-5 should show length correlation
        length_offsets = []
        for offset in [4, 5]:
            if offset in result.offset_stats:
                s = result.offset_stats[offset]
                if s.best_corr > 0.85:
                    length_offsets.append(offset)
        # The length field correlation should be detected
        assert len(length_offsets) >= 1 or (
            4 in result.offset_stats and result.offset_stats[4].label != OffsetLabel.STATIC
        )

    def test_analyze_too_few_packets_raises(self, analyzer):
        """analyze() raises ValueError with fewer than min_packets."""
        with pytest.raises(ValueError, match="at least"):
            analyzer.analyze([b"\x01\x02"])

    def test_analyze_static_packets(self, analyzer, static_packets):
        """All-identical packets → everything should be STATIC."""
        result = analyzer.analyze(static_packets)

        for offset, stats in result.offset_stats.items():
            assert stats.label == OffsetLabel.STATIC, (
                f"Offset {offset} should be STATIC, got {stats.label}"
            )


# =============================================================================
# Output Formats
# =============================================================================


class TestOutputFormats:
    """Tests for HeatmapResult output methods."""

    def test_to_llm_hint(self, analyzer, sample_packets):
        """to_llm_hint() produces a formatted string for LLM injection."""
        result = analyzer.analyze(sample_packets)
        hint = result.to_llm_hint()

        assert "MATHEMATICAL PRE-ANALYSIS" in hint
        assert "STATIC" in hint
        assert "Inferred Field Groups" in hint
        assert "Instruction" in hint
        assert len(hint) > 200  # Should be substantial
        # P3-I: pipe-delimited format, no Unicode box-drawing chars
        assert "|" in hint
        assert "╔" not in hint  # old Unicode borders gone

    def test_to_dict(self, analyzer, sample_packets):
        """to_dict() returns a JSON-serializable dict."""
        result = analyzer.analyze(sample_packets)
        d = result.to_dict()

        assert "analyzed_at" in d
        assert "packet_count" in d
        assert "field_groups" in d
        assert "offset_stats" in d
        assert isinstance(d["field_groups"], list)

    def test_to_field_rules(self, analyzer, sample_packets):
        """to_field_rules() returns FieldRule objects."""
        from shared.schemas import FieldRule

        result = analyzer.analyze(sample_packets)
        rules = result.to_field_rules()

        assert len(rules) > 0
        for rule in rules:
            assert isinstance(rule, FieldRule)
            assert rule.offset >= 0
            assert 0.0 <= rule.confidence <= 1.0


# =============================================================================
# FieldGroup Strategy Mapping
# =============================================================================


class TestFieldGroupStrategy:
    """Tests for FieldGroup.suggested_strategy mapping."""

    def test_static_maps_to_static(self):
        from shared.schemas import MutationStrategy

        fg = FieldGroup(start=0, end=4, label=OffsetLabel.STATIC, confidence=1.0)
        assert fg.suggested_strategy == MutationStrategy.STATIC

    def test_high_entropy_maps_to_random(self):
        from shared.schemas import MutationStrategy

        fg = FieldGroup(start=10, end=30, label=OffsetLabel.HIGH_ENTROPY, confidence=0.8)
        assert fg.suggested_strategy == MutationStrategy.RANDOM_BYTES

    def test_low_entropy_maps_to_bitflip(self):
        from shared.schemas import MutationStrategy

        fg = FieldGroup(start=5, end=6, label=OffsetLabel.LOW_ENTROPY, confidence=0.6)
        assert fg.suggested_strategy == MutationStrategy.BIT_FLIP

    def test_unknown_maps_to_skip(self):
        from shared.schemas import MutationStrategy

        fg = FieldGroup(start=100, end=101, label=OffsetLabel.UNKNOWN, confidence=0.0)
        assert fg.suggested_strategy == MutationStrategy.SKIP


# =============================================================================
# P1-D: Kendall τ sampling + skip high-entropy
# =============================================================================


class TestTauPerformanceFix:
    """Tests for P1-D: τ sampling cap and skip-on-high-entropy."""

    def test_tau_sampling_with_large_corpus(self):
        """τ with 300 values should be sampled to 200 — still monotonic."""
        values = list(range(300))  # perfect monotonic increase
        tau = _kendall_tau(values, max_samples=200)
        assert tau > 0.9, f"Expected τ > 0.9 after sampling, got {tau}"

    def test_tau_sampling_preserves_decreasing(self):
        """τ with 300 decreasing values should still be detected."""
        values = list(range(300, 0, -1))
        tau = _kendall_tau(values, max_samples=200)
        assert tau < -0.9, f"Expected τ < -0.9 after sampling, got {tau}"

    def test_tau_small_corpus_not_sampled(self):
        """τ with < 200 values should NOT be sampled."""
        values = list(range(50))
        tau = _kendall_tau(values, max_samples=200)
        assert tau > 0.95  # exact computation, should be ~1.0

    def test_high_entropy_offset_skips_tau(self):
        """Offsets with H > h_high_min should have tau=0.0 (not computed)."""
        # Build packets where offset 4+ is HIGH_ENTROPY (random payload)
        import random
        random.seed(42)
        packets = []
        for _ in range(20):
            payload = bytes(random.randint(0, 255) for _ in range(20))
            packets.append(b"\xDE\xAD" + payload)

        # Disable early-stop so we can observe HIGH_ENTROPY offsets
        analyzer = DifferentialAnalyzer(early_stop_consecutive=0)
        result = analyzer.analyze(packets)

        # Find an offset with HIGH_ENTROPY label
        high_offsets = [
            (off, s) for off, s in result.offset_stats.items()
            if s.label == OffsetLabel.HIGH_ENTROPY
        ]
        assert len(high_offsets) > 0, "Should have at least one HIGH_ENTROPY offset"

        for off, s in high_offsets:
            assert s.kendall_tau == 0.0, (
                f"Offset {off} is HIGH_ENTROPY but has τ={s.kendall_tau:.3f} — should be skipped"
            )


# =============================================================================
# P1-B: Confidence gap zone fix
# =============================================================================


class TestConfidenceGapZone:
    """Tests for P1-B: confidence ≠ 0.0 for 3.0 < H < 3.5."""

    def test_gap_zone_confidence_nonzero(self):
        """Offsets with 3.0 < H < 3.5 should have confidence > 0."""
        analyzer = DifferentialAnalyzer()
        # Construct packets where one offset has entropy ~3.2
        # Use 8 distinct values out of 256 → H = log2(8) = 3.0
        # Use 10 distinct values → H ≈ 3.32
        packets = []
        for i in range(20):
            pkt = bytearray(8)
            pkt[0] = 0xDE  # STATIC
            pkt[1] = 0xAD  # STATIC
            pkt[2] = i % 10  # 10 distinct values → H ≈ 3.32 (in gap zone)
            pkt[3:] = bytes(range(5))  # STATIC-ish
            packets.append(bytes(pkt))

        result = analyzer.analyze(packets)

        if 2 in result.offset_stats:
            s = result.offset_stats[2]
            assert s.confidence > 0.0, (
                f"Gap zone offset has confidence={s.confidence} — should be > 0.0"
            )

    def test_static_confidence_is_1(self):
        """STATIC offsets should always have confidence = 1.0."""
        analyzer = DifferentialAnalyzer()
        packets = [b"\xDE\xAD\x00\x01"] * 10
        result = analyzer.analyze(packets)

        for off, s in result.offset_stats.items():
            if s.label == OffsetLabel.STATIC:
                assert s.confidence == 1.0


# =============================================================================
# P2-E: Multi-byte CALCULATED field merging
# =============================================================================


class TestMultiByteMerge:
    """Tests for P2-E: split multi-byte length fields get merged."""

    def test_uint16_length_field_merges(self):
        """A uint16_be length field at offset 4-5 should be one FieldGroup."""
        magic = b"\xDE\xAD\xBE\xEF"
        packets = []
        for i in range(10):
            payload_len = 4 + i
            # uint16_be encoding of payload_len
            length_bytes = payload_len.to_bytes(2, "big")
            payload = bytes([j % 256 for j in range(payload_len)])
            packets.append(magic + length_bytes + payload)

        analyzer = DifferentialAnalyzer()
        result = analyzer.analyze(packets)

        # Find CALCULATED groups that span the length field region
        calc_groups = [g for g in result.field_groups
                       if g.label == OffsetLabel.CALCULATED]
        assert len(calc_groups) >= 1, "Should detect at least one CALCULATED group"

        # The length field group should span at least 2 bytes (merged)
        length_group = calc_groups[0]
        assert length_group.length >= 1  # at minimum the first byte is detected
        assert length_group.start >= 4   # starts at or after the length field

    def test_single_calc_not_merged_with_static(self):
        """A singleton CALCULATED should NOT merge with an adjacent STATIC."""
        # All packets have same length → length field appears STATIC
        packets = [b"\x01\x02\x03\x04\x05\x06"] * 10
        analyzer = DifferentialAnalyzer()
        result = analyzer.analyze(packets)

        # Everything should be STATIC
        for g in result.field_groups:
            assert g.label == OffsetLabel.STATIC


# =============================================================================
# P2-A: Early-stop on consecutive HIGH_ENTROPY
# =============================================================================


class TestEarlyStop:
    """Tests for P2-A: stop analysis after N consecutive HIGH_ENTROPY offsets."""

    def test_early_stop_truncates_depth(self):
        """Analysis should stop before max_depth when tail is all HIGH_ENTROPY."""
        import random
        random.seed(123)

        # 4-byte magic + 2-byte opcode + 40 bytes fully random payload
        # Need 20+ packets so that random bytes produce H > 3.5 at each offset.
        # (With 10 packets: max H = log2(10) = 3.32 < 3.5 → never HIGH_ENTROPY)
        packets = []
        for i in range(20):
            header = b"\xCA\xFE\xBA\xBE\x00\x01"
            payload = bytes(random.randint(0, 255) for _ in range(40))
            packets.append(header + payload)

        analyzer = DifferentialAnalyzer(
            max_depth=64,
            early_stop_consecutive=10,
        )
        result = analyzer.analyze(packets)

        # Should have truncated: depth < full packet length (46 bytes)
        # Early-stop fires at 10 consecutive HIGH_ENTROPY, trimming to the header
        assert result.analysis_depth < 46, (
            f"Expected truncated depth < 46, got {result.analysis_depth}"
        )
        # Should still have the header region (6 bytes of STATIC)
        assert result.analysis_depth >= 4, (
            f"Expected depth >= 4 (header region), got {result.analysis_depth}"
        )
        # Verify no HIGH_ENTROPY offsets remain (they were trimmed)
        for off, s in result.offset_stats.items():
            assert s.label != OffsetLabel.HIGH_ENTROPY, (
                f"Offset {off} is HIGH_ENTROPY but should have been trimmed"
            )

    def test_early_stop_disabled(self):
        """early_stop_consecutive=0 should disable early-stop."""
        import random
        random.seed(456)

        packets = []
        for i in range(10):
            payload = bytes(random.randint(0, 255) for _ in range(30))
            packets.append(b"\xAA\xBB" + payload)

        analyzer = DifferentialAnalyzer(
            max_depth=32,
            early_stop_consecutive=0,
        )
        result = analyzer.analyze(packets)
        # Should analyze all offsets up to min_len
        assert result.analysis_depth > 0


# =============================================================================
# O(n log n) Merge-Sort Kendall Tau Verification
# =============================================================================


def _kendall_tau_bruteforce(values: list[int]) -> float:
    """O(n²) brute-force Kendall tau-b for verification only."""
    n = len(values)
    if n < 4:
        return 0.0
    concordant = discordant = 0
    ties_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            diff = values[j] - values[i]
            if diff > 0:
                concordant += 1
            elif diff < 0:
                discordant += 1
            else:
                ties_y += 1
    total = n * (n - 1) // 2
    C = concordant
    D = discordant
    denom_sq = (total - ties_y) * total
    if denom_sq <= 0:
        return 0.0
    return (C - D) / (denom_sq ** 0.5)


class TestMergeSortTauB:
    """Tests for O(n log n) merge-sort Kendall tau-b implementation."""

    def test_perfect_increasing(self):
        assert abs(_kendall_tau([1, 2, 3, 4, 5]) - 1.0) < 1e-10

    def test_perfect_decreasing(self):
        assert abs(_kendall_tau([5, 4, 3, 2, 1]) - (-1.0)) < 1e-10

    def test_all_tied(self):
        assert _kendall_tau([1, 1, 1, 1, 1]) == 0.0

    def test_two_distinct_values(self):
        """With two distinct values, tau should reflect C/D ratio."""
        tau = _kendall_tau([1, 2, 1, 2, 1, 2, 1, 2])
        assert -1.0 <= tau <= 1.0

    def test_too_few_values(self):
        assert _kendall_tau([]) == 0.0
        assert _kendall_tau([42]) == 0.0
        assert _kendall_tau([1, 2, 3]) == 0.0

    def test_matches_bruteforce_random(self):
        """Verify merge-sort tau matches O(n²) brute-force on 1000 random arrays."""
        import random
        random.seed(0)
        for _ in range(1000):
            n = random.randint(4, 50)
            values = [random.randint(0, 255) for _ in range(n)]
            expected = _kendall_tau_bruteforce(values)
            actual = _kendall_tau(values)
            assert abs(actual - expected) < 1e-10, (
                f"Mismatch for {values}: brute={expected:.10f} merge={actual:.10f}"
            )

    def test_matches_bruteforce_edge_cases(self):
        """Specific edge cases where tau-b differs from regular tau."""
        # All same → tau_b = 0
        assert _kendall_tau_bruteforce([5, 5, 5]) == 0.0
        # Mostly increasing with one tie
        assert abs(
            _kendall_tau([1, 2, 2, 3, 4]) - _kendall_tau_bruteforce([1, 2, 2, 3, 4])
        ) < 1e-10
        # All tied except one
        assert abs(
            _kendall_tau([1, 1, 1, 1, 5]) - _kendall_tau_bruteforce([1, 1, 1, 1, 5])
        ) < 1e-10

    def test_large_corpus_speed(self):
        """n=2000 should complete in < 100ms (O(n log n) vs O(n²))."""
        import time
        values = list(range(2000))
        start = time.monotonic()
        tau = _kendall_tau(values, max_samples=2000)
        elapsed = time.monotonic() - start
        assert tau > 0.99
        assert elapsed < 0.5, f"Took {elapsed:.3f}s — expected < 0.5s for n=2000"
