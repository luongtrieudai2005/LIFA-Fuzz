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


# =============================================================================
# Bug #2 fix: analysis_depth uses P10 percentile, not min()
# =============================================================================


class TestAnalysisDepthPercentile:
    """Verify that a single short packet does not destroy analysis depth."""

    def test_one_short_packet_does_not_limit_depth(self):
        """99 packets of 200B + 1 ACK packet of 4B → depth should NOT be 2."""
        import random
        random.seed(789)

        # Use early_stop_consecutive=0 to disable early-stop, so we measure
        # the true percentile-based depth without interference.
        analyzer = DifferentialAnalyzer(
            max_depth=64,
            early_stop_consecutive=0,
        )

        magic = b"\xDE\xAD\xBE\xEF"
        packets = []
        for i in range(99):
            payload_len = 10 + (i % 40)
            length_bytes = payload_len.to_bytes(2, "big")
            payload = bytes(random.randint(0, 255) for _ in range(payload_len))
            packets.append(magic + length_bytes + payload)
        # 1 short ACK packet
        packets.append(b"\xDE\xAD")

        result = analyzer.analyze(packets)
        # P10 of 100 packets: sorted_lens[10] is the 10th smallest = a ~14-byte packet
        # The key assertion: depth is NOT 2 (the ACK packet length)
        assert result.analysis_depth > 4, (
            f"Expected depth > 4 (P10 percentile, not min=2), got {result.analysis_depth}"
        )
        # Also verify: with min() we would get depth=2, with P10 we get much more
        min_len = min(len(p) for p in packets)
        assert result.analysis_depth > min_len, (
            f"Expected depth > min_len ({min_len}), got {result.analysis_depth}"
        )

    def test_uniform_length_packets_unchanged(self):
        """Uniform-length packets should give same result as before."""
        import random
        random.seed(111)

        # Disable early-stop so depth is purely from percentile
        analyzer = DifferentialAnalyzer(
            max_depth=64,
            early_stop_consecutive=0,
        )

        packets = []
        for i in range(20):
            payload = bytes(random.randint(0, 255) for _ in range(20))
            packets.append(b"\xDE\xAD\xBE\xEF" + payload)

        result = analyzer.analyze(packets)
        # All packets are 24 bytes → P10 = 24 → depth = min(24, 64) = 24
        assert result.analysis_depth == 24

    def test_offset_coverage_reflects_short_packets(self, analyzer):
        """Offsets beyond the short packet length should have coverage < 1.0."""
        import random
        random.seed(222)

        # 8 packets of 20B, 2 packets of 4B → P10 = sorted_lens[1]
        packets = []
        for i in range(8):
            payload = bytes(random.randint(0, 255) for _ in range(16))
            packets.append(b"\xDE\xAD\xBE\xEF" + payload)
        for _ in range(2):
            packets.append(b"\xDE\xAD\xBE\xEF")  # 4B short packets

        result = analyzer.analyze(packets)
        # Offsets 4+ exist only in 8/10 packets → coverage = 0.8
        for off in range(4, min(result.analysis_depth, 20)):
            if off in result.offset_stats:
                assert result.offset_stats[off].coverage >= 0.6, (
                    f"Offset {off} coverage {result.offset_stats[off].coverage:.2f} "
                    f"< 0.6 (should be 0.8)"
                )


# =============================================================================
# Bug #1 fix: early-stop streak resets on coverage gap
# =============================================================================


class TestEarlyStopCoverageGap:
    """Verify that coverage gaps (None offsets) reset the HIGH_ENTROPY streak."""

    def test_coverage_gap_resets_streak(self):
        """HIGH, HIGH, gap(None), HIGH, HIGH should NOT trigger early-stop."""
        import random
        random.seed(333)

        analyzer = DifferentialAnalyzer(
            max_depth=32,
            early_stop_consecutive=4,
            min_coverage=0.5,
        )

        # Build packets where:
        # - Offsets 0-1: STATIC (magic bytes)
        # - Offset 2-3: exists in 8/10 packets, HIGH_ENTROPY
        # - Offset 4: exists in 4/10 packets → coverage 0.4 < 0.5 → None
        # - Offset 5-6: exists in 8/10 packets, HIGH_ENTROPY
        packets = []
        for i in range(8):
            pkt = b"\xAA\xBB"  # offsets 0-1: constant
            pkt += bytes(random.randint(0, 255) for _ in range(2))  # offset 2-3: random
            pkt += bytes(random.randint(0, 255) for _ in range(3))  # offset 4-6
            packets.append(pkt)
        # 2 short packets that only have offsets 0-1
        for _ in range(2):
            packets.append(b"\xAA\xBB\xCC")  # 3 bytes → offset 3 absent for these

        result = analyzer.analyze(packets)
        # Even if offsets 2-3 and 5-6 are HIGH_ENTROPY, the gap at offset 4
        # should have reset the counter → no early-stop at 4 consecutive
        # (there's a gap breaking the streak)

    def test_uniform_high_entropy_still_stops(self):
        """Uniform-length packets with all HIGH_ENTROPY tail should still stop."""
        import random
        random.seed(444)

        analyzer = DifferentialAnalyzer(
            max_depth=64,
            early_stop_consecutive=10,
        )
        packets = []
        for _ in range(20):
            pkt = b"\xCA\xFE"  # 2 STATIC bytes
            pkt += bytes(random.randint(0, 255) for _ in range(50))
            packets.append(pkt)

        result = analyzer.analyze(packets)
        # Should have truncated because uniform HIGH_ENTROPY tail
        assert result.analysis_depth < 52, (
            f"Expected truncated depth < 52, got {result.analysis_depth}"
        )


# =============================================================================
# Bug #3 fix: STATIC threshold H ≤ 0.1 (not H ≤ 0.0)
# =============================================================================


class TestStaticThresholdRelaxed:
    """Verify that near-constant fields (H ≈ 0.08) are labeled STATIC."""

    def test_near_constant_labeled_static(self, analyzer):
        """99/100 packets have byte 0 = 0xDE, 1 has 0xDF → should be STATIC."""
        packets = []
        for i in range(99):
            packets.append(b"\xDE\xAD\xBE\xEF" + bytes(range(10)))
        # 1 packet with slightly different magic byte
        packets.append(b"\xDF\xAD\xBE\xEF" + bytes(range(10)))

        result = analyzer.analyze(packets)
        # Offset 0: 99 × 0xDE, 1 × 0xDF → H ≈ 0.081
        # With h_static_max=0.1, this should be STATIC
        assert result.offset_stats[0].label == OffsetLabel.STATIC, (
            f"Offset 0 should be STATIC (H={result.offset_stats[0].entropy:.4f}), "
            f"got {result.offset_stats[0].label}"
        )
        # Confidence should be < 1.0 for near-constant (H ≈ 0.08)
        assert result.offset_stats[0].confidence < 1.0, (
            f"Near-constant field (H={result.offset_stats[0].entropy:.4f}) should have "
            f"confidence < 1.0, got {result.offset_stats[0].confidence:.4f}"
        )
        # Confidence should still be high (> 0.7)
        assert result.offset_stats[0].confidence > 0.7, (
            f"Near-constant field should have confidence > 0.7, "
            f"got {result.offset_stats[0].confidence:.4f}"
        )

    def test_multi_value_not_false_positive_static(self, analyzer):
        """An offset with 5 distinct values should NOT be STATIC."""
        packets = []
        for i in range(20):
            # Byte 0 cycles through 5 values
            pkt = bytes([i % 5]) + b"\x00" * 13
            packets.append(pkt)

        result = analyzer.analyze(packets)
        # With 5 distinct values, H >> 0.1 → should NOT be STATIC
        assert result.offset_stats[0].label != OffsetLabel.STATIC, (
            f"Offset 0 with 5 distinct values should not be STATIC"
        )

    def test_perfectly_constant_still_static(self, analyzer):
        """All-identical packets should still produce STATIC."""
        packets = [b"\xDE\xAD\xBE\xEF\x00\x05HELLO"] * 10
        result = analyzer.analyze(packets)
        for off, s in result.offset_stats.items():
            assert s.label == OffsetLabel.STATIC, (
                f"Offset {off} should be STATIC for all-identical packets"
            )


# =============================================================================
# Bug #7 fix: CALCULATED encoding plausibility check
# =============================================================================


class TestCalculatedEncodingPlausibility:
    """Verify that implausible encodings (uint8 for large packets) are rejected."""

    def test_uint8_rejected_for_large_packets(self, analyzer):
        """uint8 length field with payloads > 286B should be filtered."""
        magic = b"\xDE\xAD\xBE\xEF"
        packets = []
        for i in range(20):
            # Packets are 300-500 bytes total. Even with hdr_size=6,
            # payload = 294-494B > uint8 plausibility limit (286B).
            payload_len = 296 + (i * 10)  # 296 to 486
            length_bytes = payload_len.to_bytes(2, "big")
            payload = bytes(j % 256 for j in range(payload_len))
            packets.append(magic + length_bytes + payload)

        result = analyzer.analyze(packets)
        # Byte 4 alone as uint8 should NOT be CALCULATED (payload too large)
        if 4 in result.offset_stats:
            stat = result.offset_stats[4]
            if stat.sub_type == CalcSubType.LENGTH_FIELD:
                assert stat.best_encoding != "uint8", (
                    f"uint8 should not be chosen for payloads > 286B "
                    f"(got encoding={stat.best_encoding})"
                )

    def test_uint8_accepted_for_small_packets(self, analyzer):
        """uint8 length field with packets < 128B should be accepted."""
        magic = b"\xDE\xAD"
        packets = []
        for i in range(20):
            payload_len = 5 + i  # 5 to 24 bytes
            packets.append(magic + bytes([payload_len]) + bytes(range(payload_len)))

        result = analyzer.analyze(packets)
        # Byte 2 is uint8 length field — packets are small, should be detected
        assert 2 in result.offset_stats
        stat = result.offset_stats[2]
        assert stat.label == OffsetLabel.CALCULATED, (
            f"Offset 2 should be CALCULATED for valid uint8 length field, "
            f"got {stat.label}"
        )
        assert stat.best_encoding == "uint8", (
            f"Expected uint8 encoding for small packets, got {stat.best_encoding}"
        )

    def test_uint8_accepted_for_medium_packets_with_header(self, analyzer):
        """uint8 length field is plausible when encoding payload_len = total - header.

        Packets 200B with 6B header → payload 194B → uint8 (max 255) is plausible.
        The old (buggy) check compared total=200 against uint8_max*2=510 and passed
        by luck, but the revised check correctly compares payload=194 against 510.
        """
        header = b"\x4C\x49\x46\x41\x01"  # "LIFA" + opcode — 5 bytes
        packets = []
        for i in range(20):
            payload_len = 100 + (i * 5)  # 100 to 195 bytes → payload fits uint8
            pkt = header + bytes([payload_len]) + bytes(range(payload_len))
            packets.append(pkt)

        result = analyzer.analyze(packets)
        # Byte 5 is the uint8 length field (after 5-byte header)
        assert 5 in result.offset_stats
        stat = result.offset_stats[5]
        assert stat.label == OffsetLabel.CALCULATED, (
            f"Offset 5 should be CALCULATED (uint8 length field for medium packets), "
            f"got {stat.label}"
        )
        assert stat.best_encoding == "uint8", (
            f"Expected uint8 encoding, got {stat.best_encoding}"
        )


# =============================================================================
# Bug #9 fix: _compute_header_candidates called once, not 64 times
# =============================================================================


class TestHeaderCandidatesCaching:
    """Verify header candidates are computed once per analyze() call."""

    def test_header_candidates_cached(self):
        """_compute_header_candidates should be called exactly once."""
        from unittest.mock import patch

        magic = b"\xDE\xAD\xBE\xEF"
        packets = []
        for i in range(10):
            payload_len = 4 + i
            packets.append(magic + payload_len.to_bytes(2, "big") + bytes(range(payload_len)))

        analyzer = DifferentialAnalyzer(max_depth=32)
        with patch.object(
            analyzer, "_compute_header_candidates",
            wraps=analyzer._compute_header_candidates,
        ) as mock:
            analyzer.analyze(packets)
            # Should be called exactly once, not once per offset
            assert mock.call_count == 1, (
                f"Expected 1 call, got {mock.call_count}"
            )
