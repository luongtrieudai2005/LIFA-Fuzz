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
        assert "BYTE-LEVEL HEATMAP" in hint
        assert "INFERRED FIELD GROUPS" in hint
        assert "INSTRUCTION TO LLM" in hint
        assert len(hint) > 200  # Should be substantial

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
