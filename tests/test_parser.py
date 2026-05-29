"""
tests/test_parser.py
────────────────────
Unit tests for the Slow Loop Traffic Parser.

Tests cover:
    - Parser initialization
    - Bytes-to-hex conversion
    - Hex-to-bytes conversion
    - Log reading (when implemented)
    - Pattern detection (when implemented)
"""

import pytest

from slow_loop.parser import TrafficParser
from shared.schemas import Direction, TrafficRecord


class TestParserInit:
    """Tests for TrafficParser initialization."""

    def test_default_params(self):
        """Parser initializes with default parameters."""
        parser = TrafficParser()
        assert str(parser.log_path) == "/tmp/lifa_traffic.log"
        assert parser.read_interval_ms == 5000
        assert parser.max_samples_per_batch == 20

    def test_custom_params(self):
        """Parser initializes with custom parameters."""
        parser = TrafficParser(
            log_path="/var/log/test.log",
            read_interval_ms=1000,
            max_samples_per_batch=50,
        )
        assert str(parser.log_path) == "/var/log/test.log"
        assert parser.read_interval_ms == 1000
        assert parser.max_samples_per_batch == 50


class TestParserParseLog:
    """Tests for traffic log reading."""

    @pytest.mark.asyncio
    async def test_parse_log_raises_not_implemented(self):
        """parse_log() should raise NotImplementedError in Phase 3."""
        parser = TrafficParser()
        with pytest.raises(NotImplementedError):
            await parser.parse_log()


class TestParserPatternDetection:
    """Tests for lightweight pattern detection."""

    def test_infer_basic_structure_raises_not_implemented(self):
        """infer_basic_structure() should raise NotImplementedError in Phase 3."""
        parser = TrafficParser()
        with pytest.raises(NotImplementedError):
            parser.infer_basic_structure([])

    def test_find_common_prefix_raises_not_implemented(self):
        """find_common_prefix() should raise NotImplementedError in Phase 3."""
        with pytest.raises(NotImplementedError):
            TrafficParser.find_common_prefix([])

    def test_detect_length_field_raises_not_implemented(self):
        """detect_length_field() should raise NotImplementedError in Phase 3."""
        with pytest.raises(NotImplementedError):
            TrafficParser.detect_length_field([])
