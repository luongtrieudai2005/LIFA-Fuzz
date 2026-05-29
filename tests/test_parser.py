"""
tests/test_parser.py
────────────────────
Unit tests for the Slow Loop Traffic Parser.

Tests cover:
    - Parser initialization (default and custom params).
    - Incremental log reading via read_log().
    - Session grouping by temporal proximity.
    - Hex-to-ASCII conversion.
    - Hex-to-bytes conversion.
    - format_for_llm() output structure.
    - Lightweight pattern detection (common prefix, length field).
"""

import json
import time
import pytest

from slow_loop.parser import TrafficParser, InteractionSession


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_traffic_log(tmp_path):
    """Create a sample JSONL traffic log with multiple packets."""
    log_file = tmp_path / "traffic.jsonl"
    now = time.time()
    entries = [
        {
            "timestamp": now,
            "direction": "client_to_server",
            "payload": "deadbeef000b48454c4c4f5f574f524c44",
            "length": 15,
            "is_mutated": False,
        },
        {
            "timestamp": now + 0.1,
            "direction": "server_to_client",
            "payload": "deadbeef000b4543484f5f4241434b",
            "length": 14,
            "is_mutated": False,
        },
        {
            "timestamp": now + 0.2,
            "direction": "client_to_server",
            "payload": "deadbeef000648454c4c4f21",
            "length": 12,
            "is_mutated": False,
        },
        {
            "timestamp": now + 5.0,  # Large gap — should be a new session
            "direction": "client_to_server",
            "payload": "deadbeef0005574f524c44",
            "length": 11,
            "is_mutated": False,
        },
    ]
    with open(log_file, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return str(log_file)


# =============================================================================
# Parser Initialization
# =============================================================================


class TestParserInit:
    """Tests for TrafficParser initialization."""

    def test_default_params(self):
        """Parser initializes with default parameters."""
        parser = TrafficParser()
        assert str(parser.log_path) == "shared/raw_traffic.jsonl"
        assert parser.read_interval_ms == 5000

    def test_custom_params(self):
        """Parser initializes with custom parameters."""
        parser = TrafficParser(
            log_path="/var/log/test.log",
            read_interval_ms=1000,
            session_gap_threshold=3.0,
        )
        assert str(parser.log_path) == "/var/log/test.log"
        assert parser.read_interval_ms == 1000
        assert parser.session_gap_threshold == 3.0


# =============================================================================
# Log Reading
# =============================================================================


class TestParserReadLog:
    """Tests for traffic log reading."""

    @pytest.mark.asyncio
    async def test_read_log_returns_sessions(self, sample_traffic_log):
        """read_log() returns InteractionSession objects."""
        parser = TrafficParser(log_path=sample_traffic_log)
        sessions = await parser.read_log()
        assert len(sessions) == 2  # Two sessions (gap at 5.0s)
        assert isinstance(sessions[0], InteractionSession)

    @pytest.mark.asyncio
    async def test_read_log_incremental(self, sample_traffic_log):
        """Second read returns no new sessions (position advanced)."""
        parser = TrafficParser(log_path=sample_traffic_log)
        sessions1 = await parser.read_log()
        sessions2 = await parser.read_log()
        assert len(sessions1) == 2
        assert len(sessions2) == 0  # No new data

    @pytest.mark.asyncio
    async def test_read_log_missing_file(self):
        """read_log() returns empty list when log file doesn't exist."""
        parser = TrafficParser(log_path="/nonexistent/path/log.jsonl")
        sessions = await parser.read_log()
        assert sessions == []

    @pytest.mark.asyncio
    async def test_read_log_empty_file(self, tmp_path):
        """read_log() returns empty list for empty log file."""
        log_file = tmp_path / "empty.jsonl"
        log_file.write_text("")
        parser = TrafficParser(log_path=str(log_file))
        sessions = await parser.read_log()
        assert sessions == []

    @pytest.mark.asyncio
    async def test_read_log_malformed_lines(self, tmp_path):
        """read_log() skips malformed JSON lines gracefully."""
        log_file = tmp_path / "mixed.jsonl"
        log_file.write_text(
            '{"timestamp": 1.0, "direction": "client_to_server", '
            '"payload": "aa", "length": 1}\n'
            "NOT JSON\n"
            '{"timestamp": 2.0, "direction": "client_to_server", '
            '"payload": "bb", "length": 1}\n'
        )
        parser = TrafficParser(log_path=str(log_file))
        sessions = await parser.read_log()
        # Should have 1 session with 2 valid packets
        assert len(sessions) == 1
        assert sessions[0].packet_count == 2


# =============================================================================
# Session Grouping
# =============================================================================


class TestSessionGrouping:
    """Tests for temporal session grouping."""

    @pytest.mark.asyncio
    async def test_large_gap_creates_new_session(self, sample_traffic_log):
        """Packets with >2s gap are grouped into separate sessions."""
        parser = TrafficParser(
            log_path=sample_traffic_log,
            session_gap_threshold=2.0,
        )
        sessions = await parser.read_log()
        assert len(sessions) == 2
        # First session has 3 packets (gap < 2s)
        assert sessions[0].packet_count == 3
        # Second session has 1 packet
        assert sessions[1].packet_count == 1

    @pytest.mark.asyncio
    async def test_all_packets_in_one_session(self, sample_traffic_log):
        """With a large threshold, all packets are in one session."""
        parser = TrafficParser(
            log_path=sample_traffic_log,
            session_gap_threshold=10.0,
        )
        sessions = await parser.read_log()
        assert len(sessions) == 1
        assert sessions[0].packet_count == 4


# =============================================================================
# Format for LLM
# =============================================================================


class TestFormatForLLM:
    """Tests for format_for_llm() output."""

    @pytest.mark.asyncio
    async def test_format_structure(self, sample_traffic_log):
        """format_for_llm() returns the expected keys."""
        parser = TrafficParser(log_path=sample_traffic_log)
        sessions = await parser.read_log()
        payload = parser.format_for_llm(sessions)

        assert "session_count" in payload
        assert "sessions" in payload
        assert "parser_note" in payload
        assert payload["session_count"] == 2

    @pytest.mark.asyncio
    async def test_format_packet_fields(self, sample_traffic_log):
        """Each packet in formatted output has hex, ascii, direction, length."""
        parser = TrafficParser(log_path=sample_traffic_log)
        sessions = await parser.read_log()
        payload = parser.format_for_llm(sessions)

        first_session = payload["sessions"][0]
        first_packet = first_session["packets"][0]
        assert "seq" in first_packet
        assert "direction" in first_packet
        assert "hex" in first_packet
        assert "ascii" in first_packet
        assert "length" in first_packet
        assert first_packet["direction"] == "client_to_server"


# =============================================================================
# Hex Conversion
# =============================================================================


class TestHexConversion:
    """Tests for hex/ASCII conversion utilities."""

    def test_bytes_to_ascii_printable(self):
        """Printable ASCII chars are shown as-is."""
        assert TrafficParser._bytes_to_ascii("48454c4c4f") == "HELLO"

    def test_bytes_to_ascii_non_printable(self):
        """Non-printable bytes (>0x7E or <0x20) are shown as dots."""
        assert TrafficParser._bytes_to_ascii("deadbeef") == "...."

    def test_bytes_to_ascii_mixed(self):
        """Mix of non-printable bytes (<0x20, >0x7E) all become dots."""
        result = TrafficParser._bytes_to_ascii("00010203ff")
        assert result == "....."

    def test_hex_to_bytes(self):
        """hex_to_bytes() converts hex strings to bytes."""
        assert TrafficParser.hex_to_bytes("deadbeef") == b"\xde\xad\xbe\xef"

    def test_hex_to_bytes_space_separated(self):
        """hex_to_bytes() handles space-separated hex."""
        assert TrafficParser.hex_to_bytes("de ad be ef") == b"\xde\xad\xbe\xef"

    def test_hex_to_bytes_odd_length_raises(self):
        """hex_to_bytes() raises on odd-length hex strings."""
        with pytest.raises(ValueError, match="Odd-length"):
            TrafficParser.hex_to_bytes("abc")


# =============================================================================
# Pattern Detection
# =============================================================================


class TestPatternDetection:
    """Tests for lightweight local pattern detection."""

    @pytest.mark.asyncio
    async def test_find_common_prefix(self, sample_traffic_log):
        """find_common_prefix() detects the shared magic bytes."""
        parser = TrafficParser(log_path=sample_traffic_log)
        sessions = await parser.read_log()
        prefix_len, prefix_hex = TrafficParser.find_common_prefix(sessions)

        # All client→server packets share "deadbeef000"
        # (4-byte magic + first byte of length field = 0x00)
        assert prefix_len == 5
        assert prefix_hex == "deadbeef000"

    @pytest.mark.asyncio
    async def test_find_common_prefix_empty(self):
        """find_common_prefix() returns (0, '') for empty sessions."""
        result = TrafficParser.find_common_prefix([])
        assert result == (0, "")

    def test_detect_length_field(self, tmp_path):
        """detect_length_field() finds length field at correct offset."""
        # Create log with packets where bytes 4-5 (uint16 LE) = payload length
        log_file = tmp_path / "length_test.jsonl"
        now = time.time()
        # "deadbeef" + uint16_le(len of "hello") + "hello"
        entries = []
        for i, payload in enumerate([b"hello", b"world", b"test", b"abc", b"xyz"]):
            length = len(payload)
            header = b"\xDE\xAD\xBE\xEF" + length.to_bytes(2, "little")
            entries.append({
                "timestamp": now + i * 0.1,
                "direction": "client_to_server",
                "payload": (header + payload).hex(),
                "length": len(header + payload),
                "is_mutated": False,
            })
        with open(log_file, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        parser = TrafficParser(log_path=str(log_file))
        sessions = parser._group_into_sessions(entries)
        result = TrafficParser.detect_length_field(sessions)
        # Should detect the length field at offset 4, size 2
        if result:
            assert result["offset"] == 4
            assert result["size"] == 2
            assert result["correlation"] >= 0.5

    def test_detect_length_field_too_few_packets(self):
        """detect_length_field() returns None with fewer than 5 packets."""
        assert TrafficParser.detect_length_field([]) is None


# =============================================================================
# InteractionSession
# =============================================================================


class TestInteractionSession:
    """Tests for InteractionSession."""

    def test_packet_count(self):
        """packet_count returns the number of packets."""
        session = InteractionSession(session_id=0)
        session.add_packet({"timestamp": 1.0})
        session.add_packet({"timestamp": 1.1})
        assert session.packet_count == 2

    def test_total_bytes(self):
        """total_bytes sums the length of all packets."""
        session = InteractionSession(session_id=0)
        session.add_packet({"timestamp": 1.0, "length": 10})
        session.add_packet({"timestamp": 1.1, "length": 20})
        assert session.total_bytes == 30

    def test_start_end_times(self):
        """start_time and end_time track first and last packet."""
        session = InteractionSession(session_id=0)
        session.add_packet({"timestamp": 5.0})
        session.add_packet({"timestamp": 7.5})
        assert session.start_time == 5.0
        assert session.end_time == 7.5
