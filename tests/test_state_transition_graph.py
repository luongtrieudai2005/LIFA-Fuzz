"""
tests/test_state_transition_graph.py
─────────────────────────────────────
Tests for the State Transition Graph (STG) tracker — Step 3:
State-Coverage Expansion.

Covers:
    - StateEdge creation and equality
    - record_edge() — new vs duplicate edges
    - is_novel_seed() — novelty tracking
    - extract_ftp_command() — FTP command extraction
    - record_path() — full session path dedup
    - stats property — telemetry output
"""

from __future__ import annotations

import pytest

from fast_loop.state_transition_graph import StateEdge, StateTransitionGraph


# =============================================================================
# StateEdge
# =============================================================================


class TestStateEdge:
    """Test the StateEdge dataclass."""

    def test_creation(self):
        edge = StateEdge(prev_code="220", command="USER", new_code="331")
        assert edge.prev_code == "220"
        assert edge.command == "USER"
        assert edge.new_code == "331"

    def test_frozen(self):
        edge = StateEdge(prev_code="220", command="USER", new_code="331")
        with pytest.raises(AttributeError):
            edge.prev_code = "999"  # type: ignore[misc]

    def test_equality(self):
        e1 = StateEdge(prev_code="220", command="USER", new_code="331")
        e2 = StateEdge(prev_code="220", command="USER", new_code="331")
        assert e1 == e2

    def test_inequality(self):
        e1 = StateEdge(prev_code="220", command="USER", new_code="331")
        e2 = StateEdge(prev_code="220", command="PASS", new_code="230")
        assert e1 != e2

    def test_hashable(self):
        """StateEdge is frozen, so it's hashable (usable in sets/dicts)."""
        e = StateEdge(prev_code="220", command="USER", new_code="331")
        s = {e}
        assert e in s


# =============================================================================
# extract_ftp_command
# =============================================================================


class TestExtractFtpCommand:
    """Test FTP command extraction from payloads."""

    def test_user_command(self):
        payload = b"USER admin\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "USER"

    def test_pass_command(self):
        payload = b"PASS secret123\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "PASS"

    def test_syst_command(self):
        payload = b"SYST\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "SYST"

    def test_port_command(self):
        payload = b"PORT 127,0,0,1,4,1\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "PORT"

    def test_quit_command(self):
        payload = b"QUIT\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "QUIT"

    def test_list_command(self):
        payload = b"LIST\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "LIST"

    def test_retr_command(self):
        payload = b"RETR file.txt\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "RETR"

    def test_type_command(self):
        payload = b"TYPE I\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "TYPE"

    def test_extended_command(self):
        """Extended FTP commands (up to 6 chars)."""
        payload = b"EPRT |1|127.0.0.1|5001|\r\n"
        assert StateTransitionGraph.extract_ftp_command(payload) == "EPRT"

    def test_mutation_garbage(self):
        """Mutated packet with no valid command → UNKNOWN."""
        assert StateTransitionGraph.extract_ftp_command(b"\x00\x01\x02\x03") == "UNKNOWN"

    def test_empty_payload(self):
        assert StateTransitionGraph.extract_ftp_command(b"") == "UNKNOWN"

    def test_numeric_command(self):
        """Numbers are not valid FTP commands."""
        assert StateTransitionGraph.extract_ftp_command(b"123 abc\r\n") == "UNKNOWN"

    def test_too_long_command(self):
        """Commands longer than 6 chars → UNKNOWN."""
        assert StateTransitionGraph.extract_ftp_command(b"LONGCMDX arg\r\n") == "UNKNOWN"

    def test_case_insensitive(self):
        """Commands are uppercased regardless of input case."""
        assert StateTransitionGraph.extract_ftp_command(b"user admin\r\n") == "USER"

    def test_no_crlf(self):
        """Works even without CRLF terminator."""
        assert StateTransitionGraph.extract_ftp_command(b"USER admin") == "USER"

    def test_mutation_binary_with_embedded_text(self):
        """Binary mutation with ASCII command embedded."""
        payload = b"\xff\xfeUSER admin\x00\x01\r\n"
        # First line split by \r\n gives "\xff\xfeUSER admin\x00\x01"
        # First space-split token is "\xff\xfeUSER" — not alpha → UNKNOWN
        assert StateTransitionGraph.extract_ftp_command(payload) == "UNKNOWN"


# =============================================================================
# make_edge_key
# =============================================================================


class TestMakeEdgeKey:
    """Test edge key generation."""

    def test_basic(self):
        key = StateTransitionGraph.make_edge_key("220", "USER", "331")
        assert key == "220|USER|331"

    def test_different_order(self):
        k1 = StateTransitionGraph.make_edge_key("220", "USER", "331")
        k2 = StateTransitionGraph.make_edge_key("331", "USER", "220")
        assert k1 != k2

    def test_same_components(self):
        k1 = StateTransitionGraph.make_edge_key("220", "USER", "331")
        k2 = StateTransitionGraph.make_edge_key("220", "USER", "331")
        assert k1 == k2


# =============================================================================
# StateTransitionGraph — record_edge
# =============================================================================


class TestRecordEdge:
    """Test edge recording and novelty detection."""

    def test_new_edge_returns_true(self):
        stg = StateTransitionGraph()
        assert stg.record_edge("220", "USER", "331") is True

    def test_duplicate_edge_returns_false(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        assert stg.record_edge("220", "USER", "331") is False

    def test_different_edges_both_new(self):
        stg = StateTransitionGraph()
        assert stg.record_edge("220", "USER", "331") is True
        assert stg.record_edge("331", "PASS", "230") is True

    def test_states_tracked(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        stg.record_edge("331", "PASS", "230")
        assert stg.stats["unique_states"] == 3  # 220, 331, 230

    def test_states_deduped(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        stg.record_edge("220", "PASS", "530")
        # States: 220, 331, 530 → 3 unique
        assert stg.stats["unique_states"] == 3

    def test_edges_count(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        stg.record_edge("331", "PASS", "230")
        stg.record_edge("230", "SYST", "215")
        stg.record_edge("220", "USER", "331")  # duplicate
        assert stg.stats["unique_edges"] == 3

    def test_total_edge_records_includes_duplicates(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        stg.record_edge("220", "USER", "331")
        assert stg.stats["total_edge_records"] == 2

    def test_novel_seed_tracking(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="seq_001")
        assert stg.is_novel_seed("seq_001") is True

    def test_non_novel_seed(self):
        stg = StateTransitionGraph()
        assert stg.is_novel_seed("seq_999") is False

    def test_empty_sequence_id(self):
        """Recording without sequence_id should not crash."""
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="")
        assert stg.stats["novel_seed_count"] == 0

    def test_multiple_seeds_find_different_edges(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="seq_001")
        stg.record_edge("331", "PASS", "230", sequence_id="seq_002")
        assert stg.is_novel_seed("seq_001") is True
        assert stg.is_novel_seed("seq_002") is True
        assert stg.stats["novel_seed_count"] == 2


# =============================================================================
# StateTransitionGraph — record_path
# =============================================================================


class TestRecordPath:
    """Test full session path recording."""

    def test_new_path(self):
        stg = StateTransitionGraph()
        edges = [
            StateEdge("220", "USER", "331"),
            StateEdge("331", "PASS", "230"),
        ]
        assert stg.record_path(edges) is True

    def test_duplicate_path(self):
        stg = StateTransitionGraph()
        edges = [
            StateEdge("220", "USER", "331"),
            StateEdge("331", "PASS", "230"),
        ]
        stg.record_path(edges)
        assert stg.record_path(edges) is False

    def test_different_path(self):
        stg = StateTransitionGraph()
        path1 = [
            StateEdge("220", "USER", "331"),
            StateEdge("331", "PASS", "230"),
        ]
        path2 = [
            StateEdge("220", "USER", "331"),
            StateEdge("331", "PASS", "530"),
        ]
        assert stg.record_path(path1) is True
        assert stg.record_path(path2) is True
        assert stg.stats["unique_paths"] == 2

    def test_empty_path(self):
        stg = StateTransitionGraph()
        assert stg.record_path([]) is False

    def test_single_edge_path(self):
        stg = StateTransitionGraph()
        assert stg.record_path([StateEdge("220", "QUIT", "221")]) is True


# =============================================================================
# StateTransitionGraph — stats
# =============================================================================


class TestStats:
    """Test the stats property for telemetry output."""

    def test_empty_graph(self):
        stg = StateTransitionGraph()
        stats = stg.stats
        assert stats["unique_states"] == 0
        assert stats["unique_edges"] == 0
        assert stats["unique_paths"] == 0
        assert stats["total_edge_records"] == 0
        assert stats["novel_seed_count"] == 0

    def test_full_graph(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="s1")
        stg.record_edge("331", "PASS", "230", sequence_id="s2")
        stg.record_edge("230", "SYST", "215")
        stg.record_edge("220", "USER", "331")  # duplicate

        stats = stg.stats
        assert stats["unique_states"] == 4  # 220, 331, 230, 215
        assert stats["unique_edges"] == 3
        assert stats["total_edge_records"] == 4
        assert stats["novel_seed_count"] == 2


# =============================================================================
# StateTransitionGraph — clear_novel_seeds
# =============================================================================


class TestClearNovelSeeds:
    """Test periodic novel seed clearing."""

    def test_clear(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="s1")
        assert stg.is_novel_seed("s1") is True
        stg.clear_novel_seeds()
        assert stg.is_novel_seed("s1") is False

    def test_clear_preserves_edges(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331", sequence_id="s1")
        stg.clear_novel_seeds()
        # Edge is still there, just novelty flag cleared
        assert stg.stats["unique_edges"] == 1
        assert stg.stats["novel_seed_count"] == 0


# =============================================================================
# StateTransitionGraph — get_edges
# =============================================================================


class TestGetEdges:
    """Test edge retrieval for debugging."""

    def test_get_edges_empty(self):
        stg = StateTransitionGraph()
        assert stg.get_edges() == []

    def test_get_edges_returns_all(self):
        stg = StateTransitionGraph()
        stg.record_edge("220", "USER", "331")
        stg.record_edge("331", "PASS", "230")
        edges = stg.get_edges()
        assert len(edges) == 2
        edge_keys = {(e.prev_code, e.command, e.new_code) for e in edges}
        assert ("220", "USER", "331") in edge_keys
        assert ("331", "PASS", "230") in edge_keys


# =============================================================================
# NOVELTY_ENERGY_MULTIPLIER
# =============================================================================


class TestNoveltyMultiplier:
    """Test the multiplier constant is accessible."""

    def test_multiplier_value(self):
        assert StateTransitionGraph.NOVELTY_ENERGY_MULTIPLIER == 5.0

    def test_multiplier_type(self):
        assert isinstance(StateTransitionGraph.NOVELTY_ENERGY_MULTIPLIER, float)
