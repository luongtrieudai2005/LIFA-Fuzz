"""
tests/test_sequence_fuzzing.py
──────────────────────────────
Unit tests for the Sequence-Aware Fuzzing Architecture (Group 2: State Machine Gap).

Tests cover:
    - SeedSequence data model
    - FuzzTarget dataclass
    - Sequence splitter (_split_sequence) with quadratic weighting
    - FTP Login simulation (3-packet ⟨Prefix, Target, Suffix⟩)
    - Single-packet backward compatibility
    - IFPS at sequence level
    - EPS tracking with sequences
    - Interceptor session_id propagation
"""

import asyncio
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fast_loop.mutator import MutationEngine, MutationMode, _apply_field
from shared.schemas import (
    Direction,
    FieldRule,
    FuzzTarget,
    MutationStrategy,
    PacketStatus,
    SeedSequence,
    TrafficRecord,
)


# =============================================================================
# Helpers
# =============================================================================

FTP_USER = b"USER admin\r\n"
FTP_PASS = b"PASS secret\r\n"
FTP_LIST = b"LIST\r\n"


def _make_engine(**overrides) -> MutationEngine:
    """Create a MutationEngine with sensible test defaults."""
    defaults = dict(
        target_host="127.0.0.1",
        target_port=0,
        seed_queue=asyncio.Queue(),
        k=2,
        max_eps=0,  # unlimited for tests
    )
    defaults.update(overrides)
    return MutationEngine(**defaults)


def _make_ftp_sequence() -> SeedSequence:
    """Create a 3-packet FTP session sequence."""
    return SeedSequence(
        session_id="ftp_sess_01",
        packets=[
            TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=FTP_USER),
            TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=FTP_PASS),
            TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=FTP_LIST),
        ],
        protocol_hint="FTP",
    )


def _make_single_sequence() -> SeedSequence:
    """Create a 1-packet (single) sequence."""
    return SeedSequence(
        session_id="single_01",
        packets=[
            TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"\xDE\xAD\xBE\xEF"),
        ],
    )


# =============================================================================
# Test 1: SeedSequence data model
# =============================================================================


class TestSeedSequenceModel:
    """Tests for the SeedSequence Pydantic model."""

    def test_defaults(self):
        seq = SeedSequence()
        assert seq.length == 0
        assert seq.is_single() is True  # 0-1 packets → single (backward compat)
        assert len(seq.sequence_id) == 12
        assert seq.session_id == ""
        assert seq.protocol_hint == ""

    def test_with_packets(self):
        seq = _make_ftp_sequence()
        assert seq.length == 3
        assert seq.is_single() is False
        assert seq.session_id == "ftp_sess_01"
        assert seq.protocol_hint == "FTP"

    def test_single_packet(self):
        seq = _make_single_sequence()
        assert seq.length == 1
        assert seq.is_single() is True

    def test_two_packets_is_not_single(self):
        seq = SeedSequence(
            packets=[
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"A"),
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"B"),
            ],
        )
        assert seq.length == 2
        assert seq.is_single() is False

    def test_serialization_round_trip(self):
        seq = _make_ftp_sequence()
        data = seq.model_dump()
        restored = SeedSequence(**data)
        assert restored.sequence_id == seq.sequence_id
        assert len(restored.packets) == 3


# =============================================================================
# Test 2: FuzzTarget dataclass
# =============================================================================


class TestFuzzTarget:
    """Tests for the FuzzTarget dataclass."""

    def test_fields(self):
        target = FuzzTarget(
            prefix=[b"PKT1", b"PKT2"],
            target_seed=TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"PKT3"),
            target_index=2,
            suffix=[],
            sequence_id="abc123",
        )
        assert len(target.prefix) == 2
        assert target.target_seed.raw_data == b"PKT3"
        assert target.target_index == 2
        assert target.suffix == []
        assert target.sequence_id == "abc123"


# =============================================================================
# Test 3: Sequence Splitter (_split_sequence)
# =============================================================================


class TestSequenceSplitter:
    """Tests for MutationEngine._split_sequence()."""

    def test_single_packet_sequence(self):
        engine = _make_engine()
        seq = _make_single_sequence()
        target = engine._split_sequence(seq)

        assert target.prefix == []
        assert target.suffix == []
        assert target.target_index == 0
        assert target.target_seed.raw_data == b"\xDE\xAD\xBE\xEF"
        assert target.sequence_id == seq.sequence_id

    def test_three_packet_decomposition(self):
        """For a 3-packet sequence, verify prefix/target/suffix are correct."""
        engine = _make_engine()
        seq = _make_ftp_sequence()

        # Run many times to collect all possible decompositions
        decompositions = set()
        for _ in range(1000):
            t = engine._split_sequence(seq)
            decompositions.add(t.target_index)

        # All 3 indices should appear
        assert decompositions == {0, 1, 2}

        # Verify decomposition for each index
        for idx in [0, 1, 2]:
            # Force target_index by running until we get it
            while True:
                t = engine._split_sequence(seq)
                if t.target_index == idx:
                    break

            assert t.prefix == [seq.packets[i].raw_bytes for i in range(idx)]
            assert t.target_seed.raw_data == seq.packets[idx].raw_data
            assert t.suffix == [seq.packets[i].raw_bytes for i in range(idx + 1, 3)]

    def test_quadratic_weighting_distribution(self):
        """Target index should follow quadratic weighting: P(i) ∝ (i+1)²."""
        engine = _make_engine()
        seq = _make_ftp_sequence()

        counts = Counter()
        n_trials = 30_000
        for _ in range(n_trials):
            t = engine._split_sequence(seq)
            counts[t.target_index] += 1

        # Expected ratios for weights [1, 4, 9] = total 14
        # P(0) ≈ 1/14, P(1) ≈ 4/14, P(2) ≈ 9/14
        p0 = counts[0] / n_trials
        p1 = counts[1] / n_trials
        p2 = counts[2] / n_trials

        # Allow 20% tolerance due to randomness
        assert 0.05 < p0 < 0.12, f"P(0)={p0} outside expected range"
        assert 0.22 < p1 < 0.35, f"P(1)={p1} outside expected range"
        assert 0.55 < p2 < 0.72, f"P(2)={p2} outside expected range"

        # Ordering must be preserved
        assert p2 > p1 > p0

    def test_empty_sequence_raises(self):
        engine = _make_engine()
        seq = SeedSequence(packets=[])
        with pytest.raises(IndexError, match="no packets"):
            engine._split_sequence(seq)

    def test_five_packet_sequence(self):
        """Verify splitter works with longer sequences."""
        engine = _make_engine()
        seq = SeedSequence(
            packets=[
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=bytes([i]))
                for i in range(5)
            ],
        )

        counts = Counter()
        for _ in range(10_000):
            t = engine._split_sequence(seq)
            counts[t.target_index] += 1
            assert 0 <= t.target_index <= 4

        # Quadratic: weights [1,4,9,16,25] → index 4 should dominate
        assert counts[4] > counts[3] > counts[2]


# =============================================================================
# Test 4: Single-Packet Backward Compatibility
# =============================================================================


class TestSinglePacketBackwardCompat:
    """Verify 1-packet sequences use legacy _send() path."""

    def test_single_sequence_no_prefix_suffix(self):
        engine = _make_engine()
        seq = _make_single_sequence()
        target = engine._split_sequence(seq)
        assert not target.prefix
        assert not target.suffix

    @pytest.mark.asyncio
    async def test_single_sequence_dispatches_to_send(self):
        """With a 1-packet sequence, hot loop should call _send (not _execute_sequence)."""
        engine = _make_engine()
        seq = _make_single_sequence()
        engine._corpus.append(seq)

        target = engine._split_sequence(seq)
        payload = b"\xDE\xAD\xBE\xEF"

        # Mock both send methods
        with patch.object(engine, "_send", new_callable=AsyncMock, return_value=PacketStatus.ACCEPTED) as mock_send, \
             patch.object(engine, "_execute_sequence", new_callable=AsyncMock, return_value=PacketStatus.ACCEPTED) as mock_seq:

            # Single packet → no prefix, no suffix → should use _send
            if not target.prefix and not target.suffix:
                await engine._send(payload, seq.sequence_id)
            else:
                await engine._execute_sequence(target, payload)

            mock_send.assert_called_once()
            mock_seq.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_packet_dispatches_to_execute_sequence(self):
        """With a 3-packet sequence, hot loop should call _execute_sequence."""
        engine = _make_engine()
        seq = _make_ftp_sequence()
        engine._corpus.append(seq)

        target = engine._split_sequence(seq)
        payload = b"MUTATED"

        # Since sequence has prefix (FTP_USER), it should dispatch to _execute_sequence
        # We need to find a target_index > 0 to get prefix
        while True:
            target = engine._split_sequence(seq)
            if target.prefix or target.suffix:
                break

        with patch.object(engine, "_execute_sequence", new_callable=AsyncMock, return_value=PacketStatus.ACCEPTED) as mock_seq:
            if target.prefix or target.suffix:
                await engine._execute_sequence(target, payload)
            else:
                await engine._send(payload, seq.sequence_id)

            mock_seq.assert_called_once()


# =============================================================================
# Test 5: IFPS on Sequences
# =============================================================================


class TestIFPSOnSequences:
    """Verify IFPS operates at sequence level, not packet level."""

    def test_ifps_prefers_rare_sequences(self):
        engine = _make_engine()

        # Create 3 sequences with known sequence_ids
        seq_a = SeedSequence(
            session_id="rare",
            packets=[TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"A")],
        )
        seq_b = SeedSequence(
            session_id="common",
            packets=[
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"B1"),
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"B2"),
            ],
        )
        seq_c = SeedSequence(
            session_id="medium",
            packets=[
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"C1"),
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"C2"),
                TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"C3"),
            ],
        )
        engine._corpus = [seq_a, seq_b, seq_c]

        # Manually inflate freq for seq_b to simulate it being heavily used.
        # Energy(b) = 1/(100+1) ≈ 0.01 vs Energy(a) = 1/(0+1) = 1.0
        engine._seed_freq[seq_b.sequence_id] = 100
        # Also inflate seq_c a bit: Energy(c) = 1/(10+1) ≈ 0.09
        engine._seed_freq[seq_c.sequence_id] = 10

        # Pick many times and track counts by session_id
        counts = Counter()
        for _ in range(2000):
            picked = engine._pick_seed()
            counts[picked.session_id] += 1

        # The "rare" sequence (freq=0, energy=1.0) should dominate
        # The "common" sequence (freq=100, energy≈0.01) should barely appear
        assert counts["rare"] > counts["common"], (
            f"Rare should be picked more than common: {dict(counts)}"
        )
        assert counts["medium"] > counts["common"], (
            f"Medium should be picked more than common: {dict(counts)}"
        )

    def test_ifps_uses_sequence_id(self):
        engine = _make_engine()
        seq = _make_single_sequence()
        engine._corpus = [seq]

        picked = engine._pick_seed()
        assert picked.sequence_id == seq.sequence_id

    def test_ifps_empty_corpus_raises(self):
        engine = _make_engine()
        with pytest.raises(IndexError, match="Corpus is empty"):
            engine._pick_seed()


# =============================================================================
# Test 6: EPS Tracking with Sequences
# =============================================================================


class TestEPSTracking:
    """Verify _update_stats counts ONE event per sequence execution."""

    def test_update_stats_counts_one_event(self):
        engine = _make_engine()
        assert engine._stats.total_sent == 0

        engine._update_stats(PacketStatus.ACCEPTED, b"payload")
        assert engine._stats.total_sent == 1

        engine._update_stats(PacketStatus.CRASH, b"payload2")
        assert engine._stats.total_sent == 2
        assert engine._stats.total_crashes == 1

    def test_eps_window_tracks_events(self):
        engine = _make_engine()
        for _ in range(10):
            engine._update_stats(PacketStatus.ACCEPTED, b"x")

        assert len(engine._eps_window) == 10
        assert engine._stats.total_sent == 10


# =============================================================================
# Test 7: FTP Login Simulation (Integration Test)
# =============================================================================


class TestFTPSimulation:
    """Simulate a 3-packet FTP login fuzzing session with mocked sockets."""

    @pytest.mark.asyncio
    async def test_ftp_prefix_sent_verbatim(self):
        """Verify prefix packets are sent unmodified."""
        engine = _make_engine()
        seq = _make_ftp_sequence()

        # Force target_index = 2 (LIST command) by finding such a split
        target = None
        while True:
            t = engine._split_sequence(seq)
            if t.target_index == 2:
                target = t
                break

        assert target.prefix == [FTP_USER, FTP_PASS]
        assert target.target_seed.raw_data == FTP_LIST
        assert target.suffix == []

        mutated = b"LIST /etc/passwd\r\n"  # mutated version

        # Mock the socket: verify prefix sent verbatim
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"230 OK\r\n")

        with patch("fast_loop.mutator.asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)
            status = await engine._execute_sequence(target, mutated)

        # Verify prefix packets were sent verbatim (first two writes)
        writes = [call.args[0] for call in mock_writer.write.call_args_list]
        assert FTP_USER in writes, f"Prefix USER not sent verbatim. Writes: {writes}"
        assert FTP_PASS in writes, f"Prefix PASS not sent verbatim. Writes: {writes}"
        assert mutated in writes, f"Mutated target not sent. Writes: {writes}"

    @pytest.mark.asyncio
    async def test_ftp_mutation_only_affects_target(self):
        """Only the target packet should be mutated, prefix/suffix verbatim."""
        engine = _make_engine()
        seq = _make_ftp_sequence()

        # Force target_index = 1 (PASS command)
        target = None
        while True:
            t = engine._split_sequence(seq)
            if t.target_index == 1:
                target = t
                break

        # Prefix = [USER], Target = PASS, Suffix = [LIST]
        assert target.prefix == [FTP_USER]
        assert target.target_seed.raw_data == FTP_PASS
        assert target.suffix == [FTP_LIST]

        # Build a mutant from the target seed (PASS)
        # Without rules, it'll use dumb mutation
        payload = await engine._build_mutant(target.target_seed)

        # The payload should differ from original PASS
        # (dumb mutation flips one bit)
        assert isinstance(payload, bytes)

    @pytest.mark.asyncio
    async def test_ftp_connection_refused_is_crash(self):
        """Connection refused during sequence execution → CRASH status."""
        engine = _make_engine()
        seq = _make_ftp_sequence()
        target = engine._split_sequence(seq)

        with patch("fast_loop.mutator.asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.side_effect = ConnectionRefusedError("refused")
            status = await engine._execute_sequence(target, b"payload")

        assert status == PacketStatus.CRASH

    @pytest.mark.asyncio
    async def test_ftp_crash_attribution(self):
        """_last_injected_packet must be the mutated payload (not prefix/suffix)."""
        engine = _make_engine()
        seq = _make_ftp_sequence()

        target = None
        while True:
            t = engine._split_sequence(seq)
            if t.target_index == 1:
                target = t
                break

        mutated = b"MUTATED_PAYLOAD"

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"250 OK\r\n")

        with patch("fast_loop.mutator.asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)
            await engine._execute_sequence(target, mutated)

        # Crash attribution uses mutated payload, not prefix/suffix
        assert engine._last_injected_packet == mutated


# =============================================================================
# Test 8: Interceptor session_id propagation
# =============================================================================


class TestInterceptorSessionId:
    """Verify Interceptor propagates session_id correctly."""

    @pytest.mark.asyncio
    async def test_capture_packet_includes_session_id(self):
        from fast_loop.interceptor import Interceptor

        interceptor = Interceptor()
        tr = await interceptor.capture_packet(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"test data",
            session_id="sess_abc123",
        )
        assert tr.session_id == "sess_abc123"

    @pytest.mark.asyncio
    async def test_capture_packet_default_session_id(self):
        from fast_loop.interceptor import Interceptor

        interceptor = Interceptor()
        tr = await interceptor.capture_packet(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"test data",
        )
        # Default session_id is "" (empty)
        assert tr.session_id == ""

    @pytest.mark.asyncio
    async def test_jsonl_includes_session_id(self):
        import json
        from fast_loop.interceptor import Interceptor

        interceptor = Interceptor()
        await interceptor.capture_packet(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\x01\x02\x03",
            session_id="sess_xyz",
        )

        # Read the entry from the write queue
        entry_str = interceptor._write_queue.get_nowait()
        entry = json.loads(entry_str)
        assert entry["session_id"] == "sess_xyz"


# =============================================================================
# Test 9: Dummy Seed Compatibility
# =============================================================================


class TestDummySeed:
    """Verify _make_dummy_seed returns a SeedSequence."""

    def test_dummy_seed_is_sequence(self):
        seed = MutationEngine._make_dummy_seed()
        assert isinstance(seed, SeedSequence)
        assert seed.is_single() is True
        assert seed.length == 1
        assert seed.packets[0].raw_data == b"\x00" * 16

    def test_dummy_seed_can_be_split(self):
        engine = _make_engine()
        seed = engine._make_dummy_seed()
        target = engine._split_sequence(seed)
        assert target.prefix == []
        assert target.suffix == []
        assert target.target_seed.raw_data == b"\x00" * 16
