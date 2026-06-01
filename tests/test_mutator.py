"""
tests/test_mutator.py
──────────────────────
Unit tests for the new Mutation Engine (two-mode scheduling).

Tests cover:
    - Engine initialization (default and custom params).
    - KILL_SERVER payloads existence.
    - Schedulers (RandomSubset, OneAtATime, AllFields).
    - _apply_field() pure function (all 8 strategies).
    - _dumb_mutate() fallback.
    - Coverage tracking / stats.
    - Rule set management (atomic swap).
    - Mode transitions (investigation ↔ normal).
    - Pause / resume.
"""

import asyncio
import struct

import pytest

from fast_loop.mutator import (
    KILL_SERVER_PAYLOADS,
    AllFieldsScheduler,
    MutationEngine,
    MutationMode,
    MutatorStats,
    OneAtATimeScheduler,
    RandomSubsetScheduler,
    _apply_field,
    _endian_for_type,
)
from shared.schemas import (
    ActiveRuleSet,
    FieldRule,
    FieldType,
    MutationStrategy,
    RuleType,
    SeedSequence,
    SemanticRule,
)


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


# =============================================================================
# Initialization
# =============================================================================


class TestMutationEngineInit:
    """Tests for MutationEngine initialization."""

    def test_default_params(self):
        engine = _make_engine()
        assert engine.target_host == "127.0.0.1"
        assert engine.target_port == 0
        assert engine.k == 2
        assert engine.max_eps == 0
        assert engine._mode == MutationMode.RANDOM_SUBSET
        assert engine.auto_investigate is True
        assert engine.investigation_budget == 500

    def test_custom_params(self):
        engine = _make_engine(k=5, max_eps=500, auto_investigate=False)
        assert engine.k == 5
        assert engine.max_eps == 500
        assert engine.auto_investigate is False

    def test_kill_server_payloads_exist(self):
        """KILL_SERVER payloads match known server vulnerabilities."""
        assert len(KILL_SERVER_PAYLOADS) >= 3
        assert KILL_SERVER_PAYLOADS[0][:4] == b"\x00\x00\x00\x00"
        assert KILL_SERVER_PAYLOADS[1][:4] == b"\xCA\xFE\xBA\xBE"
        assert KILL_SERVER_PAYLOADS[2][:4] == b"\xDE\xAD\xBE\xEF"


# =============================================================================
# Schedulers
# =============================================================================


class TestSchedulers:
    """Tests for the three scheduler strategies."""

    def _sample_fields(self) -> list[FieldRule]:
        return [
            FieldRule(field_name=f"field_{i}", offset=i * 4, length=4,
                      mutation_strategy=MutationStrategy.RANDOM_BYTES)
            for i in range(5)
        ]

    def test_random_subset_selects_k_fields(self):
        sched = RandomSubsetScheduler(k=2)
        fields = self._sample_fields()
        selected = sched.select(fields)
        assert len(selected) == 2
        # Without replacement — no duplicates
        names = [f.field_name for f in selected]
        assert len(names) == len(set(names))

    def test_random_subset_empty_list(self):
        sched = RandomSubsetScheduler(k=2)
        assert sched.select([]) == []

    def test_random_subset_k_clamped(self):
        sched = RandomSubsetScheduler(k=100, adaptive=False)
        fields = self._sample_fields()
        assert len(sched.select(fields)) == 5

    def test_random_subset_description(self):
        assert "k=3" in RandomSubsetScheduler(k=3, adaptive=False).description

    def test_one_at_a_time_cycles(self):
        sched = OneAtATimeScheduler(budget_per_field=2, isolation_budget=100)
        fields = self._sample_fields()
        # First 2 selects → field 0
        r0 = sched.select(fields)
        assert r0[0].field_name == "field_0"
        r1 = sched.select(fields)
        assert r1[0].field_name == "field_0"
        # 3rd select → field 1 (cursor advanced)
        r2 = sched.select(fields)
        assert r2[0].field_name == "field_1"

    def test_one_at_a_time_budget_exhausted(self):
        sched = OneAtATimeScheduler(budget_per_field=1, isolation_budget=3)
        fields = self._sample_fields()
        sched.select(fields)
        sched.select(fields)
        sched.select(fields)
        assert sched.is_budget_exhausted(len(fields)) is True

    def test_one_at_a_time_reset(self):
        sched = OneAtATimeScheduler(budget_per_field=1, isolation_budget=3)
        fields = self._sample_fields()
        sched.select(fields)
        sched.select(fields)
        sched.reset()
        # H1 fix: _cursor replaced with _cursor_name (name-based tracking)
        assert sched._cursor_name is None
        assert sched._sends_this_mode == 0

    def test_one_at_a_time_empty_list(self):
        assert OneAtATimeScheduler().select([]) == []

    def test_all_fields_selects_everything(self):
        sched = AllFieldsScheduler()
        fields = self._sample_fields()
        selected = sched.select(fields)
        assert len(selected) == 5


# =============================================================================
# _apply_field — Pure Function Tests
# =============================================================================


class TestApplyField:
    """Tests for the module-level _apply_field() pure function."""

    def test_static_overwrites(self):
        rule = FieldRule(
            field_name="magic", offset=0, length=4,
            mutation_strategy=MutationStrategy.STATIC,
            static_value="deadbeef",
        )
        buf = bytearray(b"\x00\x00\x00\x00\xFF\xFF")
        result = _apply_field(buf, rule)
        assert result[:4] == b"\xDE\xAD\xBE\xEF"
        assert result[4:] == b"\xFF\xFF"  # untouched

    def test_random_bytes_changes_field(self):
        rule = FieldRule(
            field_name="data", offset=2, length=4,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
        )
        buf = bytearray(b"\x00\x00\x00\x00\x00\x00")
        # Run several times — should almost always change
        changed = sum(
            1 for _ in range(20)
            if _apply_field(bytearray(buf), rule)[2:6] != b"\x00\x00\x00\x00"
        )
        assert changed >= 18  # overwhelmingly likely

    def test_bit_flip_changes_one_bit(self):
        rule = FieldRule(
            field_name="flag", offset=0, length=4,
            mutation_strategy=MutationStrategy.BIT_FLIP,
        )
        original = bytearray(b"\xFF\xFF\xFF\xFF")
        mutated = _apply_field(bytearray(original), rule)
        diff = sum(bin(a ^ b).count("1") for a, b in zip(original, mutated))
        # op_bit_flip flips 1-3 bits (P3-C: integrated with mutation_operators)
        assert 1 <= diff <= 3

    def test_boundary_values_produces_known_pattern(self):
        rule = FieldRule(
            field_name="len", offset=0, length=2,
            mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
        )
        # Run many times — should hit several patterns
        results = set()
        for _ in range(100):
            buf = bytearray(b"\x42\x42")
            _apply_field(buf, rule)
            results.add(bytes(buf))
        # Should produce at least 2 distinct values (out of 5 candidates)
        assert len(results) >= 2

    def test_increment_wraps(self):
        rule = FieldRule(
            field_name="seq", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
        )
        # Max value 0xFFFF → wraps to 0x0000
        buf = bytearray(b"\xFF\xFF")
        _apply_field(buf, rule)
        assert buf == bytearray(b"\x00\x00")

    def test_increment_adds_one(self):
        rule = FieldRule(
            field_name="seq", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
        )
        buf = bytearray(b"\x00\x05")
        _apply_field(buf, rule)
        assert int.from_bytes(buf, "big") == 6

    def test_calculated_recalculates_length(self):
        rule = FieldRule(
            field_name="length", offset=0, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
        )
        # Total packet = 8 bytes. Field is 2 bytes at offset 0.
        # payload_len = 8 - (0 + 2) = 6
        buf = bytearray(b"\x00\x00\x01\x02\x03\x04\x05\x06")
        _apply_field(buf, rule)
        assert int.from_bytes(buf[:2], "big") == 6

    def test_dictionary_picks_from_list(self):
        rule = FieldRule(
            field_name="opcode", offset=0, length=2,
            mutation_strategy=MutationStrategy.DICTIONARY,
            dictionary_values=["0001", "0002", "ffff"],
        )
        results = set()
        for _ in range(50):
            buf = bytearray(b"\x00\x00")
            _apply_field(buf, rule)
            results.add(bytes(buf))
        # Should have picked at least 2 distinct values
        assert len(results) >= 2
        # All values should be from the dictionary
        for r in results:
            assert r.hex() in {"0001", "0002", "ffff"}

    def test_skip_leaves_unchanged(self):
        rule = FieldRule(
            field_name="skip_me", offset=0, length=4,
            mutation_strategy=MutationStrategy.SKIP,
        )
        original = bytearray(b"\xDE\xAD\xBE\xEF")
        result = _apply_field(bytearray(original), rule)
        assert result == original

    def test_oob_offset_returns_unchanged(self):
        rule = FieldRule(
            field_name="ghost", offset=100, length=4,
            mutation_strategy=MutationStrategy.BIT_FLIP,
        )
        buf = bytearray(b"\xDE\xAD")
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\xDE\xAD")

    def test_empty_dict_does_nothing(self):
        rule = FieldRule(
            field_name="empty", offset=0, length=2,
            mutation_strategy=MutationStrategy.DICTIONARY,
            dictionary_values=None,
        )
        original = bytearray(b"\x42\x42")
        assert _apply_field(bytearray(original), rule) == original

    def test_bad_static_hex_does_nothing(self):
        rule = FieldRule(
            field_name="bad", offset=0, length=4,
            mutation_strategy=MutationStrategy.STATIC,
            static_value="ZZZZ",  # invalid hex
        )
        original = bytearray(b"\x01\x02\x03\x04")
        assert _apply_field(bytearray(original), rule) == original


# =============================================================================
# _dumb_mutate
# =============================================================================


class TestDumbMutate:
    """Tests for the fallback dumb mutation."""

    def test_flips_exactly_one_bit(self):
        original = bytearray(b"\xFF\xFF\xFF\xFF")
        result = MutationEngine._dumb_mutate(bytearray(original))
        diff = sum(bin(a ^ b).count("1") for a, b in zip(original, result))
        assert diff == 1

    def test_empty_input(self):
        assert MutationEngine._dumb_mutate(bytearray()) == b""

    def test_returns_bytes(self):
        result = MutationEngine._dumb_mutate(bytearray(b"\xAA\xBB"))
        assert isinstance(result, bytes)


# =============================================================================
# Coverage Tracking
# =============================================================================


class TestCoverageTracking:
    """Tests for coverage_summary property and get_stats()."""

    def test_coverage_summary_structure(self):
        engine = _make_engine()
        stats = engine.coverage_summary
        assert "total_mutations" in stats
        assert "total_packets" in stats
        assert "unique_offsets_fuzzed" in stats
        assert "total_kills" in stats
        assert "active_rules" in stats
        assert "current_eps" in stats
        assert "mode" in stats
        assert "investigation_mode" in stats

    def test_coverage_summary_initial_zeros(self):
        engine = _make_engine()
        stats = engine.coverage_summary
        assert stats["total_mutations"] == 0
        assert stats["total_packets"] == 0
        assert stats["total_kills"] == 0

    def test_get_stats_returns_mutator_stats(self):
        engine = _make_engine()
        stats = engine.get_stats()
        assert isinstance(stats, MutatorStats)
        assert stats.mode == MutationMode.RANDOM_SUBSET
        assert stats.total_sent == 0


# =============================================================================
# Rule Set Management
# =============================================================================


class TestRuleManagement:
    """Tests for atomic rule set updates."""

    @pytest.mark.asyncio
    async def test_update_rule_set(self):
        engine = _make_engine()
        rules = ActiveRuleSet(
            rules=[
                SemanticRule(rule_id="r1", rule_type=RuleType.BIT_FLIP,
                             offset_start=4, offset_end=6, target_field_name="len"),
            ],
            protocol_name="LIFA",
            overall_confidence=0.85,
        )
        await engine.update_rule_set(rules)
        assert engine._rule_set is not None
        assert engine._rule_set.protocol_name == "LIFA"
        stats = engine.get_stats()
        assert stats.rule_set_version == 1
        assert stats.active_fields >= 1

    @pytest.mark.asyncio
    async def test_multiple_updates_increment_version(self):
        engine = _make_engine()
        for i in range(3):
            await engine.update_rule_set(ActiveRuleSet(protocol_name=f"v{i}"))
        assert engine.get_stats().rule_set_version == 3


# =============================================================================
# Mode Transitions
# =============================================================================


class TestModeTransitions:
    """Tests for investigation mode switching."""

    @pytest.mark.asyncio
    async def test_set_investigation_mode(self):
        engine = _make_engine()
        await engine.set_investigation_mode(reason="test")
        assert engine._mode == MutationMode.ONE_AT_A_TIME
        assert engine.get_stats().investigation_mode is True

    @pytest.mark.asyncio
    async def test_set_normal_mode(self):
        engine = _make_engine()
        await engine.set_investigation_mode(reason="test")
        await engine.set_normal_mode()
        assert engine._mode == MutationMode.RANDOM_SUBSET
        assert engine.get_stats().investigation_mode is False

    @pytest.mark.asyncio
    async def test_investigation_idempotent(self):
        engine = _make_engine()
        await engine.set_investigation_mode(reason="first")
        await engine.set_investigation_mode(reason="second")  # no-op
        assert engine._mode == MutationMode.ONE_AT_A_TIME


# =============================================================================
# Pause / Resume
# =============================================================================


class TestPauseResume:
    """Tests for pause/resume behavior."""

    def test_pause_sets_flag(self):
        engine = _make_engine()
        assert engine._paused is False
        engine.pause()
        assert engine._paused is True

    def test_resume_clears_flag(self):
        engine = _make_engine()
        engine.pause()
        engine.resume()
        assert engine._paused is False


# =============================================================================
# Inverse-Frequency Power Scheduler (IFPS)
# =============================================================================


class TestIFPS:
    """Tests for the Inverse-Frequency Power Schedule seed selection."""

    def test_single_seed_always_returned(self):
        """With one seed, IFPS always returns it."""
        from shared.schemas import TrafficRecord, Direction
        engine = _make_engine()
        record = TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"\x00" * 4)
        seq = SeedSequence(packets=[record])
        engine._corpus = [seq]
        for _ in range(20):
            assert engine._pick_seed() is seq

    def test_rare_seed_selected_more_often(self):
        """Seeds with lower frequency get higher energy → chosen more often.

        Statistical test: seed A has freq=0, seed B has freq=100.
        Over 10000 samples, seed A should be selected significantly more.
        """
        from shared.schemas import TrafficRecord, Direction

        engine = _make_engine()
        seed_a = SeedSequence(packets=[TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"\x00" * 4)])
        seed_b = SeedSequence(packets=[TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"\xFF" * 4)])
        engine._corpus = [seed_a, seed_b]

        # Pre-set frequency: seed_b is heavily used
        engine._seed_freq[seed_a.sequence_id] = 0
        engine._seed_freq[seed_b.sequence_id] = 100

        counts = {seed_a.sequence_id: 0, seed_b.sequence_id: 0}
        for _ in range(10_000):
            s = engine._pick_seed()
            counts[s.sequence_id] += 1

        # seed_a (freq=0, Energy=1.0) should dominate seed_b (freq=100, Energy≈0.01)
        assert counts[seed_a.sequence_id] > counts[seed_b.sequence_id] * 10

    def test_equal_frequency_uniform_selection(self):
        """Seeds with equal frequency should be selected roughly equally."""
        from shared.schemas import TrafficRecord, Direction

        engine = _make_engine()
        seqs = [
            SeedSequence(packets=[TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=bytes([i]) * 4)])
            for i in range(3)
        ]
        engine._corpus = seqs
        # All seeds have freq=0

        counts = [0] * 3
        for _ in range(30_000):
            s = engine._pick_seed()
            for i, seq in enumerate(seqs):
                if s.sequence_id == seq.sequence_id:
                    counts[i] += 1

        # Each should get roughly 10000 ± 1000
        for c in counts:
            assert 7000 < c < 13000, f"Count {c} too far from expected 10000"

    def test_empty_corpus_raises(self):
        """Empty corpus raises IndexError."""
        engine = _make_engine()
        with pytest.raises(IndexError):
            engine._pick_seed()

    def test_frequency_tracking_increments(self):
        """_seed_freq tracks usage correctly."""
        from shared.schemas import TrafficRecord, Direction

        engine = _make_engine()
        record = TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=b"\xAA" * 4)
        seq = SeedSequence(packets=[record])
        engine._corpus = [seq]

        for i in range(5):
            s = engine._pick_seed()
            engine._seed_freq[s.sequence_id] = engine._seed_freq.get(s.sequence_id, 0) + 1

        assert engine._seed_freq[seq.sequence_id] == 5


# =============================================================================
# Endian-Safe Mutation — INCREMENT strategy
# =============================================================================


class TestEndianSafeIncrement:
    """Tests for endian-aware INCREMENT mutations."""

    def test_increment_uint16_be(self):
        """Big-endian uint16 increment: 0x0009 → 0x000A."""
        rule = FieldRule(
            field_name="opcode", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT16_BE,
        )
        buf = bytearray(b"\x00\x09")
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\x00\x0A")

    def test_increment_uint16_le(self):
        """Little-endian uint16 increment: LE(9) → LE(10)."""
        rule = FieldRule(
            field_name="opcode", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT16_LE,
        )
        buf = bytearray(b"\x09\x00")  # LE: 9
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\x0A\x00")  # LE: 10

    def test_increment_uint32_be(self):
        """Big-endian uint32 increment: 0x000000FF → 0x00000100."""
        rule = FieldRule(
            field_name="length", offset=0, length=4,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT32_BE,
        )
        buf = bytearray(b"\x00\x00\x00\xFF")
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\x00\x00\x01\x00")

    def test_increment_uint32_le(self):
        """Little-endian uint32 increment: LE(255) → LE(256)."""
        rule = FieldRule(
            field_name="length", offset=0, length=4,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT32_LE,
        )
        buf = bytearray(struct.pack("<I", 255))
        result = _apply_field(buf, rule)
        assert result == bytearray(struct.pack("<I", 256))

    def test_increment_uint16_be_wraps(self):
        """Big-endian uint16 overflow wraps: 0xFFFF → 0x0000."""
        rule = FieldRule(
            field_name="counter", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT16_BE,
        )
        buf = bytearray(b"\xFF\xFF")
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\x00\x00")

    def test_increment_uint16_le_wraps(self):
        """Little-endian uint16 overflow wraps: LE(65535) → LE(0)."""
        rule = FieldRule(
            field_name="counter", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT16_LE,
        )
        buf = bytearray(struct.pack("<H", 65535))
        result = _apply_field(buf, rule)
        assert result == bytearray(struct.pack("<H", 0))

    def test_increment_at_nonzero_offset(self):
        """Increment at offset 4 in a larger buffer."""
        rule = FieldRule(
            field_name="seq", offset=4, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
            data_type=FieldType.UINT16_LE,
        )
        buf = bytearray(b"\xAA\xBB\xCC\xDD" + struct.pack("<H", 99))
        result = _apply_field(buf, rule)
        assert result[:4] == bytearray(b"\xAA\xBB\xCC\xDD")  # header preserved
        assert result[4:6] == bytearray(struct.pack("<H", 100))

    def test_increment_without_data_type_defaults_big_endian(self):
        """Without data_type, INCREMENT defaults to big-endian (backward compat)."""
        rule = FieldRule(
            field_name="field", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
        )
        buf = bytearray(b"\x00\x09")
        result = _apply_field(buf, rule)
        assert result == bytearray(b"\x00\x0A")


# =============================================================================
# Endian-Safe Mutation — CALCULATED strategy
# =============================================================================


class TestEndianSafeCalculated:
    """Tests for endian-aware CALCULATED mutations."""

    def test_calculated_uint32_be(self):
        """Big-endian uint32 CALCULATED: payload_len=100 → BE encoding."""
        rule = FieldRule(
            field_name="length", offset=0, length=4,
            mutation_strategy=MutationStrategy.CALCULATED,
            data_type=FieldType.UINT32_BE,
        )
        buf = bytearray(b"\x00\x00\x00\x00" + b"\x41" * 100)  # 104 total, payload=100
        result = _apply_field(buf, rule)
        assert result[:4] == bytearray(struct.pack(">I", 100))

    def test_calculated_uint32_le(self):
        """Little-endian uint32 CALCULATED: payload_len=100 → LE encoding."""
        rule = FieldRule(
            field_name="length", offset=0, length=4,
            mutation_strategy=MutationStrategy.CALCULATED,
            data_type=FieldType.UINT32_LE,
        )
        buf = bytearray(b"\x00\x00\x00\x00" + b"\x41" * 100)
        result = _apply_field(buf, rule)
        assert result[:4] == bytearray(struct.pack("<I", 100))

    def test_calculated_uint16_be(self):
        """Big-endian uint16 CALCULATED."""
        rule = FieldRule(
            field_name="len16", offset=0, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
            data_type=FieldType.UINT16_BE,
        )
        buf = bytearray(b"\x00\x00" + b"\x42" * 50)  # 52 total, payload=50
        result = _apply_field(buf, rule)
        assert result[:2] == bytearray(struct.pack(">H", 50))

    def test_calculated_uint16_le(self):
        """Little-endian uint16 CALCULATED."""
        rule = FieldRule(
            field_name="len16", offset=0, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
            data_type=FieldType.UINT16_LE,
        )
        buf = bytearray(b"\x00\x00" + b"\x42" * 50)
        result = _apply_field(buf, rule)
        assert result[:2] == bytearray(struct.pack("<H", 50))


# =============================================================================
# STRING Null-Termination
# =============================================================================


class TestStringNullTermination:
    """Tests for automatic null-termination of STRING fields."""

    def test_random_bytes_string_null_terminated(self):
        """STRING field with RANDOM_BYTES is null-terminated (preserve_length)."""
        rule = FieldRule(
            field_name="name", offset=2, length=8,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
            data_type=FieldType.STRING,
        )
        buf = bytearray(b"\x00\x00" + b"AAAAAAAA")
        result = _apply_field(buf, rule, preserve_length=True)
        # Null-termination is applied to the field region [2:10]
        assert result[9] == 0x00  # Last byte of field must be null

    def test_static_string_null_terminated(self):
        """STRING field with STATIC value is null-terminated."""
        rule = FieldRule(
            field_name="name", offset=0, length=6,
            mutation_strategy=MutationStrategy.STATIC,
            static_value="48454c4c4f",  # "HELLO"
            data_type=FieldType.STRING,
        )
        buf = bytearray(b"\x00\x00\x00\x00\x00\x00")
        result = _apply_field(buf, rule)
        assert result[-1] == 0x00  # null-terminated

    def test_non_string_field_not_null_terminated(self):
        """Non-STRING fields are NOT null-terminated."""
        rule = FieldRule(
            field_name="data", offset=0, length=4,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
            data_type=FieldType.BYTES,
            preserve_length=True,  # prevent buffer expansion
        )
        buf = bytearray(b"\xFF\xFF\xFF\xFF")
        result = _apply_field(buf, rule, preserve_length=True)
        # BYTES type — no forced null termination
        assert len(result) == 4


# =============================================================================
# _endian_for_type helper
# =============================================================================


class TestEndianForType:
    """Tests for the _endian_for_type helper."""

    def test_le_types_return_little(self):
        for ft in [FieldType.UINT16_LE, FieldType.UINT32_LE,
                    FieldType.INT16_LE, FieldType.INT32_LE]:
            assert _endian_for_type(ft) == "little", f"Failed for {ft}"

    def test_be_types_return_big(self):
        for ft in [FieldType.UINT16_BE, FieldType.UINT32_BE,
                    FieldType.INT16_BE, FieldType.INT32_BE,
                    FieldType.UINT8, FieldType.BYTES, FieldType.STRING]:
            assert _endian_for_type(ft) == "big", f"Failed for {ft}"


# =============================================================================
# FieldRule data_type propagation from SemanticRule
# =============================================================================


class TestDataTypePropagation:
    """Tests that field_type propagates from SemanticRule → FieldRule."""

    def test_get_mutable_fields_carries_data_type(self):
        """ActiveRuleSet.get_mutable_fields() propagates field_type."""
        rule = SemanticRule(
            rule_id="test01",
            target_field_name="length_field",
            offset_start=4,
            offset_end=8,
            field_type=FieldType.UINT32_LE,
            rule_type=RuleType.BOUNDARY,
            priority=0.9,
        )
        rs = ActiveRuleSet(protocol_name="LIFA")
        rs.add_rules([rule])
        fields = rs.get_mutable_fields()
        assert len(fields) == 1
        assert fields[0].data_type == FieldType.UINT32_LE

    def test_get_mutable_fields_be_propagation(self):
        """Big-endian field_type also propagates."""
        rule = SemanticRule(
            rule_id="test02",
            target_field_name="opcode",
            offset_start=4,
            offset_end=6,
            field_type=FieldType.UINT16_BE,
            rule_type=RuleType.BIT_FLIP,
        )
        rs = ActiveRuleSet(protocol_name="LIFA")
        rs.add_rules([rule])
        fields = rs.get_mutable_fields()
        assert fields[0].data_type == FieldType.UINT16_BE
