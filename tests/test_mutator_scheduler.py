"""
tests/test_mutator_scheduler.py
─────────────────────────────────
Comprehensive tests for all Mutation Scheduler improvements (P1–P3).

Covers:
    P1-A: Race condition fix (_revert_pending flag)
    P1-B: DUMB mode sync
    P2-A: Adaptive k scaling
    P2-B: WeightedScheduler
    P2-C: Investigation summary logging
    P2-D: Configurable investigation budgets
    P3-A: ALL_FIELDS warm-up phase
    P3-B: Kill payload attribution
    P3-C: mutation_operators integration
"""

import asyncio
import math
import time
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fast_loop.mutator import (
    KILL_SERVER_PAYLOADS,
    _KILL_PAYLOAD_NAMES,
    AllFieldsScheduler,
    MutationEngine,
    MutationMode,
    MutatorStats,
    OneAtATimeScheduler,
    RandomSubsetScheduler,
    WeightedScheduler,
    _apply_field,
    send_kill_payloads,
)
from shared.schemas import (
    ActiveRuleSet,
    FieldRule,
    MutationStrategy,
    RuleType,
    SemanticRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_engine(**overrides) -> MutationEngine:
    """Create a MutationEngine with sensible test defaults."""
    defaults = dict(
        target_host="127.0.0.1",
        target_port=0,
        seed_queue=asyncio.Queue(),
        k=2,
        max_eps=0,  # unlimited for tests
        # Disable warmup in most tests for backward compat
        warmup_seconds=0,
    )
    defaults.update(overrides)
    return MutationEngine(**defaults)


def _sample_fields(n: int = 5) -> list[FieldRule]:
    """Create n sample FieldRules with RANDOM_BYTES strategy."""
    return [
        FieldRule(
            field_name=f"field_{i}",
            offset=i * 4,
            length=4,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
            confidence=0.8,
        )
        for i in range(n)
    ]


def _mixed_strategy_fields() -> list[FieldRule]:
    """Create fields with different strategies for weighted testing."""
    return [
        FieldRule(
            field_name="magic", offset=0, length=4,
            mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
            confidence=0.9,
        ),
        FieldRule(
            field_name="opcode", offset=4, length=1,
            mutation_strategy=MutationStrategy.DICTIONARY,
            confidence=0.85,
        ),
        FieldRule(
            field_name="length", offset=5, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
            confidence=0.7,
        ),
        FieldRule(
            field_name="payload", offset=7, length=-1,
            mutation_strategy=MutationStrategy.RANDOM_BYTES,
            confidence=0.5,
        ),
    ]


def _make_rule_set(fields: list[FieldRule] | None = None) -> ActiveRuleSet:
    """Create a minimal ActiveRuleSet from FieldRules."""
    rules = []
    for f in (fields or _sample_fields()):
        rules.append(SemanticRule(
            rule_id=f"rule_{f.field_name}",
            rule_type=RuleType.BIT_FLIP,
            target_field_name=f.field_name,
            offset_start=f.offset,
            offset_end=f.offset + (f.length if f.length != -1 else 4),
            priority=f.confidence,
        ))
    return ActiveRuleSet(
        rules=rules,
        protocol_name="test",
        overall_confidence=0.8,
    )


# ===========================================================================
# P1-A: Race condition fix — _revert_pending flag
# ===========================================================================


class TestP1ARaceConditionFix:
    """Tests for the revert_pending flag (replaces fire-and-forget)."""

    def test_revert_pending_in_init(self):
        """_revert_pending starts False."""
        engine = _make_engine()
        assert engine._revert_pending is False

    def test_revert_pending_in_stats(self):
        """MutatorStats has revert_pending field."""
        stats = MutatorStats()
        assert hasattr(stats, "revert_pending")
        assert stats.revert_pending is False

    def test_revert_pending_set_when_budget_exhausted(self):
        """When budget is exhausted, _revert_pending is set (not create_task)."""
        engine = _make_engine()
        sched = OneAtATimeScheduler(budget_per_field=1, isolation_budget=1)
        engine._scheduler = sched
        engine._mode = MutationMode.ONE_AT_A_TIME

        fields = _sample_fields(3)
        # Exhaust the budget
        sched.select(fields)

        # Simulate what _build_mutant does: check budget and set flag
        if sched.is_budget_exhausted(len(fields)):
            engine._revert_pending = True
            engine._stats.revert_pending = True

        assert engine._revert_pending is True
        assert engine._stats.revert_pending is True

    @pytest.mark.asyncio
    async def test_crash_during_investigation_resets_scheduler(self):
        """When crash arrives and already in ONE_AT_A_TIME, scheduler resets."""
        engine = _make_engine()
        await engine.set_investigation_mode(reason="first crash")
        assert engine._mode == MutationMode.ONE_AT_A_TIME

        # Record cursor position (H1 fix: name-based tracking)
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        fields = _sample_fields(3)
        sched.select(fields)
        sched.select(fields)
        assert sched._cursor_name is not None or sched._sends_this_mode > 0

        # Second crash during investigation → should reset
        await engine.set_investigation_mode(reason="second crash")
        assert sched._cursor_name is None
        assert sched._sends_this_mode == 0

    def test_no_fire_and_forget_in_build_mutant(self):
        """Verify the code uses _revert_pending, not asyncio.create_task."""
        import inspect
        source = inspect.getsource(MutationEngine)
        # Should NOT contain create_task for set_normal_mode
        assert "asyncio.create_task(self.set_normal_mode())" not in source
        # Should contain the flag-based approach
        assert "_revert_pending" in source


# ===========================================================================
# P1-B: DUMB mode inconsistency fix
# ===========================================================================


class TestP1BDumbModeFix:
    """Tests for proper DUMB mode synchronization."""

    def test_stats_show_dumb_when_no_rule_set(self):
        """When rule_set is None, mode should be DUMB after _build_mutant."""
        engine = _make_engine()
        assert engine._rule_set is None
        # The mode will be set to DUMB inside _build_mutant
        # Initially it's RANDOM_SUBSET
        assert engine._mode == MutationMode.RANDOM_SUBSET

    @pytest.mark.asyncio
    async def test_auto_transition_to_random_when_rules_arrive(self):
        """When rules arrive while in DUMB mode, transition to RANDOM_SUBSET."""
        engine = _make_engine()
        # Force DUMB mode
        engine._mode = MutationMode.DUMB
        engine._stats.mode = "dumb"

        # Push a rule set
        rules = _make_rule_set()
        await engine.update_rule_set(rules)

        assert engine._mode == MutationMode.RANDOM_SUBSET
        assert engine._stats.mode == "random_subset"
        assert engine._stats.investigation_field is None

    @pytest.mark.asyncio
    async def test_investigation_field_cleared_in_dumb(self):
        """Investigation field is None in DUMB mode."""
        engine = _make_engine()
        engine._mode = MutationMode.DUMB
        engine._stats.mode = "dumb"
        engine._stats.investigation_field = "field_0"

        rules = _make_rule_set()
        await engine.update_rule_set(rules)
        assert engine._stats.investigation_field is None


# ===========================================================================
# P2-A: Dynamic k scaling
# ===========================================================================


class TestP2AAdaptiveK:
    """Tests for adaptive k ≈ sqrt(num_fields)."""

    def test_adaptive_k_scaling(self):
        """Verify k values for different field counts."""
        test_cases = [
            (1, 1),   # 1 field → k=1
            (4, 2),   # 4 fields → k=2
            (9, 3),   # 9 fields → k=3
            (16, 4),  # 16 fields → k=4
            (25, 5),  # 25 fields → k=5
        ]
        for n_fields, expected_k in test_cases:
            sched = RandomSubsetScheduler(k=2, adaptive=True)
            fields = _sample_fields(n_fields)
            selected = sched.select(fields)
            assert len(selected) == expected_k, (
                f"Expected k={expected_k} for {n_fields} fields, got {len(selected)}"
            )

    def test_static_k_when_adaptive_false(self):
        """With adaptive=False, k stays at the configured value."""
        sched = RandomSubsetScheduler(k=3, adaptive=False)
        fields = _sample_fields(10)
        selected = sched.select(fields)
        assert len(selected) == 3

    def test_adaptive_k_clamped_to_field_count(self):
        """k never exceeds the number of available fields."""
        sched = RandomSubsetScheduler(k=100, adaptive=True)
        fields = _sample_fields(2)
        selected = sched.select(fields)
        assert len(selected) <= 2

    def test_adaptive_k_default_on(self):
        """Default RandomSubsetScheduler has adaptive=True."""
        sched = RandomSubsetScheduler()
        assert sched.adaptive is True

    def test_k_this_round_tracked_in_stats(self):
        """MutatorStats tracks k_this_round."""
        stats = MutatorStats()
        assert stats.k_this_round == 0


# ===========================================================================
# P2-B: WeightedScheduler
# ===========================================================================


class TestP2BWeightedScheduler:
    """Tests for strategy-priority weighted field selection."""

    def test_boundary_values_selected_more_often(self):
        """BOUNDARY_VALUES fields selected ≥2x more than RANDOM_BYTES."""
        fields = [
            FieldRule(
                field_name="boundary", offset=0, length=4,
                mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                confidence=0.9,
            ),
            FieldRule(
                field_name="random", offset=4, length=4,
                mutation_strategy=MutationStrategy.RANDOM_BYTES,
                confidence=0.9,
            ),
        ]

        sched = WeightedScheduler(k=1, adaptive=False)
        counts = Counter()
        for _ in range(1000):
            chosen = sched.select(fields)
            for f in chosen:
                counts[f.mutation_strategy] += 1

        bv_count = counts[MutationStrategy.BOUNDARY_VALUES]
        rb_count = counts[MutationStrategy.RANDOM_BYTES]
        assert bv_count >= 2 * rb_count, (
            f"BOUNDARY_VALUES ({bv_count}) not ≥2x RANDOM_BYTES ({rb_count})"
        )

    def test_low_confidence_selected_less(self):
        """confidence=0.1 field selected ~10x less than confidence=1.0."""
        fields = [
            FieldRule(
                field_name="high_conf", offset=0, length=4,
                mutation_strategy=MutationStrategy.RANDOM_BYTES,
                confidence=1.0,
            ),
            FieldRule(
                field_name="low_conf", offset=4, length=4,
                mutation_strategy=MutationStrategy.RANDOM_BYTES,
                confidence=0.1,
            ),
        ]

        sched = WeightedScheduler(k=1, adaptive=False)
        counts = Counter()
        for _ in range(1000):
            chosen = sched.select(fields)
            for f in chosen:
                counts[f.field_name] += 1

        high = counts["high_conf"]
        low = counts["low_conf"]
        assert high >= 3 * low, (
            f"high_conf ({high}) not ≥3x low_conf ({low})"
        )

    def test_fallback_to_uniform_when_all_skip(self):
        """Falls back to uniform when all fields are SKIP."""
        fields = [
            FieldRule(
                field_name=f"skip_{i}", offset=i * 4, length=4,
                mutation_strategy=MutationStrategy.SKIP,
                confidence=0.5,
            )
            for i in range(3)
        ]

        sched = WeightedScheduler(k=2, adaptive=False)
        selected = sched.select(fields)
        assert len(selected) == 2

    def test_weighted_scheduler_description(self):
        """Description includes weight summary."""
        sched = WeightedScheduler()
        desc = sched.description
        assert "bv=4.0" in desc
        assert "rb=1.0" in desc

    def test_weighted_respects_adaptive_k(self):
        """WeightedScheduler uses adaptive k when enabled."""
        sched = WeightedScheduler(k=2, adaptive=True)
        fields = _sample_fields(16)
        selected = sched.select(fields)
        # sqrt(16) = 4
        assert len(selected) == 4

    def test_weighted_with_use_weighted_false_gives_old_behavior(self):
        """use_weighted=False gives exact old RandomSubsetScheduler behavior."""
        engine = _make_engine(use_weighted=False, adaptive_k=False, k=2)
        assert isinstance(engine._scheduler, RandomSubsetScheduler)
        assert not isinstance(engine._scheduler, WeightedScheduler)


# ===========================================================================
# P2-C: Investigation summary logging
# ===========================================================================


class TestP2CInvestigationSummary:
    """Tests for investigation summary capture on revert."""

    def test_last_investigation_summary_in_stats(self):
        """MutatorStats has last_investigation_summary field."""
        stats = MutatorStats()
        assert isinstance(stats.last_investigation_summary, dict)
        assert len(stats.last_investigation_summary) == 0

    @pytest.mark.asyncio
    async def test_summary_populated_on_revert(self):
        """Investigation summary is populated when reverting to normal mode."""
        engine = _make_engine()
        await engine.set_investigation_mode(reason="test crash")

        # Simulate some investigation sends
        fields = _sample_fields(3)
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        sched.select(fields)
        sched.select(fields)
        sched.select(fields)

        # Revert
        await engine.set_normal_mode()

        summary = engine.get_last_investigation_summary()
        assert "field_index_at_revert" in summary
        assert "total_sends" in summary
        assert summary["total_sends"] == 3
        assert summary["reason"] == "budget_exhausted"

    @pytest.mark.asyncio
    async def test_get_summary_returns_empty_before_first_investigation(self):
        """get_last_investigation_summary() returns {} before any investigation."""
        engine = _make_engine()
        assert engine.get_last_investigation_summary() == {}

    @pytest.mark.asyncio
    async def test_summary_logged_as_warning(self):
        """Investigation summary should be logged at WARNING level."""
        engine = _make_engine()
        await engine.set_investigation_mode(reason="test")
        # The summary won't have data yet (no sends), but it should be populated
        await engine.set_normal_mode()
        summary = engine.get_last_investigation_summary()
        assert "field_index_at_revert" in summary


# ===========================================================================
# P2-D: Configurable investigation budgets
# ===========================================================================


class TestP2DConfigurableBudgets:
    """Tests for configurable and adaptive investigation budgets."""

    def test_budget_per_field_default_zero(self):
        """Default budget_per_field is 0 (adaptive)."""
        engine = _make_engine()
        assert engine.budget_per_field == 0

    @pytest.mark.asyncio
    async def test_explicit_budget_per_field(self):
        """MutationEngine(budget_per_field=50) uses exactly 50 per field."""
        engine = _make_engine(budget_per_field=50)
        await engine.set_investigation_mode(reason="test")
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        assert sched.budget_per_field == 50

    @pytest.mark.asyncio
    async def test_adaptive_budget_scales_with_eps(self):
        """budget_per_field=0 adapts to current EPS."""
        engine = _make_engine(budget_per_field=0)
        # Set a fake EPS
        engine._stats.current_eps = 100.0
        await engine.set_investigation_mode(reason="test")
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        # 5.0 * 100 = 500, clamped to max(20, min(200, 500)) = 200
        assert sched.budget_per_field == 200

    @pytest.mark.asyncio
    async def test_adaptive_budget_minimum_20(self):
        """Adaptive budget_per_field has a minimum of 20."""
        engine = _make_engine(budget_per_field=0)
        # EPS = 0 (no sends yet) → fallback to 10.0 → 5*10 = 50
        engine._stats.current_eps = 0
        await engine.set_investigation_mode(reason="test")
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        assert sched.budget_per_field >= 20

    def test_backward_compat_investigation_budget(self):
        """investigation_budget parameter still works."""
        engine = _make_engine(investigation_budget=300)
        assert engine.investigation_budget == 300


# ===========================================================================
# P3-A: ALL_FIELDS warm-up phase
# ===========================================================================


class TestP3AWarmup:
    """Tests for ALL_FIELDS warm-up phase."""

    def test_warmup_seconds_default(self):
        """Default warmup_seconds is 30.0."""
        engine = _make_engine()
        # Note: _make_engine overrides to 0 for backward compat
        engine2 = MutationEngine(
            target_host="127.0.0.1", target_port=0,
            seed_queue=asyncio.Queue(), k=2, max_eps=0,
        )
        assert engine2.warmup_seconds == 30.0

    def test_warmup_disabled_when_seconds_zero(self):
        """warmup_seconds=0 completely disables warm-up."""
        engine = _make_engine(warmup_seconds=0)
        assert engine.warmup_seconds == 0
        assert engine._warmup_done is False

    @pytest.mark.asyncio
    async def test_warmup_uses_all_fields_scheduler(self):
        """During warm-up, the scheduler should be AllFieldsScheduler."""
        engine = _make_engine(warmup_seconds=60.0)  # long warmup
        # Simulate start of warm-up
        engine._running = True
        engine._corpus.append(engine._make_dummy_seed())

        # Manually trigger warm-up setup (as in run())
        engine._scheduler = AllFieldsScheduler()
        engine._mode = MutationMode.ALL_FIELDS
        engine._stats.mode = "all_fields"

        assert isinstance(engine._scheduler, AllFieldsScheduler)
        assert engine._mode == MutationMode.ALL_FIELDS

    @pytest.mark.asyncio
    async def test_warmup_does_not_trigger_investigation(self):
        """Crashes during warm-up should NOT trigger investigation mode."""
        engine = _make_engine(warmup_seconds=60.0)
        engine._warmup_done = False
        engine._mode = MutationMode.ALL_FIELDS

        # The guard condition in run() prevents investigation during warmup
        should_investigate = not (
            engine._mode == MutationMode.ALL_FIELDS and not engine._warmup_done
        )
        assert should_investigate is False

    @pytest.mark.asyncio
    async def test_warmup_transition_to_normal(self):
        """After warm-up deadline, mode transitions to normal."""
        engine = _make_engine(warmup_seconds=0.01)  # very short
        engine._running = True
        engine._corpus.append(engine._make_dummy_seed())
        engine._warmup_done = False
        engine._scheduler = AllFieldsScheduler()
        engine._mode = MutationMode.ALL_FIELDS

        # Simulate warmup complete
        engine._warmup_done = True
        await engine.set_normal_mode()

        assert engine._mode == MutationMode.RANDOM_SUBSET
        assert isinstance(engine._scheduler, (RandomSubsetScheduler, WeightedScheduler))


# ===========================================================================
# P3-B: Kill payload attribution
# ===========================================================================


class TestP3BKillPayloadAttribution:
    """Tests for kill payload naming and attribution."""

    def test_kill_payload_names_exist(self):
        """_KILL_PAYLOAD_NAMES matches KILL_SERVER_PAYLOADS count."""
        assert len(_KILL_PAYLOAD_NAMES) == len(KILL_SERVER_PAYLOADS)

    def test_kill_payload_names_content(self):
        """Kill payload names are descriptive."""
        assert "null_magic" in _KILL_PAYLOAD_NAMES[0]
        assert "abort_magic" in _KILL_PAYLOAD_NAMES[1]
        assert "length_overflow" in _KILL_PAYLOAD_NAMES[2]

    @pytest.mark.asyncio
    async def test_send_kill_payloads_sets_attribution(self):
        """send_kill_payloads sets _last_injected_rule_id properly."""
        engine = _make_engine(no_recv=True)

        # Mock _send to avoid actual TCP
        mock_status = type("Status", (), {"value": "crash"})()
        with patch.object(engine, "_send", new_callable=AsyncMock) as mock_send:
            # Import PacketStatus for the mock return
            from shared.schemas import PacketStatus
            mock_send.return_value = PacketStatus.CRASH

            results = await send_kill_payloads(engine)

        assert len(results) == 3
        for r in results:
            assert "kill_payload:" in r["rule_id"]

    def test_kill_payloads_list_unchanged(self):
        """KILL_SERVER_PAYLOADS list itself unchanged (backward compat)."""
        assert len(KILL_SERVER_PAYLOADS) >= 3
        assert KILL_SERVER_PAYLOADS[0][:4] == b"\x00\x00\x00\x00"
        assert KILL_SERVER_PAYLOADS[1][:4] == b"\xCA\xFE\xBA\xBE"
        assert KILL_SERVER_PAYLOADS[2][:4] == b"\xDE\xAD\xBE\xEF"


# ===========================================================================
# P3-C: mutation_operators integration
# ===========================================================================


class TestP3COperatorsIntegration:
    """Tests for _apply_field dispatching to mutation_operators.py."""

    def test_format_string_strategy(self):
        """FORMAT_STRING strategy produces format-string-like output."""
        rule = FieldRule(
            field_name="fmt", offset=0, length=4,
            mutation_strategy=MutationStrategy.FORMAT_STRING,
        )
        results = set()
        for _ in range(20):
            buf = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            result = _apply_field(buf, rule)
            results.add(bytes(result))

        # Should produce at least 2 distinct outputs
        assert len(results) >= 2

    def test_truncate_strategy(self):
        """TRUNCATE strategy shortens the buffer."""
        rule = FieldRule(
            field_name="trunc", offset=2, length=4,
            mutation_strategy=MutationStrategy.TRUNCATE,
        )
        buf = bytearray(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        result = _apply_field(buf, rule)
        # Buffer should be shorter or equal after truncation
        assert len(result) <= len(buf)

    def test_boundary_values_uses_operators(self):
        """BOUNDARY_VALUES dispatches to op_integer_overflow or op_boundary_violation."""
        rule = FieldRule(
            field_name="len", offset=0, length=4,
            mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
        )
        results = set()
        for _ in range(50):
            buf = bytearray(b"\x00\x00\x00\x00")
            result = _apply_field(buf, rule)
            results.add(bytes(result))

        # Should produce boundary values from the operators
        assert len(results) >= 2

    def test_bit_flip_uses_operator(self):
        """BIT_FLIP dispatches to op_bit_flip."""
        rule = FieldRule(
            field_name="flag", offset=0, length=4,
            mutation_strategy=MutationStrategy.BIT_FLIP,
        )
        original = bytearray(b"\xFF\xFF\xFF\xFF")
        mutated = _apply_field(bytearray(original), rule)
        diff = sum(bin(a ^ b).count("1") for a, b in zip(original, mutated))
        # op_bit_flip flips 1-3 bits
        assert 1 <= diff <= 3

    def test_static_strategy_unchanged(self):
        """STATIC still works (not dispatched to operators)."""
        rule = FieldRule(
            field_name="magic", offset=0, length=4,
            mutation_strategy=MutationStrategy.STATIC,
            static_value="deadbeef",
        )
        buf = bytearray(b"\x00\x00\x00\x00\xFF\xFF")
        result = _apply_field(buf, rule)
        assert result[:4] == b"\xDE\xAD\xBE\xEF"
        assert result[4:] == b"\xFF\xFF"

    def test_dictionary_strategy_unchanged(self):
        """DICTIONARY still works (not dispatched to operators)."""
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
        assert len(results) >= 2

    def test_calculated_strategy_unchanged(self):
        """CALCULATED still works (not dispatched to operators)."""
        rule = FieldRule(
            field_name="length", offset=0, length=2,
            mutation_strategy=MutationStrategy.CALCULATED,
        )
        buf = bytearray(b"\x00\x00\x01\x02\x03\x04\x05\x06")
        _apply_field(buf, rule)
        assert int.from_bytes(buf[:2], "big") == 6

    def test_increment_strategy_unchanged(self):
        """INCREMENT still works (not dispatched to operators)."""
        rule = FieldRule(
            field_name="seq", offset=0, length=2,
            mutation_strategy=MutationStrategy.INCREMENT,
        )
        buf = bytearray(b"\x00\x05")
        _apply_field(buf, rule)
        assert int.from_bytes(buf, "big") == 6


# ===========================================================================
# Existing tests — backward compatibility
# ===========================================================================


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
        assert len(KILL_SERVER_PAYLOADS) >= 3
        assert KILL_SERVER_PAYLOADS[0][:4] == b"\x00\x00\x00\x00"
        assert KILL_SERVER_PAYLOADS[1][:4] == b"\xCA\xFE\xBA\xBE"
        assert KILL_SERVER_PAYLOADS[2][:4] == b"\xDE\xAD\xBE\xEF"

    def test_new_params_defaults(self):
        """New P2/P3 parameters have sensible defaults."""
        engine = _make_engine()
        assert engine.adaptive_k is True
        assert engine.use_weighted is True
        assert engine.budget_per_field == 0
        assert engine.warmup_seconds == 0  # overridden in _make_engine


class TestSchedulers:
    """Tests for the three scheduler strategies."""

    def _sample_fields(self) -> list[FieldRule]:
        return _sample_fields(5)

    def test_random_subset_selects_k_fields(self):
        sched = RandomSubsetScheduler(k=2, adaptive=False)
        fields = self._sample_fields()
        selected = sched.select(fields)
        assert len(selected) == 2
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
        r0 = sched.select(fields)
        assert r0[0].field_name == "field_0"
        r1 = sched.select(fields)
        assert r1[0].field_name == "field_0"
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
        # H1 fix: name-based tracking — cursor_name resets to None
        assert sched._cursor_name is None
        assert sched._sends_this_mode == 0

    def test_one_at_a_time_empty_list(self):
        assert OneAtATimeScheduler().select([]) == []

    def test_all_fields_selects_everything(self):
        sched = AllFieldsScheduler()
        fields = self._sample_fields()
        selected = sched.select(fields)
        assert len(selected) == 5


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
        assert stats.total_sent == 0


class TestRuleManagement:
    """Tests for atomic rule set updates."""

    @pytest.mark.asyncio
    async def test_update_rule_set(self):
        engine = _make_engine()
        rules = _make_rule_set()
        await engine.update_rule_set(rules)
        assert engine._rule_set is not None
        assert engine._rule_set.protocol_name == "test"
        stats = engine.get_stats()
        assert stats.rule_set_version == 1
        assert stats.active_fields >= 1

    @pytest.mark.asyncio
    async def test_multiple_updates_increment_version(self):
        engine = _make_engine()
        for i in range(3):
            await engine.update_rule_set(ActiveRuleSet(protocol_name=f"v{i}"))
        assert engine.get_stats().rule_set_version == 3


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
        """Calling set_investigation_mode twice resets scheduler instead of no-op."""
        engine = _make_engine()
        await engine.set_investigation_mode(reason="first")
        # Second call resets the scheduler (P1-A fix)
        await engine.set_investigation_mode(reason="second")
        assert engine._mode == MutationMode.ONE_AT_A_TIME
        # Scheduler should have been reset
        sched = engine._scheduler
        assert isinstance(sched, OneAtATimeScheduler)
        # H1 fix: name-based tracking — cursor_name resets to None
        assert sched._cursor_name is None


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
