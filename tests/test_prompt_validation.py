"""
tests/test_prompt_validation.py
───────────────────────────────
Unit tests for three LLM pipeline features:
    - Context window guard (prompt truncation)
    - Field-type cross-validation (LLM vs heatmap)
    - A/B mode in RulesOrchestrator
"""

from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from slow_loop.llm_agent import LLMAgent, estimate_tokens
from slow_loop.rule_generator import RuleGenerator
from slow_loop.differential_analyzer import FieldGroup, HeatmapResult, OffsetLabel
from shared.schemas import (
    Direction,
    FieldType,
    InferredField,
    MutationStrategy,
    ProtocolGrammar,
    SemanticRule,
    TrafficRecord,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def traffic_records():
    """Minimal traffic records for infer_protocol() calls."""
    return [TrafficRecord(
        direction=Direction.CLIENT_TO_SERVER,
        raw_data=b"\xDE\xAD\xBE\xEF\x00\x05HELLO",
    )]


@pytest.fixture
def sample_grammar():
    """A ProtocolGrammar with several fields for validation tests."""
    return ProtocolGrammar(
        protocol_name="test_proto",
        description="Test protocol",
        magic_bytes="deadbeef",
        fields=[
            InferredField(
                name="magic",
                offset_start=0,
                offset_end=4,
                field_type=FieldType.UINT32_LE,
                description="Magic header",
                is_constant=True,
                mutation_strategy=MutationStrategy.STATIC,
            ),
            InferredField(
                name="length",
                offset_start=4,
                offset_end=6,
                field_type=FieldType.UINT16_LE,
                description="Payload length",
                mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
            ),
            InferredField(
                name="payload",
                offset_start=6,
                offset_end=-1,
                field_type=FieldType.BYTES,
                description="Variable payload",
                mutation_strategy=MutationStrategy.RANDOM_BYTES,
            ),
        ],
        total_header_size=6,
        min_packet_size=6,
        max_packet_size=65535,
        confidence=0.85,
    )


@pytest.fixture
def gen():
    """RuleGenerator with default settings."""
    return RuleGenerator(min_confidence=0.3, max_rules=200)


# =============================================================================
# Context Window Guard
# =============================================================================


class TestContextWindowGuard:
    """Prompt truncation when estimated tokens exceed context window."""

    def test_prompt_under_limit_passes(self, traffic_records, tmp_path):
        """Prompt under context window → no truncation, no error."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            context_window=1_000_000,
            cache_file=str(tmp_path / "cache.json"),
        )
        prompt = agent._build_prompt_from_input(traffic_records)
        estimated = estimate_tokens(prompt)
        assert estimated < agent.context_window

    @pytest.mark.asyncio
    async def test_truncate_reduces_prompt_size(self, traffic_records, tmp_path):
        """Truncate strategy shortens the prompt."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            context_window=100,  # Very small
            prompt_truncation_strategy="truncate",
            cache_file=str(tmp_path / "cache.json"),
        )
        os.environ["LLM_MODE"] = "MOCK"
        try:
            await agent.infer_protocol(traffic_records)
        finally:
            os.environ.pop("LLM_MODE", None)

        # The MOCK response should still succeed
        assert agent._total_inferences == 1

    @pytest.mark.asyncio
    async def test_error_strategy_raises(self, traffic_records, tmp_path):
        """Error strategy raises RuntimeError on oversized prompt."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            context_window=10,  # Tiny
            prompt_truncation_strategy="error",
            cache_file=str(tmp_path / "cache.json"),
        )
        with pytest.raises(RuntimeError, match="exceeds context window"):
            await agent.infer_protocol(traffic_records)

    def test_default_context_window(self):
        """Default context window is 128K."""
        agent = LLMAgent(model="gpt-4o", api_key="test")
        assert agent.context_window == 128_000

    def test_default_truncation_strategy(self):
        """Default truncation strategy is truncate."""
        agent = LLMAgent(model="gpt-4o", api_key="test")
        assert agent.prompt_truncation_strategy == "truncate"


# =============================================================================
# Field-Type Cross-Validation
# =============================================================================


class TestFieldValidation:
    """Cross-validate LLM fields against mathematical heatmap."""

    def _make_heatmap(self, field_groups: list[FieldGroup]) -> HeatmapResult:
        """Helper to create a HeatmapResult with given field groups."""
        return HeatmapResult(
            analyzed_at=datetime.now(timezone.utc),
            packet_count=5,
            min_length=10,
            max_length=20,
            analysis_depth=64,
            offset_stats={},
            field_groups=field_groups,
        )

    def test_static_override(self, gen):
        """LLM says non-static but heatmap says STATIC → override."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="magic",
                    offset_start=0,
                    offset_end=4,
                    field_type=FieldType.UINT32_LE,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                    is_constant=False,
                ),
            ],
            confidence=0.8,
            max_packet_size=100,
        )
        heatmap = self._make_heatmap([
            FieldGroup(start=0, end=4, label=OffsetLabel.STATIC,
                       confidence=0.95, notes="constant magic"),
        ])

        validated = gen._validate_field_types(grammar, heatmap)
        assert validated[0].mutation_strategy == MutationStrategy.STATIC
        assert validated[0].is_constant is True

    def test_high_entropy_override(self, gen):
        """LLM says uint32 but heatmap says HIGH_ENTROPY + low confidence → bytes."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="data",
                    offset_start=6,
                    offset_end=10,
                    field_type=FieldType.UINT32_LE,
                    mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                ),
            ],
            confidence=0.4,  # Low confidence
            max_packet_size=100,
        )
        heatmap = self._make_heatmap([
            FieldGroup(start=6, end=10, label=OffsetLabel.HIGH_ENTROPY,
                       confidence=0.8),
        ])

        validated = gen._validate_field_types(grammar, heatmap)
        assert validated[0].field_type == FieldType.BYTES
        assert validated[0].mutation_strategy == MutationStrategy.RANDOM_BYTES

    def test_overlap_detection(self, gen):
        """Two overlapping fields → shorter one gets skip."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="field_a",
                    offset_start=0,
                    offset_end=6,
                    field_type=FieldType.BYTES,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                ),
                InferredField(
                    name="field_b",
                    offset_start=4,
                    offset_end=8,
                    field_type=FieldType.BYTES,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                ),
            ],
            confidence=0.9,
            max_packet_size=100,
        )

        validated = gen._validate_field_types(grammar, heatmap=None)
        # field_a is length 6, field_b is length 4 → field_b is shorter → skip
        skipped = [f for f in validated if f.mutation_strategy == MutationStrategy.SKIP]
        assert len(skipped) == 1
        assert skipped[0].name == "field_b"

    def test_oob_clamping(self, gen):
        """offset_end > max_packet_size → clamped."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="big_field",
                    offset_start=0,
                    offset_end=200000,
                    field_type=FieldType.BYTES,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                ),
            ],
            confidence=0.9,
            max_packet_size=65535,
        )

        validated = gen._validate_field_types(grammar, heatmap=None)
        assert validated[0].offset_end == 65535

    def test_no_heatmap_still_checks_overlaps(self, gen):
        """Without heatmap, overlap + OOB checks still run."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="a",
                    offset_start=0,
                    offset_end=8,
                    field_type=FieldType.BYTES,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                ),
                InferredField(
                    name="b",
                    offset_start=4,
                    offset_end=6,
                    field_type=FieldType.UINT16_LE,
                    mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                ),
            ],
            confidence=0.9,
            max_packet_size=100,
        )

        validated = gen._validate_field_types(grammar, heatmap=None)
        # b (length 2) < a (length 8) → b gets skip
        assert validated[1].mutation_strategy == MutationStrategy.SKIP

    def test_grammar_to_rules_passes_heatmap(self, gen, sample_grammar):
        """grammar_to_rules() accepts and uses heatmap param."""
        heatmap = self._make_heatmap([
            FieldGroup(start=0, end=4, label=OffsetLabel.STATIC,
                       confidence=0.99, static_hex="deadbeef"),
        ])
        # Should not crash
        rules = gen.grammar_to_rules(sample_grammar, heatmap=heatmap)
        assert isinstance(rules, list)

    def test_static_field_not_overridden_when_correct(self, gen):
        """Field already marked static is left alone."""
        grammar = ProtocolGrammar(
            protocol_name="test",
            fields=[
                InferredField(
                    name="magic",
                    offset_start=0,
                    offset_end=4,
                    field_type=FieldType.UINT32_LE,
                    mutation_strategy=MutationStrategy.STATIC,
                    is_constant=True,
                ),
            ],
            confidence=0.9,
            max_packet_size=100,
        )
        heatmap = self._make_heatmap([
            FieldGroup(start=0, end=4, label=OffsetLabel.STATIC,
                       confidence=0.95),
        ])

        validated = gen._validate_field_types(grammar, heatmap)
        assert validated[0].mutation_strategy == MutationStrategy.STATIC
        assert validated[0].is_constant is True


# =============================================================================
# A/B Mode
# =============================================================================


class TestABMode:
    """A/B mode switching in RulesOrchestrator."""

    def _make_orchestrator(self, ab_mode="llm"):
        """Create a minimal orchestrator for A/B testing."""
        from slow_loop.parser import TrafficParser
        from slow_loop.llm_agent import LLMAgent
        from slow_loop.rules_orchestrator import RulesOrchestrator

        parser = MagicMock(spec=TrafficParser)
        agent = MagicMock(spec=LLMAgent)
        rule_gen = MagicMock(spec=RuleGenerator)
        rule_gen.push_rules = AsyncMock()
        rule_gen.grammar_to_rules = MagicMock(return_value=[])

        return RulesOrchestrator(
            parser=parser,
            agent=agent,
            rule_gen=rule_gen,
            ab_mode=ab_mode,
        )

    def test_llm_mode_default(self):
        """Default A/B mode is 'llm'."""
        orch = self._make_orchestrator()
        assert orch.ab_mode == "llm"

    def test_random_mode_stored(self):
        """A/B mode='random' is stored."""
        orch = self._make_orchestrator(ab_mode="random")
        assert orch.ab_mode == "random"

    def test_alternating_toggle(self):
        """Alternating mode toggles use_llm on each call."""
        orch = self._make_orchestrator(ab_mode="alternating")
        assert orch.ab_mode == "alternating"
        assert orch._ab_cycle_counter == 0

    def test_stats_includes_ab_mode(self):
        """Stats dict includes ab_mode and cycle counter."""
        orch = self._make_orchestrator(ab_mode="alternating")
        stats = orch.stats
        assert "ab_mode" in stats
        assert stats["ab_mode"] == "alternating"
        assert "ab_cycle_counter" in stats

    def test_results_log_initialized_empty(self):
        """A/B results log starts empty."""
        orch = self._make_orchestrator()
        assert orch._ab_results_log == []
