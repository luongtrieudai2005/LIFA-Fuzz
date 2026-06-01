"""
tests/test_cost_tracking.py
────────────────────────────
Unit tests for LLM Agent cost management:
    - MODEL_PRICING lookup
    - Cost calculation per inference
    - Dollar-based budget gate
    - Stats property includes cost fields
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from slow_loop.llm_agent import LLMAgent, MODEL_PRICING
from shared.schemas import Direction, TrafficRecord, ProtocolGrammar


# ---------------------------------------------------------------------------
# MODEL_PRICING dict
# ---------------------------------------------------------------------------

class TestModelPricing:
    def test_known_models_have_pricing(self):
        """All expected models should be in MODEL_PRICING."""
        for model in ["glm-5-turbo", "gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514"]:
            assert model in MODEL_PRICING, f"Missing pricing for {model}"

    def test_default_fallback_exists(self):
        """A 'default' fallback must exist."""
        assert "default" in MODEL_PRICING

    def test_pricing_has_both_fields(self):
        """Each entry must have input_per_m and output_per_m."""
        for model, pricing in MODEL_PRICING.items():
            assert "input_per_m" in pricing, f"{model} missing input_per_m"
            assert "output_per_m" in pricing, f"{model} missing output_per_m"
            assert pricing["input_per_m"] >= 0
            assert pricing["output_per_m"] >= 0


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

class TestCostTracking:
    @pytest.mark.asyncio
    async def test_cost_calculated_on_real_call(self):
        """After a successful litellm call, total_cost_usd should be > 0."""
        agent = LLMAgent(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test-key",
        )

        # Mock litellm response with known token counts
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name":"test"}'
        mock_response.usage.prompt_tokens = 1000
        mock_response.usage.completion_tokens = 500
        mock_response.usage.total_tokens = 1500

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(return_value=mock_response)

                result = await agent.call_llm("test prompt")

        assert agent.cost_per_inference > 0
        assert agent.total_cost_usd > 0

        # Manual calculation: gpt-4o-mini = $0.15/M input, $0.60/M output
        expected_input = 1000 / 1_000_000 * 0.15   # $0.00015
        expected_output = 500 / 1_000_000 * 0.60    # $0.0003
        expected_total = round(expected_input + expected_output, 6)
        assert agent.cost_per_inference == expected_total

    @pytest.mark.asyncio
    async def test_cost_accumulates_across_calls(self):
        """Multiple calls should accumulate total_cost_usd."""
        agent = LLMAgent(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test-key",
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name":"test"}'
        mock_response.usage.prompt_tokens = 1000
        mock_response.usage.completion_tokens = 500
        mock_response.usage.total_tokens = 1500

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(return_value=mock_response)
                await agent.call_llm("prompt 1")
                await agent.call_llm("prompt 2")

        # Cost should have accumulated from 2 calls
        assert agent.total_cost_usd == pytest.approx(
            agent.cost_per_inference * 2, abs=0.0001
        )

    @pytest.mark.asyncio
    async def test_unknown_model_uses_default_pricing(self):
        """An unknown model should use the 'default' pricing."""
        agent = LLMAgent(
            provider="openai",
            model="some-future-model",
            api_key="test-key",
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name":"test"}'
        mock_response.usage.prompt_tokens = 1_000_000  # 1M tokens
        mock_response.usage.completion_tokens = 0
        mock_response.usage.total_tokens = 1_000_000

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(return_value=mock_response)
                await agent.call_llm("test")

        default_input = MODEL_PRICING["default"]["input_per_m"]
        assert agent.cost_per_inference == pytest.approx(default_input, abs=0.001)


# ---------------------------------------------------------------------------
# Dollar budget gate
# ---------------------------------------------------------------------------

class TestDollarBudgetGate:
    @pytest.mark.asyncio
    async def test_budget_gate_blocks_inference(self):
        """When total_cost_usd >= session_budget_usd, infer_protocol raises."""
        agent = LLMAgent(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test-key",
            session_budget_usd=0.001,  # Very tight budget
        )
        # Simulate having already spent over budget
        agent.total_cost_usd = 0.002

        # Ensure LLM mode doesn't interfere — gate fires before any LLM call
        os.environ["LLM_MODE"] = "MOCK"
        try:
            traffic = [TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=b"\x01\x02\x03",
            )]

            with pytest.raises(RuntimeError, match="cost budget exhausted"):
                await agent.infer_protocol(traffic)
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_budget_zero_means_unlimited(self):
        """session_budget_usd=0 should never trigger the gate."""
        agent = LLMAgent(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test-key",
            session_budget_usd=0,
        )
        agent.total_cost_usd = 999.0  # Way over any reasonable budget

        os.environ["LLM_MODE"] = "MOCK"
        try:
            traffic = [TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=b"\x01\x02\x03",
            )]
            # Should NOT raise — budget is 0 (unlimited)
            result = await agent.infer_protocol(traffic)
            assert isinstance(result, ProtocolGrammar)
        finally:
            os.environ.pop("LLM_MODE", None)


# ---------------------------------------------------------------------------
# Stats property
# ---------------------------------------------------------------------------

class TestStatsProperty:
    def test_stats_includes_cost_fields(self):
        agent = LLMAgent(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test",
            session_budget_usd=5.0,
        )
        agent.cost_per_inference = 0.003
        agent.total_cost_usd = 0.15

        s = agent.stats

        assert "cost_per_inference" in s
        assert "total_cost_usd" in s
        assert "session_budget_usd" in s
        assert s["total_cost_usd"] == 0.15
        assert s["session_budget_usd"] == 5.0
        assert s["model"] == "gpt-4o-mini"

    def test_stats_total_cost_rounded(self):
        """total_cost_usd in stats should be rounded to 4 decimal places."""
        agent = LLMAgent(model="gpt-4o", api_key="test")
        agent.total_cost_usd = 0.123456789

        s = agent.stats
        assert s["total_cost_usd"] == 0.1235  # Rounded to 4 decimals


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class TestCostConstructor:
    def test_session_budget_usd_default(self):
        agent = LLMAgent(model="gpt-4o", api_key="test")
        assert agent.session_budget_usd == 0.0

    def test_session_budget_usd_custom(self):
        agent = LLMAgent(model="gpt-4o", api_key="test", session_budget_usd=25.0)
        assert agent.session_budget_usd == 25.0

    def test_initial_cost_is_zero(self):
        agent = LLMAgent(model="gpt-4o", api_key="test")
        assert agent.cost_per_inference == 0.0
        assert agent.total_cost_usd == 0.0
