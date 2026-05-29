"""
tests/test_llm_agent.py
───────────────────────
Unit tests for the Slow Loop LLM Agent.

Tests cover:
    - Agent initialization
    - Prompt construction (when implemented)
    - Response parsing (when implemented)
    - Full inference pipeline (when implemented)
"""

import pytest

from slow_loop.llm_agent import LLMAgent


class TestLLMAgentInit:
    """Tests for LLMAgent initialization."""

    def test_default_params(self):
        """Agent initializes with sensible defaults."""
        agent = LLMAgent()
        assert agent.provider == "openai"
        assert agent.model == "gpt-4o"
        assert agent.max_tokens == 4096
        assert agent.temperature == 0.2
        assert agent.max_retries == 3

    def test_custom_params(self):
        """Agent initializes with custom parameters."""
        agent = LLMAgent(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            max_tokens=8192,
            temperature=0.1,
        )
        assert agent.provider == "anthropic"
        assert agent.model == "claude-sonnet-4-20250514"
        assert agent.max_tokens == 8192
        assert agent.temperature == 0.1


class TestLLMAgentInference:
    """Tests for the inference pipeline."""

    @pytest.mark.asyncio
    async def test_infer_protocol_raises_not_implemented(self):
        """infer_protocol() should raise NotImplementedError in Phase 3."""
        agent = LLMAgent()
        with pytest.raises(NotImplementedError):
            await agent.infer_protocol([])

    def test_build_prompt_raises_not_implemented(self):
        """build_prompt() should raise NotImplementedError in Phase 3."""
        agent = LLMAgent()
        with pytest.raises(NotImplementedError):
            agent.build_prompt([])

    def test_parse_response_raises_not_implemented(self):
        """parse_response() should raise NotImplementedError in Phase 3."""
        agent = LLMAgent()
        with pytest.raises(NotImplementedError):
            agent.parse_response("{}")
