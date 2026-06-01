"""
tests/test_llm_agent.py
───────────────────────
Unit tests for the Slow Loop LLM Agent.

Tests cover:
    - Agent initialization (default and custom params).
    - Prompt construction from TrafficRecord lists.
    - Response parsing (JSON, markdown-wrapped, malformed).
    - infer_protocol() with mocked LLM API.
    - Stats tracking.
"""

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from slow_loop.llm_agent import LLMAgent, _hex_to_ascii
from shared.schemas import Direction, TrafficRecord, ProtocolGrammar


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_traffic_records():
    """A list of realistic traffic records for testing."""
    return [
        TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\xDE\xAD\xBE\xEF\x00\x05HELLO",
            is_mutated=False,
        ),
        TrafficRecord(
            direction=Direction.SERVER_TO_CLIENT,
            raw_data=b"\xDE\xAD\xBE\xEF\x00\x05ECHO!",
            is_mutated=False,
        ),
        TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\xDE\xAD\xBE\xEF\x00\x03BYE",
            is_mutated=True,
            mutation_id="rule_001",
        ),
    ]


@pytest.fixture
def sample_grammar_json():
    """Valid ProtocolGrammar JSON for testing parse_response()."""
    return {
        "protocol_name": "test_protocol",
        "description": "A test protocol with magic + length + payload",
        "magic_bytes": "deadbeef",
        "fields": [
            {
                "name": "magic",
                "offset_start": 0,
                "offset_end": 4,
                "field_type": "uint32_le",
                "description": "Protocol magic bytes",
                "possible_values": [],
                "is_constant": True,
            },
            {
                "name": "length",
                "offset_start": 4,
                "offset_end": 6,
                "field_type": "uint16_le",
                "description": "Payload length",
                "possible_values": [],
                "is_constant": False,
            },
            {
                "name": "payload",
                "offset_start": 6,
                "offset_end": -1,
                "field_type": "string",
                "description": "Variable-length payload",
                "possible_values": [],
                "is_constant": False,
            },
        ],
        "total_header_size": 6,
        "min_packet_size": 6,
        "max_packet_size": 65535,
        "confidence": 0.90,
    }


# =============================================================================
# Initialization
# =============================================================================


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
        assert agent._total_inferences == 0

    def test_custom_params(self):
        """Agent initializes with custom parameters."""
        agent = LLMAgent(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            max_tokens=8192,
            temperature=0.1,
            max_retries=5,
        )
        assert agent.provider == "anthropic"
        assert agent.model == "claude-sonnet-4-20250514"
        assert agent.max_tokens == 8192
        assert agent.temperature == 0.1
        assert agent.max_retries == 5

    def test_stats_empty(self):
        """Stats return zero values on a fresh agent."""
        agent = LLMAgent()
        stats = agent.stats
        assert stats["total_inferences"] == 0
        assert stats["total_tokens_used"] == 0


# =============================================================================
# Prompt Construction
# =============================================================================


class TestBuildPrompt:
    """Tests for prompt construction."""

    def test_build_prompt_with_records(self, sample_traffic_records):
        """build_prompt() formats traffic records into a readable prompt.

        Mutated packets are filtered out to prevent corpus contamination.
        Of the 3 sample records, only 2 are non-mutated.
        """
        agent = LLMAgent()
        prompt = agent.build_prompt(sample_traffic_records)

        # Should include header with clean (non-mutated) count
        assert "Analyze 2 clean network traffic packets" in prompt

        # Should include direction and hex in xxd format
        assert "client_to_server" in prompt
        assert "server_to_client" in prompt
        # xxd format: "de ad be ef" (spaces between bytes)
        assert "de ad be ef" in prompt

        # Should include ASCII representation inside xxd pipes
        assert "HELLO" in prompt

        # Mutated packet should be filtered out — "BYE" must NOT appear
        assert "BYE" not in prompt

    def test_build_prompt_empty(self):
        """build_prompt() returns a message when no samples provided."""
        agent = LLMAgent()
        prompt = agent.build_prompt([])
        assert "No traffic samples" in prompt

    def test_build_prompt_from_dict(self):
        """_build_prompt_from_input() accepts a formatted dict from parser."""
        agent = LLMAgent()
        payload = {
            "session_count": 1,
            "sessions": [
                {
                    "session_id": 0,
                    "packets": [
                        {"direction": "client_to_server", "hex": "deadbeef"}
                    ],
                }
            ],
        }
        prompt = agent._build_prompt_from_input(payload)
        assert "session_count" in prompt
        assert "deadbeef" in prompt
        assert "Analyze the traffic sessions" in prompt

    def test_build_prompt_invalid_type(self):
        """_build_prompt_from_input() raises TypeError for invalid input."""
        agent = LLMAgent()
        with pytest.raises(TypeError, match="Expected list"):
            agent._build_prompt_from_input("invalid")


# =============================================================================
# Response Parsing
# =============================================================================


class TestParseResponse:
    """Tests for LLM response parsing."""

    def test_parse_valid_json(self, sample_grammar_json):
        """parse_response() correctly parses valid JSON."""
        agent = LLMAgent()
        response_text = json.dumps(sample_grammar_json)
        grammar = agent.parse_response(response_text)

        assert isinstance(grammar, ProtocolGrammar)
        assert grammar.protocol_name == "test_protocol"
        assert len(grammar.fields) == 3
        assert grammar.confidence == 0.90

    def test_parse_markdown_wrapped(self, sample_grammar_json):
        """parse_response() strips markdown code blocks."""
        agent = LLMAgent()
        wrapped = f"```json\n{json.dumps(sample_grammar_json)}\n```"
        grammar = agent.parse_response(wrapped)

        assert grammar.protocol_name == "test_protocol"
        assert len(grammar.fields) == 3

    def test_parse_markdown_plain_block(self, sample_grammar_json):
        """parse_response() strips plain ``` blocks."""
        agent = LLMAgent()
        wrapped = f"```\n{json.dumps(sample_grammar_json)}\n```"
        grammar = agent.parse_response(wrapped)
        assert grammar.protocol_name == "test_protocol"

    def test_parse_json_with_surrounding_text(self, sample_grammar_json):
        """parse_response() extracts JSON from surrounding text."""
        agent = LLMAgent()
        text = f"Here is my analysis:\n{json.dumps(sample_grammar_json)}\nThat's it."
        grammar = agent.parse_response(text)
        assert grammar.protocol_name == "test_protocol"

    def test_parse_invalid_json_raises(self):
        """parse_response() raises ValueError for non-JSON."""
        agent = LLMAgent()
        with pytest.raises(ValueError, match="Failed to parse"):
            agent.parse_response("This is not JSON at all")

    def test_parse_schema_mismatch_raises(self):
        """parse_response() raises ValueError for schema violations."""
        agent = LLMAgent()
        bad_data = {"protocol_name": 123, "confidence": "not_a_float"}
        with pytest.raises(ValueError, match="does not match ProtocolGrammar"):
            agent.parse_response(json.dumps(bad_data))

    def test_parse_minimal_valid(self):
        """parse_response() accepts minimal valid grammar."""
        agent = LLMAgent()
        minimal = {
            "protocol_name": "unknown",
            "description": "",
            "fields": [],
            "confidence": 0.0,
        }
        grammar = agent.parse_response(json.dumps(minimal))
        assert grammar.protocol_name == "unknown"
        assert grammar.fields == []
        assert grammar.confidence == 0.0


# =============================================================================
# LLM API Call (Mocked)
# =============================================================================


class TestCallLLM:
    """Tests for LLM API call with mocked litellm."""

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    async def test_call_llm_no_api_key_raises(self):
        """call_llm() raises RuntimeError when no API key is set."""
        agent = LLMAgent(api_key="")
        with pytest.raises(RuntimeError, match="No API key"):
            await agent.call_llm("test prompt")

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", False)
    async def test_call_llm_no_litellm_raises(self):
        """call_llm() raises RuntimeError when litellm is not installed."""
        agent = LLMAgent(api_key="fake-key")
        with pytest.raises(RuntimeError, match="litellm is not installed"):
            await agent.call_llm("test prompt")

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_call_llm_success(self, mock_litellm):
        """call_llm() returns response content on success."""
        # Mock the async completion response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 80
        mock_response.usage.completion_tokens = 20
        mock_response.usage.total_tokens = 100

        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key")
        result = await agent.call_llm("test prompt")

        assert result == '{"protocol_name": "test"}'
        assert agent._total_tokens_used == 100
        mock_litellm.acompletion.assert_called_once()

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_call_llm_empty_response_raises(self, mock_litellm):
        """call_llm() raises RuntimeError on empty LLM response."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None

        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key", max_retries=1)
        with pytest.raises(RuntimeError, match="empty response"):
            await agent.call_llm("test prompt")

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_call_llm_retries_on_failure(self, mock_litellm):
        """call_llm() retries on transient errors."""
        mock_litellm.acompletion = AsyncMock(
            side_effect=Exception("API error")
        )

        agent = LLMAgent(api_key="test-key", max_retries=2)
        with pytest.raises(RuntimeError, match="failed after 2 attempts"):
            await agent.call_llm("test prompt")

        # Should have been called max_retries times
        assert mock_litellm.acompletion.call_count == 2


# =============================================================================
# Full Pipeline (Mocked)
# =============================================================================


class TestInferProtocol:
    """Tests for the full inference pipeline."""

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_infer_protocol_from_records(
        self, mock_litellm, sample_traffic_records, sample_grammar_json
    ):
        """infer_protocol() works with TrafficRecord input."""
        # Mock successful LLM response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(sample_grammar_json)
        mock_response.usage.prompt_tokens = 150
        mock_response.usage.completion_tokens = 50
        mock_response.usage.total_tokens = 200

        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key")
        grammar = await agent.infer_protocol(sample_traffic_records)

        assert isinstance(grammar, ProtocolGrammar)
        assert grammar.protocol_name == "test_protocol"
        assert agent._total_inferences == 1

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_infer_protocol_from_dict(
        self, mock_litellm, sample_grammar_json
    ):
        """infer_protocol() works with pre-formatted dict input."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(sample_grammar_json)
        mock_response.usage.prompt_tokens = 120
        mock_response.usage.completion_tokens = 30
        mock_response.usage.total_tokens = 150

        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key")
        payload = {"session_count": 1, "sessions": []}
        grammar = await agent.infer_protocol(payload)

        assert isinstance(grammar, ProtocolGrammar)
        assert grammar.protocol_name == "test_protocol"


# =============================================================================
# Math Hint Injection (Phase 6)
# =============================================================================


class TestMathHint:
    """Tests for the mathematical pre-analysis hint injection."""

    def test_build_prompt_from_dict_with_hint(self):
        """_build_prompt_from_input() injects math_hint into dict prompts."""
        agent = LLMAgent()
        payload = {"session_count": 1, "sessions": [{"packets": []}]}
        hint = "MATHEMATICAL PRE-ANALYSIS: field [0-3] STATIC, field [4-5] CALCULATED"
        prompt = agent._build_prompt_from_input(payload, math_hint=hint)

        assert hint in prompt
        assert "Analyze the traffic sessions" in prompt

    def test_build_prompt_from_dict_without_hint(self):
        """_build_prompt_from_input() works normally when no hint is given."""
        agent = LLMAgent()
        payload = {"session_count": 1, "sessions": []}
        prompt = agent._build_prompt_from_input(payload)

        assert "Analyze the traffic sessions" in prompt
        # Should NOT contain any heatmap text
        assert "MATHEMATICAL" not in prompt

    def test_build_prompt_from_records_with_hint(self, sample_traffic_records):
        """build_prompt() injects math_hint BEFORE traffic samples."""
        agent = LLMAgent()
        hint = "HEATMAP: byte 0 = STATIC (H=0.0)"
        prompt = agent.build_prompt(sample_traffic_records, math_hint=hint)

        assert hint in prompt
        # xxd format has spaces: "de ad be ef"
        assert "de ad be ef" in prompt
        # Heatmap should come BEFORE packet data
        assert prompt.index(hint) < prompt.index("de ad be ef")

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_infer_protocol_passes_math_hint(
        self, mock_litellm, sample_traffic_records, sample_grammar_json
    ):
        """infer_protocol() forwards math_hint to prompt builder."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(sample_grammar_json)
        mock_response.usage.prompt_tokens = 80
        mock_response.usage.completion_tokens = 20
        mock_response.usage.total_tokens = 100

        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key")
        hint = "HEATMAP: all offsets classified"
        grammar = await agent.infer_protocol(
            sample_traffic_records, math_hint=hint
        )

        assert isinstance(grammar, ProtocolGrammar)
        # Verify the hint was passed through to the prompt
        call_args = mock_litellm.acompletion.call_args
        messages = call_args.kwargs.get("messages", call_args[1].get("messages", []))
        user_msg = next(m["content"] for m in messages if m["role"] == "user")
        assert hint in user_msg

    @pytest.mark.asyncio
    async def test_infer_protocol_mock_with_hint(self, sample_traffic_records):
        """infer_protocol() works with math_hint in MOCK mode."""
        os.environ["LLM_MODE"] = "MOCK"
        try:
            agent = LLMAgent(api_key="test")
            grammar = await agent.infer_protocol(
                sample_traffic_records,
                math_hint="HEATMAP: [0-3] STATIC conf=1.0",
            )
            assert isinstance(grammar, ProtocolGrammar)
            assert grammar.protocol_name == "mock_inferred_protocol"
        finally:
            os.environ.pop("LLM_MODE", None)

    def test_system_prompt_has_fusion_guidelines(self):
        """SYSTEM_PROMPT includes the mathematical pre-analysis guidelines."""
        from slow_loop.llm_agent import SYSTEM_PROMPT, SYSTEM_PROMPT_FUSION_APPEND
        combined = SYSTEM_PROMPT + SYSTEM_PROMPT_FUSION_APPEND
        assert "MATHEMATICAL PRE-ANALYSIS" in combined
        assert "STATIC" in combined
        assert "CALCULATED" in combined
        assert "HIGH_ENTROPY" in combined
        assert "LOW_ENTROPY" in combined
        assert "reasoning" in combined.lower()


# =============================================================================
# Hex to ASCII Helper
# =============================================================================


class TestHexToAscii:
    """Tests for the _hex_to_ascii helper."""

    def test_printable(self):
        assert _hex_to_ascii("48454c4c4f") == "HELLO"

    def test_non_printable(self):
        """Non-printable bytes (>0x7E or <0x20) all become dots."""
        assert _hex_to_ascii("deadbeef") == "...."

    def test_mixed(self):
        """Mix of non-printable bytes — all < 0x20 or > 0x7E → all dots."""
        result = _hex_to_ascii("00010203ff")
        assert result == "....."

    def test_empty(self):
        assert _hex_to_ascii("") == ""


# =============================================================================
# API Base & Multi-Provider Handling
# =============================================================================


class TestApiBaseHandling:
    """Tests for api_base parameter and multi-provider support."""

    def test_api_base_default_empty(self):
        """api_base defaults to empty string."""
        agent = LLMAgent()
        assert agent.api_base == ""

    def test_api_base_stored(self):
        """api_base is stored when provided."""
        agent = LLMAgent(api_base="https://api.z.ai/api/coding/paas/v4")
        assert agent.api_base == "https://api.z.ai/api/coding/paas/v4"

    def test_stats_includes_api_base(self):
        """Stats dict includes the configured api_base."""
        agent = LLMAgent(api_base="https://custom.endpoint/v1")
        assert agent.stats["api_base"] == "https://custom.endpoint/v1"

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_call_llm_passes_api_base(self, mock_litellm):
        """call_llm() passes api_base to litellm.acompletion when set."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(
            provider="openai",
            model="glm-5-turbo",
            api_key="test-key",
            api_base="https://api.z.ai/api/coding/paas/v4",
        )
        await agent.call_llm("test prompt")

        call_kwargs = mock_litellm.acompletion.call_args.kwargs
        assert call_kwargs["api_base"] == "https://api.z.ai/api/coding/paas/v4"
        assert call_kwargs["model"] == "openai/glm-5-turbo"

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_call_llm_omits_api_base_when_empty(self, mock_litellm):
        """call_llm() does NOT pass api_base to litellm when empty."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(api_key="test-key", api_base="")
        await agent.call_llm("test prompt")

        call_kwargs = mock_litellm.acompletion.call_args.kwargs
        assert "api_base" not in call_kwargs

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_ollama_model_string(self, mock_litellm):
        """Ollama provider constructs correct model string."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(provider="ollama", model="llama3.2", api_key="")
        await agent.call_llm("test prompt")

        call_kwargs = mock_litellm.acompletion.call_args.kwargs
        assert call_kwargs["model"] == "ollama/llama3.2"

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    @patch("slow_loop.llm_agent.litellm", create=True)
    async def test_ollama_no_api_key_required(self, mock_litellm):
        """Ollama provider works without an API key (local model)."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = LLMAgent(provider="ollama", model="llama3.2", api_key="")
        result = await agent.call_llm("test prompt")
        assert result == '{"protocol_name": "test"}'

    @pytest.mark.asyncio
    @patch("slow_loop.llm_agent.HAS_LITELM", True)
    async def test_non_ollama_empty_api_key_raises(self):
        """Non-Ollama providers raise RuntimeError when API key is empty."""
        agent = LLMAgent(provider="openai", model="gpt-4o", api_key="")
        with pytest.raises(RuntimeError, match="No API key"):
            await agent.call_llm("test prompt")


# ---------------------------------------------------------------------------
# Fallback Logic Tests
# ---------------------------------------------------------------------------

class TestLLMFallback:
    """Tests for the LLM Agent's fallback mechanism.

    When the LLM API fails 3+ times consecutively, infer_protocol()
    should return the last known good grammar instead of raising.
    """

    @pytest.mark.asyncio
    async def test_fallback_returns_cached_grammar(self):
        """After 3 consecutive failures, infer_protocol returns cached grammar."""
        agent = LLMAgent(
            provider="openai", model="gpt-4o", api_key="test-key",
            cache_file="/tmp/_lifa_test_no_exist.json",
        )

        # Simulate a previously successful inference
        cached_grammar = ProtocolGrammar(
            protocol_name="cached_proto",
            description="From a previous successful call",
            confidence=0.9,
        )
        agent._last_known_good_grammar = cached_grammar
        agent._consecutive_failures = 3  # At the failure threshold

        # Call infer_protocol — should return cached grammar WITHOUT calling LLM
        traffic = [TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\x01\x02\x03",
        )]
        result = await agent.infer_protocol(traffic)

        assert result.protocol_name == "cached_proto"
        assert result.confidence == 0.9

    @pytest.mark.asyncio
    async def test_no_fallback_when_under_threshold(self):
        """With < 3 consecutive failures, infer_protocol should still call LLM."""
        agent = LLMAgent(
            provider="openai", model="gpt-4o", api_key="test-key",
            cache_file="/tmp/_lifa_test_no_exist.json",
        )

        cached_grammar = ProtocolGrammar(
            protocol_name="cached_proto",
            confidence=0.9,
        )
        agent._last_known_good_grammar = cached_grammar
        agent._consecutive_failures = 2  # Below threshold

        # This should attempt to call the LLM (in REAL mode it will fail
        # because there's no real API). But with MOCK mode it should work.
        os.environ["LLM_MODE"] = "MOCK"
        try:
            traffic = [TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=b"\x01\x02\x03",
            )]
            result = await agent.infer_protocol(traffic)
            # In MOCK mode, it returns a mock grammar, NOT the cached one
            assert result.protocol_name != "cached_proto"
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_consecutive_failures_incremented(self):
        """call_llm() increments _consecutive_failures on final failure."""
        agent = LLMAgent(
            provider="openai", model="gpt-4o", api_key="test-key",
            max_retries=1,
        )

        assert agent._consecutive_failures == 0

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(
                    side_effect=RuntimeError("API down")
                )
                with pytest.raises(RuntimeError):
                    await agent.call_llm("test prompt")

        assert agent._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_cache_cleared_on_success(self):
        """After a successful inference, _consecutive_failures resets to 0."""
        agent = LLMAgent(
            provider="openai", model="gpt-4o", api_key="test-key",
            cache_file="/tmp/_lifa_test_no_exist.json",
        )
        agent._consecutive_failures = 2  # Below 3-failure gate threshold

        os.environ["LLM_MODE"] = "MOCK"
        try:
            traffic = [TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=b"\x01\x02\x03",
            )]
            await agent.infer_protocol(traffic)
            assert agent._consecutive_failures == 0
            assert agent._last_known_good_grammar is not None
        finally:
            os.environ.pop("LLM_MODE", None)

    def test_reset_clears_cache(self):
        """reset() clears both the cached grammar and failure counter."""
        agent = LLMAgent(provider="openai", model="gpt-4o", api_key="test-key")
        agent._last_known_good_grammar = ProtocolGrammar(protocol_name="test")
        agent._consecutive_failures = 10

        agent.reset()

        assert agent._last_known_good_grammar is None
        assert agent._consecutive_failures == 0
