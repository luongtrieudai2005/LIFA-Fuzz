"""
tests/test_llm_resilience.py
────────────────────────────
Unit tests for LLMAgent resilience features:
    - Immediate graceful fallback on single failure
    - Persistent cache surviving agent re-creation
    - Circuit breaker (open / skip / reset)
    - 401 auth error immediate abort
    - reset() clears circuit breaker + cache file
"""

from __future__ import annotations

import json
import os
import time

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from slow_loop.llm_agent import LLMAgent, _is_auth_error
from shared.schemas import Direction, ProtocolGrammar, TrafficRecord


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
    """A valid ProtocolGrammar for cache tests."""
    return ProtocolGrammar(
        protocol_name="test_cached_proto",
        description="Cached from a previous session",
        confidence=0.85,
    )


# =============================================================================
# Graceful Fallback
# =============================================================================


class TestGracefulFallback:
    """After a single call_llm() failure, infer_protocol() returns cached
    grammar immediately instead of propagating RuntimeError."""

    @pytest.mark.asyncio
    async def test_single_failure_returns_cached_grammar(
        self, traffic_records, sample_grammar, tmp_path
    ):
        """If cache exists, one failure → cached grammar (not RuntimeError)."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            cache_file=str(tmp_path / "cache.json"),
        )
        agent._last_known_good_grammar = sample_grammar

        with patch.object(agent, "call_llm", side_effect=RuntimeError("API down")):
            result = await agent.infer_protocol(traffic_records)

        assert result.protocol_name == "test_cached_proto"

    @pytest.mark.asyncio
    async def test_single_failure_no_cache_propagates(self, traffic_records, tmp_path):
        """If no cache exists, RuntimeError propagates to caller."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            cache_file=str(tmp_path / "no_cache_here.json"),
        )
        assert agent._last_known_good_grammar is None

        with patch.object(agent, "call_llm", side_effect=RuntimeError("API down")):
            with pytest.raises(RuntimeError, match="API down"):
                await agent.infer_protocol(traffic_records)

    @pytest.mark.asyncio
    async def test_fallback_increments_inferences(
        self, traffic_records, sample_grammar, tmp_path
    ):
        """Returning cached grammar should increment _total_inferences."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            cache_file=str(tmp_path / "cache.json"),
        )
        agent._last_known_good_grammar = sample_grammar

        with patch.object(agent, "call_llm", side_effect=RuntimeError("fail")):
            await agent.infer_protocol(traffic_records)

        assert agent._total_inferences == 1


# =============================================================================
# Persistent Cache
# =============================================================================


class TestPersistentCache:
    """Grammar cache survives process restarts via JSON file."""

    def test_save_cache_writes_file(self, tmp_path, sample_grammar):
        """_save_cache() writes valid JSON to the cache file."""
        cache_file = str(tmp_path / "cache.json")
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        agent._last_known_good_grammar = sample_grammar
        agent._save_cache()

        with open(cache_file) as f:
            data = json.load(f)

        assert data["protocol_name"] == "test_cached_proto"

    def test_load_cache_restores_grammar(self, tmp_path, sample_grammar):
        """_load_cache() restores grammar from file on init."""
        cache_file = str(tmp_path / "cache.json")
        agent_a = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        agent_a._last_known_good_grammar = sample_grammar
        agent_a._save_cache()

        agent_b = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        assert agent_b._last_known_good_grammar is not None
        assert agent_b._last_known_good_grammar.protocol_name == "test_cached_proto"

    def test_load_cache_corrupted_file(self, tmp_path):
        """Corrupted JSON file → _last_known_good_grammar stays None."""
        cache_file = str(tmp_path / "cache.json")
        with open(cache_file, "w") as f:
            f.write("{not valid json!!!")

        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        assert agent._last_known_good_grammar is None

    def test_load_cache_missing_file(self, tmp_path):
        """Missing file → _last_known_good_grammar stays None."""
        cache_file = str(tmp_path / "nonexistent.json")
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        assert agent._last_known_good_grammar is None

    def test_cache_survives_agent_recreation(self, tmp_path, sample_grammar):
        """Grammar saved by agent A is available to fresh agent B."""
        cache_file = str(tmp_path / "cache.json")

        agent_a = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        agent_a._last_known_good_grammar = sample_grammar
        agent_a._save_cache()

        # Completely new agent instance
        agent_b = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        assert agent_b._last_known_good_grammar.protocol_name == "test_cached_proto"
        assert agent_b._last_known_good_grammar.confidence == 0.85

    def test_roundtrip_serialization(self, tmp_path):
        """Full ProtocolGrammar with fields roundtrips through cache."""
        grammar = ProtocolGrammar(
            protocol_name="lifa",
            description="Test protocol",
            magic_bytes="4c494641",
            fields=[
                {
                    "name": "magic",
                    "offset_start": 0,
                    "offset_end": 4,
                    "field_type": "uint32_le",
                    "description": "Magic header",
                    "possible_values": ["4c494641"],
                    "is_constant": True,
                },
                {
                    "name": "opcode",
                    "offset_start": 4,
                    "offset_end": 5,
                    "field_type": "uint8",
                    "description": "Command opcode",
                    "possible_values": ["01", "02"],
                    "is_constant": False,
                },
            ],
            total_header_size=6,
            min_packet_size=6,
            max_packet_size=65535,
            confidence=0.92,
        )

        cache_file = str(tmp_path / "cache.json")
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        agent._last_known_good_grammar = grammar
        agent._save_cache()

        agent2 = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        loaded = agent2._last_known_good_grammar
        assert loaded is not None
        assert loaded.protocol_name == "lifa"
        assert len(loaded.fields) == 2
        assert loaded.confidence == 0.92

    def test_save_cache_none_skips_write(self, tmp_path):
        """_save_cache() does nothing when grammar is None."""
        cache_file = str(tmp_path / "cache.json")
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        assert agent._last_known_good_grammar is None
        agent._save_cache()
        assert not os.path.exists(cache_file)


# =============================================================================
# Circuit Breaker
# =============================================================================


class TestCircuitBreaker:
    """Circuit breaker prevents API calls during sustained outages."""

    @pytest.mark.asyncio
    async def test_circuit_opens_after_exhaustion(self, tmp_path):
        """After all retries exhausted, circuit opens."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key", max_retries=1,
            circuit_retry_after_s=300,
            cache_file=str(tmp_path / "cache.json"),
        )

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(
                    side_effect=RuntimeError("API down")
                )
                with pytest.raises(RuntimeError):
                    await agent.call_llm("test")

        assert agent._circuit_open_until > 0

    @pytest.mark.asyncio
    async def test_circuit_skips_api_calls(self, tmp_path):
        """When circuit is open, call_llm() raises without hitting the API."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            cache_file=str(tmp_path / "cache.json"),
        )
        # Manually open the circuit
        agent._circuit_open_until = time.monotonic() + 600

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                with pytest.raises(RuntimeError, match="Circuit breaker"):
                    await agent.call_llm("test")
                # litellm should NOT have been called
                mock_litellm.acompletion.assert_not_called()

    @pytest.mark.asyncio
    async def test_circuit_resets_on_success(self, tmp_path):
        """A successful API call resets the circuit breaker."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            cache_file=str(tmp_path / "cache.json"),
        )
        # Set circuit to a past time (already expired) so the call proceeds
        agent._circuit_open_until = time.monotonic() - 1  # expired

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(return_value=mock_response)
                await agent.call_llm("test")

        # Circuit should be fully reset (0.0, not just expired)
        assert agent._circuit_open_until == 0.0

    @pytest.mark.asyncio
    async def test_circuit_auto_expires(self, tmp_path):
        """Circuit allows calls after cooldown expires."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key",
            circuit_retry_after_s=0.01,  # 10ms — expires almost immediately
            cache_file=str(tmp_path / "cache.json"),
        )
        # Open circuit with a very short cooldown
        agent._circuit_open_until = time.monotonic() + 0.01

        # Wait for it to expire
        time.sleep(0.05)

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"protocol_name": "test"}'
        mock_response.usage.prompt_tokens = 40
        mock_response.usage.completion_tokens = 10
        mock_response.usage.total_tokens = 50

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(return_value=mock_response)
                result = await agent.call_llm("test")

        assert result == '{"protocol_name": "test"}'


# =============================================================================
# Auth Error Detection
# =============================================================================


class TestAuthError:
    """401/auth errors abort immediately without retries."""

    def test_is_auth_error_detects_401(self):
        assert _is_auth_error("AuthenticationError", "401 unauthorized") is True

    def test_is_auth_error_detects_invalid_key(self):
        assert _is_auth_error("APIError", "invalid api key provided") is True

    def test_is_auth_error_detects_forbidden(self):
        assert _is_auth_error("ForbiddenError", "access denied for resource") is True

    def test_is_auth_error_ignores_server_error(self):
        assert _is_auth_error("APIError", "500 internal server error") is False

    def test_is_auth_error_ignores_rate_limit(self):
        assert _is_auth_error("RateLimitError", "429 too many requests") is False

    @pytest.mark.asyncio
    async def test_401_stops_immediately_no_retry(self, tmp_path):
        """Auth error → only 1 API call, not max_retries."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key", max_retries=3,
            cache_file=str(tmp_path / "cache.json"),
        )

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(
                    side_effect=RuntimeError("401 Unauthorized: invalid API key")
                )
                with pytest.raises(RuntimeError, match="Authentication error"):
                    await agent.call_llm("test")

        # Should have been called exactly ONCE (no retries)
        assert mock_litellm.acompletion.call_count == 1

    @pytest.mark.asyncio
    async def test_401_opens_circuit(self, tmp_path):
        """Auth error also opens the circuit breaker."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test-key", max_retries=3,
            circuit_retry_after_s=300,
            cache_file=str(tmp_path / "cache.json"),
        )

        with patch("slow_loop.llm_agent.HAS_LITELM", True):
            with patch("slow_loop.llm_agent.litellm", create=True) as mock_litellm:
                mock_litellm.acompletion = AsyncMock(
                    side_effect=RuntimeError("401 Unauthorized")
                )
                with pytest.raises(RuntimeError):
                    await agent.call_llm("test")

        assert agent._circuit_open_until > 0
        assert agent._consecutive_failures == 1


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    """reset() clears all resilience state."""

    def test_reset_clears_circuit(self, tmp_path):
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=str(tmp_path / "cache.json"),
        )
        agent._circuit_open_until = time.monotonic() + 600
        agent.reset()
        assert agent._circuit_open_until == 0.0

    def test_reset_clears_failure_counter(self, tmp_path):
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=str(tmp_path / "cache.json"),
        )
        agent._consecutive_failures = 5
        agent.reset()
        assert agent._consecutive_failures == 0

    def test_reset_deletes_cache_file(self, tmp_path, sample_grammar):
        cache_file = str(tmp_path / "cache.json")
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=cache_file,
        )
        agent._last_known_good_grammar = sample_grammar
        agent._save_cache()
        assert os.path.exists(cache_file)

        agent.reset()
        assert not os.path.exists(cache_file)
        assert agent._last_known_good_grammar is None

    def test_reset_handles_missing_cache_file(self, tmp_path):
        """reset() does not crash if cache file is missing."""
        agent = LLMAgent(
            model="gpt-4o", api_key="test",
            cache_file=str(tmp_path / "nonexistent.json"),
        )
        agent._consecutive_failures = 3
        agent._circuit_open_until = time.monotonic() + 100
        # Should not raise
        agent.reset()
        assert agent._consecutive_failures == 0
        assert agent._circuit_open_until == 0.0
