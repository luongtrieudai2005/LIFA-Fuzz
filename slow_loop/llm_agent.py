"""
slow_loop/llm_agent.py
──────────────────────
LLM Agent — interacts with a Large Language Model to infer protocol
semantics from parsed traffic.

Responsibilities:
    - Build structured prompts from traffic samples.
    - Call the LLM API (via litellm for provider-agnostic access).
    - Parse the LLM's response into a ProtocolGrammar object.
    - Handle retries, timeouts, and rate limiting.

Provider Support:
    Uses ``litellm`` which abstracts the differences between providers:
    - OpenAI (GPT-4o, GPT-4o-mini)
    - Anthropic (Claude)
    - Local models (Ollama, vLLM)
    - Any OpenAI-compatible endpoint

Prompt Engineering:
    The prompt instructs the LLM to analyze traffic patterns and output
    a structured JSON describing the protocol grammar. The prompt includes:
    - System message: role definition and output schema.
    - Traffic samples: hex dumps with metadata (direction, length, context).
    - Few-shot examples (optional): for improved accuracy.

Token Budget:
    Traffic samples are truncated to fit within the model's context window.
    ``tiktoken`` is used for accurate token counting.

TODO (Phase 3):
    - [ ] Implement prompt template (system + few-shot examples)
    - [ ] Implement call_llm() with litellm
    - [ ] Implement infer_protocol() end-to-end pipeline
    - [ ] Implement token budgeting with tiktoken
    - [ ] Add retry logic with exponential backoff
    - [ ] Add response validation (ensure LLM returns valid JSON)
"""

from __future__ import annotations

from typing import Any, Optional

from shared.logger import get_logger
from shared.schemas import ProtocolGrammar, TrafficRecord

logger = get_logger("slow_loop.llm_agent")


# =============================================================================
# Prompt Templates
# =============================================================================

SYSTEM_PROMPT = """\
You are a protocol analysis engine. Your job is to analyze network traffic \
captures and infer the protocol's wire format.

You will receive traffic samples as hex dumps with metadata. For each sample, \
analyze the byte patterns and infer:
1. Magic bytes / protocol header signature
2. Field layout (offset, length, type)
3. Length fields (and what they describe)
4. Checksum fields (if any)
5. Enum/constant fields
6. Variable-length data regions

Output your analysis as a JSON object with this schema:
{
    "protocol_name": "string",
    "description": "string",
    "magic_bytes": "hex string or null",
    "fields": [
        {
            "name": "string",
            "offset_start": int,
            "offset_end": int,
            "field_type": "uint8|uint16_le|uint16_be|uint32_le|uint32_be|int8|int16_le|int16_be|int32_le|int32_be|string|bytes|enum|bool|reserved",
            "description": "string",
            "possible_values": ["list of values if enum"],
            "is_constant": bool
        }
    ],
    "total_header_size": int or null,
    "min_packet_size": int,
    "max_packet_size": int,
    "confidence": float (0.0 to 1.0)
}

Be precise with offsets. If unsure, mark confidence low. Do not invent \
fields without evidence from the traffic data.
"""

TRAFFIC_SAMPLE_TEMPLATE = """\
--- Sample #{index} ---
Direction: {direction}
Length: {length} bytes
Hex: {hex_data}
Mutated: {is_mutated}
"""


class LLMAgent:
    """Protocol inference via LLM.

    Coordinates the full inference pipeline:
    1. Receive traffic samples from the Parser.
    2. Build a prompt from the samples.
    3. Call the LLM API.
    4. Parse the response into a ``ProtocolGrammar``.

    Args:
        provider:        litellm provider string (``"openai"``, ``"anthropic"``, etc.).
        model:           Model name (``"gpt-4o"``, ``"claude-sonnet-4-20250514"``, etc.).
        api_key:         API key for the provider (read from env var).
        max_tokens:      Maximum tokens in the LLM response.
        temperature:     Sampling temperature (low for deterministic inference).
        timeout_seconds: Request timeout.
        max_retries:     Number of retries on transient failures.

    Example:
        >>> agent = LLMAgent(provider="openai", model="gpt-4o")
        >>> grammar = await agent.infer_protocol(traffic_samples)
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        api_key: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.2,
        timeout_seconds: int = 60,
        max_retries: int = 3,
    ) -> None:
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

        # Stats
        self._total_inferences: int = 0
        self._total_tokens_used: int = 0

    # -----------------------------------------------------------------
    # Core Inference Pipeline
    # -----------------------------------------------------------------

    async def infer_protocol(
        self,
        traffic_samples: list[TrafficRecord],
    ) -> ProtocolGrammar:
        """Analyze traffic samples and infer the protocol grammar.

        This is the main entry point. It orchestrates:
        1. Prompt construction from samples.
        2. LLM API call.
        3. Response parsing and validation.

        Args:
            traffic_samples: List of captured traffic records to analyze.

        Returns:
            A ``ProtocolGrammar`` object with inferred protocol structure.

        Raises:
            ValueError: If the LLM response cannot be parsed.
            RuntimeError: If the LLM API call fails after all retries.

        TODO (Phase 3): Implement.
        """
        raise NotImplementedError("TODO: Implement full inference pipeline")

    # -----------------------------------------------------------------
    # Prompt Construction
    # -----------------------------------------------------------------

    def build_prompt(self, samples: list[TrafficRecord]) -> str:
        """Construct the user prompt from traffic samples.

        Formats each sample as a readable hex dump with metadata,
        then concatenates them into a single prompt string.

        Args:
            samples: Traffic records to include in the prompt.

        Returns:
            The formatted user message string.

        TODO (Phase 3): Implement.
        - Format each sample using TRAFFIC_SAMPLE_TEMPLATE
        - Truncate to fit token budget
        - Add context about the number of samples
        """
        raise NotImplementedError("TODO: Implement prompt construction")

    # -----------------------------------------------------------------
    # LLM API Call
    # -----------------------------------------------------------------

    async def call_llm(self, prompt: str) -> str:
        """Call the LLM API with the given prompt.

        Uses litellm for provider-agnostic API access.
        Implements retry with exponential backoff on transient failures.

        Args:
            prompt: The full user prompt string.

        Returns:
            The LLM's response text.

        Raises:
            RuntimeError: If the call fails after max_retries.

        TODO (Phase 3): Implement.
        - Use litellm.acompletion()
        - Handle rate limits (429) with backoff
        - Handle timeouts
        - Log token usage
        """
        raise NotImplementedError("TODO: Implement LLM API call")

    # -----------------------------------------------------------------
    # Response Parsing
    # -----------------------------------------------------------------

    def parse_response(self, response_text: str) -> ProtocolGrammar:
        """Parse the LLM's JSON response into a ProtocolGrammar.

        Handles common issues:
        - Response wrapped in markdown code blocks (```json ... ```)
        - Extra text before/after the JSON
        - Partial or malformed JSON

        Args:
            response_text: Raw text from the LLM.

        Returns:
            A validated ``ProtocolGrammar`` object.

        Raises:
            ValueError: If the response cannot be parsed as valid JSON.

        TODO (Phase 3): Implement.
        """
        raise NotImplementedError("TODO: Implement response parsing")
