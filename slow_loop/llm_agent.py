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
    - Support MOCK mode for free testing without API keys.
    - Track token budgets and surface errors to the Web Dashboard.

Operating Modes:
    Controlled by the ``LLM_MODE`` environment variable:
      - ``REAL`` (default): Calls the actual LLM API via litellm.
      - ``MOCK``: Returns a pre-built simulated ProtocolGrammar after
        a short delay. No API key required. Used for end-to-end
        validation of the full fuzzing loop.

Provider Support (REAL mode):
    Uses ``litellm`` which abstracts the differences between providers:
    - OpenAI (GPT-4o, GPT-4o-mini)
    - Anthropic (Claude)
    - Local models (Ollama, vLLM)
    - Any OpenAI-compatible endpoint

Structured Output:
    Uses ``response_format={"type": "json_object"}`` via litellm to force
    JSON output, then validates against the Pydantic ``ProtocolGrammar`` model.

Error Handling Strategy:
    - Rate limits (429) → exponential backoff up to 120s
    - Timeouts → retry with same timeout (transient network issue)
    - API errors (5xx) → exponential backoff up to 60s
    - Parse/schema errors → NO retry (same prompt → same bad output), raise ValueError
    - Network errors → exponential backoff up to 60s
    All errors are logged to ``shared/llm_last_inference.json`` for Dashboard display.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional, Union

from shared.logger import get_logger
from shared.schemas import ProtocolGrammar, TrafficRecord

logger = get_logger("slow_loop.llm_agent")

# Lazy import — litellm is an optional runtime dependency
try:
    import litellm

    # Suppress litellm's verbose logging
    litellm.suppress_debug_info = True
    HAS_LITELM = True
except ImportError:
    HAS_LITELM = False
    logger.warning(
        "litellm is not installed — LLM inference will be unavailable. "
        "Install with: pip install litellm"
    )


# =============================================================================
# Model Pricing (USD per 1M tokens)
# =============================================================================
MODEL_PRICING: dict[str, dict[str, float]] = {
    "glm-5-turbo":                 {"input_per_m": 0.60,  "output_per_m": 1.92},
    "gpt-4o":                      {"input_per_m": 2.50,  "output_per_m": 10.00},
    "gpt-4o-mini":                 {"input_per_m": 0.15,  "output_per_m": 0.60},
    "claude-sonnet-4-20250514":    {"input_per_m": 3.00,  "output_per_m": 15.00},
    "default":                     {"input_per_m": 1.00,  "output_per_m": 2.00},
}


# =============================================================================
# Mock LLM Mode — for free end-to-end testing
# =============================================================================

_MOCK_LLM_DELAY_S: float = 2.0  # Simulated API latency

_MOCK_RESPONSE_JSON: str = json.dumps({
    "protocol_name": "mock_inferred_protocol",
    "description": "Simulated protocol inference from LLM (MOCK mode). "
                   "Generates rules targeting magic, length, and payload fields.",
    "magic_bytes": "deadbeef",
    "fields": [
        {
            "name": "magic",
            "offset_start": 0,
            "offset_end": 4,
            "field_type": "uint32_le",
            "description": "Protocol magic header — constant across all packets",
            "possible_values": ["deadbeef"],
            "is_constant": True,
            "mutation_strategy": "static",
        },
        {
            "name": "length",
            "offset_start": 4,
            "offset_end": 6,
            "field_type": "uint16_le",
            "description": "Payload length field — controls how many bytes follow",
            "possible_values": [],
            "is_constant": False,
            "mutation_strategy": "boundary_values",
        },
        {
            "name": "payload",
            "offset_start": 6,
            "offset_end": -1,
            "field_type": "bytes",
            "description": "Variable-length payload data",
            "possible_values": [],
            "is_constant": False,
            "mutation_strategy": "random_bytes",
        },
    ],
    "total_header_size": 6,
    "min_packet_size": 6,
    "max_packet_size": 65535,
    "confidence": 0.80,
})


def is_mock_mode() -> bool:
    """Check if the LLM Agent should operate in MOCK mode.

    Reads the ``LLM_MODE`` environment variable.
    Returns True if set to ``MOCK``, False otherwise (default: REAL).
    """
    return os.environ.get("LLM_MODE", "REAL").upper() == "MOCK"


# =============================================================================
# Expert System Prompt — Protocol Reverse Engineering
# =============================================================================

SYSTEM_PROMPT = """\
You are an elite Cybersecurity Researcher and Protocol Reverse Engineer \
with deep expertise in:
- Black-box protocol analysis and fuzzing of proprietary/custom protocols
- Memory corruption vulnerability research (heap/stack buffer overflows, \
integer overflows, use-after-free, double-free, off-by-one)
- Network protocol state machine inference and state-fuzzing
- Binary format analysis and wire protocol dissection
- CVE analysis and exploit development

## YOUR MISSION

Analyze raw network traffic captures (hex dumps with ASCII representations) \
to reverse-engineer the wire format of an unknown/proprietary network \
protocol. Then prescribe targeted mutation strategies that maximize the \
probability of discovering memory corruption vulnerabilities in the \
protocol parser implementation.

## ANALYSIS METHODOLOGY

Follow this systematic methodology for every traffic capture:

### Step 1: Identify Protocol Frame Structure
For each packet, determine the overall frame layout:
- Fixed header length (look for consistent minimum packet size across \
  all packets)
- Delimiters or frame boundaries (magic bytes at fixed offsets, \
  length-prefixed fields)
- Trailer/checksum fields (bytes at packet end that change when \
  payload changes)

### Step 2: Detect Invariant Prefixes (Magic Bytes / Headers)
- Find byte sequences identical across ALL packets at the same offset.
- These are protocol magic numbers, version fields, or fixed headers.
- Mark them as `is_constant: true` with `mutation_strategy: "static"`.
- CRITICAL: NEVER fuzz these — they are required for the packet to \
  reach the parser's main logic. Without them, the server rejects the \
  packet before reaching any vulnerable code path.

### Step 3: Discover Length Fields
This is the HIGHEST-VALUE finding. Length fields are historically the \
#1 source of parser bugs. Look for numeric fields whose decoded value \
correlates with:
  a) Total packet length minus header size
  b) Length of a subsequent variable-length payload region
  c) Remaining bytes after this field
  d) Size of a sub-structure or nested TLV element

Common patterns:
- 1-byte length (uint8) at offset right before payload
- 2-byte length (uint16_le or uint16_be) — very common in custom protocols
- 4-byte length (uint32_le or uint32_be) — used in larger protocols

For each length field, document: offset, byte width, endianness, what \
it measures, and whether the value is consistent with actual packet size.

### Step 4: Identify Opcodes / Command Types / Message IDs
- Look for fields (usually 1-2 bytes at a fixed offset after the magic \
  header) that take a limited set of discrete values.
- These are command opcodes, message types, or state identifiers.
- Enumerate ALL observed values and their associated packet structures.
- Different opcodes trigger different server code paths — essential for \
  fuzzing coverage.
- Mark these as `field_type: "enum"` with all observed `possible_values`.

### Step 5: Detect State Machine Patterns
- Observe if certain packet sequences always appear in a specific order.
- Look for request-response patterns (client sends opcode X, server \
  responds with Y).
- Identify authentication/handshake phases vs. data exchange phases.
- Check for sequence numbers or session tokens that increment.
- Note: state-dependent fields may have different meanings in different \
  contexts.

### Step 6: Analyze Variable-Length Regions
- Identify payload regions whose size varies between packets.
- Check if a preceding length field accurately describes their size.
- Look for null terminators in string-like regions (0x00 bytes).
- Detect TLV (Type-Length-Value) nested structures.
- Look for padding/alignment bytes after variable-length fields.

### Step 7: Check for Checksums/CRCs
- Fields at fixed offsets (often the last 2-4 bytes) that change when \
  payload changes.
- Common algorithms: CRC16, CRC32, XOR checksum, Adler32, Fletcher.
- Compare: do any 2-4 byte fields at the end correlate with the rest?
- If the checksum is wrong, the server may reject before reaching \
  vulnerable code. Mark as `calculated` strategy.
- SOMETIMES servers skip validation in debug builds — wrong checksum \
  may reach deeper code paths.

## MUTATION STRATEGY SELECTION

For each identified field, assign the mutation strategy MOST LIKELY to \
trigger a memory corruption vulnerability. Use the following priority guide:

### CRITICAL PRIORITY — Highest Historical Bug Yield:
1. **Length Fields** → `boundary_values`
   Test values: 0, MAX_UINT, MAX_UINT-1, MAX_UINT+1 (overflow), negative \
   (if signed interpretation is possible), values much larger than actual \
   payload, value=1 (off-by-one), value=actual+1 (off-by-one on read).
   Primary vulnerability vectors:
   - Heap buffer overflow: length says 1000 but only 100 bytes follow
   - Stack buffer overflow: length used for memcpy into stack buffer
   - Integer overflow: length + header > MAX_UINT → undersized malloc
   - Off-by-one: fencepost error in loop bound

2. **Opcodes / Command IDs** → `dictionary`
   Cycle through all known values PLUS invalid/unassigned/out-of-range values.
   Primary vulnerability vectors:
   - Missing default case in switch → fallthrough to uninitialized handler
   - Array index out-of-bounds: opcode used as direct array index
   - Negative opcode: signed/unsigned confusion

### HIGH PRIORITY:
3. **Numeric Fields (non-length)** → `boundary_values`
   Test: 0, 1, MAX, MAX-1, MIN, MIN+1, 0x7FFFFFFF, 0x80000000.
   Primary vectors:
   - Integer signedness bugs
   - Division by zero
   - Arithmetic overflow in size calculations

4. **String Fields** → `random_bytes`
   Inject: format strings (%s%s%s%n), path traversal (../../../etc/passwd), \
   null bytes (0x00 mid-string), oversized strings, command injection payloads.
   Primary vectors:
   - Format string vulnerabilities (printf family)
   - Null terminator confusion (different strlen vs buffer size)
   - Path traversal / directory traversal

### MEDIUM PRIORITY:
5. **Checksum/CRC Fields** → `calculated`
   Intentionally compute WRONG checksums or zero them out.
   Sometimes servers skip validation — mutated payload reaches deeper code.

6. **Payload/Body Regions** → `random_bytes`
   Random mutation of payload bytes. Good baseline coverage.

### LOW PRIORITY:
7. **Magic Bytes / Fixed Headers** → `static`
   DO NOT FUZZ. Required for packet to be parsed at all.

8. **Reserved / Padding** → `bit_flip`
   Low priority but sometimes triggers uninitialized memory reads or \
   alignment-related bugs.

## FIELD TYPE REFERENCE

The `field_type` MUST be one of exactly 8 values:
- `uint8`         — unsigned 8-bit integer
- `uint16_le`     — unsigned 16-bit little-endian
- `uint16_be`     — unsigned 16-bit big-endian
- `uint32_le`     — unsigned 32-bit little-endian
- `uint32_be`     — unsigned 32-bit big-endian
- `bytes`         — raw unstructured bytes (payloads, unknown regions, padding)
- `enum`          — discrete set of values (opcodes, command types, flags)
- `string`        — null-terminated or length-delimited text

NOTE: For signed fields, use the unsigned type of the same width.
NOTE: For boolean fields, use `enum` with `possible_values: ["00", "01"]`.
NOTE: For padding/reserved regions, use `bytes` with `is_constant: true`.

## MUTATION STRATEGY REFERENCE

The `mutation_strategy` MUST be one of these exact values:
- `static` — DO NOT mutate (magic bytes, fixed headers)
- `random_bytes` — Replace with random data
- `bit_flip` — Flip individual bits
- `boundary_values` — Test edge-case numeric values (0, MAX, MIN, overflow)
- `increment` — Sequential increment/decrement
- `calculated` — Derived from other fields (checksums)
- `dictionary` — Cycle through known + invalid values (enums)
- `skip` — Temporarily skip this field

## OUTPUT FORMAT

You MUST respond with a single valid JSON object matching this exact schema:

{
    "protocol_name": "string — your best guess at the protocol name",
    "description": "string — brief description of the protocol purpose",
    "magic_bytes": "hex_string_or_null — detected magic/header bytes",
    "fields": [
        {
            "name": "string — descriptive field name",
            "offset_start": 0,
            "offset_end": 4,
            "field_type": "uint32_le",
            "description": "string — what this field does and WHY you identified it",
            "possible_values": ["list of observed hex values for enum fields"],
            "is_constant": false,
            "mutation_strategy": "boundary_values"
        }
    ],
    "total_header_size": 6,
    "min_packet_size": 6,
    "max_packet_size": 65535,
    "confidence": 0.85,
    "reasoning": "string — explain your analysis methodology, key findings, and strategy rationale"
}

## CRITICAL RULES
1. Byte offsets are 0-indexed. Be PRECISE with offset_start and offset_end.
2. offset_end is EXCLUSIVE (Python-style slice convention). \
   EXAMPLE: Bytes at positions 0,1,2,3 → offset_start=0, offset_end=4. \
   Byte at position 4 alone → offset_start=4, offset_end=5. \
   WRONG: offset_start=0, offset_end=3 (this covers only 3 bytes, not 4).
3. If multiple packets share identical bytes at the same offset, those are \
   constant/magic bytes → mark `is_constant: true`.
4. Length fields typically appear just before the variable-length payload \
   they describe.
5. Do NOT invent fields without evidence from the traffic data.
6. When uncertain, set confidence LOW and is_constant=false.
7. Always include a "reasoning" field explaining your analysis.
8. Respond with ONLY the JSON object — no markdown, no explanation.

## EXAMPLE OUTPUT

Here is a correct example for a simple 3-field binary protocol:
Packet: de ad be ef  00 07  48 65 6c 6c 6f 0d 0a
        [magic 4B ] [len2B] [payload 7B          ]

Correct output:
{
    "protocol_name": "example_tlv",
    "description": "Simple TLV protocol with magic header and length-prefixed payload",
    "magic_bytes": "deadbeef",
    "fields": [
        {"name": "magic",   "offset_start": 0, "offset_end": 4,
         "field_type": "bytes", "is_constant": true,
         "mutation_strategy": "static",
         "description": "Magic header 0xDEADBEEF — constant across all packets"},
        {"name": "length",  "offset_start": 4, "offset_end": 6,
         "field_type": "uint16_be", "is_constant": false,
         "mutation_strategy": "boundary_values",
         "description": "Big-endian length field = 7, matches remaining payload bytes"},
        {"name": "payload", "offset_start": 6, "offset_end": -1,
         "field_type": "bytes", "is_constant": false,
         "mutation_strategy": "random_bytes",
         "description": "Variable-length payload data"}
    ],
    "total_header_size": 6, "min_packet_size": 6, "max_packet_size": 65535,
    "confidence": 0.92,
    "reasoning": "Bytes 0-3 are constant 0xDEADBEEF across packets → magic header. \
Bytes 4-5 decode as uint16_be=7 which equals the remaining 7 bytes → length field. \
Bytes 6 onwards vary in content and length → variable payload."
}

Now analyze the actual traffic below and infer the protocol wire format.
"""

SYSTEM_PROMPT_FUSION_APPEND = """\

## MATHEMATICAL PRE-ANALYSIS GUIDELINES

When a "MATHEMATICAL PRE-ANALYSIS" block is provided in the user prompt, \
it contains byte-level statistical classifications computed from the raw \
traffic corpus BEFORE your analysis. These are NOT guesses — they are \
derived from Shannon entropy, Pearson correlation, and Kendall's tau.

You MUST follow these rules:

1. **STATIC fields** (❄): These bytes are constant across ALL packets. \
   Do NOT re-derive or re-invent them. Mark them as `is_constant: true` \
   with `mutation_strategy: "static"`. Focus your analysis on NAMING \
   them (e.g. "magic_header", "protocol_version") rather than discovering \
   that they are constant.

2. **CALCULATED fields** (⚙): These are deterministic but derived from \
   other packet properties (length fields, sequence numbers). Focus your \
   `boundary_values` strategy here — this is the highest-value fuzzing \
   target. Confirm the encoding (endianness, width) and what each \
   length field measures.

3. **HIGH_ENTROPY fields** (🔥): These bytes vary widely — likely payload, \
   encrypted, or random data. Use `random_bytes` strategy. Your job is to \
   identify if there are sub-structures (TLV, nested headers) within these \
   regions that the math layer cannot detect.

4. **LOW_ENTROPY fields** (〰): These bytes take a limited set of values — \
   likely flags, enums, or type codes. Use `bit_flip` or `dictionary` \
   strategy. Enumerate all observed values and test invalid/out-of-range \
   values.

5. **REASONING REQUIREMENT**: In your "reasoning" field, explicitly state \
   how your semantic analysis CONFIRMS or CONTRADICTS the mathematical \
   heatmap. If you disagree with a classification, explain why with \
   evidence from the traffic data.

6. **DO NOT re-derive** what the heatmap already tells you. Your value-add \
   is: semantic naming, cross-field relationships, state machine patterns, \
   checksum detection, and vulnerability-focused strategy refinement.
"""

TRAFFIC_SAMPLE_TEMPLATE = """\
--- Packet #{index} (Direction: {direction}, Length: {length}B) ---
{hex_xxd}
"""


# =============================================================================
# LLMAgent
# =============================================================================


class LLMAgent:
    """Protocol inference via LLM.

    Coordinates the full inference pipeline:
    1. Receive traffic data (TrafficRecords or pre-formatted parser payload).
    2. Build a prompt from the samples.
    3. Call the LLM API via litellm.
    4. Parse the response into a validated ``ProtocolGrammar``.

    Error Handling:
        - Rate limits (429): exponential backoff up to 120s
        - Timeouts: retry with standard backoff
        - API errors (5xx): exponential backoff up to 60s
        - Parse errors: NO retry (same prompt → same bad output), raise ValueError
        - Network errors: exponential backoff up to 60s
        All errors logged to shared/llm_last_inference.json for Dashboard.

    Args:
        provider:        litellm provider string (``"openai"``, ``"anthropic"``, etc.).
        model:           Model name (``"gpt-4o"``, ``"claude-sonnet-4-20250514"``, etc.).
        api_key:         API key for the provider (read from env var at init).
        max_tokens:      Maximum tokens in the LLM response.
        temperature:     Sampling temperature (low = deterministic).
        timeout_seconds: Request timeout.
        max_retries:     Number of retries on transient failures.
        session_budget_tokens: Maximum total tokens to spend per session. \
                        0 = unlimited.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        api_key: str = "",
        api_base: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.2,
        timeout_seconds: int = 60,
        max_retries: int = 3,
        session_budget_tokens: int = 0,
        session_budget_usd: float = 0.0,
        cache_file: str = "shared/last_known_grammar.json",
        circuit_retry_after_s: float = 300.0,
        context_window: int = 128_000,
        prompt_truncation_strategy: str = "truncate",
    ) -> None:
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.session_budget_tokens = session_budget_tokens
        self.session_budget_usd = session_budget_usd
        self.enable_thinking = True  # Override via setter after init

        # Runtime stats
        self._total_inferences: int = 0
        self._total_tokens_used: int = 0
        self._session_tokens_used: int = 0
        self._last_response: str = ""
        self._last_error: str = ""

        # Fallback cache — survives transient LLM failures
        self._last_known_good_grammar: Optional[ProtocolGrammar] = None
        self._consecutive_failures: int = 0

        # Cost tracking (USD)
        self.cost_per_inference: float = 0.0
        self.total_cost_usd: float = 0.0
        # session_budget_usd is already set above from the constructor param

        # Context window guard
        self.context_window: int = context_window
        self.prompt_truncation_strategy: str = prompt_truncation_strategy

        # Resilience: persistent cache and circuit breaker
        self._cache_file: str = cache_file
        self._circuit_retry_after_s: float = circuit_retry_after_s
        self._circuit_open_until: float = 0.0  # monotonic timestamp; 0 = closed

        # Load persistent cache from disk (survives process restarts)
        self._load_cache()

    # -----------------------------------------------------------------
    # Core Inference Pipeline
    # -----------------------------------------------------------------

    async def infer_protocol(
        self,
        traffic_input: Union[list[TrafficRecord], dict[str, Any]],
        math_hint: Optional[str] = None,
    ) -> ProtocolGrammar:
        """Analyze traffic and infer protocol grammar.

        Accepts two input types:
        - ``list[TrafficRecord]``: raw traffic records (builds prompt from hex).
        - ``dict``: pre-formatted LLM payload from \
        ``TrafficParser.format_for_llm()``.

        Args:
            traffic_input: Traffic data to analyze.
            math_hint:     Optional pre-computed heatmap string from the
                           DifferentialAnalyzer. When provided, it is injected
                           into the LLM prompt so the model can focus on
                           semantic naming and confirmation rather than raw
                           byte-level discovery.

        Returns:
            A validated ``ProtocolGrammar`` with inferred protocol structure.

        Raises:
            TypeError:  If input is not a list or dict.
            RuntimeError: If the LLM API call fails after all retries.
            ValueError: If the LLM response cannot be parsed.
        """
        prompt = self._build_prompt_from_input(traffic_input, math_hint=math_hint)

        # ── Context window guard ─────────────────────────────────────
        estimated = estimate_tokens(prompt)
        if estimated > self.context_window:
            if self.prompt_truncation_strategy == "error":
                raise RuntimeError(
                    f"Prompt exceeds context window "
                    f"({estimated} > {self.context_window} tokens)"
                )
            elif self.prompt_truncation_strategy == "truncate":
                max_chars = int(
                    len(prompt) * (self.context_window * 0.9 / estimated)
                )
                prompt = prompt[:max_chars]
                logger.warning(
                    f"Prompt truncated to {max_chars} chars "
                    f"(estimated {estimated} > {self.context_window} tokens)"
                )

        logger.info(
            f"Starting protocol inference "
            f"(mode={'MOCK' if is_mock_mode() else 'REAL'}, "
            f"model={self.model}, prompt={len(prompt)} chars)"
        )

        # ── Budget gate (tokens) ────────────────────────────────────
        if (
            self.session_budget_tokens > 0
            and self._session_tokens_used >= self.session_budget_tokens
        ):
            msg = (
                f"Session token budget exhausted "
                f"({self._session_tokens_used}/{self.session_budget_tokens}). "
                f"Skipping inference."
            )
            logger.warning(msg)
            self._last_error = msg
            self._log_error(RuntimeError(msg), prompt)
            raise RuntimeError(msg)

        # ── Budget gate (USD) ──────────────────────────────────────
        if (
            self.session_budget_usd > 0
            and self.total_cost_usd >= self.session_budget_usd
        ):
            msg = (
                f"Session cost budget exhausted "
                f"(${self.total_cost_usd:.4f}/${self.session_budget_usd:.2f}). "
                f"Skipping inference."
            )
            logger.warning(msg)
            self._last_error = msg
            self._log_error(RuntimeError(msg), prompt)
            raise RuntimeError(msg)

        # ── Fallback gate ─────────────────────────────────────────
        # If the LLM has failed 3+ times in a row, short-circuit and
        # return the last known good grammar instead of attempting
        # another call.  This prevents crash-loops in the Slow Loop
        # during transient API outages.
        if (
            self._consecutive_failures >= 3
            and self._last_known_good_grammar is not None
        ):
            logger.warning(
                f"LLM failed {self._consecutive_failures}x consecutively — "
                "returning cached grammar as fallback"
            )
            self._total_inferences += 1
            return self._last_known_good_grammar

        try:
            response_text = await self.call_llm(prompt)
        except RuntimeError:
            # call_llm() exhausted all retries — fallback immediately
            if self._last_known_good_grammar is not None:
                logger.warning(
                    "LLM call failed — returning cached grammar as fallback"
                )
                self._total_inferences += 1
                return self._last_known_good_grammar
            # No cache available — propagate to caller (orchestrator)
            raise

        self._last_response = response_text

        try:
            grammar = self.parse_response(response_text)
        except ValueError:
            # API call succeeded but response was malformed.
            # Do NOT increment _consecutive_failures — that tracks API
            # failures, not parse errors.  Return cached grammar if available.
            if self._last_known_good_grammar is not None:
                logger.warning(
                    "LLM response parse failed — returning cached grammar"
                )
                self._total_inferences += 1
                return self._last_known_good_grammar
            raise

        # Cache successful grammar for fallback + persist to disk
        self._last_known_good_grammar = grammar
        self._save_cache()
        self._consecutive_failures = 0

        self._total_inferences += 1
        logger.info(
            f"Inference #{self._total_inferences} complete: "
            f"protocol='{grammar.protocol_name}', "
            f"fields={len(grammar.fields)}, "
            f"confidence={grammar.confidence:.2f}"
        )

        # Write the prompt + response to shared file for the Web Dashboard
        self._log_inference(prompt, response_text, grammar)

        return grammar

    # -----------------------------------------------------------------
    # Fallback & Reset
    # -----------------------------------------------------------------

    def _local_fallback(self) -> Optional[ProtocolGrammar]:
        """Return the last successfully inferred grammar (or None).

        Used by ``infer_protocol()`` when the LLM API is persistently
        unavailable.  The cached grammar allows the Slow Loop to keep
        producing rules from a previously successful inference rather
        than crashing.
        """
        if self._last_known_good_grammar is not None:
            logger.warning(
                "Falling back to cached grammar from previous inference "
                f"(protocol={self._last_known_good_grammar.protocol_name})"
            )
            return self._last_known_good_grammar
        return None

    def _save_cache(self) -> None:
        """Persist ``_last_known_good_grammar`` to the cache file.

        Uses atomic write (temp + rename) to avoid partial reads.
        Silently ignores errors — the cache is a best-effort optimization.
        """
        if self._last_known_good_grammar is None:
            return

        from pathlib import Path as _Path

        try:
            out = _Path(self._cache_file)
            out.parent.mkdir(parents=True, exist_ok=True)

            data = self._last_known_good_grammar.model_dump(mode="json")

            # Atomic write — same pattern as _log_inference
            tmp = out.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            tmp.rename(out)

            logger.debug(f"Grammar cache saved to {self._cache_file}")
        except Exception as e:
            logger.debug(f"Failed to save grammar cache: {e}")

    def _load_cache(self) -> None:
        """Load ``_last_known_good_grammar`` from the cache file.

        Called during ``__init__`` to restore state across process restarts.
        Silently ignores errors (missing file, corrupted data, schema mismatch).
        """
        from pathlib import Path as _Path

        try:
            path = _Path(self._cache_file)
            if not path.exists():
                return

            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            self._last_known_good_grammar = ProtocolGrammar.model_validate(data)
            logger.info(
                f"Loaded cached grammar from {self._cache_file} "
                f"(protocol={self._last_known_good_grammar.protocol_name})"
            )
        except json.JSONDecodeError:
            logger.warning(
                f"Cache file {self._cache_file} is corrupted — ignoring"
            )
        except Exception as e:
            logger.debug(f"Failed to load grammar cache: {e}")

    def reset(self) -> None:
        """Clear cached grammar, failure counter, circuit breaker, and cache file.

        Call this to force a fresh LLM inference on the next cycle
        (e.g., after a config change, manual operator trigger, or after
        fixing an API key that was causing 401 errors).
        """
        self._last_known_good_grammar = None
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

        # Delete the persistent cache file
        from pathlib import Path as _Path

        try:
            cache_path = _Path(self._cache_file)
            if cache_path.exists():
                cache_path.unlink()
                logger.info(f"Deleted cache file: {self._cache_file}")
        except Exception as e:
            logger.debug(f"Failed to delete cache file: {e}")

        logger.info("LLMAgent cache, failure counter, and circuit breaker reset")

    @property
    def stats(self) -> dict[str, Any]:
        """Return a snapshot of agent runtime statistics."""
        return {
            "total_inferences": self._total_inferences,
            "total_tokens_used": self._total_tokens_used,
            "session_tokens_used": self._session_tokens_used,
            "session_budget_tokens": self.session_budget_tokens,
            "cost_per_inference": self.cost_per_inference,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "session_budget_usd": self.session_budget_usd,
            "consecutive_failures": self._consecutive_failures,
            "circuit_open": self._circuit_open_until > time.monotonic(),
            "circuit_retry_after_s": self._circuit_retry_after_s,
            "cache_file": self._cache_file,
            "model": self.model,
            "provider": self.provider,
            "api_base": self.api_base,
            "last_error": self._last_error,
        }

    # -----------------------------------------------------------------
    # Prompt Construction
    # -----------------------------------------------------------------

    def build_prompt(
        self, samples: list[TrafficRecord], math_hint: Optional[str] = None
    ) -> str:
        """Construct the user prompt from traffic samples.

        Formats each sample as an xxd-style hex dump with offset rulers,
        then concatenates them into a single prompt string.

        Key design decisions:
            - Mutated packets are FILTERED OUT to prevent the LLM from
              inferring protocol structure from corrupted/fuzzed payloads.
            - The math heatmap is placed BEFORE traffic samples so the
              LLM treats it as a prior, not an afterthought.
            - xxd-style formatting with offset rulers eliminates off-by-one
              errors in offset_start/offset_end.

        Args:
            samples: Traffic records to include in the prompt.
            math_hint: Optional pre-computed heatmap from DifferentialAnalyzer.

        Returns:
            The formatted user message string.
        """
        if not samples:
            return "No traffic samples available for analysis."

        # Filter out mutated packets — they corrupt grammar inference.
        clean_samples = [s for s in samples if not s.is_mutated]
        if not clean_samples:
            return "No clean (non-mutated) traffic samples available for analysis."

        parts: list[str] = []
        for idx, sample in enumerate(clean_samples):
            hex_str = sample.raw_data.hex() if sample.raw_data else ""
            hex_xxd = _format_hex_xxd(hex_str)
            parts.append(
                TRAFFIC_SAMPLE_TEMPLATE.format(
                    index=idx,
                    direction=sample.direction.value,
                    length=len(sample.raw_data),
                    hex_xxd=hex_xxd,
                )
            )

        header = (
            f"Analyze {len(clean_samples)} clean network traffic packets below.\n"
            f"Each packet shows hex data with byte-offset rulers.\n"
            f"Identify magic bytes, length fields, checksums, enum values, "
            f"and any repeating structural patterns.\n\n"
        )

        # Heatmap BEFORE samples — LLM reads top-to-bottom, so the
        # mathematical priors establish a framework before seeing raw bytes.
        prompt = header
        if math_hint:
            prompt += math_hint + "\n\n"
            prompt += (
                "Using the heatmap above as priors, "
                "analyze the raw packets below:\n\n"
            )
        prompt += "\n".join(parts)

        return prompt

    def _build_prompt_from_input(
        self,
        traffic_input: Union[list[TrafficRecord], dict[str, Any]],
        math_hint: Optional[str] = None,
    ) -> str:
        """Route to the correct prompt builder based on input type."""
        if isinstance(traffic_input, dict):
            # Pre-formatted payload from TrafficParser.format_for_llm()
            traffic_str = json.dumps(
                traffic_input, indent=2, ensure_ascii=False
            )
            # Heatmap BEFORE traffic — same rationale as build_prompt()
            prompt = ""
            if math_hint:
                prompt += math_hint + "\n\n"
                prompt += (
                    "Using the mathematical heatmap above as priors, "
                    "analyze the traffic sessions below:\n\n"
                )
            prompt += traffic_str
            prompt += (
                "\n\nAnalyze the traffic sessions above and infer the "
                "protocol wire format. Output a single JSON object."
            )
            return prompt
        elif isinstance(traffic_input, list):
            return self.build_prompt(traffic_input, math_hint=math_hint)
        else:
            raise TypeError(
                f"Expected list[TrafficRecord] or dict, got {type(traffic_input)}"
            )

    # -----------------------------------------------------------------
    # LLM API Call
    # -----------------------------------------------------------------

    async def call_llm(self, prompt: str) -> str:
        """Call the LLM API with retry logic (or use mock response).

        Two operating modes controlled by ``LLM_MODE`` env var:

        - **REAL** (default): Uses litellm for provider-agnostic access.
          Implements retry with exponential backoff on transient failures.
          Error categorization:
            - Rate limit (429) → backoff up to 120s
            - Timeout → standard backoff
            - API error (5xx) → backoff up to 60s
            - Network error → backoff up to 60s

        - **MOCK**: Returns a pre-built simulated ProtocolGrammar JSON
          after a short delay. No API key or litellm required.

        Args:
            prompt: The full user prompt string.

        Returns:
            The LLM's response text (real or simulated).

        Raises:
            RuntimeError: If REAL mode and litellm is not installed or
                no API key is set, or call fails after all retries.
        """
        # ── Circuit breaker ────────────────────────────────────────────
        if self._circuit_open_until > 0 and time.monotonic() < self._circuit_open_until:
            remaining = self._circuit_open_until - time.monotonic()
            raise RuntimeError(
                f"Circuit breaker is OPEN — skipping API call "
                f"(cooldown remaining: {remaining:.0f}s)"
            )

        # ── MOCK mode: return simulated response ───────────────────
        if is_mock_mode():
            logger.info(
                f"[MOCK] Simulating LLM response "
                f"(delay={_MOCK_LLM_DELAY_S}s, prompt={len(prompt)} chars)"
            )
            await asyncio.sleep(_MOCK_LLM_DELAY_S)
            self._total_tokens_used += 500  # Simulated token count
            self._session_tokens_used += 500
            return _MOCK_RESPONSE_JSON

        # ── REAL mode: call actual LLM API ────────────────────────
        if not HAS_LITELM:
            raise RuntimeError(
                "litellm is not installed. Install with: pip install litellm"
            )
        if not self.api_key and self.provider != "ollama":
            raise RuntimeError(
                "No API key configured. Set the appropriate environment "
                f"variable (e.g., OPENAI_API_KEY for provider={self.provider})."
            )

        # Build system prompt — only include fusion instructions when
        # math_hint was actually provided.  Sending fusion instructions
        # without a heatmap causes the LLM to hallucinate a non-existent
        # "MATHEMATICAL PRE-ANALYSIS block" → ~30% more spurious fields.
        system_content = SYSTEM_PROMPT
        # Check if this inference cycle had a math hint by inspecting
        # the prompt for the heatmap marker.  This is safe because
        # build_prompt() injects it deterministically.
        if "MATHEMATICAL PRE-ANALYSIS" in prompt:
            system_content += SYSTEM_PROMPT_FUSION_APPEND

        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": prompt},
        ]

        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(
                    f"LLM call attempt {attempt}/{self.max_retries} "
                    f"(model={self.model})"
                )

                # Build the litellm model string
                # e.g., "openai/gpt-4o" or "anthropic/claude-sonnet-4-20250514"
                model_str = self.model
                if self.provider and "/" not in self.model:
                    model_str = f"{self.provider}/{self.model}"

                # Build call kwargs — conditionally add api_base for
                # custom endpoints (ZhipuAI, vLLM, etc.)
                call_kwargs: dict[str, Any] = dict(
                    model=model_str,
                    messages=messages,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    timeout=self.timeout_seconds,
                    # Force structured JSON output
                    response_format={"type": "json_object"},
                )

                # Pass API key when set (Ollama may have empty key)
                if self.api_key:
                    call_kwargs["api_key"] = self.api_key

                # Pass custom api_base when configured
                if self.api_base:
                    call_kwargs["api_base"] = self.api_base

                if not self.enable_thinking:
                    call_kwargs["extra_body"] = {
                        **call_kwargs.get("extra_body", {}),
                        "enable_thinking": False,
                    }

                response = await litellm.acompletion(**call_kwargs)

                content = response.choices[0].message.content
                if not content:
                    raise RuntimeError("LLM returned an empty response")

                # Track token usage
                if hasattr(response, "usage") and response.usage:
                    tokens = response.usage.total_tokens or 0
                    self._total_tokens_used += tokens
                    self._session_tokens_used += tokens

                    # Track USD cost
                    pricing = MODEL_PRICING.get(
                        self.model, MODEL_PRICING["default"]
                    )
                    input_cost = (
                        (response.usage.prompt_tokens or 0)
                        / 1_000_000
                        * pricing["input_per_m"]
                    )
                    output_cost = (
                        (response.usage.completion_tokens or 0)
                        / 1_000_000
                        * pricing["output_per_m"]
                    )
                    self.cost_per_inference = round(input_cost + output_cost, 6)
                    self.total_cost_usd += self.cost_per_inference

                    logger.debug(
                        f"Token usage: prompt={response.usage.prompt_tokens}, "
                        f"completion={response.usage.completion_tokens}, "
                        f"total={tokens}, "
                        f"cost=${self.cost_per_inference:.4f}"
                    )

                # Clear last error on success
                self._last_error = ""
                self._circuit_open_until = 0.0  # Reset circuit breaker
                return content

            except Exception as e:
                last_error = e
                error_name = type(e).__name__
                error_msg = str(e).lower()

                # ── Auth errors: abort immediately, no retry ──────────
                if _is_auth_error(error_name, error_msg):
                    logger.critical(
                        f"Authentication failed — API key may be invalid. "
                        f"Not retrying. [{error_name}]: {e}"
                    )
                    self._last_error = f"[AUTH] {error_name}: {e}"
                    self._log_error(e, prompt)
                    self._consecutive_failures += 1
                    self._circuit_open_until = (
                        time.monotonic() + self._circuit_retry_after_s
                    )
                    raise RuntimeError(
                        f"Authentication error — not retrying: "
                        f"[{error_name}] {e}"
                    ) from e

                # ── Categorize error for appropriate backoff ────
                backoff = self._compute_backoff(
                    attempt, error_name, error_msg
                )

                logger.warning(
                    f"LLM call attempt {attempt}/{self.max_retries} failed "
                    f"[{error_name}]: {e}"
                )

                if attempt < self.max_retries:
                    logger.info(
                        f"Retrying in {backoff}s "
                        f"(error_type={error_name})"
                    )
                    await asyncio.sleep(backoff)
                else:
                    # All retries exhausted — log for Dashboard
                    self._last_error = f"[{error_name}] {e}"
                    self._log_error(e, prompt)

        # All retries exhausted — increment failure counter
        self._consecutive_failures += 1
        self._circuit_open_until = time.monotonic() + self._circuit_retry_after_s
        logger.warning(
            f"Circuit breaker OPENED for {self._circuit_retry_after_s}s "
            f"(consecutive_failures={self._consecutive_failures})"
        )

        raise RuntimeError(
            f"LLM API call failed after {self.max_retries} attempts: "
            f"{last_error}"
        ) from last_error

    def _compute_backoff(
        self, attempt: int, error_name: str, error_msg: str
    ) -> float:
        """Compute backoff delay with jitter based on error type and attempt.

        Uses exponential backoff with ±25% random jitter to prevent
        thundering herd when multiple instances retry simultaneously.

        Args:
            attempt:    Current attempt number (1-based).
            error_name: Exception class name (e.g., "RateLimitError").
            error_msg:  Lowercase error message string.

        Returns:
            Backoff delay in seconds (with jitter applied).
        """
        import random

        # Rate limit (429) → aggressive backoff
        if (
            "ratelimit" in error_name.lower()
            or "rate" in error_name.lower()
            or "429" in error_msg
            or "rate_limit" in error_name.lower()
        ):
            base = min(2 ** (attempt + 2), 120)

        # Timeout → standard backoff (don't punish too hard)
        elif "timeout" in error_name.lower() or "timeout" in error_msg:
            base = min(2 ** attempt, 30)

        # API connection / network errors → moderate backoff
        elif (
            "connection" in error_name.lower()
            or "connection" in error_msg
            or "network" in error_msg
        ):
            base = min(2 ** attempt, 60)

        # Default → standard exponential backoff
        else:
            base = min(2 ** attempt, 60)

        # Apply ±25% jitter to prevent synchronized retries
        jitter = base * 0.25 * (2 * random.random() - 1)
        return max(0.5, base + jitter)

    # -----------------------------------------------------------------
    # Response Parsing
    # -----------------------------------------------------------------

    def parse_response(self, response_text: str) -> ProtocolGrammar:
        """Parse the LLM's JSON response into a ProtocolGrammar.

        Handles common LLM output issues:
        - Response wrapped in markdown code blocks (```json ... ```)
        - Extra text before/after the JSON
        - Partial or malformed JSON (attempts extraction)

        Args:
            response_text: Raw text from the LLM.

        Returns:
            A validated ``ProtocolGrammar`` object.

        Raises:
            ValueError: If the response cannot be parsed as valid JSON
                matching the ProtocolGrammar schema.
        """
        text = response_text.strip()

        # Strip markdown code blocks
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        # Try direct parse
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            # Attempt to extract JSON object from surrounding text
            json_match = re.search(r"\{.*\}", text, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                except json.JSONDecodeError:
                    raise ValueError(
                        f"Failed to parse LLM response as JSON: {e}\n"
                        f"Response excerpt: {text[:500]}"
                    ) from e
            else:
                raise ValueError(
                    f"Failed to parse LLM response as JSON: {e}\n"
                    f"Response excerpt: {text[:500]}"
                ) from e

        # Validate against Pydantic model
        try:
            grammar = ProtocolGrammar.model_validate(data)
        except Exception as e:
            # Log the raw response for debugging before raising
            logger.error(
                f"LLM response schema validation failed: {e}\n"
                f"Response data: {json.dumps(data, indent=2, ensure_ascii=False)[:1000]}"
            )
            self._log_error(e, response_text[:2000])
            raise ValueError(
                f"LLM response does not match ProtocolGrammar schema: {e}\n"
                f"Response data: {json.dumps(data, indent=2)[:500]}"
            ) from e

        return grammar

    # -----------------------------------------------------------------
    # Inference Logging (for Web Dashboard)
    # -----------------------------------------------------------------

    def _log_inference(
        self,
        prompt: str,
        response: str,
        grammar: ProtocolGrammar,
        log_path: str = "shared/llm_last_inference.json",
    ) -> None:
        """Write the latest prompt/response to a shared file for the Dashboard.

        Uses atomic write (temp + rename) to avoid partial reads.
        The Dashboard reads this file to populate the "LLM Insights" panel.

        Args:
            prompt:     The full prompt sent to the LLM.
            response:   The raw LLM response text.
            grammar:    The parsed ProtocolGrammar.
            log_path:   Path to the shared inference log file.
        """
        from pathlib import Path as _Path

        try:
            out = _Path(log_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "success",
                "model": self.model,
                "provider": self.provider,
                "mode": "MOCK" if is_mock_mode() else "REAL",
                "prompt": prompt[:5000],  # Cap to avoid huge files
                "response": response[:5000],
                "protocol_name": grammar.protocol_name,
                "fields_count": len(grammar.fields),
                "confidence": grammar.confidence,
                "inference_number": self._total_inferences,
                "reasoning": grammar.reasoning[:2000] if grammar.reasoning else None,
                "tokens_used": self._session_tokens_used,
                "session_budget": self.session_budget_tokens,
            }

            # Atomic write
            tmp = out.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
            tmp.rename(out)

            logger.debug(f"LLM inference logged to {log_path}")
        except Exception as e:
            logger.debug(f"Failed to log inference for dashboard: {e}")

    def _log_error(
        self,
        error: Exception,
        prompt: str,
        log_path: str = "shared/llm_last_inference.json",
    ) -> None:
        """Log an error to the shared file for Dashboard display.

        The Dashboard shows the last error in the LLM Insights panel
        so the operator can diagnose API issues without reading logs.

        Args:
            error:     The exception that occurred.
            prompt:    The prompt that was being sent (truncated for file size).
            log_path:  Path to the shared inference log file.
        """
        from pathlib import Path as _Path

        try:
            out = _Path(log_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "error",
                "error_type": type(error).__name__,
                "error_message": str(error)[:1000],
                "model": self.model,
                "provider": self.provider,
                "mode": "MOCK" if is_mock_mode() else "REAL",
                "prompt_preview": prompt[:1000],
                "tokens_used": self._session_tokens_used,
                "session_budget": self.session_budget_tokens,
            }

            # Atomic write
            tmp = out.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
            tmp.rename(out)

            logger.debug(f"LLM error logged to {log_path}")
        except Exception as e:
            logger.debug(f"Failed to log error for dashboard: {e}")


# =============================================================================
# Module-level helpers
# =============================================================================


def _is_auth_error(error_name: str, error_msg: str) -> bool:
    """Check if an error is an authentication/authorization failure.

    Auth errors should NOT be retried — the API key is invalid or revoked.
    """
    auth_patterns = [
        "401", "unauthorized", "authentication", "invalid api key",
        "invalid_api_key", "access denied", "forbidden",
    ]
    combined = (error_name + " " + error_msg).lower()
    return any(p in combined for p in auth_patterns)


def _hex_to_ascii(hex_str: str) -> str:
    """Convert a hex string to a human-readable ASCII representation.

    Printable ASCII characters (0x20–0x7E) are shown as-is.
    All other bytes are represented as ``.`` (dot).

    Args:
        hex_str: Hex string (e.g., ``"deadbeef"``).

    Returns:
        ASCII representation string of the same byte length.
    """
    result: list[str] = []
    for i in range(0, len(hex_str), 2):
        if i + 2 > len(hex_str):
            result.append(".")
            continue
        byte_val = int(hex_str[i : i + 2], 16)
        result.append(chr(byte_val) if 0x20 <= byte_val <= 0x7E else ".")
    return "".join(result)


def _format_hex_xxd(hex_str: str, bytes_per_row: int = 16) -> str:
    """Format hex as xxd-style dump with offset rulers.

    Each row shows: offset, hex bytes, and ASCII representation.
    This makes byte offsets immediately readable by the LLM,
    eliminating off-by-one errors in offset_start/offset_end.

    Example output::

        0000:  de ad be ef 00 07 48 65  6c 6c 6f 0d 0a 00 00 00  |.......Hello.....|
        0010:  01 02 03                                          |...|

    Args:
        hex_str:       Hex string of the packet payload.
        bytes_per_row: Number of bytes per row (default 16).

    Returns:
        xxd-formatted string.
    """
    raw = bytes.fromhex(hex_str) if hex_str else b""
    if not raw:
        return "(empty packet)"
    lines: list[str] = []
    for i in range(0, len(raw), bytes_per_row):
        chunk = raw[i : i + bytes_per_row]
        # Two groups of 8 bytes for readability
        hex_parts = []
        for j, b in enumerate(chunk):
            if j == 8:
                hex_parts.append(" ")
            hex_parts.append(f"{b:02x}")
        hex_line = " ".join(hex_parts)
        ascii_line = "".join(
            chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk
        )
        lines.append(
            f"  {i:04x}:  {hex_line:<{bytes_per_row * 3}}  |{ascii_line}|"
        )
    return "\n".join(lines)


def estimate_tokens(text: str) -> int:
    """Estimate the number of tokens in a text string.

    Uses a heuristic calibrated for mixed hex/English content:
    - Hex characters are token-inefficient (~2 chars per token)
    - English text is ~4 chars per token
    - Add 200 tokens overhead for system prompt and formatting

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.
    """
    hex_chars = sum(1 for c in text if c in "0123456789abcdef")
    other_chars = len(text) - hex_chars
    return int(hex_chars / 2 + other_chars / 4 + 200)
