"""
shared/schemas.py
─────────────────
Pydantic models for all cross-block data contracts.

These schemas define the *shape* of data flowing between the Fast Loop,
Slow Loop, and shared components. Every module in LIFA-Fuzz imports from
here to ensure type consistency.

Design Notes:
    - All models use Pydantic v2 ( BaseModel ).
    - Enums are used for fixed-choice fields to prevent typos.
    - Each model has a `model_config` with `json_schema_extra` examples
      so downstream consumers (and LLMs) can see expected shapes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_serializer, field_validator


# =============================================================================
# Enums
# =============================================================================


class Direction(str, Enum):
    """Direction of a packet relative to the target server."""

    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class RuleType(str, Enum):
    """Category of a mutation rule.

    - ``bit_flip``      — Flip individual bits in a byte range.
    - ``boundary``      — Fuzz boundary values (0, MAX, MAX-1, MIN+1, etc.).
    - ``structural``   — Mutate a semantic field (length, checksum, enum value).
    - ``state``         — Sequence-level mutation (reorder, drop, duplicate).
    - ``violation``     — Semantic-violation action (SemFuzz-style add/remove/update).
    """

    BIT_FLIP = "bit_flip"
    BOUNDARY = "boundary"
    STRUCTURAL = "structural"
    STATE = "state"
    VIOLATION = "violation"


class ViolationAction(str, Enum):
    """Atomic structural action that violates a semantic construction rule.

    Faithful to SemFuzz (Sun et al., 2026, §3.5.1) which defines exactly
    ``add``, ``remove``, ``update``. (An earlier draft added ``reorder``;
    that is dropped — the paper does not define it and a byte-range swap is
    fragile on flat field models.)
    """

    ADD = "add"        # Insert bytes at an offset (then recompute length)
    REMOVE = "remove"  # Delete a byte range (then recompute length)
    UPDATE = "update"  # Overwrite a byte range in place


class ResponseCategory(str, Enum):
    """SemFuzz 2-category response oracle (paper §3.4, Appendix C).

    A test that violates a construction rule expects an *error* response; if
    the server answers *normal* instead, that divergence is a potential
    semantic vulnerability. Categories are protocol-specific (HTTP 200 vs
    4xx/5xx, TLS handshake-continue vs Alert, etc.).
    """

    NORMAL = "normal"
    ERROR = "error"


class ViolationStrategy(BaseModel):
    """One concrete way to violate a semantic rule, with the expected response.

    LIFA has no RFC, so the expected response is *inferred* ("a structural
    violation should make the server answer *error*") rather than derived from
    a specification — coarser than SemFuzz's RFC-grounded processing rule, and
    a documented limitation.
    """

    action: ViolationAction
    target_field: str = ""
    target_offset: int = 0
    target_length: int = 0
    insert_value: Optional[str] = Field(
        default=None,
        description="Hex bytes for ADD/UPDATE. None ⇒ ADD inserts a single 0x00.",
    )
    expected_category: ResponseCategory = Field(
        default=ResponseCategory.ERROR,
        description="Expected server response category for this violation.",
    )
    description: str = ""


class FieldType(str, Enum):
    """Wire-type of a protocol field.

    Naming convention follows standard endianness suffixes:
    ``uint16_le`` = unsigned 16-bit little-endian, etc.
    """

    UINT8 = "uint8"
    UINT16_LE = "uint16_le"
    UINT16_BE = "uint16_be"
    UINT32_LE = "uint32_le"
    UINT32_BE = "uint32_be"
    INT8 = "int8"
    INT16_LE = "int16_le"
    INT16_BE = "int16_be"
    INT32_LE = "int32_le"
    INT32_BE = "int32_be"
    STRING = "string"
    BYTES = "bytes"
    ENUM = "enum"
    BOOL = "bool"
    RESERVED = "reserved"  # Padding / unused bytes


class Signal(str, Enum):
    """POSIX signal names relevant to crash detection."""

    SIGSEGV = "SIGSEGV"
    SIGABRT = "SIGABRT"
    SIGFPE = "SIGFPE"
    SIGBUS = "SIGBUS"
    SIGILL = "SIGILL"
    SIGTERM = "SIGTERM"
    SIGKILL = "SIGKILL"
    SIGUSR1 = "SIGUSR1"
    SIGUSR2 = "SIGUSR2"
    SIGPIPE = "SIGPIPE"
    SIGALRM = "SIGALRM"


class PacketStatus(str, Enum):
    """Observed server response status after a packet is sent by the Mutator.

    Used by the Interceptor to classify whether a mutation was accepted,
    rejected, or caused a crash.
    """

    ACCEPTED = "accepted"   # Server responded normally — packet was processed
    REJECTED = "rejected"   # Server sent error / closed conn / empty response
    TIMEOUT  = "timeout"    # No response within the configured deadline
    CRASH    = "crash"      # Target server process went down (connection refused)


class SlowLoopTrigger(str, Enum):
    """What event caused the Fast Loop to invoke the Slow Loop.

    Attached to ``TrafficLog`` batches so the Slow Loop knows *why*
    it is being called and can adjust its analysis accordingly.
    """

    STUCK     = "stuck"      # Rejection rate exceeded configured threshold
    CRASH     = "crash"      # A crash was detected — send context to LLM
    SCHEDULED = "scheduled"  # Periodic scheduled rule refresh
    MANUAL    = "manual"     # Operator-triggered via CLI / API


class MutationStrategy(str, Enum):
    """Per-field mutation strategy assigned by the LLM Rule Generator.

    This is the LLM's per-field instruction, richer than ``RuleType``
    which describes the mutation *action*. The RuleGenerator converts
    each ``MutationStrategy`` into one or more ``SemanticRule`` objects.

    STATIC          → Copy field verbatim (magic bytes, fixed headers — DO NOT FUZZ)
    RANDOM_BYTES    → Replace with os.urandom(field_length)
    BIT_FLIP        → Flip a random bit within the field
    BOUNDARY_VALUES → Substitute 0x00, 0xFF, 0x7F, 0x80, max-int variants
    INCREMENT       → Monotonically increment as a big-endian integer
    CALCULATED      → Derived from another field (e.g. length = len(payload))
    DICTIONARY      → Pick from a list of known-interesting hex values
    FORMAT_STRING   → Inject C-style format-string payloads (%s%s%s%n etc.)
    PAYLOAD_EXTEND  → Grow a variable-length field with extra bytes (overflow class)
    TRUNCATE        → Truncate the packet at or near the field offset
    SKIP            → Leave field unchanged for this mutation round

    PAYLOAD_EXTEND is assigned to variable-length tail fields (offset_end == -1).
    Buffer overflows live in length-delimited payloads — the most common
    memory-corruption class — so the fuzzer must periodically GROW the actual
    payload bytes, not just rewrite them in place. A server that clamps the
    declared length to bytes-received is immune to a bare length-field overflow;
    only growing real bytes reaches the vulnerable memcpy/strcpy.
    """

    STATIC          = "static"
    RANDOM_BYTES    = "random_bytes"
    BIT_FLIP        = "bit_flip"
    BOUNDARY_VALUES = "boundary_values"
    INCREMENT       = "increment"
    CALCULATED      = "calculated"
    DICTIONARY      = "dictionary"
    FORMAT_STRING   = "format_string"
    PAYLOAD_EXTEND  = "payload_extend"
    TRUNCATE        = "truncate"
    SKIP            = "skip"


# =============================================================================
# Bootstrap Field Rule (from DifferentialAnalyzer)
# =============================================================================


class FieldRule(BaseModel):
    """A single mutation rule bootstrap-generated by the DifferentialAnalyzer.

    Lighter than ``SemanticRule`` — produced by pure math before the LLM
    responds. The ``RulesOrchestrator`` converts these to full
    ``SemanticRule`` objects via ``_convert_field_rules()``.

    Attributes:
        field_name:         Descriptive name (e.g. ``"field_00_static"``).
        offset:             Start byte offset in the packet.
        length:             Field byte length. ``-1`` means variable / remainder.
        mutation_strategy:  How the mutation engine should treat this field.
        static_value:       Hex string of constant value (only for STATIC fields).
        calculation_source: What this field derives from (e.g. ``"payload"``).
        notes:              Free-text annotation.
        confidence:         How confident the analyzer is ∈ [0, 1].
    """

    field_name: str
    offset: int = Field(ge=0)
    length: int = Field(
        ge=-1, description="Field byte length, -1 = variable/remainder"
    )
    mutation_strategy: MutationStrategy = MutationStrategy.RANDOM_BYTES
    static_value: Optional[str] = None
    calculation_source: Optional[str] = None
    notes: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    dictionary_values: Optional[list[str]] = Field(
        default=None,
        description="Known-interesting hex values for DICTIONARY strategy",
    )
    data_type: Optional[FieldType] = Field(
        default=None,
        description="Type-aware dispatch: endian-safe encoding for binary fields",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "field_name": "field_00_static",
                    "offset": 0,
                    "length": 4,
                    "mutation_strategy": "static",
                    "static_value": "deadbeef",
                    "confidence": 1.0,
                    "notes": "Constant value: 0xdeadbeef",
                }
            ]
        }
    }


# =============================================================================
# Crash Report (persisted by CrashManager)
# =============================================================================


class CrashReport(BaseModel):
    """Detailed crash report persisted by CrashManager.

    One report per unique crash signature. Saved alongside the raw
    binary PoC file for replay and submission.

    Attributes:
        crash_id:            Primary SHA256[:16] signature — unique per crash.
        detected_at:         When the crash was first detected (UTC).
        triggering_packet:   Hex-encoded bytes that triggered the crash.
        active_rule_set_id:  UUID of the SemanticRuleSet active at crash time.
        crash_type:          Classification string (e.g. ``"connection_refused"``).
        poc_file_path:       Path to the saved binary PoC file.
        notes:               Free-text annotation (e.g. stack trace snippet).
    """

    crash_id: str
    detected_at: datetime
    triggering_packet: str
    active_rule_set_id: Optional[str] = None
    crash_type: str = "unknown"
    poc_file_path: str = ""
    notes: str = ""
    # Post-crash confirmation (Phase 1): whether this PoC was verified by
    # replay on a clean target (deterministic) or only attributed.
    reproduced: bool = False
    confirmation_method: str = "window_last"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "crash_id": "a1b2c3d4e5f6a7b8",
                    "crash_type": "connection_refused",
                    "triggering_packet": "deadbeef0005ffff",
                }
            ]
        }
    }


# =============================================================================
# Block 2 → Block 3: Traffic Record
# =============================================================================


class TrafficRecord(BaseModel):
    """A single captured packet, written by the Interceptor.

    This is the atomic unit stored in the traffic log ring buffer.
    The Slow Loop's Parser reads batches of these.

    Attributes:
        record_id:       Unique identifier for this record.
        timestamp:       Unix epoch seconds when the packet was captured.
        direction:       Was this from the client or the server?
        raw_data:        Raw bytes of the packet payload.
        raw_hex:         Hex-encoded string of ``raw_data`` (convenience).
        session_id:      UUID of the TCP session this packet belongs to.
        packet_length:    Length of ``raw_data`` in bytes.
        is_mutated:      True if this packet was generated by the Mutation Engine.
        mutation_id:      ID of the SemanticRule used to mutate (if applicable).
    """

    record_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    direction: Direction
    raw_data: bytes
    raw_hex: str = ""
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    packet_length: int = 0
    is_mutated: bool = False
    mutation_id: Optional[str] = None
    status: PacketStatus = PacketStatus.ACCEPTED

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "direction": "client_to_server",
                    "raw_hex": "deadbeef",
                    "is_mutated": False,
                }
            ]
        }
    }

    @field_serializer("raw_data")
    def serialize_raw_data(self, data: bytes, _info: Any) -> str:
        """Serialize bytes as hex string for JSON output."""
        return data.hex()

    @field_validator("raw_data", mode="before")
    @classmethod
    def validate_raw_data(cls, v: Any) -> bytes:
        """Accept bytes or hex string, always store as bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise TypeError(f"Expected bytes or hex string, got {type(v)}")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Auto-derive convenience fields
        if self.raw_data and not self.raw_hex:
            self.raw_hex = self.raw_data.hex()
        if self.raw_data and self.packet_length == 0:
            self.packet_length = len(self.raw_data)

    # -- Property aliases for new MutationEngine compatibility --
    @property
    def raw_bytes(self) -> bytes:
        """Alias for raw_data — used by new MutationEngine."""
        return self.raw_data

    @property
    def packet_id(self) -> str:
        """Alias for record_id — used by new MutationEngine."""
        return self.record_id

    @property
    def hex_payload(self) -> str:
        """Alias for raw_hex — used by new MutationEngine."""
        return self.raw_hex

    @property
    def byte_length(self) -> int:
        """Alias for packet_length — used by new MutationEngine."""
        return self.packet_length


# =============================================================================
# Sequence-Aware Fuzzing: SeedSequence + FuzzTarget
# =============================================================================


class SeedSequence(BaseModel):
    """Ordered sequence of packets representing one complete protocol session.

    The fundamental unit for sequence-aware fuzzing (M = ⟨Prefix, Target, Suffix⟩).
    Packets arrive from the Interceptor grouped by ``session_id``, forming a
    replayable multi-step session (e.g. FTP USER → PASS → LIST).

    A 1-packet sequence is backward-compatible with the legacy single-packet path.
    """

    sequence_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique ID for this sequence (used by IFPS tracking)",
    )
    session_id: str = Field(
        default="",
        description="TCP session ID from the Interceptor",
    )
    packets: list[TrafficRecord] = Field(
        default_factory=list,
        description="Ordered packets captured during one TCP session",
    )
    protocol_hint: str = Field(
        default="",
        description="Optional protocol name hint (e.g. 'FTP', 'HTTP')",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "sequence_id": "a1b2c3d4e5f6",
                    "session_id": "sess_001",
                    "packets": [
                        {"direction": "client_to_server", "raw_hex": "555345522061646d696e"},
                        {"direction": "client_to_server", "raw_hex": "5041535320736563726574"},
                        {"direction": "client_to_server", "raw_hex": "4c495354"},
                    ],
                    "protocol_hint": "FTP",
                }
            ]
        }
    }

    @property
    def length(self) -> int:
        """Number of packets in this sequence."""
        return len(self.packets)

    def is_single(self) -> bool:
        """True if this sequence contains at most one packet (legacy path)."""
        return len(self.packets) <= 1


class FuzzTarget(BaseModel):
    """Result of splitting a SeedSequence for fuzzing.

    Implements the M = ⟨Prefix, Mutated_Target, Suffix⟩ paradigm:
      - prefix:  verbatim packets sent before the target to drive server state
      - target_seed:  the single packet selected for mutation
      - suffix:  verbatim packets sent after the mutated target

    Only target_seed is passed through the Mutation Engine; all other
    packets are sent as-is to maintain protocol state correctness.
    """

    prefix: list[bytes]
    target_seed: TrafficRecord
    target_index: int
    suffix: list[bytes]
    sequence_id: str


# =============================================================================
# Block 3 → Block 2: Mutation Constraints
# =============================================================================


class MutationConstraints(BaseModel):
    """Typed constraints governing how a field may be mutated.

    Provides structure to what was previously an untyped ``dict[str, Any]``.
    Not all fields are relevant to every rule_type — unused ones default to
    ``None`` and are ignored by the Mutation Engine.

    Attributes:
        min_value:      Minimum numeric value (for boundary/structural rules).
        max_value:      Maximum numeric value (for boundary/structural rules).
        allowed_values: Enum-style list of valid values (for enum fields).
        invalid_values: Explicitly inject these invalid values (for negative testing).
        must_preserve:   Bytes that MUST remain unchanged during mutation
                        (e.g., magic bytes at packet start, checksum seeds).
        step:           Increment/decrement step size (for sequential fuzzing).
    """

    min_value: Optional[int] = None
    max_value: Optional[int] = None
    allowed_values: list[Any] = Field(default_factory=list)
    invalid_values: list[Any] = Field(default_factory=list)
    must_preserve: bytes = b""
    step: Optional[int] = None

    @field_serializer("must_preserve")
    def serialize_must_preserve(self, data: bytes, _info: Any) -> str:
        """Serialize bytes as hex string for JSON output."""
        return data.hex()

    @field_validator("must_preserve", mode="before")
    @classmethod
    def validate_must_preserve(cls, v: Any) -> bytes:
        """Accept bytes or hex string, always store as bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise TypeError(f"Expected bytes or hex string, got {type(v)}")


# =============================================================================
# Block 3 → Block 2: Semantic Rule
# =============================================================================


class SemanticRule(BaseModel):
    """A single mutation rule, generated by the Slow Loop's Rule Generator.

    The Fast Loop's Mutation Engine maintains a list of these and applies
    them to captured packets. Rules describe *where* and *how* to mutate.

    Attributes:
        rule_id:        Unique identifier.
        rule_type:      Category of mutation (bit_flip, boundary, structural, state).
        target_field_name: Human-readable name of the field being targeted
                        (e.g. ``"header_length"``).
        mutation_type:  Alias for rule_type — which mutation strategy to apply.
        offset_start:   Start byte offset in the packet (inclusive).
        offset_end:      End byte offset (exclusive).
        field_type:      Wire-type of the field being mutated.
        constraints:     Typed constraints governing valid mutations.
        preserve_bytes:  Bytes outside the target range that must remain
                        unchanged during mutation (e.g., magic bytes, valid
                        protocol prefix). The mutator copies these verbatim.
        static_values_to_keep: Explicit list of byte values at specific offsets
                        that must not be altered (e.g., ``{0: 0xDE}`` means
                        byte 0 must always be 0xDE).
        priority:        Estimated effectiveness score (0.0–1.0). Higher = more promising.
        protocol_state:  If the protocol has states, which state must be active.
        created_at:      Timestamp when this rule was generated.
        hit_count:       Number of times this rule has been applied.
        crash_count:     Number of crashes caused by mutations using this rule.
        description:     Free-text description of what this rule does.
    """

    rule_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    rule_type: RuleType = RuleType.BIT_FLIP
    target_field_name: str = ""
    mutation_type: RuleType = RuleType.BIT_FLIP
    offset_start: int = Field(ge=0, description="Start byte offset (inclusive)")
    offset_end: int = Field(ge=0, description="End byte offset (exclusive)")
    field_type: FieldType = FieldType.BYTES
    constraints: MutationConstraints = Field(default_factory=MutationConstraints)
    preserve_bytes: bytes = b""
    static_values_to_keep: dict[int, int] = Field(default_factory=dict)
    priority: float = Field(default=0.5, ge=0.0, le=1.0)
    protocol_state: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    hit_count: int = Field(default=0, ge=0)
    crash_count: int = Field(default=0, ge=0)
    description: str = ""
    # ── Semantic enrichment fields ────────────────────────────────────
    # Preserve LLM-inferred enum values and strategy overrides so the
    # Fast Loop mutator can use targeted mutations (DICTIONARY, FORMAT_STRING)
    # instead of falling back to generic RANDOM_BYTES.
    dictionary_values: list[str] = Field(
        default_factory=list,
        description=(
            "Known-interesting hex values for DICTIONARY mutation strategy. "
            "Populated from LLM-inferred enum possible_values or math-layer "
            "LOW_ENTROPY discrete values. When non-empty, the mutator picks "
            "from these values instead of random bytes."
        ),
    )
    mutation_strategy_override: Optional[MutationStrategy] = Field(
        default=None,
        description=(
            "If set, overrides the _rule_type_to_strategy() mapping for this "
            "rule. Enables strategies like FORMAT_STRING and TRUNCATE that "
            "don't have a dedicated RuleType enum value."
        ),
    )
    violation_strategies: list[ViolationStrategy] = Field(
        default_factory=list,
        description=(
            "SemFuzz-style structural violations (add/remove/update) attached "
            "to this rule. Each carries an expected response category; the "
            "oracle flags a divergence (actual ≠ expected) as a potential "
            "semantic bug. Populated by case-study modules (e.g. FTP) now; "
            "LLM generation is a later phase."
        ),
    )

    @field_serializer("preserve_bytes")
    def serialize_preserve_bytes(self, data: bytes, _info: Any) -> str:
        """Serialize bytes as hex string for JSON output."""
        return data.hex()

    @field_validator("preserve_bytes", mode="before")
    @classmethod
    def validate_preserve_bytes(cls, v: Any) -> bytes:
        """Accept bytes or hex string, always store as bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise TypeError(f"Expected bytes or hex string, got {type(v)}")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "rule_type": "boundary",
                    "target_field_name": "header_length",
                    "offset_start": 4,
                    "offset_end": 8,
                    "field_type": "uint32_le",
                    "constraints": {"min_value": 0, "max_value": 65535},
                    "preserve_bytes": "deadbeef",
                    "priority": 0.8,
                    "description": "Fuzz the 4-byte length field at offset 4, preserving magic header",
                }
            ]
        }
    }

    @property
    def field_name(self) -> str:
        """Backward-compatible alias for ``target_field_name``."""
        return self.target_field_name

    @property
    def field_length(self) -> int:
        """Return the byte length of the target field."""
        return self.offset_end - self.offset_start

    @property
    def crash_rate(self) -> float:
        """Return crashes per hit (0.0 if never hit)."""
        if self.hit_count == 0:
            return 0.0
        return self.crash_count / self.hit_count


# =============================================================================
# Active Rule Set
# =============================================================================


class ActiveRuleSet(BaseModel):
    """The current set of active mutation rules in the Fast Loop.

    The Mutation Engine reads from this. The Rule Watcher updates it
    when the Slow Loop pushes new rules.

    Also serves as ``SemanticRuleSet`` for the new MutationEngine's
    scheduling system — provides ``get_mutable_fields()`` and
    ``get_static_fields()`` that convert ``SemanticRule`` → ``FieldRule``.
    """

    rules: list[SemanticRule] = Field(default_factory=list)
    base_packet: Optional[str] = Field(
        None,
        description="Hex string of a known-valid seed packet for mutation",
    )
    version: int = Field(default=0, ge=0)
    last_updated: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # -- Fields for new MutationEngine scheduling --
    rule_set_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique ID for this rule set version",
    )
    protocol_name: str = Field(default="unknown")
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # -- Stateful protocol support (setup sequence before fuzzing) --
    setup_packets: list[str] = Field(
        default_factory=list,
        description=(
            "Hex-encoded setup packets to send before the mutated payload. "
            "Used for stateful protocols that require a handshake "
            "(e.g., FTP USER→PASS, SMTP HELO→MAIL). The Fast Loop sends "
            "these sequentially on the same TCP connection before the "
            "fuzzing payload."
        ),
    )

    def add_rules(self, new_rules: list[SemanticRule]) -> None:
        """Add new rules, deduplicating by rule_id."""
        existing_ids = {r.rule_id for r in self.rules}
        for rule in new_rules:
            if rule.rule_id not in existing_ids:
                self.rules.append(rule)
                existing_ids.add(rule.rule_id)
        self.version += 1
        self.last_updated = datetime.now(timezone.utc).isoformat()

    def get_top_rules(self, n: int = 10) -> list[SemanticRule]:
        """Return the top N rules sorted by priority (descending)."""
        return sorted(self.rules, key=lambda r: r.priority, reverse=True)[:n]

    def prune_stale(self, max_rules: int = 200) -> list[SemanticRule]:
        """Remove lowest-priority rules if the set exceeds max_rules.

        Returns the pruned rules for logging.
        """
        if len(self.rules) <= max_rules:
            return []
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        pruned = self.rules[max_rules:]
        self.rules = self.rules[:max_rules]
        self.version += 1
        self.last_updated = datetime.now(timezone.utc).isoformat()
        return pruned

    # -- Methods for new MutationEngine scheduling --

    def get_mutable_fields(self) -> list[FieldRule]:
        """Return FieldRules for all non-STATIC fields from the active rules.

        Converts SemanticRule → FieldRule for the scheduler system.
        STATIC fields are excluded (they are applied separately via
        ``get_static_fields()`` before mutation).
        """
        result: list[FieldRule] = []
        for r in self.rules:
            strategy = _rule_type_to_strategy(
                r.rule_type,
                dictionary_values=r.dictionary_values,
                mutation_strategy_override=r.mutation_strategy_override,
            )
            if strategy != MutationStrategy.STATIC:
                result.append(FieldRule(
                    field_name=r.target_field_name,
                    offset=r.offset_start,
                    length=r.field_length,
                    mutation_strategy=strategy,
                    static_value=r.preserve_bytes.hex() if r.preserve_bytes else None,
                    confidence=r.priority,
                    data_type=r.field_type,
                    dictionary_values=r.dictionary_values if r.dictionary_values else None,
                ))
        return result

    def get_static_fields(self) -> list[FieldRule]:
        """Return FieldRules for STATIC fields (magic bytes, headers to preserve).

        Returns ALL unique non-overlapping static regions from rules'
        ``preserve_bytes``.  Overlapping regions (same start offset) are
        merged into the longest one.  This preserves static bytes at
        non-zero offsets (e.g. version fields, reserved fields in headers)
        that were previously silently dropped.
        """
        # Collect (offset, bytes) pairs; merge overlapping at same offset
        by_offset: dict[int, bytes] = {}
        for r in self.rules:
            if not r.preserve_bytes:
                continue
            # SemanticRule preserve_bytes always starts at offset 0
            off = 0
            existing = by_offset.get(off)
            if existing is None or len(r.preserve_bytes) > len(existing):
                by_offset[off] = r.preserve_bytes

        if not by_offset:
            return []

        result: list[FieldRule] = []
        for off, raw in sorted(by_offset.items()):
            magic_hex = raw.hex()
            result.append(FieldRule(
                field_name=f"_preserve_static_{off:03d}_{magic_hex[:8]}",
                offset=off,
                length=len(raw),
                mutation_strategy=MutationStrategy.STATIC,
                static_value=magic_hex,
                confidence=1.0,
            ))
        return result


def _rule_type_to_strategy(
    rule_type: RuleType,
    dictionary_values: list[str] | None = None,
    mutation_strategy_override: MutationStrategy | None = None,
) -> MutationStrategy:
    """Map a SemanticRule's RuleType to a MutationStrategy for scheduling.

    Priority order:
        1. mutation_strategy_override — explicit per-rule override (FORMAT_STRING, etc.)
        2. dictionary_values — non-empty list triggers DICTIONARY strategy
        3. RuleType → MutationStrategy mapping — default mapping
    """
    # Explicit override takes highest priority
    if mutation_strategy_override is not None:
        return mutation_strategy_override
    # Non-empty dictionary_values → DICTIONARY strategy
    if dictionary_values:
        return MutationStrategy.DICTIONARY
    # Default mapping
    mapping = {
        RuleType.BIT_FLIP: MutationStrategy.BIT_FLIP,
        RuleType.BOUNDARY: MutationStrategy.BOUNDARY_VALUES,
        RuleType.STRUCTURAL: MutationStrategy.RANDOM_BYTES,
        RuleType.STATE: MutationStrategy.RANDOM_BYTES,
    }
    return mapping.get(rule_type, MutationStrategy.RANDOM_BYTES)


class CrashRecord(BaseModel):
    """Recorded when the Crash Monitor detects the target has crashed.

    Saved to the crash corpus directory for later replay and analysis.
    """

    crash_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = Field(
        default_factory=lambda: datetime.now(timezone.utc).timestamp()
    )
    exit_code: int = Field(ge=-128)
    # NOTE: Allows negative exit codes because Python's subprocess.poll()
    # returns negative values when a process is killed by signal
    # (e.g., -11 for SIGSEGV).  Sandboxes should normalise to 128+signum
    # where possible, but the schema tolerates raw negatives as a safety net.
    signal: Optional[Signal] = None
    offending_packet: bytes = b""
    offending_packet_hex: str = ""
    mutation_rule_id: Optional[str] = None
    stack_trace: Optional[str] = None
    poc_file_path: Optional[str] = None
    reproduction_command: Optional[str] = None
    # Post-crash confirmation (Phase 1): whether the offending_packet was
    # verified by replay on a clean target (reproduced=True) or only
    # attributed from the window (reproduced=False). Mirrors CrashReport so
    # the crash_monitor's own artifact (crashes/*.json) reflects the same
    # confirmation status the CrashManager records.
    reproduced: bool = False
    confirmation_method: str = "window_last"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "exit_code": 139,
                    "signal": "SIGSEGV",
                    "offending_packet_hex": "CAFEBABE00000001",
                }
            ]
        }
    }

    @field_serializer("offending_packet")
    def serialize_offending_packet(self, data: bytes, _info: Any) -> str:
        """Serialize bytes as hex string for JSON output."""
        return data.hex()

    @field_validator("offending_packet", mode="before")
    @classmethod
    def validate_offending_packet(cls, v: Any) -> bytes:
        """Accept bytes or hex string, always store as bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise TypeError(f"Expected bytes or hex string, got {type(v)}")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.offending_packet and not self.offending_packet_hex:
            self.offending_packet_hex = self.offending_packet.hex()


# =============================================================================
# LLM Output: Protocol Grammar (Intermediate Representation)
# =============================================================================


class InferredField(BaseModel):
    """A single field inferred by the LLM from traffic analysis."""

    name: str
    offset_start: int
    offset_end: int
    field_type: FieldType = FieldType.BYTES
    description: str = ""
    possible_values: list[str] = Field(default_factory=list)
    is_constant: bool = False  # True if this field is always the same value
    mutation_strategy: MutationStrategy = MutationStrategy.RANDOM_BYTES

    @field_validator("possible_values", mode="before")
    @classmethod
    def coerce_possible_values(cls, v: Any) -> list[str]:
        """LLMs often return null/None instead of [] — coerce to empty list."""
        if v is None:
            return []
        return v


class ProtocolGrammar(BaseModel):
    """Full protocol grammar as inferred by the LLM.

    This is the intermediate output between the LLM Agent and the
    Rule Generator. The Rule Generator converts these into SemanticRules.
    """

    protocol_name: str = "unknown"
    description: str = ""
    magic_bytes: Optional[str] = None  # Hex string of expected magic/header bytes
    fields: list[InferredField] = Field(default_factory=list)
    total_header_size: Optional[int] = None
    min_packet_size: int = 0
    max_packet_size: int = 65535
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    state_machine: Optional[dict[str, Any]] = None  # Future: state transitions
    reasoning: Optional[str] = Field(
        default=None,
        description="LLM's analysis reasoning — explains inference decisions and strategy choices",
    )

    @field_validator("fields", mode="before")
    @classmethod
    def coerce_fields(cls, v: Any) -> list:
        """LLMs may return null/None for fields — coerce to empty list."""
        if v is None:
            return []
        return v

    @field_validator("state_machine", mode="before")
    @classmethod
    def coerce_state_machine(cls, v: Any) -> Optional[dict]:
        """LLMs may return empty string or [] for state_machine — coerce to None."""
        if v is None or v == "" or isinstance(v, list):
            return None
        return v


# =============================================================================
# Block 2 → Block 3: Traffic Log Batch
# =============================================================================


class TrafficLog(BaseModel):
    """A batch of TrafficRecords dispatched from Block 2 to Block 3.

    The Interceptor or Health Monitor assembles this when a trigger fires
    (stuck, crash, scheduled, manual). The Slow Loop's Parser receives
    this and converts it to a structured LLM prompt.

    The ``trigger`` and ``rejection_rate`` fields give the Slow Loop
    context about *why* it was invoked, enabling it to tailor its analysis.
    """

    log_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    trigger: SlowLoopTrigger = SlowLoopTrigger.SCHEDULED
    target_host: str = "localhost"
    target_port: int = Field(default=9999, ge=1, le=65535)
    packets: list[TrafficRecord] = Field(default_factory=list)
    rejection_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def packet_count(self) -> int:
        return len(self.packets)


# =============================================================================
# Aliases for new MutationEngine compatibility
# =============================================================================

SemanticRuleSet = ActiveRuleSet
PacketRecord = TrafficRecord
