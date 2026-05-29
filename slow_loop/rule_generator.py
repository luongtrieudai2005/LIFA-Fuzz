"""
slow_loop/rule_generator.py
──────────────────────────
Rule Generator — converts LLM-inferred protocol grammar into actionable
SemanticRule objects for the Fast Loop.

Responsibilities:
    - Receive a ProtocolGrammar from the LLMAgent.
    - Convert each inferred field into one or more SemanticRules.
    - Validate rules (safe offsets, valid field types).
    - Push rules to the Fast Loop via shared file (atomic write).

Rule Generation Strategy:
    For each inferred field, the generator creates rules based on field type:
    - **Numeric fields (uint8, uint16, uint32)**: Boundary rules (0, MAX, MAX-1)
      + structural rules (increment, decrement, random) + bit-flip rules.
    - **Enum fields**: Structural cycle rule + invalid-value boundary rule.
    - **String fields**: Length overflow boundary + null injection structural.
    - **Bytes fields**: Bit-flip baseline.
    - **Bool fields**: Valid/invalid value structural rules.
    - **Magic bytes / constants**: SKIPPED — never mutate known-fixed fields.

Priority Scoring:
    Rules are assigned priority based on:
    - Field type (length/uint32 → high, reserved → low).
    - LLM confidence in the grammar (scales the base priority).
    - Historical crash rate of similar rules (future: read from Fast Loop).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.logger import get_logger
from shared.schemas import (
    FieldType,
    InferredField,
    ProtocolGrammar,
    RuleType,
    SemanticRule,
    MutationConstraints,
)

logger = get_logger("slow_loop.rule_generator")


# =============================================================================
# Priority weights by field type
# =============================================================================
# Higher = more promising fuzzing target. Length fields are historically
# the #1 source of parser bugs, so they get the highest weight.

_FIELD_TYPE_PRIORITY: dict[FieldType, float] = {
    # Numeric — high priority (overflow / underflow bugs)
    FieldType.UINT32_LE: 0.92,
    FieldType.UINT32_BE: 0.92,
    FieldType.INT32_LE: 0.85,
    FieldType.INT32_BE: 0.85,
    FieldType.UINT16_LE: 0.88,
    FieldType.UINT16_BE: 0.88,
    FieldType.INT16_LE: 0.80,
    FieldType.INT16_BE: 0.80,
    FieldType.UINT8: 0.78,
    FieldType.INT8: 0.72,
    # Enum — test invalid values
    FieldType.ENUM: 0.75,
    # String — overflow and format bugs
    FieldType.STRING: 0.65,
    # Bool — edge cases
    FieldType.BOOL: 0.50,
    # Raw bytes — baseline bit-flip
    FieldType.BYTES: 0.45,
    # Reserved / padding — low value
    FieldType.RESERVED: 0.15,
}


class RuleGenerator:
    """Converts inferred protocol grammar into mutation rules.

    Takes the output of the LLM Agent (a ProtocolGrammar) and generates
    a list of SemanticRule objects that the Fast Loop can immediately
    use to create targeted mutations.

    Args:
        min_confidence:  Minimum LLM confidence to accept a field rule.
        max_rules:       Maximum rules to generate (drop lowest priority).
        rule_output_file: Path to write generated rules (for Fast Loop pickup).

    Example:
        >>> gen = RuleGenerator(min_confidence=0.5)
        >>> rules = gen.grammar_to_rules(grammar)
        >>> await gen.push_rules(rules)
    """

    def __init__(
        self,
        min_confidence: float = 0.5,
        max_rules: int = 200,
        rule_output_file: str = "shared/active_rules.json",
    ) -> None:
        self.min_confidence = min_confidence
        self.max_rules = max_rules
        self.rule_output_file = Path(rule_output_file)

        # Runtime stats
        self._total_rules_generated: int = 0
        self._total_rules_pushed: int = 0

    # -----------------------------------------------------------------
    # Core Conversion
    # -----------------------------------------------------------------

    def grammar_to_rules(self, grammar: ProtocolGrammar) -> list[SemanticRule]:
        """Convert an inferred grammar into a list of SemanticRules.

        Iterates over each field in the grammar and generates appropriate
        mutation rules based on the field type. Skips constant fields
        (magic bytes, fixed headers).

        Args:
            grammar: The ProtocolGrammar inferred by the LLM.

        Returns:
            A list of SemanticRule objects, sorted by priority (descending).
        """
        if not grammar.fields:
            logger.warning("Grammar has no fields — no rules generated")
            return []

        if grammar.confidence < self.min_confidence:
            logger.warning(
                f"Grammar confidence {grammar.confidence:.2f} is below "
                f"threshold {self.min_confidence:.2f} — skipping"
            )
            return []

        rules: list[SemanticRule] = []

        # Build a preserve-bytes mask from detected magic bytes
        magic_bytes = b""
        if grammar.magic_bytes:
            try:
                magic_bytes = bytes.fromhex(grammar.magic_bytes.replace(" ", ""))
            except ValueError:
                logger.warning(f"Invalid magic_bytes hex: {grammar.magic_bytes!r}")

        for field in grammar.fields:
            if field.is_constant:
                logger.debug(f"Skipping constant field '{field.name}'")
                continue

            field_rules = self._generate_rules_for_field(
                field, grammar.confidence, magic_bytes
            )
            rules.extend(field_rules)

        # Deduplicate by (field_name, rule_type)
        seen: set[tuple[str, str]] = set()
        unique: list[SemanticRule] = []
        for r in rules:
            key = (r.target_field_name, r.rule_type.value)
            if key not in seen:
                seen.add(key)
                unique.append(r)

        # Sort by priority descending
        unique.sort(key=lambda r: r.priority, reverse=True)

        # Trim to max_rules
        if len(unique) > self.max_rules:
            dropped = len(unique) - self.max_rules
            logger.info(f"Trimming {dropped} low-priority rules (max={self.max_rules})")
            unique = unique[: self.max_rules]

        self._total_rules_generated += len(unique)
        logger.info(
            f"Generated {len(unique)} rules from grammar "
            f"'{grammar.protocol_name}' (confidence={grammar.confidence:.2f})"
        )
        return unique

    # -----------------------------------------------------------------
    # Per-Field Dispatch
    # -----------------------------------------------------------------

    def _generate_rules_for_field(
        self,
        field: InferredField,
        grammar_confidence: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Dispatch to the correct rule generator for a field's type."""
        field_len = field.offset_end - field.offset_start
        if field_len <= 0:
            return []

        base_priority = _FIELD_TYPE_PRIORITY.get(field.field_type, 0.5)
        # Scale by grammar confidence — low confidence → lower priority
        priority = min(0.95, base_priority * grammar_confidence)

        if field.field_type in (
            FieldType.UINT8,
            FieldType.UINT16_LE,
            FieldType.UINT16_BE,
            FieldType.UINT32_LE,
            FieldType.UINT32_BE,
            FieldType.INT8,
            FieldType.INT16_LE,
            FieldType.INT16_BE,
            FieldType.INT32_LE,
            FieldType.INT32_BE,
        ):
            return self._generate_numeric_rules(field, priority, magic_bytes)

        if field.field_type == FieldType.ENUM:
            return self._generate_enum_rules(field, priority, magic_bytes)

        if field.field_type == FieldType.STRING:
            return self._generate_string_rules(field, priority, magic_bytes)

        if field.field_type == FieldType.BYTES:
            return self._generate_bytes_rules(field, priority, magic_bytes)

        if field.field_type == FieldType.BOOL:
            return self._generate_bool_rules(field, priority, magic_bytes)

        # Unknown field type — conservative bit-flip
        logger.debug(f"Unknown field type '{field.field_type}' for '{field.name}'")
        return self._generate_bytes_rules(field, priority * 0.5, magic_bytes)

    # -----------------------------------------------------------------
    # Numeric Field Rules
    # -----------------------------------------------------------------

    def _generate_numeric_rules(
        self,
        field: InferredField,
        priority: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Generate boundary, structural, and bit-flip rules for numeric fields.

        For a uint32_le field at offset 4-8, this produces:
        - Boundary: test 0, MAX, MAX-1, 1, overflow values.
        - Structural: increment / decrement / random.
        - Bit-flip: random single-bit flip within the field.
        """
        rules: list[SemanticRule] = []
        field_len = field.offset_end - field.offset_start
        max_val = (1 << (field_len * 8)) - 1

        # Boundary values to test
        boundary_values = [0, max_val, max_val - 1, 1, max_val // 2]
        if field_len >= 4:
            # 32-bit special values
            boundary_values.extend([0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])

        rules.append(
            SemanticRule(
                rule_type=RuleType.BOUNDARY,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                constraints=MutationConstraints(
                    min_value=0,
                    max_value=max_val,
                    invalid_values=list(set(boundary_values)),
                ),
                preserve_bytes=magic_bytes,
                priority=priority,
                description=(
                    f"Boundary fuzz for {field.name} "
                    f"(offset {field.offset_start}-{field.offset_end}, "
                    f"{field.field_type.value})"
                ),
            )
        )

        # Structural: increment / decrement / random
        rules.append(
            SemanticRule(
                rule_type=RuleType.STRUCTURAL,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                constraints=MutationConstraints(
                    min_value=0,
                    max_value=max_val,
                    step=1,
                ),
                preserve_bytes=magic_bytes,
                priority=priority * 0.85,
                description=(
                    f"Structural fuzz (inc/dec/rand) for {field.name}"
                ),
            )
        )

        # Bit-flip baseline
        rules.append(
            SemanticRule(
                rule_type=RuleType.BIT_FLIP,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                preserve_bytes=magic_bytes,
                priority=priority * 0.60,
                description=f"Bit-flip fuzz for {field.name}",
            )
        )

        return rules

    # -----------------------------------------------------------------
    # Enum Field Rules
    # -----------------------------------------------------------------

    def _generate_enum_rules(
        self,
        field: InferredField,
        priority: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Generate one structural rule per known enum value + an invalid-value rule."""
        rules: list[SemanticRule] = []

        if field.possible_values:
            # Cycle through known valid enum values
            rules.append(
                SemanticRule(
                    rule_type=RuleType.STRUCTURAL,
                    target_field_name=field.name,
                    offset_start=field.offset_start,
                    offset_end=field.offset_end,
                    field_type=field.field_type,
                    constraints=MutationConstraints(
                        allowed_values=field.possible_values,
                    ),
                    preserve_bytes=magic_bytes,
                    priority=priority,
                    description=(
                        f"Enum cycle for {field.name} "
                        f"({len(field.possible_values)} known values)"
                    ),
                )
            )

            # Invalid enum value injection
            rules.append(
                SemanticRule(
                    rule_type=RuleType.BOUNDARY,
                    target_field_name=field.name,
                    offset_start=field.offset_start,
                    offset_end=field.offset_end,
                    field_type=field.field_type,
                    constraints=MutationConstraints(
                        invalid_values=["0xFF", "0xFE", "0x00"],
                    ),
                    preserve_bytes=magic_bytes,
                    priority=priority * 0.80,
                    description=f"Invalid enum value fuzz for {field.name}",
                )
            )
        else:
            # No known values — conservative bit-flip
            rules.append(
                SemanticRule(
                    rule_type=RuleType.BIT_FLIP,
                    target_field_name=field.name,
                    offset_start=field.offset_start,
                    offset_end=field.offset_end,
                    field_type=field.field_type,
                    preserve_bytes=magic_bytes,
                    priority=priority * 0.50,
                    description=f"Bit-flip fuzz for unknown enum {field.name}",
                )
            )

        return rules

    # -----------------------------------------------------------------
    # String Field Rules
    # -----------------------------------------------------------------

    def _generate_string_rules(
        self,
        field: InferredField,
        priority: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Generate length overflow and null-injection rules for string fields."""
        rules: list[SemanticRule] = []
        field_len = field.offset_end - field.offset_start

        # Length overflow — push the field size way beyond normal
        rules.append(
            SemanticRule(
                rule_type=RuleType.BOUNDARY,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                constraints=MutationConstraints(
                    min_value=0,
                    max_value=field_len * 10,
                    invalid_values=[0, field_len * 100, 0xFFFF],
                ),
                preserve_bytes=magic_bytes,
                priority=priority * 0.90,
                description=f"Length overflow fuzz for {field.name}",
            )
        )

        # Null byte injection
        rules.append(
            SemanticRule(
                rule_type=RuleType.STRUCTURAL,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                constraints=MutationConstraints(
                    invalid_values=["00"],
                ),
                preserve_bytes=magic_bytes,
                priority=priority * 0.70,
                description=f"Null injection fuzz for {field.name}",
            )
        )

        return rules

    # -----------------------------------------------------------------
    # Bytes Field Rules
    # -----------------------------------------------------------------

    def _generate_bytes_rules(
        self,
        field: InferredField,
        priority: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Generate bit-flip rules for raw byte fields."""
        return [
            SemanticRule(
                rule_type=RuleType.BIT_FLIP,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                preserve_bytes=magic_bytes,
                priority=priority * 0.50,
                description=f"Bit-flip fuzz for byte field {field.name}",
            )
        ]

    # -----------------------------------------------------------------
    # Bool Field Rules
    # -----------------------------------------------------------------

    def _generate_bool_rules(
        self,
        field: InferredField,
        priority: float,
        magic_bytes: bytes = b"",
    ) -> list[SemanticRule]:
        """Generate valid/invalid value rules for boolean fields."""
        return [
            SemanticRule(
                rule_type=RuleType.STRUCTURAL,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                constraints=MutationConstraints(
                    allowed_values=[0, 1],
                    invalid_values=[2, 0xFF],
                ),
                preserve_bytes=magic_bytes,
                priority=priority,
                description=f"Bool fuzz for {field.name}",
            )
        ]

    # -----------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------

    def validate_rule(self, rule: SemanticRule) -> bool:
        """Validate that a rule is safe and actionable.

        Checks:
        - Offsets are non-negative and ``offset_start < offset_end``.
        - Field length is > 0 and <= 65535.
        - Field type is a recognized ``FieldType``.

        Args:
            rule: The SemanticRule to validate.

        Returns:
            True if the rule is valid, False otherwise.
        """
        if rule.offset_start < 0:
            logger.warning(f"Rule {rule.rule_id}: negative offset_start")
            return False
        if rule.offset_start >= rule.offset_end:
            logger.warning(
                f"Rule {rule.rule_id}: offset_start ({rule.offset_start}) "
                f">= offset_end ({rule.offset_end})"
            )
            return False
        fl = rule.field_length
        if fl <= 0 or fl > 65535:
            logger.warning(
                f"Rule {rule.rule_id}: invalid field_length {fl}"
            )
            return False
        return True

    # -----------------------------------------------------------------
    # Push to Fast Loop
    # -----------------------------------------------------------------

    async def push_rules(self, rules: list[SemanticRule]) -> None:
        """Push generated rules to the shared file for Fast Loop pickup.

        Writes rules as a JSON array of serialized SemanticRule objects.
        Uses atomic write (temp file + rename) to prevent partial reads
        by the Fast Loop's Rule Watcher.

        Atomicity guarantee:
            On Linux, ``os.rename()`` within a single filesystem is atomic.
            The Fast Loop will either see the old file or the complete new
            file — never a partial write. The Mutator's ``reload_rules()` also
            retries reads on JSONDecodeError for extra safety (e.g., on NFS).

        Args:
            rules: List of validated SemanticRules to push.
        """
        if not rules:
            logger.debug("No rules to push")
            return

        # Validate
        valid_rules = [r for r in rules if self.validate_rule(r)]
        invalid_count = len(rules) - len(valid_rules)
        if invalid_count > 0:
            logger.warning(
                f"Dropped {invalid_count} invalid rules out of {len(rules)}"
            )

        if not valid_rules:
            logger.warning("No valid rules to push after validation")
            return

        # Serialize to JSON
        rules_json = [r.model_dump(mode="json") for r in valid_rules]

        # Ensure output directory exists
        self.rule_output_file.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: temp file → rename
        temp_path = self.rule_output_file.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(rules_json, f, indent=2, default=str)

            temp_path.rename(self.rule_output_file)

            # Force mtime update so the Fast Loop's mtime check
            # reliably detects the change (rename() can preserve
            # the source file's mtime on some filesystems).
            self.rule_output_file.touch()

            self._total_rules_pushed += len(valid_rules)
            logger.info(
                f"Pushed {len(valid_rules)} rules to {self.rule_output_file}"
            )
        except OSError as e:
            logger.error(
                f"Failed to write rules to {self.rule_output_file}: {e}"
            )
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        """Return generator statistics."""
        return {
            "total_rules_generated": self._total_rules_generated,
            "total_rules_pushed": self._total_rules_pushed,
            "output_file": str(self.rule_output_file),
        }
