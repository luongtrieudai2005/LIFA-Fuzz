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
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from shared.logger import get_logger
from shared.schemas import (
    FieldType,
    InferredField,
    MutationConstraints,
    MutationStrategy,
    ProtocolGrammar,
    RuleType,
    SemanticRule,
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
        rule_output_file: str = "/tmp/lifa_rules.json",
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

    def grammar_to_rules(
        self,
        grammar: ProtocolGrammar,
        heatmap: Any = None,
    ) -> list[SemanticRule]:
        """Convert an inferred grammar into a list of SemanticRules.

        Iterates over each field in the grammar and generates appropriate
        mutation rules based on the field type. Skips constant fields
        (magic bytes, fixed headers).

        Optionally cross-validates LLM-inferred field types against the
        mathematical heatmap from DifferentialAnalyzer.

        Args:
            grammar: The ProtocolGrammar inferred by the LLM.
            heatmap: Optional HeatmapResult from DifferentialAnalyzer for
                     field-type cross-validation.

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

        # ── Text / line-protocol fast path (generic tokenizer) ──────
        # If the LLM-inferred grammar describes a text/line protocol whose
        # fields carry no fixed byte offsets, generate token-based rules via
        # the generic text tokenizer instead of dropping every unplaceable
        # field to zero rules. Generic / black-box — the tokenizer knows only
        # universal delimiters; all semantics come from the LLM grammar. See
        # shared/text_tokenizer.py and tests/test_text_protocol_integrity.py.
        if self._is_text_grammar(grammar):
            logger.info(
                f"Text/line protocol detected ('{grammar.protocol_name}', "
                f"fields={len(grammar.fields)}) — generating token-based "
                f"rules via the generic text tokenizer"
            )
            return self._finalize_rules(
                self._generate_text_rules(grammar), grammar
            )

        # ── Cross-validate LLM fields against mathematical heatmap ────
        validated_fields = self._validate_field_types(grammar, heatmap)

        rules: list[SemanticRule] = []

        # Build a preserve-bytes mask from detected magic bytes
        magic_bytes = b""
        if grammar.magic_bytes:
            try:
                magic_bytes = bytes.fromhex(grammar.magic_bytes.replace(" ", ""))
            except ValueError:
                logger.warning(f"Invalid magic_bytes hex: {grammar.magic_bytes!r}")

        for field in validated_fields:
            if field.is_constant:
                logger.debug(f"Skipping constant field '{field.name}'")
                continue

            # _validate_field_types() marks overlapping fields as SKIP. Without
            # this guard those SKIP fields would still generate rules here,
            # making the overlap detection dead code — overlapping fields
            # would produce conflicting rules whose mutations corrupt each other.
            if field.mutation_strategy == MutationStrategy.SKIP:
                logger.debug(f"Skipping SKIP field '{field.name}' (overlap-resolved)")
                continue

            # Guard: drop fields with invalid byte ranges instead of letting
            # them crash SemanticRule construction (offset_start has ge=0).
            # LLMs often describe trailer/checksum/CRLF fields with negative
            # offsets (e.g. "last 2 bytes" → offset_start=-2) or inverted
            # ranges (end <= start). Without this guard, ONE such field raises
            # a ValidationError out of grammar_to_rules(), which the
            # orchestrator catches as ValueError and turns into a full
            # bootstrap fallback — so even a successful LLM inference yields
            # zero rules for baseline C.
            if field.offset_start < 0:
                logger.warning(
                    f"Dropping field '{field.name}': negative offset_start="
                    f"{field.offset_start} (LLM described a trailer/relative "
                    f"offset that has no absolute position)."
                )
                continue
            # Treat offset_end <= offset_start (other than negative = variable-length,
            # handled below) as an empty/invalid range and skip it.
            if field.offset_end >= 0 and field.offset_end <= field.offset_start:
                logger.warning(
                    f"Dropping field '{field.name}': empty/inverted range "
                    f"[{field.offset_start}, {field.offset_end})."
                )
                continue

            # Resolve variable-length fields (offset_end=-1) to a concrete
            # size so they are NOT silently dropped by _generate_rules_for_field().
            # The mutator's _apply_field() clamps to the actual packet size at
            # runtime, so using a generous upper bound here is safe.
            was_variable = field.offset_end < 0  # any negative = variable-length (with trailing delimiter)
            if field.offset_end < 0:
                resolved_end = min(
                    field.offset_start + 1024,
                    grammar.max_packet_size,
                )
                field = field.model_copy(update={"offset_end": resolved_end})
                logger.info(
                    f"Variable-length field '{field.name}' resolved "
                    f"offset_end=-1 → {resolved_end} "
                    f"(max_packet_size={grammar.max_packet_size})"
                )

            field_rules = self._generate_rules_for_field(
                field, grammar.confidence, magic_bytes
            )

            # Structural growth guarantee for variable-length fields. A
            # length-delimited field is where buffer overflows live (the #1
            # memory-corruption class), so the fuzzer MUST test size
            # escalation on it regardless of how the field is semantically
            # labelled. The LLM legitimately assigns random_bytes (value
            # mutation) to a payload it reads as "opaque data", but value
            # mutation alone never grows the actual bytes — and a server that
            # clamps the declared length to bytes-received is then immune. This
            # appends a PAYLOAD_EXTEND rule independent of the LLM strategy so
            # overflow coverage does not depend on the LLM happening to pick a
            # growth strategy. General for any protocol with a variable-length
            # tail field; the dedup step below collapses it if the LLM already
            # produced one.
            if was_variable:
                field_rules.append(
                    SemanticRule(
                        rule_type=RuleType.STRUCTURAL,
                        target_field_name=field.name,
                        offset_start=field.offset_start,
                        offset_end=field.offset_end,
                        field_type=field.field_type,
                        preserve_bytes=magic_bytes,
                        priority=grammar.confidence * 0.80,
                        mutation_strategy_override=MutationStrategy.PAYLOAD_EXTEND,
                        description=(
                            f"Structural growth rule for variable-length field "
                            f"'{field.name}' (overflow-class coverage, "
                            f"strategy-label-independent)"
                        ),
                    )
                )
            rules.extend(field_rules)

        return self._finalize_rules(rules, grammar)

    def _finalize_rules(
        self, rules: list[SemanticRule], grammar: ProtocolGrammar
    ) -> list[SemanticRule]:
        """Dedup → sort → trim → log → attach grammar violations.

        Shared by the binary/offset path and the text/token path so both
        receive identical post-processing.
        """
        # Deduplicate by (field_name, rule_type, has_dictionary, strategy_override)
        # Extended key allows dictionary and non-dictionary STRUCTURAL rules
        # to coexist for the same field (Issue O3/R4 fix).
        seen: set[tuple[str, str, bool, Optional[str]]] = set()
        unique: list[SemanticRule] = []
        for r in rules:
            override_key = (
                r.mutation_strategy_override.value
                if r.mutation_strategy_override
                else None
            )
            key = (
                r.target_field_name,
                r.rule_type.value,
                bool(r.dictionary_values),
                override_key,
            )
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

        # Attach grammar-targeted semantic violations (SemFuzz-inspired). For
        # each inferred field, attach 1-2 structural violations (remove /
        # update) that target THAT field. Unlike the naive case-study
        # violations (mild CRLF/verb perturbation a lenient server tolerates),
        # these target the field's actual role: nuke the magic, drop the
        # length field, set an enum to an invalid value. A spec-compliant
        # server should answer "error"; a "normal" answer is the divergence
        # the oracle flags. This is deterministic and grammar-driven (no LLM
        # cost, no protocol-specific hardcoding) — a cheap first test of
        # whether grammar-targeting beats naive violations. LLM-generated
        # violations remain a later phase.
        self._attach_grammar_violations(unique, grammar)

        return unique

    # -----------------------------------------------------------------
    # Text / line-protocol path (generic tokenizer — black-box)
    # -----------------------------------------------------------------

    def _is_text_grammar(self, grammar: ProtocolGrammar) -> bool:
        """Detect a text/line-based grammar from LLM-supplied signals ONLY.

        No protocol-specific knowledge. Triggers on either:
          (a) the LLM's own description/protocol_name containing a generic
              text keyword ("text", "ascii", "header", "line", "crlf",
              "delimited") — these words come from the LLM, not from us; or
          (b) a structural signature: most non-constant fields carry no fixed
              byte offset (LLM returned ``-1`` or ``[0,0)``) AND a MAJORITY
              are typed string/enum — i.e. the offset model genuinely does
              not fit.

        Binary grammars (placeable offsets) never match, so this path is
        opt-in by detection and cannot affect binary targets.
        """
        blob = (
            (grammar.description or "") + " " + (grammar.protocol_name or "")
        ).lower()
        if any(
            k in blob
            for k in ("text", "ascii", "header", "line", "crlf", "delimited")
        ):
            return True
        non_const = [f for f in grammar.fields if not f.is_constant]
        if len(non_const) < 2:
            return False
        unplaceable = sum(
            1
            for f in non_const
            if f.offset_end < 0 or f.offset_end <= f.offset_start
        )
        # MAJORITY (not all) of non-const fields must be string/enum. A text
        # protocol legitimately carries a binary/bytes body field (e.g. a
        # payload body typed BYTES) which would falsely fail an `all` check —
        # leaving detection dependent solely on the LLM description keyword
        # above, which the LLM omits on some inferences (observed: 2/8 cycles
        # missed text). Majority makes detection deterministic.
        text_typed = sum(
            1
            for f in non_const
            if f.field_type in (FieldType.STRING, FieldType.ENUM)
        )
        if (
            unplaceable / len(non_const) >= 0.5
            and text_typed / len(non_const) >= 0.6
        ):
            return True
        return False

    def _generate_text_rules(
        self, grammar: ProtocolGrammar
    ) -> list[SemanticRule]:
        """Generate token-based rules for a text/line grammar.

        Each non-constant field becomes ONE text rule carrying a
        ``text_selector`` resolved at runtime by the generic tokenizer
        (``shared/text_tokenizer.py``):

          - Enum field with LLM ``possible_values`` → ``{"locate":
            "match_dictionary"}``: locate the token whose bytes equal one of
            the LLM-supplied values, then DICTIONARY-mutate it. This is the
            precise, fully-LLM-driven case (e.g. fuzzing the method verb).
          - Other fields → ``{"nth_token": i}``: the i-th mutable token in
            document order (header names are treated as static labels; the
            value is the mutable unit — universal for ``Name: value``
            framing). A runtime miss (token absent in this seed) is a no-op.

        Mutation strategies reuse the existing generic operators; NO
        protocol-specific content is embedded (red line enforced by
        ``tests/test_text_protocol_integrity.py``).
        """
        rules: list[SemanticRule] = []
        nth = 0  # document-order token index (LLM field order ↔ token order)
        for field in grammar.fields:
            if field.mutation_strategy == MutationStrategy.SKIP:
                continue
            pv = list(getattr(field, "possible_values", None) or [])
            if not field.is_constant and field.field_type == FieldType.ENUM and pv:
                rules.append(
                    self._make_text_rule(
                        field, grammar,
                        selector={"locate": "match_dictionary"},
                        strat=MutationStrategy.DICTIONARY,
                        dictionary=[self._coerce_hex(v) for v in pv],
                    )
                )
            elif not field.is_constant:
                rules.append(
                    self._make_text_rule(
                        field, grammar,
                        selector={"nth_token": nth},
                        strat=field.mutation_strategy or MutationStrategy.RANDOM_BYTES,
                        dictionary=[],
                    )
                )
            # Constant fields emit no rule but still occupy a document token
            # slot, so the nth index stays aligned with runtime token order.
            nth += 1
        return rules

    @staticmethod
    def _coerce_hex(value: str) -> str:
        """Normalise a possible_value to a hex string.

        Binary enum values arrive as hex (e.g. "01"); text tokens arrive as
        ASCII words (e.g. a method verb). Hex is returned unchanged; an ASCII
        word is hex-encoded so it round-trips through ``dictionary_values``
        (a list[str] of hex) and the tokenizer resolver.
        """
        v = (value or "").strip()
        try:
            bytes.fromhex(v)
            return v.lower()
        except ValueError:
            return v.encode("utf-8").hex()

    def _make_text_rule(
        self,
        field,
        grammar: ProtocolGrammar,
        selector: dict,
        strat: MutationStrategy,
        dictionary: list[str],
    ) -> SemanticRule:
        return SemanticRule(
            rule_type=RuleType.STRUCTURAL,
            target_field_name=field.name or "text_field",
            offset_start=0,  # placeholder; text_selector is authoritative
            offset_end=0,
            field_type=field.field_type,
            priority=max(0.1, min(1.0, grammar.confidence)),
            mutation_strategy_override=strat,
            dictionary_values=dictionary,
            text_selector=selector,
            description=(
                f"Text-protocol rule for '{field.name}' via generic tokenizer "
                f"(selector={selector})"
            ),
        )

    def _attach_grammar_violations(
        self, rules: list[SemanticRule], grammar: ProtocolGrammar
    ) -> None:
        """Attach grammar-targeted ViolationStrategy to each field's rule."""
        from shared.schemas import (
            ViolationAction, ViolationStrategy, ResponseCategory, FieldType,
        )
        # Map field name → the rule that owns it (by target_field_name).
        by_field = {r.target_field_name: r for r in rules if r.target_field_name}
        for field in grammar.fields:
            name = field.name or ""
            rule = by_field.get(name)
            if rule is None:
                continue
            ftype = field.field_type
            flen = (field.offset_end - field.offset_start) if field.offset_end and field.offset_end > 0 else (1024 if field.offset_end < 0 else 1)
            vstrats: list[ViolationStrategy] = []
            # Magic/static header: overwrite with NULs ⇒ server should reject
            # (no/unknown framing). Expected error.
            if field.is_constant or ftype == FieldType.BYTES:
                vstrats.append(ViolationStrategy(
                    action=ViolationAction.UPDATE, target_field=name,
                    target_length=max(1, flen),
                    insert_value="00",
                    expected_category=ResponseCategory.ERROR,
                    description=f"Null the {name} field — server should reject",
                ))
            # Numeric/length/enum: set an out-of-band value ⇒ error.
            elif ftype.value.startswith(("uint", "int")) or field.mutation_strategy.value == "enum":
                vstrats.append(ViolationStrategy(
                    action=ViolationAction.UPDATE, target_field=name,
                    target_length=max(1, flen),
                    insert_value="ff",
                    expected_category=ResponseCategory.ERROR,
                    description=f"Set {name} to max value — server should error",
                ))
            # Always also offer a REMOVE of the field (missing mandatory field).
            if flen and flen > 0:
                vstrats.append(ViolationStrategy(
                    action=ViolationAction.REMOVE, target_field=name,
                    target_length=flen,
                    expected_category=ResponseCategory.ERROR,
                    description=f"Drop the {name} field — server should reject",
                ))
            if vstrats:
                rule.violation_strategies = vstrats

    # -----------------------------------------------------------------
    # Field Cross-Validation
    # -----------------------------------------------------------------

    # Numeric field types that the LLM might hallucinate over entropy regions
    _NUMERIC_TYPES: set[FieldType] = {
        FieldType.UINT8, FieldType.UINT16_LE, FieldType.UINT16_BE,
        FieldType.UINT32_LE, FieldType.UINT32_BE,
        FieldType.INT8, FieldType.INT16_LE, FieldType.INT16_BE,
        FieldType.INT32_LE, FieldType.INT32_BE,
    }

    def _validate_field_types(
        self,
        grammar: ProtocolGrammar,
        heatmap: Any = None,
    ) -> list[InferredField]:
        """Cross-validate LLM-inferred fields against mathematical heatmap.

        Applies correction rules that produce warnings (not errors).
        Returns a (potentially modified) copy of grammar.fields.

        Rules:
        1. STATIC override: heatmap says STATIC (conf >= 0.9) but LLM says
           non-static → override to static + is_constant.
        2. HIGH_ENTROPY override: heatmap says HIGH_ENTROPY but LLM says
           numeric type with low grammar confidence → override to bytes.
        3. Overlap detection: overlapping fields → shorter one gets skip.
        4. OOB clamping: offset_end > max_packet_size → clamp.
        """
        fields = list(grammar.fields)  # shallow copy

        # Build offset → FieldGroup lookup from heatmap (if available)
        heatmap_map: dict[int, Any] = {}
        if heatmap is not None and hasattr(heatmap, "field_groups"):
            for fg in heatmap.field_groups:
                for off in range(fg.start, fg.end):
                    heatmap_map[off] = fg

        # ── Per-field heatmap validation ──────────────────────────────
        for i, field in enumerate(fields):
            # Rule 4: OOB clamping (always applies, no heatmap needed)
            if (
                field.offset_end >= 0
                and field.offset_end > grammar.max_packet_size > 0
            ):
                old_end = field.offset_end
                fields[i] = field.model_copy(update={
                    "offset_end": grammar.max_packet_size,
                })
                logger.warning(
                    f"Field '{field.name}' offset_end={old_end} exceeds "
                    f"max_packet_size={grammar.max_packet_size} — clamped"
                )
                field = fields[i]

            if not heatmap_map:
                continue

            # Collect ALL heatmap groups covering this field's byte range,
            # not just the first byte.  A multi-byte field should only be
            # overridden to STATIC if ALL its bytes are STATIC in the heatmap.
            field_end = field.offset_end if field.offset_end >= 0 else field.offset_start + 1
            covering_groups: list[Any] = []
            for off in range(field.offset_start, field_end):
                g = heatmap_map.get(off)
                if g is not None:
                    covering_groups.append(g)

            if not covering_groups:
                continue

            # Use the MAJORITY label across the field's bytes for cross-validation
            label_counts = Counter(g.label.value for g in covering_groups)
            dominant_label = label_counts.most_common(1)[0][0]
            # Use the minimum confidence across covering groups (conservative)
            min_confidence = min(g.confidence for g in covering_groups)

            # Rule 1: STATIC override — only if ALL bytes are STATIC
            all_static = all(g.label.value == "STATIC" for g in covering_groups)
            if (
                all_static
                and min_confidence >= 0.9
                and field.mutation_strategy != MutationStrategy.STATIC
            ):
                logger.warning(
                    f"Field '{field.name}': LLM says strategy="
                    f"{field.mutation_strategy.value}, but heatmap says "
                    f"STATIC for ALL {len(covering_groups)} bytes "
                    f"(min_conf={min_confidence:.2f}) → overriding to static"
                )
                fields[i] = field.model_copy(update={
                    "mutation_strategy": MutationStrategy.STATIC,
                    "is_constant": True,
                })
                continue

            # Rule 2: HIGH_ENTROPY override — if majority of bytes are HIGH_ENTROPY
            if (
                dominant_label == "HIGH_ENTROPY"
                and field.field_type in self._NUMERIC_TYPES
                and grammar.confidence < 0.6
            ):
                logger.warning(
                    f"Field '{field.name}': LLM says type="
                    f"{field.field_type.value}, but heatmap says HIGH_ENTROPY "
                    f"and grammar confidence is low ({grammar.confidence:.2f}) "
                    f"→ overriding to bytes/random_bytes"
                )
                fields[i] = field.model_copy(update={
                    "field_type": FieldType.BYTES,
                    "mutation_strategy": MutationStrategy.RANDOM_BYTES,
                })

        # ── Rule 3: Overlap detection ─────────────────────────────────
        for i in range(len(fields)):
            for j in range(i + 1, len(fields)):
                fi, fj = fields[i], fields[j]
                if fi.mutation_strategy == MutationStrategy.SKIP:
                    continue
                if fj.mutation_strategy == MutationStrategy.SKIP:
                    continue
                # -1 means "rest of packet" — skip overlap check for it
                if fi.offset_end < 0 or fj.offset_end < 0:
                    continue
                # Check [offset_start, offset_end) overlap
                if fi.offset_start < fj.offset_end and fj.offset_start < fi.offset_end:
                    # Override the shorter field
                    len_i = fi.offset_end - fi.offset_start
                    len_j = fj.offset_end - fj.offset_start
                    if len_i <= len_j:
                        victim_idx, victim_name = i, fi.name
                    else:
                        victim_idx, victim_name = j, fj.name
                    logger.warning(
                        f"Overlap detected: '{fi.name}' [{fi.offset_start},{fi.offset_end}) "
                        f"∩ '{fj.name}' [{fj.offset_start},{fj.offset_end}) "
                        f"→ setting shorter '{victim_name}' to skip"
                    )
                    fields[victim_idx] = fields[victim_idx].model_copy(update={
                        "mutation_strategy": MutationStrategy.SKIP,
                    })

        return fields

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

        if field.field_type == FieldType.RESERVED:
            # Padding / unused bytes — must NOT be mutated. Mutating them only
            # risks server rejection (or, for length-prefixed protocols, length
            # mismatch) without any chance of reaching vulnerable logic. The
            # prompt tells the LLM to pair RESERVED with is_constant=true
            # (which is filtered above), but if it forgets, treat it as static.
            logger.debug(
                f"RESERVED field '{field.name}' — not mutating (padding/unused)"
            )
            return []

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
                    invalid_values=list(dict.fromkeys(boundary_values)),
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

            # Dictionary: pick from known enum values directly
            rules.append(
                SemanticRule(
                    rule_type=RuleType.STRUCTURAL,
                    target_field_name=field.name,
                    offset_start=field.offset_start,
                    offset_end=field.offset_end,
                    field_type=field.field_type,
                    preserve_bytes=magic_bytes,
                    dictionary_values=field.possible_values,
                    priority=priority * 0.90,
                    description=(
                        f"Dictionary fuzz for {field.name} "
                        f"({len(field.possible_values)} known enum values)"
                    ),
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

        # Format string injection — targets printf-family vulnerabilities
        # (%s%s%s%n, %x%x%x, etc.). Uses mutation_strategy_override
        # to bypass the STRUCTURAL → RANDOM_BYTES default mapping.
        rules.append(
            SemanticRule(
                rule_type=RuleType.STRUCTURAL,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                preserve_bytes=magic_bytes,
                mutation_strategy_override=MutationStrategy.FORMAT_STRING,
                priority=priority * 0.60,
                description=f"Format-string fuzz for {field.name}",
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
        """Generate bit-flip and random-bytes rules for raw byte fields.

        Previously only yielded BIT_FLIP — now also includes RANDOM_BYTES
        for broader coverage of payload regions (Issue R1).
        """
        rules: list[SemanticRule] = []

        # Bit-flip baseline
        rules.append(
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
        )

        # Random-bytes replacement — covers more ground than bit-flip alone
        rules.append(
            SemanticRule(
                rule_type=RuleType.STRUCTURAL,
                target_field_name=field.name,
                offset_start=field.offset_start,
                offset_end=field.offset_end,
                field_type=field.field_type,
                preserve_bytes=magic_bytes,
                priority=priority * 0.35,
                description=f"Random-bytes fuzz for byte field {field.name}",
            )
        )

        # Payload-extend rule for VARIABLE-LENGTH byte fields (overflow class).
        # Only added when the field is variable-length (offset_end < 0 at
        # grammar level — resolved to a concrete bound by grammar_to_rules()
        # before reaching here, so we key on the strategy the analyzer/LLM
        # assigned). Grows the actual payload bytes via op_buffer_overflow, the
        # only operator that defeats a server which clamps the declared length
        # to the bytes received. General for any length-delimited protocol.
        if field.mutation_strategy == MutationStrategy.PAYLOAD_EXTEND:
            rules.append(
                SemanticRule(
                    rule_type=RuleType.STRUCTURAL,
                    target_field_name=field.name,
                    offset_start=field.offset_start,
                    offset_end=field.offset_end,
                    field_type=field.field_type,
                    preserve_bytes=magic_bytes,
                    priority=priority * 0.80,
                    mutation_strategy_override=MutationStrategy.PAYLOAD_EXTEND,
                    description=(
                        f"Grow variable-length payload field {field.name} "
                        f"(overflow class)"
                    ),
                )
            )

        return rules

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

    async def push_rules(
        self,
        rules: list[SemanticRule],
        grammar: Optional[ProtocolGrammar] = None,
        overall_confidence: Optional[float] = None,
        protocol_name: Optional[str] = None,
    ) -> None:
        """Push generated rules to the shared file for Fast Loop pickup.

        Writes rules as a JSON object containing the rule list and optional
        setup_packets (for stateful protocols).  Uses atomic write (temp
        file + rename) to prevent partial reads by the Fast Loop's Rule
        Watcher.

        Atomicity guarantee:
            On Linux, ``os.rename()`` within a single filesystem is atomic.
            The Fast Loop will either see the old file or the complete new
            file — never a partial write. The Mutator's ``reload_rules()`` also
            retries reads on JSONDecodeError for extra safety (e.g., on NFS).

        Args:
            rules: List of validated SemanticRules to push.
            grammar: Optional ProtocolGrammar — if it has a state_machine
                with a ``setup_sequence``, the hex-encoded packets are
                included in the output for stateful protocol support.
            overall_confidence: C4 fix — overall confidence score to pass
                through to the Fast Loop so it doesn't show 0%.
            protocol_name: C4 fix — protocol name to pass through.
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

        # Extract setup_packets from grammar's state_machine (stateful protocols)
        setup_packets: list[str] = []
        if grammar and grammar.state_machine:
            raw = grammar.state_machine.get("setup_sequence", [])
            if isinstance(raw, list):
                # Accept hex strings directly, or convert bytes-like entries
                for pkt in raw:
                    if isinstance(pkt, str) and pkt:
                        setup_packets.append(pkt)

        payload = {
            "rules": rules_json,
            "setup_packets": setup_packets,
            # C4 fix: include confidence metadata so the Fast Loop's
            # _poll_rules_file() can restore overall_confidence instead
            # of defaulting to 0.0.
            "overall_confidence": overall_confidence or 0.0,
            "protocol_name": protocol_name or "unknown",
        }

        # Ensure output directory exists
        self.rule_output_file.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: temp file → rename
        temp_path = self.rule_output_file.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)

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
