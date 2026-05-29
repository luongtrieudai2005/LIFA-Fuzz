"""
tests/test_schemas.py
─────────────────────
Unit tests for the shared Pydantic schemas.

Tests cover:
    - TrafficRecord auto-derivation (raw_hex, packet_length)
    - SemanticRule fields (target_field_name, preserve_bytes, constraints)
    - SemanticRule property methods (field_length, crash_rate)
    - MutationConstraints typed model
    - ActiveRuleSet add/prune/top operations
    - CrashRecord auto-derivation (offending_packet_hex)
    - JSON serialization round-trip
"""

import pytest

from shared.schemas import (
    ActiveRuleSet,
    CrashRecord,
    Direction,
    FieldType,
    MutationConstraints,
    RuleType,
    SemanticRule,
    TrafficRecord,
)


class TestTrafficRecord:
    """Tests for TrafficRecord."""

    def test_auto_derive_hex_and_length(self):
        """raw_hex and packet_length are auto-derived from raw_data."""
        record = TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\xDE\xAD\xBE\xEF",
        )
        assert record.raw_hex == "deadbeef"
        assert record.packet_length == 4

    def test_json_round_trip(self):
        """TrafficRecord serializes and deserializes correctly."""
        original = TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=b"\x00\x01\x02\x03",
            session_id="sess123",
        )
        json_str = original.model_dump_json()
        restored = TrafficRecord.model_validate_json(json_str)
        assert restored.raw_data == original.raw_data
        assert restored.session_id == "sess123"

    def test_mutated_packet_tracking(self):
        """Mutated packets store the mutation_id."""
        record = TrafficRecord(
            direction=Direction.SERVER_TO_CLIENT,
            raw_data=b"\xFF\xFF",
            is_mutated=True,
            mutation_id="rule_abc",
        )
        assert record.is_mutated is True
        assert record.mutation_id == "rule_abc"


class TestMutationConstraints:
    """Tests for the typed MutationConstraints model."""

    def test_default_constraints(self):
        """Default constraints are empty / None."""
        c = MutationConstraints()
        assert c.min_value is None
        assert c.max_value is None
        assert c.allowed_values == []
        assert c.invalid_values == []
        assert c.must_preserve == b""
        assert c.step is None

    def test_typed_constraints(self):
        """Constraints accept typed values."""
        c = MutationConstraints(
            min_value=0,
            max_value=65535,
            allowed_values=[1, 2, 4, 8],
            must_preserve=b"\xDE\xAD\xBE\xEF",
            step=1,
        )
        assert c.min_value == 0
        assert c.max_value == 65535
        assert len(c.allowed_values) == 4
        assert c.must_preserve == b"\xDE\xAD\xBE\xEF"

    def test_json_round_trip(self):
        """Constraints serialize and deserialize correctly."""
        original = MutationConstraints(min_value=0, max_value=255, step=1)
        json_str = original.model_dump_json()
        restored = MutationConstraints.model_validate_json(json_str)
        assert restored.min_value == 0
        assert restored.max_value == 255
        assert restored.step == 1


class TestSemanticRule:
    """Tests for SemanticRule."""

    def test_field_length_property(self):
        """field_length returns the correct byte span."""
        rule = SemanticRule(offset_start=4, offset_end=8)
        assert rule.field_length == 4

    def test_crash_rate_zero_division(self):
        """crash_rate returns 0.0 when hit_count is 0."""
        rule = SemanticRule(offset_start=0, offset_end=4, crash_count=0, hit_count=0)
        assert rule.crash_rate == 0.0

    def test_crash_rate_normal(self):
        """crash_rate computes correctly."""
        rule = SemanticRule(offset_start=0, offset_end=4, crash_count=3, hit_count=100)
        assert rule.crash_rate == 0.03

    def test_target_field_name(self):
        """target_field_name is the primary field identifier."""
        rule = SemanticRule(
            offset_start=0,
            offset_end=4,
            target_field_name="magic_bytes",
        )
        assert rule.target_field_name == "magic_bytes"

    def test_field_name_backward_compat(self):
        """field_name property aliases target_field_name."""
        rule = SemanticRule(
            offset_start=0,
            offset_end=4,
            target_field_name="header_length",
        )
        assert rule.field_name == "header_length"

    def test_preserve_bytes(self):
        """preserve_bytes stores bytes that must not be mutated."""
        rule = SemanticRule(
            offset_start=4,
            offset_end=8,
            preserve_bytes=b"\xDE\xAD\xBE\xEF",
        )
        assert rule.preserve_bytes == b"\xDE\xAD\xBE\xEF"

    def test_static_values_to_keep(self):
        """static_values_to_keep maps offset → value."""
        rule = SemanticRule(
            offset_start=4,
            offset_end=8,
            static_values_to_keep={0: 0xDE, 1: 0xAD},
        )
        assert rule.static_values_to_keep[0] == 0xDE
        assert rule.static_values_to_keep[1] == 0xAD

    def test_mutation_constraints_typed(self):
        """constraints field accepts a MutationConstraints instance."""
        rule = SemanticRule(
            offset_start=4,
            offset_end=6,
            constraints=MutationConstraints(min_value=0, max_value=65535),
        )
        assert rule.constraints.min_value == 0
        assert rule.constraints.max_value == 65535

    def test_json_round_trip(self):
        """SemanticRule serializes and deserializes correctly."""
        original = SemanticRule(
            rule_type=RuleType.STRUCTURAL,
            target_field_name="magic",
            offset_start=0,
            offset_end=4,
            field_type=FieldType.BYTES,
            preserve_bytes=b"\xDE\xAD",
            priority=0.9,
        )
        json_str = original.model_dump_json()
        restored = SemanticRule.model_validate_json(json_str)
        assert restored.rule_type == RuleType.STRUCTURAL
        assert restored.target_field_name == "magic"
        assert restored.preserve_bytes == b"\xDE\xAD"
        assert restored.priority == 0.9


class TestActiveRuleSet:
    """Tests for ActiveRuleSet."""

    def test_add_rules(self):
        """add_rules appends without duplicates."""
        rule_set = ActiveRuleSet()
        rule = SemanticRule(rule_id="r1", offset_start=0, offset_end=4)
        rule_set.add_rules([rule])
        assert len(rule_set.rules) == 1

        # Adding the same rule again does not duplicate
        rule_set.add_rules([rule])
        assert len(rule_set.rules) == 1

    def test_add_multiple_rules(self):
        """Multiple distinct rules are all added."""
        rule_set = ActiveRuleSet()
        rules = [
            SemanticRule(rule_id=f"r{i}", offset_start=i, offset_end=i + 2)
            for i in range(5)
        ]
        rule_set.add_rules(rules)
        assert len(rule_set.rules) == 5

    def test_get_top_rules(self):
        """get_top_rules returns N rules sorted by priority."""
        rule_set = ActiveRuleSet()
        rules = [
            SemanticRule(rule_id="low", offset_start=0, offset_end=4, priority=0.1),
            SemanticRule(rule_id="high", offset_start=4, offset_end=8, priority=0.9),
            SemanticRule(rule_id="mid", offset_start=8, offset_end=12, priority=0.5),
        ]
        rule_set.add_rules(rules)
        top = rule_set.get_top_rules(n=2)
        assert len(top) == 2
        assert top[0].priority >= top[1].priority

    def test_prune_stale(self):
        """prune_stale removes lowest-priority rules when over capacity."""
        rule_set = ActiveRuleSet()
        rules = [
            SemanticRule(rule_id=f"r{i}", offset_start=i, offset_end=i + 2, priority=float(i) / 9.0)
            for i in range(10)
        ]
        rule_set.add_rules(rules)
        assert len(rule_set.rules) == 10

        pruned = rule_set.prune_stale(max_rules=5)
        assert len(pruned) == 5
        assert len(rule_set.rules) == 5
        # Remaining rules should be highest priority
        assert rule_set.rules[0].priority > rule_set.rules[-1].priority

    def test_prune_under_capacity(self):
        """prune_stale is a no-op when under capacity."""
        rule_set = ActiveRuleSet()
        rules = [SemanticRule(rule_id="r1", offset_start=0, offset_end=4, priority=0.5)]
        rule_set.add_rules(rules)
        pruned = rule_set.prune_stale(max_rules=10)
        assert len(pruned) == 0
        assert len(rule_set.rules) == 1


class TestCrashRecord:
    """Tests for CrashRecord."""

    def test_auto_derive_hex(self):
        """offending_packet_hex is auto-derived from offending_packet."""
        crash = CrashRecord(
            exit_code=139,
            offending_packet=b"\xDE\xAD\xBE\xEF",
        )
        assert crash.offending_packet_hex == "deadbeef"

    def test_json_round_trip(self):
        """CrashRecord serializes and deserializes correctly."""
        original = CrashRecord(
            exit_code=134,
            offending_packet=b"\xCA\xFE",
            mutation_rule_id="rule_123",
        )
        json_str = original.model_dump_json()
        restored = CrashRecord.model_validate_json(json_str)
        assert restored.exit_code == 134
        assert restored.offending_packet == b"\xCA\xFE"
