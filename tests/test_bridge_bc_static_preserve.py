"""Regression tests: B↔C bridge — STATIC preserve_bytes contract.

Guards the contract that ActiveRuleSet.get_static_fields() treats
preserve_bytes as an offset-0 packet prefix. The math-bootstrap bridge
(RulesOrchestrator._convert_field_rules, used by Baseline B and by
Baseline C's LLM-failure fallback) must only emit preserve_bytes for
the offset-0 STATIC field, never for non-zero STATIC fields.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest
from shared.schemas import (
    ActiveRuleSet, FieldRule, MutationStrategy,
)
from slow_loop.rules_orchestrator import RulesOrchestrator


def _convert(field_rules):
    """Bridge path shared by Baseline B and Baseline C fallback."""
    orch = RulesOrchestrator.__new__(RulesOrchestrator)
    return orch._convert_field_rules(field_rules)


def test_offset0_static_carries_preserve_bytes():
    # Magic header at offset 0 — must be preserved at offset 0.
    fr = FieldRule(
        field_name="magic", offset=0, length=4,
        mutation_strategy=MutationStrategy.STATIC, static_value="deadbeef",
        confidence=0.99,
    )
    rules = _convert([fr])
    assert len(rules) == 1
    assert rules[0].preserve_bytes == b"\xde\xad\xbe\xef"
    ars = ActiveRuleSet(rules=rules)
    statics = ars.get_static_fields()
    assert len(statics) == 1
    assert statics[0].offset == 0
    assert statics[0].static_value == "deadbeef"


def test_nonzero_static_does_not_carry_preserve_bytes():
    # A constant version/opcode field at offset 6. Before the fix this was
    # emitted with preserve_bytes = the field value, which get_static_fields()
    # mis-anchored at offset 0 (dropping it, or corrupting the magic if longer).
    fr = FieldRule(
        field_name="version", offset=6, length=1,
        mutation_strategy=MutationStrategy.STATIC, static_value="02",
        confidence=0.95,
    )
    rules = _convert([fr])
    assert len(rules) == 1
    assert rules[0].preserve_bytes == b""   # contract fix
    # Excluded from mutation (passes through seed unchanged):
    assert rules[0].mutation_strategy_override == MutationStrategy.STATIC
    ars = ActiveRuleSet(rules=rules)
    assert ars.get_static_fields() == []     # no spurious offset-0 region
    assert ars.get_mutable_fields() == []    # not mutated


def test_magic_not_overwritten_by_longer_nonzero_static():
    # The regression that motivated the fix: a non-zero STATIC field whose
    # preserve_bytes is LONGER than the real magic. Pre-fix, get_static_fields()
    # picked the longest region and wrote it at offset 0, corrupting the magic.
    magic = FieldRule(
        field_name="magic", offset=0, length=4,
        mutation_strategy=MutationStrategy.STATIC, static_value="deadbeef",
        confidence=0.99,
    )
    # Hypothetical 6-byte static region at offset 10.
    big_static = FieldRule(
        field_name="trailer", offset=10, length=6,
        mutation_strategy=MutationStrategy.STATIC, static_value="010203040506",
        confidence=0.9,
    )
    rules = _convert([magic, big_static])
    ars = ActiveRuleSet(rules=rules)
    statics = ars.get_static_fields()
    assert len(statics) == 1
    assert statics[0].offset == 0
    assert statics[0].static_value == "deadbeef"   # magic survives, not corrupted


def test_mutable_fields_unchanged_by_fix():
    # Sanity: non-STATIC fields are still mutable and carry no preserve_bytes.
    length = FieldRule(
        field_name="length", offset=4, length=2,
        mutation_strategy=MutationStrategy.CALCULATED, confidence=0.8,
    )
    rules = _convert([length])
    assert len(rules) == 1
    assert rules[0].preserve_bytes == b""
    ars = ActiveRuleSet(rules=rules)
    mutable = ars.get_mutable_fields()
    assert len(mutable) == 1
    assert mutable[0].offset == 4
