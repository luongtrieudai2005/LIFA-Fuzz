"""Deep-audit regression tests for rule_generator.py.

1. Overlapping fields resolved to SKIP by _validate_field_types must NOT
   generate rules (overlap detection was dead code before the fix).
2. RESERVED (padding) fields must NOT generate mutation rules.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest
from slow_loop.rule_generator import RuleGenerator
from shared.schemas import (
    ProtocolGrammar, InferredField, FieldType,
)


def _fld(o, e, t=FieldType.UINT16_LE, name="f", ms="boundary_values"):
    return InferredField(
        name=name, offset_start=o, offset_end=e, field_type=t,
        mutation_strategy=ms, is_constant=False, possible_values=[],
    )


def _gmk(fields):
    return ProtocolGrammar(
        protocol_name="t", magic_bytes="", fields=fields, confidence=0.9,
    )


def test_skip_field_from_overlap_does_not_generate_rules():
    """Two overlapping numeric fields: the shorter is SKIP'd and must not
    produce rules. Previously both generated rules, making overlap detection
    dead code and producing conflicting mutations."""
    rg = RuleGenerator()
    g = _gmk([_fld(4, 8, name="len"), _fld(4, 6, name="sub")])
    rules = rg.grammar_to_rules(g)
    names = {r.target_field_name for r in rules}
    assert "sub" not in names, "SKIP'd overlap field must not generate rules"
    assert "len" in names, "the surviving (longer) field still generates rules"


def test_reserved_field_not_mutated():
    """RESERVED (padding/unused) must produce zero rules even when the LLM
    forgot to mark is_constant=True."""
    rg = RuleGenerator()
    g = _gmk([
        InferredField(
            name="pad", offset_start=10, offset_end=12,
            field_type=FieldType.RESERVED,
            mutation_strategy="static", is_constant=False, possible_values=[],
        )
    ])
    rules = rg.grammar_to_rules(g)
    assert rules == [], "RESERVED field must not be mutated"


def test_normal_fields_still_generate_rules():
    """Sanity: a plain numeric field still produces rules (regression guard)."""
    rg = RuleGenerator()
    g = _gmk([_fld(4, 8, FieldType.UINT32_LE, name="length")])
    rules = rg.grammar_to_rules(g)
    assert len(rules) >= 1
