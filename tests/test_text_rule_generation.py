"""
tests/test_text_rule_generation.py
──────────────────────────────────
Tests for the text/line-protocol rule path in slow_loop/rule_generator.py
and its runtime application in fast_loop/mutator.py.

Key invariant: a grammar whose fields carry no fixed byte offsets (the
text-protocol case that previously produced 0 rules) now yields token-based
rules, and those rules mutate the INTENDED token at runtime. Binary
grammars are unaffected (the text path is opt-in by detection).
"""

import random

from shared.schemas import (
    ActiveRuleSet,
    FieldType,
    InferredField,
    MutationStrategy,
    ProtocolGrammar,
)
from shared.text_tokenizer import tokenize_text
from slow_loop.rule_generator import RuleGenerator
from fast_loop.mutator import _apply_field


def _text_grammar():
    return ProtocolGrammar(
        protocol_name="Generic text",
        description="text-based ASCII headers delimited by CRLF",
        fields=[
            InferredField(
                name="method", offset_start=0, offset_end=0,
                field_type=FieldType.ENUM, is_constant=False,
                mutation_strategy=MutationStrategy.DICTIONARY,
                possible_values=["CMDA", "CMDB", "CMDC"],
            ),
            InferredField(
                name="resource", offset_start=-1, offset_end=-1,
                field_type=FieldType.STRING, is_constant=False,
                mutation_strategy=MutationStrategy.RANDOM_BYTES,
            ),
            InferredField(
                name="version", offset_start=-1, offset_end=-1,
                field_type=FieldType.STRING, is_constant=True,
                mutation_strategy=MutationStrategy.STATIC,
            ),
            InferredField(
                name="cseq_hdr", offset_start=0, offset_end=0,
                field_type=FieldType.STRING, is_constant=True,
                mutation_strategy=MutationStrategy.STATIC,
            ),
            InferredField(
                name="cseq_val", offset_start=0, offset_end=0,
                field_type=FieldType.STRING, is_constant=False,
                mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
            ),
        ],
        confidence=0.99,
    )


class TestTextRuleGeneration:
    def test_text_grammar_yields_rules_not_zero(self):
        """Regression: an all-unplaceable text grammar used to yield 0 rules."""
        rules = RuleGenerator().grammar_to_rules(_text_grammar())
        assert len(rules) > 0
        assert all(r.text_selector is not None for r in rules)

    def test_enum_field_uses_match_dictionary(self):
        rules = RuleGenerator().grammar_to_rules(_text_grammar())
        method = next(r for r in rules if r.target_field_name == "method")
        assert method.text_selector == {"locate": "match_dictionary"}
        assert method.dictionary_values  # hex-encoded method values
        # hex decodes to ASCII words
        assert bytes.fromhex(method.dictionary_values[0]) in (
            b"CMDA", b"CMDB", b"CMDC",
        )

    def test_constant_fields_get_no_rule(self):
        rules = RuleGenerator().grammar_to_rules(_text_grammar())
        names = {r.target_field_name for r in rules}
        assert "version" not in names  # constant
        assert "cseq_hdr" not in names  # constant

    def test_binary_grammar_uses_offset_path(self):
        """A binary grammar with placeable offsets must NOT take the text path."""
        g = ProtocolGrammar(
            protocol_name="binary_proto",
            description="fixed-offset binary protocol",
            fields=[
                InferredField(
                    name="magic", offset_start=0, offset_end=4,
                    field_type=FieldType.BYTES, is_constant=True,
                    mutation_strategy=MutationStrategy.STATIC,
                ),
                InferredField(
                    name="length", offset_start=4, offset_end=8,
                    field_type=FieldType.UINT32_LE, is_constant=False,
                    mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                ),
            ],
            confidence=0.99,
        )
        rules = RuleGenerator().grammar_to_rules(g)
        assert all(r.text_selector is None for r in rules)

    def test_text_grammar_with_bytes_body_field_detected_without_keyword(self):
        """Regression (#1): a text protocol that carries a BYTES body field
        (e.g. RTSP payload_body) AND whose description lacks a text keyword
        must STILL be detected as text via the structural majority check.
        Previously the strict `all(string/enum)` failed on the BYTES field,
        so detection depended on the LLM description wording — non-
        deterministic across inferences (2/8 cycles missed text)."""
        g = ProtocolGrammar(
            protocol_name="Generic Proto",  # no text keyword
            description="A request/response message format.",  # no keyword
            fields=[
                InferredField(
                    name="method", offset_start=0, offset_end=0,
                    field_type=FieldType.ENUM, is_constant=False,
                    mutation_strategy=MutationStrategy.DICTIONARY,
                    possible_values=["AAA", "BBB"],
                ),
                InferredField(
                    name="uri", offset_start=-1, offset_end=-1,
                    field_type=FieldType.STRING, is_constant=False,
                    mutation_strategy=MutationStrategy.RANDOM_BYTES,
                ),
                InferredField(
                    name="ver", offset_start=-1, offset_end=-1,
                    field_type=FieldType.STRING, is_constant=False,
                    mutation_strategy=MutationStrategy.STATIC,
                ),
                InferredField(
                    name="hdr_val", offset_start=0, offset_end=0,
                    field_type=FieldType.STRING, is_constant=False,
                    mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                ),
                InferredField(
                    name="body", offset_start=-1, offset_end=-1,
                    field_type=FieldType.BYTES, is_constant=False,
                    mutation_strategy=MutationStrategy.PAYLOAD_EXTEND,
                ),
            ],
            confidence=0.95,
        )
        rg = RuleGenerator()
        assert rg._is_text_grammar(g) is True
        rules = rg.grammar_to_rules(g)
        # text rules generated despite the BYTES body field + no keyword
        assert any(r.text_selector is not None for r in rules)


class TestTextRuleRuntime:
    def test_method_rule_mutates_method_token(self):
        random.seed(0)
        rules = RuleGenerator().grammar_to_rules(_text_grammar())
        ars = ActiveRuleSet(
            rule_set_id="t", protocol_name="text", fields=[],
            rules=rules, overall_confidence=0.99,
        )
        mutable = ars.get_mutable_fields()
        pkt = b"CMDA scheme://h/p VER\r\nCSeq: 1\r\n\r\n"
        method_rule = next(f for f in mutable if f.field_name == "method")
        seen = set()
        for _ in range(10):
            out = _apply_field(bytearray(pkt), method_rule, preserve_length=True)
            seen.add(bytes(out[0:4]))
        # method token was swapped among the dictionary values
        assert seen.issubset({b"CMDA", b"CMDB", b"CMDC"})
        assert len(seen) >= 2

    def test_nth_token_maps_to_intended_token(self):
        """resource (nth_token=1) hits the resource token; cseq_val hits the
        header VALUE (not the name) via the generic name→value shift."""
        random.seed(1)
        rules = RuleGenerator().grammar_to_rules(_text_grammar())
        ars = ActiveRuleSet(
            rule_set_id="t", protocol_name="text", fields=[],
            rules=rules, overall_confidence=0.99,
        )
        mutable = ars.get_mutable_fields()
        pkt = b"CMDA scheme://h/p VER\r\nCSeq: 1\r\n\r\n"
        toks = tokenize_text(pkt)

        resource = next(f for f in mutable if f.field_name == "resource")
        assert resource.text_selector == {"nth_token": 1}
        out = _apply_field(bytearray(pkt), resource, preserve_length=True)
        # resource token region changed, method + CSeq name untouched
        res_tok = next(t for t in toks if pkt[t.start:t.end] == b"scheme://h/p")
        assert out[res_tok.start:res_tok.end] != pkt[res_tok.start:res_tok.end]
        assert out[0:4] == b"CMDA"

        cseq = next(f for f in mutable if f.field_name == "cseq_val")
        out2 = _apply_field(bytearray(pkt), cseq, preserve_length=True)
        val_tok = next(t for t in toks if t.kind == "header_value")
        # header VALUE changed, header NAME intact
        assert out2[val_tok.start:val_tok.end] != pkt[val_tok.start:val_tok.end]
        name_tok = next(t for t in toks if t.kind == "header_name")
        assert out2[name_tok.start:name_tok.end] == b"CSeq"
