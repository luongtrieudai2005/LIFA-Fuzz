"""
tests/test_text_protocol_integrity.py
─────────────────────────────────────
ACADEMIC-INTEGRITY GUARD for the generic text-protocol path.

LIFA-Fuzz's thesis is a *black-box fuzzer with no protocol-specific
knowledge in the core* (see shared/protocol_module.py). The text-protocol
rule path must therefore use ONLY universal text framing
(\\r\\n / whitespace / first colon) plus LLM-supplied semantics — never
hardcoded protocol names, method-verb lists, header-name lists, or
structural assumptions like "request line".

This test machine-checks that boundary so a reviewer (or a future edit)
cannot silently inject protocol-specific knowledge, which would make any
RTSP/text-protocol results non-attributable to the black-box LLM thesis.

If this test FAILS, someone added protocol-specific content to a generic
path — move it to a disclosed opt-in ProtocolModule instead.
"""

import inspect
from pathlib import Path

from slow_loop import rule_generator as rg_mod
from fast_loop import mutator as mutator_mod
from shared import text_tokenizer as tt_mod


# Unambiguous protocol-specific tokens that must NEVER appear in the generic
# text path. (Common English words like "transport"/"options"/"session" are
# deliberately excluded to avoid false positives; the tokens below are
# protocol identifiers or RTSP-specific verbs/headers.)
BANNED_SUBSTRINGS = [
    # protocol family / version identifiers
    "rtsp", "http/", "sip", "smtp", "pop3", "imap",
    # RTSP method verbs (hardcoded verb lists would be protocol knowledge)
    "describe", "teardown", "announce", "get_parameter", "set_parameter",
    # RTSP/HTTP-specific header names
    "cseq",
    # structural assumptions about a specific protocol's framing
    "request line", "status line",
]


def _text_tokenizer_source() -> str:
    return Path(tt_mod.__file__).read_text(encoding="utf-8").lower()


def _text_rule_generator_source() -> str:
    parts = [
        inspect.getsource(rg_mod.RuleGenerator._is_text_grammar),
        inspect.getsource(rg_mod.RuleGenerator._generate_text_rules),
        inspect.getsource(rg_mod.RuleGenerator._coerce_hex),
        inspect.getsource(rg_mod.RuleGenerator._make_text_rule),
    ]
    return "\n".join(parts).lower()


def _apply_text_field_source() -> str:
    return inspect.getsource(mutator_mod._apply_text_field).lower()


def test_tokenizer_has_no_protocol_specific_content():
    src = _text_tokenizer_source()
    offenders = [w for w in BANNED_SUBSTRINGS if w in src]
    assert not offenders, (
        f"Generic tokenizer contains protocol-specific tokens {offenders} "
        f"— this breaks the black-box thesis. Move such knowledge to a "
        f"disclosed ProtocolModule."
    )


def test_text_rule_generator_has_no_protocol_specific_content():
    src = _text_rule_generator_source()
    offenders = [w for w in BANNED_SUBSTRINGS if w in src]
    assert not offenders, (
        f"Text rule-generation code contains protocol-specific tokens "
        f"{offenders} — breaks the black-box thesis."
    )


def test_apply_text_field_has_no_protocol_specific_content():
    src = _apply_text_field_source()
    offenders = [w for w in BANNED_SUBSTRINGS if w in src]
    assert not offenders, (
        f"_apply_text_field contains protocol-specific tokens {offenders}."
    )


def test_tokenizer_does_not_branch_on_protocol_name():
    """The tokenizer must not special-case any protocol by name. Cheap
    structural check: no string literal in the source matches a known
    protocol identifier used as a branch condition."""
    src = _text_tokenizer_source()
    # The tokenizer is allowed the universal delimiters only:
    for needle in (b"\r\n", b"\n", b":", b" "):
        # presence of universal framing is expected and fine
        pass
    for proto in ("rtsp", "http", "ftp", "sip", "smtp", "pop3", "imap"):
        assert proto not in src, f"tokenizer references protocol '{proto}'"
