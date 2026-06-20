"""
tests/test_text_tokenizer.py
────────────────────────────
Unit tests for the generic text tokenizer (shared/text_tokenizer.py).

The tokenizer is the integrity boundary for text-protocol handling: it may
use ONLY universal text framing (\\r\\n / whitespace / first colon). These
tests pin that behaviour with generic (non-protocol-specific) payloads.
"""

from shared.text_tokenizer import (
    TextToken,
    find_token_by_value,
    is_text_like,
    token_at,
    tokenize_text,
)


def _kinds(tokens):
    return [(t.kind, t.line_idx, t.token_idx) for t in tokens]


class TestIsTextLike:
    def test_ascii_text_is_text(self):
        assert is_text_like(b"CMD arg\r\nHeader: val\r\n")

    def test_binary_is_not_text(self):
        assert not is_text_like(b"\xde\xad\xbe\xef\x00\x01\x02\xff" * 4)

    def test_empty_is_not_text(self):
        assert not is_text_like(b"")


class TestTokenizeText:
    def test_request_line_split_on_whitespace(self):
        pkt = b"AAA bbb ccc\r\n"
        toks = tokenize_text(pkt)
        assert _kinds(toks) == [
            ("line_token", 0, 0),
            ("line_token", 0, 1),
            ("line_token", 0, 2),
        ]
        assert pkt[toks[0].start:toks[0].end] == b"AAA"
        assert pkt[toks[1].start:toks[1].end] == b"bbb"
        assert pkt[toks[2].start:toks[2].end] == b"ccc"

    def test_colon_in_uri_does_not_make_header(self):
        """A request-line token containing ':' (e.g. scheme://host) must NOT
        be mis-parsed as a header — the bytes before the first colon contain
        a space, so the universal header rule rejects it."""
        pkt = b"CMD scheme://host:9000/path VER\r\n"
        toks = tokenize_text(pkt)
        kinds = [t.kind for t in toks]
        assert "header_name" not in kinds
        assert "header_value" not in kinds
        # three whitespace words
        assert len(toks) == 3
        assert pkt[toks[1].start:toks[1].end] == b"scheme://host:9000/path"

    def test_header_line_name_value(self):
        pkt = b"Label: alpha beta\r\n"
        toks = tokenize_text(pkt)
        assert _kinds(toks) == [
            ("header_name", 0, 0),
            ("header_value", 0, 1),
        ]
        assert pkt[toks[0].start:toks[0].end] == b"Label"
        assert pkt[toks[1].start:toks[1].end] == b"alpha beta"

    def test_multiple_lines_indexed(self):
        pkt = b"AAA bbb ccc\r\nName: val\r\nOther: x\r\n"
        toks = tokenize_text(pkt)
        # line 0: 3 words; line 1: name+val; line 2: name+val
        assert _kinds(toks) == [
            ("line_token", 0, 0),
            ("line_token", 0, 1),
            ("line_token", 0, 2),
            ("header_name", 1, 0),
            ("header_value", 1, 1),
            ("header_name", 2, 0),
            ("header_value", 2, 1),
        ]

    def test_bare_lf_also_splits(self):
        pkt = b"AAA bbb\nName: val\n"
        toks = tokenize_text(pkt)
        assert pkt[toks[0].start:toks[0].end] == b"AAA"
        # toks = [AAA, bbb, Name(header_name), val(header_value)]
        assert toks[3].kind == "header_value"
        assert pkt[toks[3].start:toks[3].end] == b"val"

    def test_empty_lines_skipped(self):
        pkt = b"AAA\r\n\r\nName: val\r\n"
        toks = tokenize_text(pkt)
        # no token emitted for the blank line
        assert all(t.line_idx in (0, 2) for t in toks)

    def test_offsets_are_absolute_and_in_bounds(self):
        pkt = b"AAA bbb\r\nName: val\r\n"
        for t in tokenize_text(pkt):
            assert 0 <= t.start < t.end <= len(pkt)
            assert pkt[t.start:t.end].strip() != b""


class TestLocators:
    def test_find_token_by_value(self):
        pkt = b"AAA bbb ccc\r\n"
        t = find_token_by_value(pkt, [b"bbb", b"zzz"])
        assert t is not None
        assert pkt[t.start:t.end] == b"bbb"

    def test_find_token_by_value_missing(self):
        assert find_token_by_value(b"AAA bbb\r\n", [b"zzz"]) is None

    def test_token_at(self):
        pkt = b"AAA bbb\r\nName: val\r\n"
        toks = tokenize_text(pkt)
        t = token_at(toks, 1, 1)
        assert t is not None
        assert pkt[t.start:t.end] == b"val"
        assert token_at(toks, 99, 99) is None
