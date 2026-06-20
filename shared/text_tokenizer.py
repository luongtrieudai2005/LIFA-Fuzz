"""
shared/text_tokenizer.py
────────────────────────
Generic text-protocol tokenizer for the black-box core.

Splits an arbitrary bytes payload into addressable tokens using ONLY
universal text framing — line separators (``\\r\\n``), whitespace, and the
first colon of header-shaped lines. This is the structural counterpart of
``DifferentialAnalyzer``'s entropy heuristics: a general, protocol-agnostic
way to locate mutable units in text/line-based traffic, so the LLM-inferred
fields of a text protocol (which have no fixed byte offsets) can still be
mutated meaningfully instead of being dropped to zero rules.

────────────────────────────────────────────────────────────────────────
ACADEMIC-INTEGRITY RED LINE
────────────────────────────────────────────────────────────────────────
This module contains NO protocol-specific knowledge: no protocol names, no
method/verb lists, no header-name lists, no structural assumptions about
any specific protocol's line layout. It knows only "text split on universal
delimiters".
Any protocol-specific handling belongs in a disclosed opt-in ProtocolModule
(see ``shared/protocol_module.py``), never here. A machine-checked
banned-content test (``tests/test_text_protocol_integrity.py``) enforces
this so the black-box thesis stays verifiable.
────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


_WS = b" \t\r\n\x0b\x0c"


def _is_ws(b: int) -> bool:
    return b in _WS


@dataclass(frozen=True)
class TextToken:
    """A mutable unit located within a text payload.

    ``start``/``end`` are byte offsets into the ORIGINAL packet (end
    exclusive). ``line_idx`` is the 0-based line (split on ``\\r\\n`` /
    ``\\n``). ``token_idx`` is the 0-based token within that line.
    ``kind`` labels how the token was derived so the mutator can pick a
    sensible mutation strategy:

      - ``"line_token"``      — a whitespace-separated word (e.g. the
                                space-separated words of a line).
      - ``"header_name"``     — the name part of a ``Name: value`` line.
      - ``"header_value"``    — the value part of a ``Name: value`` line.
    """

    start: int
    end: int
    line_idx: int
    token_idx: int
    kind: str


def is_text_like(packet: bytes, threshold: float = 0.85) -> bool:
    """Heuristic: is ``packet`` text-like enough to tokenize?

    Generic — no protocol knowledge. Returns True when at least ``threshold``
    fraction of bytes are printable ASCII or common whitespace (TAB/CR/LF).
    Used by the rule generator to decide whether the text path applies.
    """
    if not packet:
        return False
    printable = sum(
        1 for b in packet if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return (printable / len(packet)) >= threshold


def tokenize_text(packet: bytes) -> List[TextToken]:
    """Tokenize a text payload into addressable tokens (document order).

    Universal framing only:

      1. Split into lines on ``\\r\\n`` (a bare ``\\n`` is also accepted).
      2. For each line, decide header vs. words:
         - A line is **header-shaped** iff it contains a colon AND the bytes
           before the FIRST colon contain no whitespace. This single rule
           correctly treats ``Name: value`` lines as headers while leaving a
           line like ``CMD scheme://host/x VER/1.0`` as plain words (the
           text before its first colon contains a space). No
           protocol-specific structure is assumed — "a header name is a
           single whitespace-free token" is universal text framing.
         - Header line → emit ``header_name`` (before colon) and
           ``header_value`` (after colon, whitespace-trimmed) tokens.
         - Otherwise → emit each whitespace-separated word as a
           ``line_token``.

    Empty lines and empty tokens are skipped. Returns tokens in document
    order with absolute byte offsets.
    """
    tokens: List[TextToken] = []
    pos = 0
    line_idx = 0
    n = len(packet)
    while pos < n:
        cr = packet.find(b"\r\n", pos)
        lf = packet.find(b"\n", pos)
        candidates = [e for e in (cr, lf) if e != -1]
        line_end = min(candidates) if candidates else n
        _emit_line_tokens(tokens, packet[pos:line_end], pos, line_idx)
        if cr != -1 and cr == line_end:
            pos = line_end + 2
        elif lf != -1 and lf == line_end:
            pos = line_end + 1
        else:
            pos = n
        line_idx += 1
    return tokens


def _emit_line_tokens(
    out: List[TextToken], line: bytes, base: int, line_idx: int
) -> None:
    """Append tokens for one line. ``base`` is the absolute offset of line[0]."""
    if not line.strip():
        return
    colon = line.find(b":")
    if colon > 0:
        before = line[:colon]
        # Header-shaped iff the name part has no whitespace (universal rule).
        if not _contains_ws(before):
            name_start = _leading_ws(line, 0)
            if name_start < colon:
                out.append(
                    TextToken(base + name_start, base + colon,
                              line_idx, 0, "header_name")
                )
            val_start = _leading_ws(line, colon + 1)
            val_end = _trailing_ws(line)
            if val_start < val_end:
                out.append(
                    TextToken(base + val_start, base + val_end,
                              line_idx, 1, "header_value")
                )
            return
    # Plain words: split on whitespace.
    tok_idx = 0
    i = 0
    L = len(line)
    while i < L:
        if _is_ws(line[i]):
            i += 1
            continue
        j = i
        while j < L and not _is_ws(line[j]):
            j += 1
        out.append(
            TextToken(base + i, base + j, line_idx, tok_idx, "line_token")
        )
        tok_idx += 1
        i = j


def _contains_ws(seg: bytes) -> bool:
    return any(_is_ws(b) for b in seg)


def _leading_ws(line: bytes, start: int) -> int:
    i = start
    L = len(line)
    while i < L and _is_ws(line[i]):
        i += 1
    return i


def _trailing_ws(line: bytes) -> int:
    e = len(line)
    while e > 0 and _is_ws(line[e - 1]):
        e -= 1
    return e


def find_token_by_value(packet: bytes, values, tokens=None) -> TextToken | None:
    """Locate the first token whose bytes equal one of ``values``.

    ``values`` is an iterable of ``bytes`` (callers convert hex/str values
    via ``bytes.fromhex``/``.encode``). Used to resolve a
    ``{"locate": "match_dictionary"}`` selector: the value set is supplied by
    the LLM (enum ``possible_values``), so this locates a field by its
    LLM-inferred content — no protocol-specific knowledge involved.
    """
    toks = tokens if tokens is not None else tokenize_text(packet)
    value_set = {v if isinstance(v, bytes) else bytes(v) for v in values}
    for t in toks:
        if packet[t.start:t.end] in value_set:
            return t
    return None


def token_at(tokens: List[TextToken], line_idx: int, token_idx: int) -> TextToken | None:
    """Locate a token by (line, token) index. None if absent."""
    for t in tokens:
        if t.line_idx == line_idx and t.token_idx == token_idx:
            return t
    return None
