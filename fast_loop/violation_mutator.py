"""
fast_loop/violation_mutator.py
──────────────────────────────
FlatFieldViolationMutator — SemFuzz-style structural-violation engine.

Applies the three atomic actions defined in the paper (Sun et al., 2026,
§3.5.1): ``add``, ``remove``, ``update`` — NO ``reorder`` (the paper does not
define it, and a byte-range swap is fragile on flat field models). It operates
on a flat ``FieldRule`` list (offset/length), not a tree: LIFA-Fuzz has no
field hierarchy, so this is the faithful flat adaptation.

Text protocol support (addition to the paper):
  Fields with ``text_selector`` set carry no fixed byte offsets. Their byte
  span is resolved at runtime by the generic tokenizer. The mutator first
  tries ``_resolve_text_target()`` — if the field has a ``text_selector``,
  resolve the token to a concrete (offset, length) BEFORE applying the action.
  This enables ADD/REMOVE/UPDATE on text/line protocol tokens without
  hardcoding any protocol-specific knowledge.

Faithfulness to the paper (§3.5.2 message-mutation engine):
  - Actions are deterministic byte-range ops; the LLM only emits high-level
    intent (Phase 2), never raw bytes here.
  - After ``add``/``remove`` change the packet size, the engine RECOMPUTES the
    dependent length field so the packet stays syntactically valid — exactly
    the paper's "if an extension is inserted, the engine computes and updates
    extension_len". A structurally-valid violation reaches the server's deep
    parser logic instead of being rejected at a length check.
  - For text fields with ``text_selector``: ADD inserts a complete token line
    (value + CRLF), REMOVE deletes the token span, UPDATE replaces in-place.

This module has NO protocol knowledge and NO LIFA-specific hardcoding.
"""
from __future__ import annotations

from typing import Any, Optional

from shared.schemas import ViolationAction, ViolationStrategy


_CRLF = b"\r\n"


def _resolve_offset(buf_len: int, offset: int) -> int:
    """Resolve a possibly-negative (relative-to-end) offset to an absolute one.

    SemFuzz-style strategies may target the tail of a message (e.g. FTP CRLF
    at offset -2). A negative offset counts from the end of the buffer.
    """
    if offset < 0:
        off = buf_len + offset
        return max(0, off)
    return min(offset, buf_len)


def _coerce_value(value: Optional[str], default: bytes = b"\x00") -> bytes:
    """Hex string → bytes, with a default for ADD (single NUL)."""
    if value is None:
        return default
    try:
        return bytes.fromhex(value)
    except (ValueError, TypeError):
        return default


class FlatFieldViolationMutator:
    """Deterministic structural-violation engine over a flat field model.

    Each action returns the mutated ``bytearray``. Callers pass the active
    ``fields`` (FieldRule list) so length fields can be recomputed after any
    size change.
    """

    def __init__(self, fields: Optional[list] = None) -> None:
        self._fields = fields or []

    # ── Text protocol helpers ─────────────────────────────────────────────

    def _find_field_by_name(self, name: str) -> Optional[Any]:
        """Find a FieldRule by field_name."""
        if not name or not self._fields:
            return None
        for f in self._fields:
            if getattr(f, "field_name", "") == name:
                return f
        return None

    def _resolve_text_span(self, field: Any, buf: bytearray) -> Optional[tuple[int, int]]:
        """Resolve a text_selector field to a concrete (start, length) byte span.

        Returns None if the selector cannot be resolved (token absent
        in this particular packet — a no-op is the correct behaviour).
        """
        sel = getattr(field, "text_selector", None)
        if not sel:
            return None

        from shared.text_tokenizer import find_token_by_value, tokenize_text

        packet = bytes(buf)
        tokens = tokenize_text(packet)

        if "nth_token" in sel:
            idx = int(sel["nth_token"])
            if 0 <= idx < len(tokens):
                t = tokens[idx]
                return (t.start, t.end - t.start)

        if sel.get("locate") == "match_dictionary":
            values = []
            for hv in (getattr(field, "dictionary_values", None) or []):
                try:
                    values.append(bytes.fromhex(hv))
                except (ValueError, TypeError):
                    values.append(hv.encode("utf-8", errors="ignore"))
            tok = find_token_by_value(packet, values, tokens)
            if tok is not None:
                return (tok.start, tok.end - tok.start)

        return None

    def _resolve_target(
        self, strategy: ViolationStrategy, buf: Optional[bytearray] = None
    ) -> tuple[int, int]:
        """Resolve a strategy's target to (offset, length).

        Preference order:
          1. Text field: if ``target_field`` has ``text_selector``, resolve
             token span via the generic tokenizer.
          2. Offset field: ``target_field`` name → FieldRule offset/length.
          3. Explicit ``target_offset`` / ``target_length`` (fallback).

        Returns (offset, length). length=-1 means "to end of buffer".
        """
        name = (strategy.target_field or "").strip()
        if name and self._fields:
            field = self._find_field_by_name(name)
            if field is not None:
                # Try text_selector resolution first
                if buf is not None:
                    span = self._resolve_text_span(field, buf)
                    if span is not None:
                        return span
                # Fall back to offset/length
                off = getattr(field, "offset", 0)
                flen = getattr(field, "length", 0)
                return off, flen
        return strategy.target_offset, strategy.target_length

    # ── Atomic actions ───────────────────────────────────────────────────

    def add(self, buf: bytearray, offset: int, value: Optional[bytes]) -> bytearray:
        """Insert bytes at offset (relative-to-end allowed). Recompute length.

        For text fields, ``value`` is inserted as a complete token line.
        If the buffer ends with CRLF, the new value is inserted before the
        trailing CRLF so the packet stays as a valid sequence of lines.
        """
        v = value if value is not None else b"\x00"
        off = _resolve_offset(len(buf), offset)

        # Text-friendly ADD: if inserting near end and buffer has CRLF,
        # insert just before the trailing CRLF to keep line framing valid.
        if off >= len(buf) - 2 and buf[-2:] == _CRLF:
            off = len(buf) - 2
            # Ensure the inserted value itself ends with CRLF
            if not v.endswith(_CRLF):
                v = v + _CRLF

        buf[off:off] = v
        self._recompute_length(buf)
        return buf

    def remove(self, buf: bytearray, offset: int, length: int) -> bytearray:
        """Delete [offset, offset+length) bytes. Recompute length.

        For text tokens, if the removed span includes a trailing CRLF,
        extend the removal to include it (avoids orphan CRLF artifacts
        that would create empty lines in the packet).
        """
        off = _resolve_offset(len(buf), offset)

        # Extend removal to include trailing CRLF if present
        end = off + max(0, length)
        if end + 2 <= len(buf) and buf[end:end + 2] == _CRLF:
            end += 2

        end = min(end, len(buf))
        del buf[off:end]
        self._recompute_length(buf)
        return buf

    def update(self, buf: bytearray, offset: int, value: bytes) -> bytearray:
        """Overwrite bytes at offset in place (no size change, no recompute).

        If the new value is shorter than the target span, the remainder
        is left as-is. If longer, only the first ``span_len`` bytes are
        written (preserves buffer length for multi-field safety).
        """
        if not value:
            return buf
        off = _resolve_offset(len(buf), offset)
        end = min(off + len(value), len(buf))
        buf[off:end] = value[: end - off]
        return buf

    def _recompute_length(self, buf: bytearray) -> None:
        """Recompute length field(s) after a size change (paper §3.5.2).

        Delegated to ``mutator._recompute_length_fields`` which identifies the
        length field structurally. Imported lazily to avoid a circular import
        (mutator imports operators/schemas, not this module at module load).
        """
        if not self._fields:
            return
        try:
            from fast_loop.mutator import _recompute_length_fields

            _recompute_length_fields(buf, self._fields)
        except Exception:
            pass

    # ── Execute ──────────────────────────────────────────────────────────

    def execute(self, buf: bytearray, strategy: ViolationStrategy) -> bytearray:
        """Dispatch a ViolationStrategy to its atomic action.

        Resolves the target byte span (supporting both offset-based and
        text_selector-based fields), then applies the action.
        """
        offset, length = self._resolve_target(strategy, buf=buf)

        if strategy.action == ViolationAction.ADD:
            return self.add(
                buf, offset,
                _coerce_value(strategy.insert_value, default=b"\x00"),
            )
        if strategy.action == ViolationAction.REMOVE:
            return self.remove(buf, offset, length)
        if strategy.action == ViolationAction.UPDATE:
            return self.update(
                buf, offset,
                _coerce_value(strategy.insert_value, default=b"\x00"),
            )
        return buf
