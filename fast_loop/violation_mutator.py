"""
fast_loop/violation_mutator.py
──────────────────────────────
FlatFieldViolationMutator — SemFuzz-style structural-violation engine.

Applies the three atomic actions defined in the paper (Sun et al., 2026,
§3.5.1): ``add``, ``remove``, ``update`` — NO ``reorder`` (the paper does not
define it, and a byte-range swap is fragile on flat field models). It operates
on a flat ``FieldRule`` list (offset/length), not a tree: LIFA-Fuzz has no
field hierarchy, so this is the faithful flat adaptation.

Faithfulness to the paper (§3.5.2 message-mutation engine):
  - Actions are deterministic byte-range ops; the LLM only emits high-level
    intent (Phase 2), never raw bytes here.
  - After ``add``/``remove`` change the packet size, the engine RECOMPUTES the
    dependent length field so the packet stays syntactically valid — exactly
    the paper's "if an extension is inserted, the engine computes and updates
    extension_len". A structurally-valid violation reaches the server's deep
    parser logic instead of being rejected at a length check. The length
    recompute is delegated to ``mutator._recompute_length_fields``, identified
    structurally (no protocol-specific offset/label).

This module has NO protocol knowledge and NO LIFA-specific hardcoding.
"""
from __future__ import annotations

from typing import Any, Optional

from shared.schemas import ViolationAction, ViolationStrategy


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

    def add(self, buf: bytearray, offset: int, value: Optional[bytes]) -> bytearray:
        """Insert bytes at offset (relative-to-end allowed). Recompute length."""
        v = value if value is not None else b"\x00"
        off = _resolve_offset(len(buf), offset)
        buf[off:off] = v
        self._recompute_length(buf)
        return buf

    def remove(self, buf: bytearray, offset: int, length: int) -> bytearray:
        """Delete [offset, offset+length) bytes. Recompute length."""
        off = _resolve_offset(len(buf), offset)
        end = min(off + max(0, length), len(buf))
        del buf[off:end]
        self._recompute_length(buf)
        return buf

    def update(self, buf: bytearray, offset: int, value: bytes) -> bytearray:
        """Overwrite bytes at offset in place (no size change, no recompute)."""
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
            # Length recompute is best-effort; a stale length is itself a
            # valid violation test, never a crash of the engine.
            pass

    def _resolve_target(self, strategy: ViolationStrategy) -> tuple[int, int]:
        """Resolve a strategy's target to (offset, length).

        Preference order (paper §3.5.1: LLM emits high-level field intent, the
        deterministic engine resolves bytes):
          1. ``target_field`` name → FieldRule offset/length (LLM path).
          2. explicit ``target_offset`` (case-study / relative-to-end path).
        Returns (offset, length). length=-1 means "to end of buffer".
        """
        name = (strategy.target_field or "").strip()
        if name and self._fields:
            for f in self._fields:
                fname = getattr(f, "field_name", "") or ""
                if fname and fname == name:
                    off = getattr(f, "offset", 0)
                    flen = getattr(f, "length", 0)
                    return off, flen
        return strategy.target_offset, strategy.target_length

    def execute(self, buf: bytearray, strategy: ViolationStrategy) -> bytearray:
        """Dispatch a ViolationStrategy to its atomic action."""
        offset, length = self._resolve_target(strategy)
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
