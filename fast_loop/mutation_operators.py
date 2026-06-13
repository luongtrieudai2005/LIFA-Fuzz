"""
fast_loop/mutation_operators.py
─────────────────────────────────
Binary Mutation Arsenal — concrete byte-level mutation operators.

Each operator is a pure function that takes a ``bytearray`` and mutation
parameters, applies a specific binary transformation, and returns the
modified ``bytearray``.  All operators are OOB-safe: if the LLM
hallucinates an offset beyond the current packet length, the buffer is
zero-padded rather than raising ``IndexError``.

Operator Catalogue:
    1. op_buffer_overflow      — inject massive payloads (1 000–10 000 bytes)
    2. op_integer_overflow     — critical boundary values (0xFF, 0xFFFF, …)
    3. op_bit_flip             — XOR / random bitwise flips (1–3 bits)
    4. op_boundary_violation   — read existing value, mutate mathematically
    5. op_format_string        — inject C-style format-string payloads
    6. op_omission             — truncate packet at / near target offset
    7. op_random_byte_injection— inject purely random junk bytes

Design Principles:
    - **In-place mutation** — operators modify the passed ``bytearray``
      directly (no deep copies) for maximum throughput.
    - **OOB safety** — every operator calls ``safe_slice()`` first,
      which extends the buffer with zero-padding if offsets exceed length.
    - **Composability** — operators are pure functions; the dispatch
      logic lives in ``MutationEngine.apply_rule()``.

Usage:
    from fast_loop.mutation_operators import (
        safe_slice,
        op_buffer_overflow,
        op_integer_overflow,
        op_bit_flip,
        op_boundary_violation,
        op_format_string,
        op_omission,
        op_random_byte_injection,
    )
"""

from __future__ import annotations

import os
import random
import struct
from typing import Optional

from shared.schemas import FieldType, MutationConstraints

# =============================================================================
# OOB Safety Helper
# =============================================================================


def safe_slice(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
) -> bytearray:
    """Ensure *buf* has room for ``[offset_start : offset_end]``.

    If either offset is beyond the current length, the buffer is extended
    with zero-filled bytes so that subsequent ``buf[i]`` accesses are
    safe.  Returns *buf* for chaining.

    Args:
        buf:          The packet buffer to potentially extend.
        offset_start: Inclusive start index.
        offset_end:   Exclusive end index.

    Returns:
        The same *buf* (possibly extended).
    """
    needed = max(offset_start, offset_end)
    if needed > len(buf):
        buf.extend(b"\x00" * (needed - len(buf)))
    return buf


# =============================================================================
# Encoding Helpers (shared across operators)
# =============================================================================

# FieldType → (struct format, byte size)
_FMT_MAP: dict[FieldType, tuple[str, int]] = {
    FieldType.UINT8:     ("B", 1),
    FieldType.UINT16_LE: ("<H", 2),
    FieldType.UINT16_BE: (">H", 2),
    FieldType.UINT32_LE: ("<I", 4),
    FieldType.UINT32_BE: (">I", 4),
    FieldType.INT8:      ("b", 1),
    FieldType.INT16_LE:  ("<h", 2),
    FieldType.INT16_BE:  (">h", 2),
    FieldType.INT32_LE:  ("<i", 4),
    FieldType.INT32_BE:  (">i", 4),
}


def _encode(value: int, field_type: FieldType, field_len: int) -> bytes:
    """Encode an integer according to *field_type* and *field_len*.

    H7 fix: when ``field_len > size`` (e.g. UINT16 annotated on a 4-byte
    region), the upper bytes are padded with zeros so the entire field is
    written.  Previously only ``size`` bytes were encoded, leaving the
    upper bytes untouched (incomplete mutation).
    """
    if field_type in _FMT_MAP:
        fmt, size = _FMT_MAP[field_type]
        # Clamp to struct range to avoid struct.error on overflow
        encoded = struct.pack(fmt, value & ((1 << (size * 8)) - 1))
        if field_len > size:
            # Pad upper bytes with zeros to match the declared field length
            encoded = encoded + b"\x00" * (field_len - size)
        return encoded[:field_len]
    # Fallback for non-numeric types (BYTES, STRING, etc.): big-endian,
    # consistent with _endian_for_type() in mutator.py.
    return (value & ((1 << (field_len * 8)) - 1)).to_bytes(
        field_len, byteorder="big"
    )


def _decode(buf: bytearray, offset: int, field_type: FieldType,
            field_len: int) -> int:
    """Decode an integer from *buf* at *offset* according to *field_type*.

    Returns 0 if the buffer is too short for the requested field (bounds-safe).
    """
    if field_type in _FMT_MAP:
        fmt, size = _FMT_MAP[field_type]
        needed = offset + size
        if needed > len(buf):
            return 0  # Buffer too short — return default
        return struct.unpack(fmt, bytes(buf[offset : needed]))[0]
    # Fallback for non-numeric types: big-endian, consistent with _encode.
    needed = offset + field_len
    if needed > len(buf):
        return 0  # Buffer too short — return default
    return int.from_bytes(
        bytes(buf[offset : needed]), byteorder="big"
    )


def _field_len_from_type(field_type: FieldType, fallback: int = 4) -> int:
    """Return byte width for a known numeric FieldType, else *fallback*."""
    if field_type in _FMT_MAP:
        return _FMT_MAP[field_type][1]
    return fallback


# =============================================================================
# Operator 1: Buffer Overflow
# =============================================================================


def op_buffer_overflow(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Inject a massive payload (1 000–10 000 bytes) at *offset_start*.

    The payload is either ``0x41`` ('A') or random bytes, chosen randomly.
    This replaces the field region ``[offset_start:offset_end]`` and
    expands the packet dramatically — the classic buffer-overflow test.

    Returns:
        Modified *buf* (likely much larger than input).
    """
    buf = safe_slice(buf, offset_start, max(offset_end, offset_start + 1))
    size = random.randint(1000, 10000)

    if random.random() < 0.5:
        payload = bytearray(b"\x41" * size)  # 'A' flood
    else:
        payload = bytearray(os.urandom(size))

    buf[offset_start:offset_end] = payload
    return buf


# =============================================================================
# Operator 2: Integer Overflow
# =============================================================================


# Critical boundary values keyed by byte-width
_INT_OVERFLOW_TABLE: dict[int, list[int]] = {
    1: [0x00, 0xFF],
    2: [0x0000, 0xFFFF, 0x7FFF, 0x8000],
    4: [0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000],
}


def op_integer_overflow(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Replace the integer at *offset_start* with a critical boundary value.

    Chooses from a table of well-known overflow triggers (0x00, MAX,
    MAX-1, SIGN_BIT, etc.) based on the field's byte width.  The value
    is encoded with the correct endianness from *field_type*.

    Returns:
        Modified *buf* (same length).
    """
    buf = safe_slice(buf, offset_start, offset_end)
    flen = offset_end - offset_start
    key = flen if flen in _INT_OVERFLOW_TABLE else 4
    value = random.choice(_INT_OVERFLOW_TABLE[key])
    encoded = _encode(value, field_type, flen)
    buf[offset_start : offset_start + len(encoded)] = encoded
    return buf


# =============================================================================
# Operator 3: Bit Flip
# =============================================================================


def op_bit_flip(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Flip 1–3 random bits within ``[offset_start : offset_end]``.

    Returns:
        Modified *buf* (same length).
    """
    buf = safe_slice(buf, offset_start, offset_end)
    span = offset_end - offset_start
    if span <= 0:
        return buf

    n_flips = random.randint(1, min(3, span * 8))
    for _ in range(n_flips):
        byte_idx = offset_start + random.randint(0, span - 1)
        bit_idx = random.randint(0, 7)
        buf[byte_idx] ^= 1 << bit_idx

    return buf


# =============================================================================
# Operator 4: Boundary Violation
# =============================================================================


def op_boundary_violation(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Read the existing integer at *offset_start*, mutate mathematically.

    Applies one of: ``+1``, ``-1``, ``* -1``, ``>> 1``, ``<< 1``.
    The result is encoded with the correct endianness and written back.

    Returns:
        Modified *buf* (same length).
    """
    buf = safe_slice(buf, offset_start, offset_end)
    flen = offset_end - offset_start
    if flen <= 0:
        return buf

    # Decode current value — always use _decode for consistent endianness
    current = _decode(buf, offset_start, field_type, flen)

    # Apply mutation
    mask = (1 << (flen * 8)) - 1
    mutation = random.choice(["inc", "dec", "neg", "shr", "shl"])
    if mutation == "inc":
        current = (current + 1) & mask
    elif mutation == "dec":
        current = (current - 1) & mask
    elif mutation == "neg":
        current = (current * -1) & mask
    elif mutation == "shr":
        current = (current >> 1) & mask
    else:  # shl
        current = (current << 1) & mask

    encoded = _encode(current, field_type, flen)
    buf[offset_start : offset_start + len(encoded)] = encoded
    return buf


# =============================================================================
# Operator 5: Format String
# =============================================================================


_FORMAT_STRING_PAYLOADS: list[bytes] = [
    b"%s%s%s%s%n",
    b"%x%x%x%x%x",
    b"%p%p%p%p",
    b"%n%d%s%p",
    b"%s" * 50,
    b"AAAA%p%p%p%p%p%p%p%p%p%p",
    b"%08x.%08x.%08x.%08x",
    b"%%%dc%%%d$s%%%d$n",
    b"%n" * 20,
]


def op_format_string(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Inject a C-style format-string payload at *offset_start*.

    Replaces the field region with a randomly chosen format-string
    pattern (e.g., ``%s%s%s%n``, ``%x%x%x%x``, long ``%s`` chains).

    Returns:
        Modified *buf* (may grow or shrink).
    """
    buf = safe_slice(buf, offset_start, max(offset_end, offset_start + 1))
    payload = random.choice(_FORMAT_STRING_PAYLOADS)
    buf[offset_start:offset_end] = payload
    return buf


# =============================================================================
# Operator 6: Omission (Truncation)
# =============================================================================


def op_omission(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Truncate the packet at or shortly after *offset_start*.

    The cut point is ``offset_start + random(0, 4)`` to test both
    exact truncation and off-by-a-few-bytes scenarios.

    Returns:
        Modified *buf* (shorter than input).
    """
    buf = safe_slice(buf, offset_start, offset_end)
    cut = offset_start + random.randint(0, 4)
    # Trim in-place
    del buf[cut:]
    return buf


# =============================================================================
# Operator 7: Random Byte Injection
# =============================================================================


def op_random_byte_injection(
    buf: bytearray,
    offset_start: int,
    offset_end: int,
    field_type: FieldType,
    constraints: MutationConstraints,
) -> bytearray:
    """Replace the field region with random bytes, or inject extra junk.

    Two modes (chosen randomly):
      - **Replace** — overwrite ``[offset_start:offset_end]`` with
        ``os.urandom(field_length)``.
      - **Inject** — insert 8–64 random bytes at *offset_start*,
        growing the packet.

    Returns:
        Modified *buf* (may be longer).
    """
    buf = safe_slice(buf, offset_start, max(offset_end, offset_start + 1))
    field_len = offset_end - offset_start

    if random.random() < 0.6 or field_len <= 0:
        # Inject mode — insert extra bytes
        inject_len = random.randint(8, 64)
        payload = bytearray(os.urandom(inject_len))
        # Insert at offset_start (shifts everything right)
        buf[offset_start:offset_start] = payload
    else:
        # Replace mode
        payload = bytearray(os.urandom(field_len))
        buf[offset_start:offset_end] = payload

    return buf
