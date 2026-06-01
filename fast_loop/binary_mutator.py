"""
fast_loop/binary_mutator.py
───────────────────────────
Low-level, high-throughput binary mutation engine.

Operates on raw ``bytearray`` / ``memoryview`` at microsecond speed.
All mutations are in-place — no copies, no allocations on the hot path.

The ``mutate()`` method accepts an optional list of ``FieldGroup`` objects
from ``differential_analyzer.py``.  Fields labeled ``STATIC`` are never
touched — preserving protocol headers / magic bytes.

Design contract:
    - No async, no networking, no I/O — pure computation on bytearrays.
    - Optional ``seed`` for reproducibility (uses ``random.Random(seed)``).
    - Returns the *same* bytearray (mutated in-place) for chaining.
"""

from __future__ import annotations

import random
import struct
from typing import Optional

from slow_loop.differential_analyzer import FieldGroup, OffsetLabel

# ---------------------------------------------------------------------------
# Interesting constants (borrowed from AFL / libFuzzer heuristics)
# ---------------------------------------------------------------------------
_INTERESTING_1: list[int] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
_INTERESTING_2: list[int] = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
_INTERESTING_4: list[int] = [
    0x00000000, 0x00000001,
    0x7FFFFFFF, 0x80000000,
    0xFFFFFFFE, 0xFFFFFFFF,
]
_ARITH_DELTAS: list[int] = [-1, +1, -2, +2, -16, +16, -128, +128, -32768, +32768]

# All strategy names in stable order
ALL_STRATEGIES: list[str] = [
    "bit_flip_1",
    "bit_flip_2",
    "bit_flip_4",
    "byte_overwrite_1",
    "byte_overwrite_2",
    "byte_overwrite_4",
    "arith_add",
    "arith_sub",
    "interesting_1",
    "interesting_2",
    "interesting_4",
    "block_dup",
    "block_del",
    "block_truncate",
]


class BinaryMutator:
    """Pure byte-level mutation engine for fuzzing.

    Parameters
    ----------
    seed : int | None
        If provided, an isolated RNG is created for reproducibility.
        If ``None``, the system ``random`` module is used (non-deterministic).
    """

    def __init__(self, seed: int | None = None) -> None:
        if seed is not None:
            self._rng: random.Random | random._random.Random = random.Random(seed)
        else:
            self._rng = random

    # ===================================================================
    # Public API
    # ===================================================================

    def mutate(
        self,
        data: bytearray,
        field_groups: list[FieldGroup] | None = None,
        strategies: list[str] | None = None,
    ) -> bytearray:
        """Mutate *data* in-place using a random strategy.

        Parameters
        ----------
        data : bytearray
            The packet buffer. Mutated **in-place** and also returned.
        field_groups : list[FieldGroup] | None
            Optional field layout from DifferentialAnalyzer. ``STATIC``
            regions are never modified.
        strategies : list[str] | None
            Allowlist of strategy names. Defaults to ``ALL_STRATEGIES``.

        Returns
        -------
        bytearray
            The same object passed in (mutated in-place).
        """
        if len(data) == 0:
            return data

        # Pre-compute static ranges and mutable offsets ONCE per call
        sr = _build_static_ranges(field_groups)
        mutable = _compute_mutable_offsets(data, sr)

        if not mutable:
            return data

        allowed = strategies if strategies is not None else ALL_STRATEGIES
        strategy = self._rng.choice(allowed)
        self._apply_strategy(data, strategy, sr, mutable)
        return data

    # ===================================================================
    # Strategy dispatch
    # ===================================================================

    def _apply_strategy(
        self,
        data: bytearray,
        strategy: str,
        sr: list[tuple[int, int]],
        mutable: list[int],
    ) -> None:
        """Dispatch to the correct strategy implementation."""
        dispatch = {
            "bit_flip_1":       self._strat_bit_flip_1,
            "bit_flip_2":       self._strat_bit_flip_2,
            "bit_flip_4":       self._strat_bit_flip_4,
            "byte_overwrite_1": self._strat_byte_overwrite_1,
            "byte_overwrite_2": self._strat_byte_overwrite_2,
            "byte_overwrite_4": self._strat_byte_overwrite_4,
            "arith_add":        self._strat_arith_add,
            "arith_sub":        self._strat_arith_sub,
            "interesting_1":    self._strat_interesting_1,
            "interesting_2":    self._strat_interesting_2,
            "interesting_4":    self._strat_interesting_4,
            "block_dup":        self._strat_block_dup,
            "block_del":        self._strat_block_del,
            "block_truncate":   self._strat_block_truncate,
        }
        fn = dispatch.get(strategy)
        if fn is not None:
            fn(data, sr, mutable)

    # ===================================================================
    # Internal offset pickers (use pre-computed mutable list)
    # ===================================================================

    def _pick_offset(self, mutable: list[int]) -> int | None:
        """Return a random mutable byte offset, or None."""
        if not mutable:
            return None
        return self._rng.choice(mutable)

    def _pick_range(
        self,
        n: int,
        length: int,
        sr: list[tuple[int, int]],
        mutable: list[int],
    ) -> int | None:
        """Find a random contiguous *length*-byte region that is fully mutable.

        Returns the start offset, or None if no such region exists.
        Uses the pre-computed ``mutable`` set for fast rejection.
        """
        if length > n:
            return None
        if not sr:
            return self._rng.randint(0, n - length)

        mutable_set = set(mutable)
        candidates: list[int] = []
        for start in range(n - length + 1):
            # Check if [start, start+length) is fully mutable
            if all((start + i) in mutable_set for i in range(length)):
                candidates.append(start)

        if not candidates:
            return None
        return self._rng.choice(candidates)

    # ===================================================================
    # Bit-flip strategies
    # ===================================================================

    def _strat_bit_flip_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip exactly 1 random bit in a random mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        bit = self._rng.randint(0, 7)
        data[offset] ^= (1 << bit)

    def _strat_bit_flip_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip 2 adjacent bits in a random mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        start_bit = self._rng.randint(0, 6)  # 0..6 so bit+1 ≤ 7
        data[offset] ^= (0b11 << start_bit)

    def _strat_bit_flip_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Flip a random nibble (4 adjacent bits) in a mutable byte."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        nibble_start = self._rng.choice([0, 4])
        data[offset] ^= (0b1111 << nibble_start)

    # ===================================================================
    # Byte-overwrite strategies
    # ===================================================================

    def _strat_byte_overwrite_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 1 mutable byte with a random value."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        data[offset] = self._rng.randint(0, 255)

    def _strat_byte_overwrite_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 2 mutable bytes with a random 16-bit value (random endian)."""
        start = self._pick_range(len(data), 2, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">H", "<H"])
        val = self._rng.randint(0, 0xFFFF)
        struct.pack_into(fmt, data, start, val)

    def _strat_byte_overwrite_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 4 mutable bytes with a random 32-bit value (random endian)."""
        start = self._pick_range(len(data), 4, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">I", "<I"])
        val = self._rng.randint(0, 0xFFFFFFFF)
        struct.pack_into(fmt, data, start, val)

    # ===================================================================
    # Arithmetic strategies
    # ===================================================================

    def _strat_arith(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int], sign: int) -> None:
        """Shared implementation for add/sub — pick 1/2/4-byte region, add delta."""
        width = self._rng.choice([1, 2, 4])
        start = self._pick_range(len(data), width, sr, mutable)
        if start is None:
            return
        fmt_map = {
            1: ("B", 0xFF),
            2: (self._rng.choice([">H", "<H"]), 0xFFFF),
            4: (self._rng.choice([">I", "<I"]), 0xFFFFFFFF),
        }
        fmt, mask = fmt_map[width]
        current = struct.unpack_from(fmt, data, start)[0]
        delta = self._rng.choice(_ARITH_DELTAS) * sign
        new_val = (current + delta) & mask
        struct.pack_into(fmt, data, start, new_val)

    def _strat_arith_add(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        self._strat_arith(data, sr, mutable, sign=+1)

    def _strat_arith_sub(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        self._strat_arith(data, sr, mutable, sign=-1)

    # ===================================================================
    # Interesting-value strategies
    # ===================================================================

    def _strat_interesting_1(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 1 mutable byte with a known-interesting value."""
        offset = self._pick_offset(mutable)
        if offset is None:
            return
        data[offset] = self._rng.choice(_INTERESTING_1)

    def _strat_interesting_2(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 2 mutable bytes with a known-interesting 16-bit value."""
        start = self._pick_range(len(data), 2, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">H", "<H"])
        val = self._rng.choice(_INTERESTING_2)
        struct.pack_into(fmt, data, start, val)

    def _strat_interesting_4(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Overwrite 4 mutable bytes with a known-interesting 32-bit value."""
        start = self._pick_range(len(data), 4, sr, mutable)
        if start is None:
            return
        fmt = self._rng.choice([">I", "<I"])
        val = self._rng.choice(_INTERESTING_4)
        struct.pack_into(fmt, data, start, val)

    # ===================================================================
    # Block strategies (change data length)
    # ===================================================================

    def _strat_block_dup(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Duplicate a random chunk of 8-64 bytes and insert at a mutable position.

        When static ranges are present, insertion is restricted to positions that
        will **not shift** any static bytes.  This means inserting only at the
        boundary *after* the last static region, or at the very end of the data.
        """
        n = len(data)
        if n < 2:
            return

        chunk_len = self._rng.randint(8, min(64, n))
        src_start = self._rng.randint(0, n - chunk_len)
        chunk = bytes(data[src_start : src_start + chunk_len])

        if sr:
            # Earliest safe insertion point = end of the last static region.
            # Anything before that would shift at least one static byte.
            last_static_end = max(e for _, e in sr)
            if last_static_end >= n:
                return
            insert_at = self._rng.randint(last_static_end, n)
        else:
            insert_at = self._rng.randint(0, n)

        data[insert_at:insert_at] = chunk

    def _strat_block_del(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Delete a random chunk of 8-64 bytes from a mutable region."""
        n = len(data)
        if n < 8:
            return

        chunk_len = self._rng.randint(8, min(64, n))

        # Find a range to delete that doesn't overlap static regions
        start = self._pick_range(n, chunk_len, sr, mutable)
        if start is None:
            return
        del data[start : start + chunk_len]

    def _strat_block_truncate(self, data: bytearray, sr: list[tuple[int, int]], mutable: list[int]) -> None:
        """Truncate the data to 25%-100% of its original length, preserving all static regions."""
        n = len(data)
        if n < 2:
            return

        # Minimum length = end of the rightmost static region.
        # We must never cut into or past any static bytes.
        min_keep = 0
        if sr:
            min_keep = max(e for _, e in sr)

        lower = max(min_keep, n // 4)
        upper = n

        if lower >= upper:
            return

        new_len = self._rng.randint(lower, upper)
        if new_len < n:
            del data[new_len:]


# ===================================================================
# Module-level helpers (no self — avoid repeated bound-method lookups)
# ===================================================================

def _build_static_ranges(
    field_groups: list[FieldGroup] | None,
) -> list[tuple[int, int]]:
    """Return sorted list of (start, end) ranges that are STATIC."""
    if not field_groups:
        return []
    return sorted(
        (fg.start, fg.end) for fg in field_groups if fg.label == OffsetLabel.STATIC
    )


def _compute_mutable_offsets(
    data: bytearray,
    sr: list[tuple[int, int]],
) -> list[int]:
    """Return all byte offsets that are NOT in a static range.

    Uses an interval-subtraction algorithm instead of per-offset iteration,
    making it O(mutable + static) rather than O(len(data) * num_static).
    """
    n = len(data)
    if not sr:
        return list(range(n))

    # Build mutable intervals by subtracting static ranges from [0, n)
    intervals: list[tuple[int, int]] = []
    cursor = 0
    for s, e in sr:
        if cursor < s:
            intervals.append((cursor, s))
        cursor = max(cursor, e)
    if cursor < n:
        intervals.append((cursor, n))

    # Flatten intervals into a list of offsets
    result: list[int] = []
    for start, end in intervals:
        result.extend(range(start, end))
    return result
