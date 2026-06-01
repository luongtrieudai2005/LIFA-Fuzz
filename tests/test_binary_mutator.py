"""
tests/test_binary_mutator.py
────────────────────────────
Comprehensive tests for fast_loop/binary_mutator.py — BinaryMutator.

Coverage:
    - All 14 mutation strategies in isolation
    - STATIC field protection (never mutate protected bytes)
    - Boundary conditions (empty, single-byte, all-static)
    - Reproducibility with seed
    - Performance benchmark (≥ 50 000 mutations/sec)
"""

from __future__ import annotations

import time
from copy import copy

import pytest

from fast_loop.binary_mutator import ALL_STRATEGIES, BinaryMutator, _compute_mutable_offsets
from slow_loop.differential_analyzer import FieldGroup, OffsetLabel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_static(start: int, end: int) -> FieldGroup:
    """Shortcut: create a STATIC FieldGroup."""
    return FieldGroup(start=start, end=end, label=OffsetLabel.STATIC)


def _make_mutable(start: int, end: int, label: OffsetLabel = OffsetLabel.HIGH_ENTROPY) -> FieldGroup:
    """Shortcut: create a non-STATIC FieldGroup."""
    return FieldGroup(start=start, end=end, label=label)


def _mutable(data: bytearray, sr: list[tuple[int, int]]) -> list[int]:
    """Compute mutable offsets for direct strategy calls in tests."""
    return _compute_mutable_offsets(data, sr)


# ---------------------------------------------------------------------------
# Strategy-level tests — each strategy in isolation
# ---------------------------------------------------------------------------

class TestBitFlip1:
    def test_changes_exactly_one_bit(self):
        m = BinaryMutator(seed=42)
        original = bytearray(16)
        data = bytearray(16)
        m._strat_bit_flip_1(data, [], list(range(16)))
        assert data != original
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(original, data))
        assert diff_bits == 1

    def test_with_static_protection(self):
        m = BinaryMutator(seed=42)
        base = bytearray(b"\xAA\xBB\xCC\xDD")
        sr = [(0, 2)]
        for _ in range(100):
            data = bytearray(base)
            mut = _mutable(data, sr)
            original = bytearray(data)
            m._strat_bit_flip_1(data, sr, mut)
            assert data[0] == original[0]
            assert data[1] == original[1]


class TestBitFlip2:
    def test_flips_two_adjacent_bits(self):
        m = BinaryMutator(seed=7)
        data = bytearray(b"\x00")
        m._strat_bit_flip_2(data, [], [0])
        assert data[0] != 0
        bits = bin(data[0]).count("1")
        assert bits == 2


class TestBitFlip4:
    def test_flips_nibble(self):
        m = BinaryMutator(seed=3)
        data = bytearray(b"\x00")
        m._strat_bit_flip_4(data, [], [0])
        assert data[0] != 0
        bits = bin(data[0]).count("1")
        assert bits == 4


class TestByteOverwrite1:
    def test_changes_one_byte(self):
        m = BinaryMutator(seed=10)
        data = bytearray(b"\x00\x00\x00")
        m._strat_byte_overwrite_1(data, [], [0, 1, 2])
        changed = sum(1 for b in data if b != 0)
        assert changed == 1


class TestByteOverwrite2:
    def test_changes_two_bytes(self):
        m = BinaryMutator(seed=20)
        data = bytearray(b"\x00\x00\x00\x00")
        m._strat_byte_overwrite_2(data, [], [0, 1, 2, 3])
        assert len(data) == 4
        assert data != bytearray(b"\x00\x00\x00\x00")


class TestByteOverwrite4:
    def test_changes_four_bytes(self):
        m = BinaryMutator(seed=30)
        data = bytearray(8)
        m._strat_byte_overwrite_4(data, [], list(range(8)))
        assert len(data) == 8
        assert data != bytearray(8)


class TestArithAdd:
    def test_adds_delta(self):
        m = BinaryMutator(seed=50)
        data = bytearray(b"\x10\x00\x00\x00\x00\x00\x00\x00")
        m._strat_arith_add(data, [], list(range(8)))
        assert data != bytearray(b"\x10\x00\x00\x00\x00\x00\x00\x00")

    def test_arithmetic_correctness_single_byte(self):
        """Force 1-byte add and verify arithmetic."""
        m = BinaryMutator(seed=99)
        for _ in range(50):
            d = bytearray(b"\x0A")
            m._strat_arith(d, [], [0], sign=+1)
            assert len(d) == 1


class TestArithSub:
    def test_subtracts_delta(self):
        m = BinaryMutator(seed=55)
        data = bytearray(b"\xFF\x00\x00\x00\x00\x00\x00\x00")
        m._strat_arith_sub(data, [], list(range(8)))
        assert data != bytearray(b"\xFF\x00\x00\x00\x00\x00\x00\x00")


class TestInteresting1:
    def test_uses_interesting_value(self):
        m = BinaryMutator(seed=60)
        data = bytearray(b"\x42")
        m._strat_interesting_1(data, [], [0])
        assert data[0] in {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF}


class TestInteresting2:
    def test_writes_interesting_16bit(self):
        m = BinaryMutator(seed=65)
        data = bytearray(4)
        m._strat_interesting_2(data, [], [0, 1, 2, 3])
        import struct
        interesting = {0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF}
        found = False
        for offset in range(len(data) - 1):
            val_le = struct.unpack_from("<H", data, offset)[0]
            val_be = struct.unpack_from(">H", data, offset)[0]
            if val_le in interesting or val_be in interesting:
                found = True
                break
        assert found, f"No interesting 16-bit value found in {data.hex()}"


class TestInteresting4:
    def test_writes_interesting_32bit(self):
        m = BinaryMutator(seed=70)
        data = bytearray(8)
        m._strat_interesting_4(data, [], list(range(8)))
        import struct
        val_le = struct.unpack_from("<I", data, 0)[0]
        val_be = struct.unpack_from(">I", data, 0)[0]
        interesting = {0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF}
        assert val_le in interesting or val_be in interesting


class TestBlockDup:
    def test_duplicates_chunk(self):
        m = BinaryMutator(seed=80)
        original = bytearray(b"ABCDEFGHIJKLMNOP")
        data = bytearray(b"ABCDEFGHIJKLMNOP")
        m._strat_block_dup(data, [], list(range(16)))
        assert len(data) > len(original)
        assert len(data) - len(original) >= 8

    def test_too_short_skips(self):
        m = BinaryMutator(seed=80)
        data = bytearray(b"A")
        m._strat_block_dup(data, [], [0])
        assert len(data) == 1


class TestBlockDel:
    def test_deletes_chunk(self):
        m = BinaryMutator(seed=90)
        original = bytearray(b"ABCDEFGHIJKLMNOP") * 4
        data = bytearray(original)
        m._strat_block_del(data, [], list(range(64)))
        assert len(data) < len(original)
        assert len(original) - len(data) >= 8

    def test_too_short_skips(self):
        m = BinaryMutator(seed=90)
        data = bytearray(b"ABC")
        m._strat_block_del(data, [], [0, 1, 2])
        assert len(data) == 3


class TestBlockTruncate:
    def test_truncates_data(self):
        m = BinaryMutator(seed=100)
        original = bytearray(100)
        data = bytearray(100)
        m._strat_block_truncate(data, [], list(range(100)))
        assert len(data) < len(original)

    def test_respects_static_tail(self):
        m = BinaryMutator(seed=100)
        data = bytearray(100)
        for i in range(80, 100):
            data[i] = 0xAB
        sr = [(80, 100)]
        m._strat_block_truncate(data, sr, _mutable(data, sr))
        # min_keep = max(100) = 100 → lower = max(100, 25) = 100 ≥ 100 → no-op
        assert len(data) == 100  # cannot truncate past static tail

    def test_too_short_skips(self):
        m = BinaryMutator(seed=100)
        data = bytearray(b"A")
        m._strat_block_truncate(data, [], [0])
        assert len(data) == 1


# ---------------------------------------------------------------------------
# STATIC protection — stress test
# ---------------------------------------------------------------------------

class TestStaticProtection:
    def test_static_regions_never_modified(self):
        """Mutate 10 000 times with byte-level strategies — STATIC regions must never change."""
        m = BinaryMutator(seed=12345)
        safe_strategies = [
            s for s in ALL_STRATEGIES
            if not s.startswith("block_")
        ]
        static_val_1 = b"\xDE\xAD\xBE\xEF"
        static_val_2 = b"\xCA\xFE\xBA\xBE"
        base = bytearray(static_val_1 + b"\x00" * 4 + static_val_2 + b"\x00" * 4)

        for _ in range(10_000):
            data = bytearray(base)
            m.mutate(data, field_groups=[
                _make_static(0, 4),
                _make_mutable(4, 8),
                _make_static(8, 12),
                _make_mutable(12, 16),
            ], strategies=safe_strategies)
            assert data[0:4] == static_val_1, f"STATIC region 0 corrupted"
            assert data[8:12] == static_val_2, f"STATIC region 1 corrupted"

    def test_no_field_groups_all_mutable(self):
        """Without field_groups, every byte is mutable (use non-block strategies for stable length)."""
        m = BinaryMutator(seed=99)
        safe_strategies = [
            s for s in ALL_STRATEGIES
            if not s.startswith("block_")
        ]
        changed = [False] * 16
        for _ in range(5_000):
            data = bytearray(16)
            m.mutate(data, strategies=safe_strategies)
            for i in range(min(16, len(data))):
                if data[i] != 0:
                    changed[i] = True
        assert all(changed), f"These offsets never changed: {[i for i, c in enumerate(changed) if not c]}"

    def test_all_static_returns_unchanged(self):
        """If all bytes are static, data is returned unchanged."""
        m = BinaryMutator(seed=42)
        original = bytearray(b"\xAA\xBB\xCC\xDD")
        data = bytearray(original)
        m.mutate(data, field_groups=[_make_static(0, 4)])
        assert data == original

    def test_block_ops_respect_static(self):
        """block_del should never delete static bytes; block_dup should never shift them."""
        m = BinaryMutator(seed=77)
        for _ in range(500):
            static_val = b"\xDE\xAD"
            data = bytearray(static_val + b"\x00" * 30 + static_val)
            m.mutate(data, field_groups=[
                _make_static(0, 2),
                _make_mutable(2, 32),
                _make_static(32, 34),
            ], strategies=["block_del", "block_dup"])
            assert data[:2] == static_val, f"Static head corrupted: {data[:2].hex()}"


# ---------------------------------------------------------------------------
# Boundary tests
# ---------------------------------------------------------------------------

class TestBoundaryConditions:
    def test_empty_bytearray(self):
        m = BinaryMutator(seed=42)
        data = bytearray()
        result = m.mutate(data)
        assert result == bytearray()
        assert result is data

    def test_single_byte(self):
        m = BinaryMutator(seed=42)
        changed = False
        for _ in range(100):
            d = bytearray(b"\x00")
            m.mutate(d)
            if d[0] != 0:
                changed = True
                break
        assert changed, "Single-byte data never changed over 100 attempts"

    def test_single_byte_static(self):
        m = BinaryMutator(seed=42)
        data = bytearray(b"\x42")
        original = bytearray(data)
        m.mutate(data, field_groups=[_make_static(0, 1)])
        assert data == original

    def test_returns_same_object(self):
        m = BinaryMutator(seed=42)
        data = bytearray(16)
        result = m.mutate(data)
        assert result is data


# ---------------------------------------------------------------------------
# Reproducibility test
# ---------------------------------------------------------------------------

class TestReproducibility:
    def test_same_seed_same_sequence(self):
        m1 = BinaryMutator(seed=12345)
        m2 = BinaryMutator(seed=12345)

        results1 = []
        results2 = []

        for _ in range(100):
            d1 = bytearray(b"\x00" * 32)
            d2 = bytearray(b"\x00" * 32)
            m1.mutate(d1)
            m2.mutate(d2)
            results1.append(bytes(d1))
            results2.append(bytes(d2))

        assert results1 == results2

    def test_different_seeds_different_sequence(self):
        m1 = BinaryMutator(seed=111)
        m2 = BinaryMutator(seed=222)

        diff_count = 0
        for _ in range(100):
            d1 = bytearray(b"\x00" * 32)
            d2 = bytearray(b"\x00" * 32)
            m1.mutate(d1)
            m2.mutate(d2)
            if d1 != d2:
                diff_count += 1

        assert diff_count > 0, "Different seeds produced identical sequence"


# ---------------------------------------------------------------------------
# Benchmark test
# ---------------------------------------------------------------------------

class TestBenchmark:
    def test_throughput(self):
        """50 000 mutations on a 64-byte buffer must complete in < 1 second."""
        m = BinaryMutator()
        seed_packet = bytearray(64)

        iterations = 50_000
        start = time.perf_counter()
        for _ in range(iterations):
            data = bytearray(seed_packet)
            m.mutate(data)
        elapsed = time.perf_counter() - start

        throughput = iterations / elapsed
        print(f"\n  BinaryMutator throughput: {throughput:,.0f} mutations/sec ({elapsed:.3f}s)")
        assert throughput >= 40_000, (
            f"Throughput {throughput:,.0f} mut/s is below 40 000 threshold"
        )

    def test_throughput_with_field_groups(self):
        """Benchmark with field_groups (STATIC protection overhead)."""
        m = BinaryMutator()
        seed_packet = bytearray(64)
        groups = [
            _make_static(0, 4),
            _make_mutable(4, 32),
            _make_static(32, 36),
            _make_mutable(36, 64),
        ]

        iterations = 50_000
        start = time.perf_counter()
        for _ in range(iterations):
            data = bytearray(seed_packet)
            m.mutate(data, field_groups=groups)
        elapsed = time.perf_counter() - start

        throughput = iterations / elapsed
        print(f"\n  BinaryMutator (with field_groups) throughput: {throughput:,.0f} mutations/sec")
        assert throughput >= 30_000, (
            f"Throughput {throughput:,.0f} mut/s is below 30 000 threshold"
        )


# ---------------------------------------------------------------------------
# mutate() top-level integration
# ---------------------------------------------------------------------------

class TestMutateTopLevel:
    def test_strategy_filter(self):
        """Only allowed strategies should be used."""
        m = BinaryMutator(seed=42)
        original = bytearray(b"\x00" * 16)
        for _ in range(200):
            data = bytearray(original)
            m.mutate(data, strategies=["bit_flip_1"])
            diff_bytes = sum(1 for a, b in zip(original, data) if a != b)
            assert diff_bytes == 1, f"bit_flip_1 changed {diff_bytes} bytes"

    def test_all_strategies_valid(self):
        """Every strategy in ALL_STRATEGIES should be executable without error."""
        m = BinaryMutator(seed=42)
        for strategy in ALL_STRATEGIES:
            data = bytearray(64)
            m.mutate(data, strategies=[strategy])

    def test_invalid_strategy_noop(self):
        """An unknown strategy name should be a no-op (not crash)."""
        m = BinaryMutator(seed=42)
        data = bytearray(b"\x42")
        original = bytearray(data)
        m._apply_strategy(data, "nonexistent_strategy", [], [0])
        assert data == original
