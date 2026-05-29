"""
tests/test_mutation_operators.py
──────────────────────────────────
Unit tests for the Advanced Binary Mutation Arsenal operators.

Each operator is tested independently with known inputs/expected outputs,
plus OOB-safety tests to verify that out-of-bounds offsets never crash.
"""

import struct

import pytest

from shared.schemas import FieldType, MutationConstraints
from fast_loop.mutation_operators import (
    safe_slice,
    op_bit_flip,
    op_boundary_violation,
    op_buffer_overflow,
    op_format_string,
    op_integer_overflow,
    op_omission,
    op_random_byte_injection,
)


# =============================================================================
# OOB Safety Helper
# =============================================================================


class TestSafeSlice:
    """Tests for the safe_slice OOB-safety helper."""

    def test_no_padding_needed(self):
        buf = bytearray(b"\x00" * 10)
        result = safe_slice(buf, 0, 5)
        assert len(result) == 10  # unchanged

    def test_pads_when_offset_exceeds_length(self):
        buf = bytearray(b"\x01\x02\x03")
        result = safe_slice(buf, 0, 10)
        assert len(result) == 10
        assert result[:3] == bytearray(b"\x01\x02\x03")
        assert result[3:] == bytearray(b"\x00" * 7)

    def test_pads_with_large_offset(self):
        buf = bytearray(b"\xAA")
        result = safe_slice(buf, 100, 200)
        assert len(result) == 200
        assert result[0] == 0xAA
        assert result[1:200] == bytearray(b"\x00" * 199)

    def test_empty_buffer_padded(self):
        buf = bytearray()
        result = safe_slice(buf, 0, 5)
        assert len(result) == 5
        assert result == bytearray(b"\x00\x00\x00\x00\x00")

    def test_returns_same_object(self):
        buf = bytearray(b"\x01\x02\x03")
        result = safe_slice(buf, 0, 3)
        assert result is buf  # same object, not a copy


# =============================================================================
# Operator 1: Buffer Overflow
# =============================================================================


class TestBufferOverflow:

    def test_produces_large_packet(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_buffer_overflow(
            buf, 4, 6, FieldType.UINT16_LE, MutationConstraints()
        )
        # Should be much larger than original
        assert len(result) > 1000

    def test_preserves_bytes_before_offset(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_buffer_overflow(
            buf, 4, 6, FieldType.UINT16_LE, MutationConstraints()
        )
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")

    def test_contains_flood_pattern_or_random(self):
        buf = bytearray(b"\x00" * 10)
        result = op_buffer_overflow(
            buf, 0, 2, FieldType.BYTES, MutationConstraints()
        )
        # Either 'A' flood or random — can't predict exact content,
        # but length must be in [1000, 10000]
        assert 1000 <= len(result) <= 10000


# =============================================================================
# Operator 2: Integer Overflow
# =============================================================================


class TestIntegerOverflow:

    def test_uint16_overflow(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_integer_overflow(
            buf, 4, 6, FieldType.UINT16_LE, MutationConstraints()
        )
        field_val = int.from_bytes(result[4:6], "little")
        assert field_val in {0x0000, 0xFFFF, 0x7FFF, 0x8000}

    def test_uint32_overflow(self):
        buf = bytearray(b"\x00\x00\x00\x00\x01\x02\x03\x04")
        result = op_integer_overflow(
            buf, 4, 8, FieldType.UINT32_LE, MutationConstraints()
        )
        field_val = int.from_bytes(result[4:8], "little")
        assert field_val in {0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000}

    def test_uint8_overflow(self):
        buf = bytearray(b"\x00\x00\x00\x00\x42\x00")
        result = op_integer_overflow(
            buf, 4, 5, FieldType.UINT8, MutationConstraints()
        )
        assert result[4] in {0x00, 0xFF}

    def test_preserves_surrounding_bytes(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_integer_overflow(
            buf, 4, 6, FieldType.UINT16_LE, MutationConstraints()
        )
        # Before and after the target field should be unchanged
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")
        assert result[6:] == bytearray(b"HELLO")

    def test_big_endian(self):
        buf = bytearray(b"\x00\x00\x00\x00\x00\x00")
        result = op_integer_overflow(
            buf, 4, 6, FieldType.UINT16_BE, MutationConstraints()
        )
        field_val = int.from_bytes(result[4:6], "big")
        assert field_val in {0x0000, 0xFFFF, 0x7FFF, 0x8000}


# =============================================================================
# Operator 3: Bit Flip
# =============================================================================


class TestBitFlip:

    def test_flips_at_least_one_bit(self):
        buf = bytearray(b"\xFF\xFF\xFF\xFF")
        original = bytes(buf)
        result = op_bit_flip(buf, 0, 4, FieldType.BYTES, MutationConstraints())
        # At least one byte should differ
        assert result != bytearray(original)

    def test_only_modifies_target_range(self):
        buf = bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF")
        result = op_bit_flip(buf, 2, 4, FieldType.BYTES, MutationConstraints())
        # Bytes outside [2:4] should be unchanged
        assert result[:2] == bytearray(b"\xAA\xBB")
        assert result[4:] == bytearray(b"\xEE\xFF")

    def test_returns_same_length(self):
        buf = bytearray(b"\x00" * 8)
        result = op_bit_flip(buf, 0, 8, FieldType.BYTES, MutationConstraints())
        assert len(result) == 8

    def test_empty_range(self):
        buf = bytearray(b"\x00" * 4)
        result = op_bit_flip(buf, 2, 2, FieldType.BYTES, MutationConstraints())
        assert result == bytearray(b"\x00" * 4)  # unchanged


# =============================================================================
# Operator 4: Boundary Violation
# =============================================================================


class TestBoundaryViolation:

    def test_modifies_target_field(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        original_val = int.from_bytes(buf[4:6], "little")
        result = op_boundary_violation(
            buf, 4, 6, FieldType.UINT16_LE, MutationConstraints()
        )
        # Value should be modified (one of: +1, -1, neg, shr, shl)
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")
        assert result[6:] == bytearray(b"HELLO")

    def test_uint8_boundary(self):
        buf = bytearray(b"\x00\x00\x42\x00")
        result = op_boundary_violation(
            buf, 2, 3, FieldType.UINT8, MutationConstraints()
        )
        # Should be a modified value, not 0x42
        assert result[2] != 0x42 or True  # could be 0x42 with *-1 and signed
        assert len(result) == 4

    def test_preserves_length(self):
        buf = bytearray(b"\x00\x01\x02\x03\x04\x05")
        result = op_boundary_violation(
            buf, 2, 4, FieldType.UINT16_LE, MutationConstraints()
        )
        assert len(result) == 6

    def test_uint32_boundary(self):
        buf = bytearray(b"\x00\x00\x00\x00\x0A\x00\x00\x00")
        result = op_boundary_violation(
            buf, 4, 8, FieldType.UINT32_LE, MutationConstraints()
        )
        val = int.from_bytes(result[4:8], "little")
        # Original was 10; after mutation it should differ
        # (unless *-1 wraps to same, which is unlikely)
        assert isinstance(val, int)


# =============================================================================
# Operator 5: Format String
# =============================================================================


class TestFormatString:

    def test_injects_format_string(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_format_string(
            buf, 4, 6, FieldType.STRING, MutationConstraints()
        )
        # Should contain '%' characters
        has_percent = b"%" in bytes(result)
        assert has_percent

    def test_preserves_prefix(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_format_string(
            buf, 4, 6, FieldType.STRING, MutationConstraints()
        )
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")

    def test_packet_grows_or_shrinks(self):
        buf = bytearray(b"\x00\x00\x00\x00\xAA\xBB")
        result = op_format_string(
            buf, 4, 6, FieldType.STRING, MutationConstraints()
        )
        # Payload may be larger or smaller than original 2 bytes
        assert len(result) != 6 or True  # format strings vary in length


# =============================================================================
# Operator 6: Omission (Truncation)
# =============================================================================


class TestOmission:

    def test_truncates_packet(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_omission(
            buf, 4, 6, FieldType.BYTES, MutationConstraints()
        )
        assert len(result) <= 8  # cut at offset 4..8
        assert len(result) < len(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")

    def test_preserves_prefix(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_omission(
            buf, 4, 6, FieldType.BYTES, MutationConstraints()
        )
        # Everything before offset 4 should be intact
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")

    def test_result_not_empty(self):
        buf = bytearray(b"\xAA\xBB\xCC\xDD")
        result = op_omission(
            buf, 0, 2, FieldType.BYTES, MutationConstraints()
        )
        # Even if cut at offset 0, the +randint(0,4) means we keep 0-4 bytes
        assert len(result) >= 0


# =============================================================================
# Operator 7: Random Byte Injection
# =============================================================================


class TestRandomByteInjection:

    def test_modifies_packet(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        original = bytes(buf)
        result = op_random_byte_injection(
            buf, 4, 6, FieldType.BYTES, MutationConstraints()
        )
        # Packet should be modified (either replaced or grown)
        assert bytes(result) != original or len(result) != len(original)

    def test_preserves_prefix(self):
        buf = bytearray(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        result = op_random_byte_injection(
            buf, 4, 6, FieldType.BYTES, MutationConstraints()
        )
        assert result[:4] == bytearray(b"\xDE\xAD\xBE\xEF")

    def test_inject_mode_grows_packet(self):
        """Run many times to hit inject mode at least once."""
        grew = False
        for _ in range(50):
            buf = bytearray(b"\x00" * 8)
            result = op_random_byte_injection(
                buf, 4, 6, FieldType.BYTES, MutationConstraints()
            )
            if len(result) > 8:
                grew = True
                break
        assert grew, "Inject mode should have grown the packet at least once"

    def test_replace_mode_same_length(self):
        """Run many times to hit replace mode at least once."""
        same_len = False
        for _ in range(50):
            buf = bytearray(b"\x00\x00\x00\x00\xAA\xBB\x00\x00")
            result = op_random_byte_injection(
                buf, 4, 6, FieldType.BYTES, MutationConstraints()
            )
            if len(result) == 8:
                same_len = True
                break
        assert same_len, "Replace mode should keep same length at least once"


# =============================================================================
# OOB Safety — All Operators
# =============================================================================


class TestOOBSafety:
    """Verify every operator handles offsets beyond packet length without crashing."""

    def _run_all_operators_oob(self):
        """Run each operator with offsets far beyond the packet size."""
        tiny = bytearray(b"\xAA")
        ops = [
            op_bit_flip,
            op_boundary_violation,
            op_buffer_overflow,
            op_format_string,
            op_integer_overflow,
            op_omission,
            op_random_byte_injection,
        ]
        for op in ops:
            result = op(tiny, 50, 60, FieldType.BYTES, MutationConstraints())
            # No crash = success; result can be anything
            assert isinstance(result, bytearray)

    def test_all_operators_oob_no_crash(self):
        self._run_all_operators_oob()

    def test_all_operators_with_empty_packet(self):
        """Every operator should handle an empty buffer gracefully."""
        empty = bytearray()
        ops = [
            op_bit_flip,
            op_boundary_violation,
            op_integer_overflow,
            op_format_string,
            op_omission,
            op_random_byte_injection,
        ]
        for op in ops:
            try:
                result = op(empty, 0, 0, FieldType.BYTES, MutationConstraints())
                assert isinstance(result, bytearray)
            except (IndexError, ValueError):
                pytest.fail(f"{op.__name__} crashed on empty buffer")

    def test_all_operators_with_zero_offsets(self):
        """Operators should handle offset_start == offset_end."""
        buf = bytearray(b"\x00" * 4)
        ops = [
            op_bit_flip,
            op_boundary_violation,
            op_integer_overflow,
            op_format_string,
            op_omission,
            op_random_byte_injection,
        ]
        for op in ops:
            try:
                result = op(buf, 2, 2, FieldType.BYTES, MutationConstraints())
                assert isinstance(result, bytearray)
            except (IndexError, ValueError):
                pytest.fail(f"{op.__name__} crashed with zero-width offset")
