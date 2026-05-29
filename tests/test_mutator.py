"""
tests/test_mutator.py
──────────────────────
Unit tests for the Fast Loop Mutation Engine.
"""

import pytest

from fast_loop.mutator import KILL_SERVER_PAYLOADS, MutationEngine
from shared.schemas import FieldType, MutationConstraints, RuleType, SemanticRule


def _mock_interceptor():
    """Create a mock interceptor for testing."""
    interceptor = type("MockInterceptor", (), {
        "inject_mutation": AsyncMock(),
    })()
    return interceptor


# Override AsyncMock import at module level
from unittest.mock import AsyncMock

def _mock_interceptor():
    m = type("MockInterceptor", (), {
        "inject_mutation": AsyncMock(),
    })()
    return m


class TestMutationEngineInit:
    """Tests for MutationEngine initialization."""

    def test_default_params(self):
        engine = MutationEngine(interceptor=_mock_interceptor())
        assert engine.mode == "smart"
        assert engine.mutations_per_packet == 5
        assert engine.kill_server_ratio == 0.01

    def test_random_mode(self):
        engine = MutationEngine(
            interceptor=_mock_interceptor(),
            mode="random",
            mutations_per_packet=10,
        )
        assert engine.mode == "random"
        assert engine.mutations_per_packet == 10

    def test_kill_server_payloads_exist(self):
        """KILL_SERVER payloads match known server vulnerabilities."""
        assert len(KILL_SERVER_PAYLOADS) >= 3
        # Null magic
        assert KILL_SERVER_PAYLOADS[0][:4] == b"\x00\x00\x00\x00"
        # Abort magic
        assert KILL_SERVER_PAYLOADS[1][:4] == b"\xCA\xFE\xBA\xBE"


class TestMutationEngineMutate:
    """Tests for the core mutate() method."""

    @pytest.mark.asyncio
    async def test_mutate_injects_variants(self):
        """mutate() generates and injects at least one variant."""
        interceptor = _mock_interceptor()
        engine = MutationEngine(
            interceptor=interceptor,
            mutations_per_packet=3,
            kill_server_ratio=0.0,  # Disable KILL_SERVER for deterministic test
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        variants = await engine.mutate(packet)
        # Should inject at least one mutation (bit-flip baseline)
        assert interceptor.inject_mutation.call_count >= 1

    @pytest.mark.asyncio
    async def test_mutate_updates_stats(self):
        """mutate() updates packet and mutation counters."""
        interceptor = _mock_interceptor()
        engine = MutationEngine(
            interceptor=interceptor,
            kill_server_ratio=0.0,
        )
        await engine.mutate(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        stats = engine.coverage_summary
        assert stats["total_packets"] == 1
        assert stats["total_mutations"] >= 1


class TestRandomMutations:
    """Tests for random mutation methods."""

    def test_random_bitflip_changes_exactly_one_bit(self):
        """random_bitflip changes exactly one bit from the original."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        original = b"\xFF\xFF\xFF\xFF"
        mutated = engine.random_bitflip(original)
        # XOR should yield exactly one bit set
        diff = sum(
            bin(a ^ b).count("1") for a, b in zip(original, mutated)
        )
        assert diff == 1
        assert len(mutated) == len(original)

    def test_random_byte_substitution_changes_one_byte(self):
        """random_byte_substitution changes exactly one byte position."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        original = b"\xAA\xBB\xCC\xDD"
        mutated = engine.random_byte_substitution(original)
        changed_positions = sum(
            1 for a, b in zip(original, mutated) if a != b
        )
        assert changed_positions == 1

    def test_random_bitflip_empty_data(self):
        """random_bitflip returns empty for empty input."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        assert engine.random_bitflip(b"") == b""


class TestApplyRule:
    """Tests for rule-based mutations."""

    def test_apply_bit_flip_rule(self):
        """apply_rule with BIT_FLIP flips a bit in the target range."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.BIT_FLIP,
            offset_start=4,
            offset_end=6,
            target_field_name="length",
            field_type=FieldType.UINT16_LE,
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        mutated = engine.apply_rule(packet, rule)
        # First 4 bytes (magic) should be unchanged
        assert mutated[:4] == b"\xDE\xAD\xBE\xEF"
        # Bytes 4-6 may be different (bit-flipped)
        # But the rest should be unchanged
        assert mutated[6:] == b"HELLO"

    def test_apply_boundary_rule(self):
        """apply_rule with BOUNDARY sets field to a boundary value."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.BOUNDARY,
            offset_start=4,
            offset_end=6,
            target_field_name="length",
            field_type=FieldType.UINT16_LE,
            constraints=MutationConstraints(min_value=0, max_value=0xFFFF),
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        mutated = engine.apply_rule(packet, rule)
        # Field should now be a boundary value (0, 0xFFFF, min, or max)
        field_val = int.from_bytes(mutated[4:6], "little")
        assert field_val in {0, 0xFFFF, 0}

    def test_preserve_bytes_kept(self):
        """apply_rule preserves the preserve_bytes prefix."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.BIT_FLIP,
            offset_start=4,
            offset_end=8,
            preserve_bytes=b"\xDE\xAD\xBE\xEF",
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05\x00\x00HELLO"
        mutated = engine.apply_rule(packet, rule)
        assert mutated[:4] == b"\xDE\xAD\xBE\xEF"  # Preserved


class TestCoverageTracking:
    """Tests for coverage tracking."""

    def test_coverage_summary_structure(self):
        """coverage_summary returns the expected keys."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        stats = engine.coverage_summary
        assert "total_mutations" in stats
        assert "total_packets" in stats
        assert "unique_offsets_fuzzed" in stats
        assert "total_kills" in stats
        assert "active_rules" in stats
        assert stats["total_mutations"] == 0


class TestRuleManagement:
    """Tests for rule set management."""

    def test_update_rules(self):
        """update_rules adds new rules without duplicates."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        r1 = SemanticRule(rule_id="r1", offset_start=0, offset_end=4)
        r2 = SemanticRule(rule_id="r2", offset_start=4, offset_end=8)
        engine.update_rules([r1, r2])
        assert engine.coverage_summary["active_rules"] == 2

        # Add r1 again (dedup)
        engine.update_rules([r1])
        assert engine.coverage_summary["active_rules"] == 2
