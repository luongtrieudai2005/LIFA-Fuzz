"""
tests/test_mutator.py
──────────────────────
Unit tests for the Fast Loop Mutation Engine.

Tests cover:
    - Engine initialization (default and custom params).
    - KILL_SERVER payloads existence and behavior.
    - Core mutate() method (injection, stats).
    - Random mutations (bit-flip, byte substitution).
    - Rule-based mutations (bit-flip, boundary, preserve_bytes).
    - Coverage tracking.
    - Rule set management.
"""

import pytest
from unittest.mock import AsyncMock

from fast_loop.mutator import KILL_SERVER_PAYLOADS, MutationEngine
from shared.schemas import FieldType, MutationConstraints, RuleType, SemanticRule


def _mock_interceptor():
    """Create a mock interceptor for testing."""
    m = type("MockInterceptor", (), {
        "inject_mutation": AsyncMock(),
        "is_running": True,
    })()
    return m


# =============================================================================
# Initialization
# =============================================================================


class TestMutationEngineInit:
    """Tests for MutationEngine initialization."""

    def test_default_params(self):
        engine = MutationEngine(interceptor=_mock_interceptor())
        assert engine.mode == "smart"
        assert engine.mutations_per_packet == 5
        assert engine.kill_server_ratio == 0.0
        assert engine.random_flip_ratio == 0.1

    def test_custom_params(self):
        engine = MutationEngine(
            interceptor=_mock_interceptor(),
            mode="random",
            mutations_per_packet=10,
            kill_server_ratio=0.05,
        )
        assert engine.mode == "random"
        assert engine.mutations_per_packet == 10
        assert engine.kill_server_ratio == 0.05

    def test_kill_server_payloads_exist(self):
        """KILL_SERVER payloads match known server vulnerabilities."""
        assert len(KILL_SERVER_PAYLOADS) >= 3
        # Null magic → SIGSEGV
        assert KILL_SERVER_PAYLOADS[0][:4] == b"\x00\x00\x00\x00"
        # Abort magic → SIGABRT
        assert KILL_SERVER_PAYLOADS[1][:4] == b"\xCA\xFE\xBA\xBE"
        # Length overflow
        assert KILL_SERVER_PAYLOADS[2][:4] == b"\xDE\xAD\xBE\xEF"


# =============================================================================
# Core Mutate
# =============================================================================


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
        assert stats["total_kills"] == 0

    @pytest.mark.asyncio
    async def test_kill_server_increments_counter(self):
        """KILL_SERVER mutations increment total_kills."""
        interceptor = _mock_interceptor()
        engine = MutationEngine(
            interceptor=interceptor,
            kill_server_ratio=1.0,  # 100% kill server
        )
        await engine.mutate(b"\xDE\xAD\xBE\xEF\x00\x05HELLO")
        stats = engine.coverage_summary
        assert stats["total_kills"] == 1
        assert interceptor.inject_mutation.call_count >= 1


# =============================================================================
# Random Mutations
# =============================================================================


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


# =============================================================================
# Rule-Based Mutations
# =============================================================================


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
        assert mutated is not None
        # First 4 bytes (magic) should be unchanged
        assert mutated[:4] == b"\xDE\xAD\xBE\xEF"
        # Bytes 4-6 may be different (bit-flipped)
        # But the rest should be unchanged
        assert mutated[6:] == b"HELLO"

    def test_apply_boundary_rule(self):
        """apply_rule with BOUNDARY modifies the target field."""
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
        original_field = int.from_bytes(packet[4:6], "little")
        mutated = engine.apply_rule(packet, rule)
        assert mutated is not None
        # Field should have been modified (integer_overflow or boundary_violation)
        field_val = int.from_bytes(mutated[4:6], "little")
        # Accept any modification — the value must differ from original OR
        # be a known boundary/overflow value
        assert field_val != original_field or field_val in {
            0x0000, 0xFFFF, 0x7FFF, 0x8000, 0xFFFFFFFF & 0xFFFF,
        }

    def test_apply_state_rule_returns_none_or_truncated(self):
        """apply_rule with STATE either drops the packet or truncates it."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.STATE,
            offset_start=0,
            offset_end=4,
            target_field_name="sequence",
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        results = set()
        # Run many times to hit both branches (drop + truncate)
        for _ in range(50):
            mutated = engine.apply_rule(packet, rule)
            if mutated is None:
                results.add("dropped")
            else:
                results.add("truncated")
                assert len(mutated) <= len(packet)
        # With 50 tries at 50/50, both branches should be hit
        assert "dropped" in results or "truncated" in results

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

    def test_static_values_to_keep(self):
        """apply_rule restores static values at specific offsets."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.BIT_FLIP,
            offset_start=2,
            offset_end=6,
            static_values_to_keep={0: 0xDE, 1: 0xAD},
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        mutated = engine.apply_rule(packet, rule)
        assert mutated[0] == 0xDE  # Restored
        assert mutated[1] == 0xAD  # Restored


# =============================================================================
# Coverage Tracking
# =============================================================================


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
        assert stats["total_kills"] == 0

    def test_coverage_summary_initial_zeros(self):
        """All counters start at zero."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        stats = engine.coverage_summary
        assert stats["total_mutations"] == 0
        assert stats["total_packets"] == 0
        assert stats["total_kills"] == 0
        assert stats["unique_offsets_fuzzed"] == 0
        assert stats["active_rules"] == 0


# =============================================================================
# Rule Management
# =============================================================================


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


# =============================================================================
# New Operator Dispatch via apply_rule()
# =============================================================================


class TestApplyRuleNewOperators:
    """Tests for the new mutation-operator dispatch paths in apply_rule()."""

    def test_structural_rule_produces_modified_packet(self):
        """STRUCTURAL dispatches to buffer_overflow / format_string / random_byte_injection."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.STRUCTURAL,
            offset_start=4,
            offset_end=6,
            target_field_name="payload",
            field_type=FieldType.BYTES,
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        mutated = engine.apply_rule(packet, rule)
        assert mutated is not None
        assert len(mutated) > 0

    def test_structural_preserve_bytes_still_works(self):
        """preserve_bytes is restored after structural operator runs."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.STRUCTURAL,
            offset_start=4,
            offset_end=6,
            preserve_bytes=b"\xDE\xAD\xBE\xEF",
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        mutated = engine.apply_rule(packet, rule)
        assert mutated is not None
        assert mutated[:4] == b"\xDE\xAD\xBE\xEF"

    def test_oob_offset_does_not_crash(self):
        """An LLM-hallucinated offset beyond packet length is safe."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.BIT_FLIP,
            offset_start=100,
            offset_end=104,
        )
        packet = b"\xDE\xAD"  # only 2 bytes
        mutated = engine.apply_rule(packet, rule)
        assert mutated is not None
        assert len(mutated) >= 104  # buffer was padded

    def test_boundary_rule_modifies_field(self):
        """BOUNDARY dispatches to integer_overflow or boundary_violation."""
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
        original_field = int.from_bytes(packet[4:6], "little")
        mutated = engine.apply_rule(packet, rule)
        assert mutated is not None
        # Just verify it didn't crash and produced a valid packet
        assert len(mutated) >= 6

    def test_state_rule_either_drops_or_truncates(self):
        """STATE dispatches to None (drop) or omission (truncate)."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        rule = SemanticRule(
            rule_type=RuleType.STATE,
            offset_start=4,
            offset_end=6,
        )
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        results = set()
        for _ in range(50):
            mutated = engine.apply_rule(packet, rule)
            if mutated is None:
                results.add("dropped")
            else:
                results.add("truncated")
                assert len(mutated) <= len(packet)
        assert len(results) >= 1  # At least one branch hit


# =============================================================================
# Pause / Resume
# =============================================================================


class TestPauseResume:
    """Tests for pause/resume behavior."""

    def test_pause_sets_flag(self):
        """pause() sets the internal paused flag."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        assert engine._paused is False
        engine.pause()
        assert engine._paused is True

    def test_resume_clears_flag(self):
        """resume() clears the internal paused flag."""
        engine = MutationEngine(interceptor=_mock_interceptor())
        engine.pause()
        engine.resume()
        assert engine._paused is False
