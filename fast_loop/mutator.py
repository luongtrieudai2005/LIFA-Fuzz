"""
fast_loop/mutator.py
───────────────────
Mutation Engine — generates fuzz variants of captured packets.

Mutation Strategies:
    1. Random Bit-Flip    — flip one random bit (baseline coverage).
    2. Byte Substitution  — replace one byte with a random value.
    3. Boundary Fuzzing   — target numeric fields with 0, MAX, MAX-1.
    4. Structural         — use SemanticRules to mutate specific fields.
    5. KILL_SERVER        — 1% chance of sending a known crash trigger.

The engine runs an async loop that:
    1. Waits for a captured packet from the Interceptor.
    2. Generates N mutated variants.
    3. Queues each variant for injection via Interceptor.inject_mutation().
"""

from __future__ import annotations

import asyncio
import random
import struct
from typing import TYPE_CHECKING, Optional

from shared.logger import get_logger
from shared.schemas import FieldType, RuleType, SemanticRule

if TYPE_CHECKING:
    from fast_loop.interceptor import Interceptor

logger = get_logger("fast_loop.mutator")

# Known crash triggers matching sandbox/server/server.py vulnerabilities
KILL_SERVER_PAYLOADS: list[bytes] = [
    b"\x00\x00\x00\x00\x00\x00",        # null magic → SIGSEGV
    b"\xCA\xFE\xBA\xBE\x00\x00",        # abort magic → SIGABRT
    b"\xDE\xAD\xBE\xEF\xFF\xFF\x00\x01", # length overflow → buffer overflow
]


class MutationEngine:
    """Generates and injects fuzzed variants of captured packets.

    Args:
        interceptor:       The Interceptor to inject mutations into.
        mode:               "random" (bit-flip only) or "smart" (rule-based + random).
        mutations_per_packet: Variants per captured packet.
        random_flip_ratio:   Fraction of mutations that are pure random.
        max_packet_size:    Cap on mutated packet size.
        kill_server_ratio:  Probability (0.0-1.0) of sending a KILL_SERVER payload.
    """

    def __init__(
        self,
        interceptor: "Interceptor",
        mode: str = "smart",
        mutations_per_packet: int = 5,
        random_flip_ratio: float = 0.1,
        max_packet_size: int = 65535,
        kill_server_ratio: float = 0.01,
    ) -> None:
        self.interceptor = interceptor
        self.mode = mode
        self.mutations_per_packet = mutations_per_packet
        self.random_flip_ratio = random_flip_ratio
        self.max_packet_size = max_packet_size
        self.kill_server_ratio = kill_server_ratio

        self._rules: list[SemanticRule] = []
        self._fuzzed_offsets: set[tuple[int, int]] = set()
        self._total_mutations: int = 0
        self._total_packets: int = 0
        self._total_kills: int = 0

    # -----------------------------------------------------------------
    # Core Mutation API
    # -----------------------------------------------------------------

    async def mutate(self, original_packet: bytes) -> list[bytes]:
        """Generate mutated variants and inject them via the Interceptor."""
        self._total_packets += 1
        variants: list[bytes] = []

        # 1% KILL_SERVER mutation (for testing crash detection)
        if random.random() < self.kill_server_ratio:
            kill_payload = random.choice(KILL_SERVER_PAYLOADS)
            variants.append(kill_payload)
            self._total_kills += 1
            logger.warning(
                f"KILL_SERVER mutation #{self._total_kills} "
                f"(1% trigger, payload: {kill_payload.hex()})"
            )

        # Decide split between random and rule-based
        n_random = max(1, int(self.mutations_per_packet * self.random_flip_ratio))
        n_rule_based = max(0, self.mutations_per_packet - n_random - len(variants))

        # Random mutations (baseline)
        for _ in range(n_random):
            variant = self.random_bitflip(original_packet)
            variants.append(variant)

        # Rule-based mutations (smart)
        if self.mode == "smart" and self._rules:
            for _ in range(n_rule_based):
                variant = self._apply_best_rule(original_packet)
                if variant is not None:
                    variants.append(variant)

        # Inject all variants
        for v in variants:
            if len(v) <= self.max_packet_size:
                await self.interceptor.inject_mutation(v)
                self._total_mutations += 1

        logger.info(
            f"Mutated packet #{self._total_packets}: "
            f"{len(variants)} variants injected "
            f"(total mutations: {self._total_mutations})"
        )
        return variants

    # -----------------------------------------------------------------
    # Random Mutations (Baseline)
    # -----------------------------------------------------------------

    def random_bitflip(self, data: bytes) -> bytes:
        """Flip one random bit in the packet."""
        if not data:
            return data
        buf = bytearray(data)
        byte_idx = random.randint(0, len(buf) - 1)
        bit_idx = random.randint(0, 7)
        buf[byte_idx] ^= (1 << bit_idx)
        return bytes(buf)

    def random_byte_substitution(self, data: bytes) -> bytes:
        """Replace one random byte with a random value."""
        if not data:
            return data
        buf = bytearray(data)
        idx = random.randint(0, len(buf) - 1)
        buf[idx] = random.randint(0, 255)
        return bytes(buf)

    # -----------------------------------------------------------------
    # Rule-Based Mutations
    # -----------------------------------------------------------------

    def _apply_best_rule(self, packet: bytes) -> Optional[bytes]:
        """Apply the highest-priority applicable rule to the packet."""
        # Find rules that fit within the packet
        applicable = [
            r for r in self._rules
            if r.offset_end <= len(packet) and r.offset_start < r.offset_end
        ]
        if not applicable:
            # Fall back to random
            return self.random_byte_substitution(packet)

        # Pick highest priority
        rule = max(applicable, key=lambda r: r.priority)
        return self.apply_rule(packet, rule)

    def apply_rule(self, packet: bytes, rule: SemanticRule) -> bytes:
        """Apply a single semantic rule to a packet."""
        buf = bytearray(packet)
        field_len = rule.field_length

        if rule.rule_type == RuleType.BIT_FLIP:
            # Flip a random bit in the target range
            byte_offset = random.randint(rule.offset_start, rule.offset_end - 1)
            bit = random.randint(0, 7)
            buf[byte_offset] ^= (1 << bit)

        elif rule.rule_type == RuleType.BOUNDARY:
            value = self._pick_boundary_value(rule)
            encoded = self._encode_value(value, rule.field_type, field_len)
            buf[rule.offset_start:rule.offset_start + len(encoded)] = encoded

        elif rule.rule_type == RuleType.STRUCTURAL:
            value = self._pick_structural_value(rule)
            encoded = self._encode_value(value, rule.field_type, field_len)
            buf[rule.offset_start:rule.offset_start + len(encoded)] = encoded

        elif rule.rule_type == RuleType.STATE:
            # Drop the packet (state-based mutation)
            return None

        # Track coverage
        self._fuzzed_offsets.add((rule.offset_start, rule.offset_end))

        # Restore preserved bytes
        if rule.preserve_bytes:
            buf[:len(rule.preserve_bytes)] = rule.preserve_bytes

        return bytes(buf)

    def _pick_boundary_value(self, rule: SemanticRule) -> int:
        """Pick a boundary value based on field type."""
        values = [0, (1 << (rule.field_length * 8)) - 1]  # 0 and MAX

        if rule.constraints.min_value is not None:
            values.append(rule.constraints.min_value)
        if rule.constraints.max_value is not None:
            values.append(rule.constraints.max_value)

        if rule.constraints.invalid_values:
            values.extend(v for v in rule.constraints.invalid_values if isinstance(v, int))

        return random.choice(values)

    def _pick_structural_value(self, rule: SemanticRule) -> int:
        """Pick a structural value (increment/decrement/random)."""
        strategy = random.choice(["increment", "decrement", "random"])

        if strategy == "random":
            max_val = (1 << (rule.field_length * 8)) - 1
            return random.randint(0, max_val)
        elif strategy == "increment":
            return 1
        else:  # decrement
            return -1

    @staticmethod
    def _encode_value(value: int, field_type: FieldType, field_len: int) -> bytes:
        """Encode an integer value according to field type."""
        fmt_map = {
            FieldType.UINT8: ("B", 1),
            FieldType.UINT16_LE: ("<H", 2),
            FieldType.UINT16_BE: (">H", 2),
            FieldType.UINT32_LE: ("<I", 4),
            FieldType.UINT32_BE: (">I", 4),
            FieldType.INT8: ("b", 1),
            FieldType.INT16_LE: ("<h", 2),
            FieldType.INT16_BE: (">h", 2),
            FieldType.INT32_LE: ("<i", 4),
            FieldType.INT32_BE: (">i", 4),
        }

        if field_type in fmt_map:
            fmt, size = fmt_map[field_type]
            return struct.pack(fmt, value)

        # Fallback: raw bytes
        return value.to_bytes(field_len, byteorder="little", signed=False)

    # -----------------------------------------------------------------
    # Rule Set Management
    # -----------------------------------------------------------------

    def update_rules(self, new_rules: list[SemanticRule]) -> None:
        """Hot-swap the active rule set."""
        existing_ids = {r.rule_id for r in self._rules}
        added = 0
        for rule in new_rules:
            if rule.rule_id not in existing_ids:
                self._rules.append(rule)
                existing_ids.add(rule.rule_id)
                added += 1
        logger.info(f"Rules updated: +{added} rules (total: {len(self._rules)})")

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def coverage_summary(self) -> dict:
        return {
            "total_mutations": self._total_mutations,
            "total_packets": self._total_packets,
            "unique_offsets_fuzzed": len(self._fuzzed_offsets),
            "total_kills": self._total_kills,
            "active_rules": len(self._rules),
        }
