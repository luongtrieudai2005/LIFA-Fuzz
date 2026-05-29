"""
fast_loop/mutator.py
───────────────────
Mutation Engine — generates fuzz variants of captured packets.

Mutation Strategies:
    1. Random Bit-Flip    — flip one random bit (baseline coverage).
    2. Byte Substitution  — replace one byte with a random value.
    3. Boundary Fuzzing   — target numeric fields with 0, MAX, MAX-1.
    4. Structural         — use SemanticRules to mutate specific fields.
    5. KILL_SERVER        — inject known crash payloads (configurable ratio).
    6. Dynamic Rule Reload — periodically loads rules from shared/active_rules.json.

The engine runs an async ``mutation_loop()`` that:
    1. Reads the traffic log for new client→server packets.
    2. Periodically reloads rules from ``shared/active_rules.json``.
    3. Generates mutated variants based on active rules.
    4. Queues each variant for injection via ``Interceptor.inject_mutation()``.
    5. Tracks the last injected packet for crash attribution.
"""

from __future__ import annotations

import asyncio
import json
import random
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from shared.logger import get_logger
from shared.schemas import FieldType, RuleType, SemanticRule

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

if TYPE_CHECKING:
    from fast_loop.interceptor import Interceptor

logger = get_logger("fast_loop.mutator")


# =============================================================================
# Known Crash Payloads — for KILL_SERVER mutation strategy
# =============================================================================
# These payloads are known to crash the vulnerable test server (sandbox/server/server.py).
# In production, this list is empty — real crashes are discovered by the fuzzer.
KILL_SERVER_PAYLOADS: list[bytes] = [
    b"\x00\x00\x00\x00",              # Null magic → SIGSEGV (null pointer deref)
    b"\xCA\xFE\xBA\xBE",             # Abort magic → SIGABRT
    b"\xDE\xAD\xBE\xEF\xFF\xFF",     # Length overflow → buffer overflow crash
]


class MutationEngine:
    """Generates and injects fuzzed variants of captured packets.

    Args:
        interceptor:       The Interceptor to inject mutations into.
        mode:               "random" (bit-flip only) or "smart" (rule-based + random).
        mutations_per_packet: Variants per captured packet.
        random_flip_ratio:   Fraction of mutations that are pure random (vs rule-based).
        kill_server_ratio:   Fraction of mutations that use known crash payloads (0.0-1.0).
                            Set to 0.0 in production; only non-zero for testing.
        max_packet_size:    Cap on mutated packet size.
        rules_file:         Path to shared/active_rules.json for dynamic rule reload.
        rule_reload_interval_s: How often to check for new rules (seconds).
    """

    def __init__(
        self,
        interceptor: "Interceptor",
        mode: str = "smart",
        mutations_per_packet: int = 5,
        random_flip_ratio: float = 0.1,
        kill_server_ratio: float = 0.0,
        max_packet_size: int = 65535,
        rules_file: str = "shared/active_rules.json",
        rule_reload_interval_s: float = 5.0,
    ) -> None:
        self.interceptor = interceptor
        self.mode = mode
        self.mutations_per_packet = mutations_per_packet
        self.random_flip_ratio = random_flip_ratio
        self.kill_server_ratio = kill_server_ratio
        self.max_packet_size = max_packet_size

        # ── Dynamic rule management ─────────────────────────────────
        self._rules: list[SemanticRule] = []
        self._rules_file = Path(rules_file)
        self._rule_reload_interval = rule_reload_interval_s
        self._last_rules_mtime: float = 0.0

        # ── Coverage tracking ─────────────────────────────────────────
        self._fuzzed_offsets: set[tuple[int, int]] = set()
        self._total_mutations: int = 0
        self._total_packets: int = 0
        self._total_kills: int = 0

        # ── Crash attribution ───────────────────────────────────────────
        self._last_injected_packet: bytes = b""
        self._last_injected_rule_id: Optional[str] = None

        # ── Pause state (set by CrashMonitor) ───────────────────────
        self._paused: bool = False

    # -----------------------------------------------------------------
    # Core Mutation API
    # -----------------------------------------------------------------

    async def mutate(self, original_packet: bytes) -> list[bytes]:
        """Generate mutated variants and inject them via the Interceptor."""
        self._total_packets += 1
        variants: list[bytes] = []

        # ── KILL_SERVER strategy (testing only) ──────────────────────
        if self.kill_server_ratio > 0 and random.random() < self.kill_server_ratio:
            payload = random.choice(KILL_SERVER_PAYLOADS)
            variants.append(payload)
            self._total_kills += 1
            self._last_injected_rule_id = "KILL_SERVER"
            logger.warning(
                f"KILL_SERVER payload injected ({len(payload)} bytes) "
                f"[total kills: {self._total_kills}]"
            )
        else:
            # Decide split between random and rule-based
            n_random = max(1, int(self.mutations_per_packet * self.random_flip_ratio))
            n_rule_based = max(0, self.mutations_per_packet - n_random)

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

        # Inject all variants and track the last injected for crash attribution
        for v in variants:
            if len(v) <= self.max_packet_size:
                await self.interceptor.inject_mutation(v)
                self._total_mutations += 1
                self._last_injected_packet = v
                if not self._last_injected_rule_id:
                    self._last_injected_rule_id = (
                        "rule_based" if self._rules else "random"
                    )

        logger.info(
            f"Mutated packet #{self._total_packets}: "
            f"{len(variants)} variants injected "
            f"(total mutations: {self._total_mutations})"
        )
        return variants

    # -----------------------------------------------------------------
    # Dynamic Rule Reload
    # -----------------------------------------------------------------

    async def reload_rules(self) -> int:
        """Reload rules from shared/active_rules.json.

        Uses mtime check to avoid re-parsing every cycle. The Slow Loop
        writes the file atomically (temp + rename) — on Linux, ``rename()``
        is atomic within a single filesystem, so the Fast Loop will either
        see the old file or the new file, never a partial write.

        For extra safety, if a read encounters a JSONDecodeError (possible
        on NFS or unusual filesystems), we retry with a short backoff.

        Returns:
            Number of newly loaded rules, or 0 if file is unchanged/missing.
        """
        if not self._rules_file.exists():
            return 0

        try:
            mtime = self._rules_file.stat().st_mtime
        except OSError:
            return 0

        if mtime <= self._last_rules_mtime:
            return 0

        # Retry read up to 3 times with backoff (handles transient
        # partial reads on non-atomic filesystems like NFS)
        max_read_retries = 3
        for attempt in range(max_read_retries):
            try:
                # Use explicit file descriptor (not Path.read_text) to
                # ensure the file handle is opened atomically relative
                # to any concurrent rename by the Slow Loop writer.
                with open(self._rules_file, "r", encoding="utf-8") as f:
                    data = f.read()
                rules_data = json.loads(data)
                break  # Success — exit retry loop
            except (json.JSONDecodeError, OSError) as e:
                if attempt < max_read_retries - 1:
                    logger.debug(
                        f"Rules file read attempt {attempt + 1} failed "
                        f"(will retry): {e}"
                    )
                    await asyncio.sleep(0.1 * (attempt + 1))
                else:
                    logger.warning(
                        f"Failed to read rules file after {max_read_retries} "
                        f"attempts (will retry on next cycle): {e}"
                    )
                    return 0

        try:
            new_rules = [
                SemanticRule.model_validate(r) for r in rules_data
            ]
        except Exception as e:
            logger.warning(f"Invalid rules in file (skipping): {e}")
            return 0

        added = 0
        existing_ids = {r.rule_id for r in self._rules}
        for rule in new_rules:
            if rule.rule_id not in existing_ids:
                self._rules.append(rule)
                existing_ids.add(rule.rule_id)
                added += 1

        if added > 0:
            self._last_rules_mtime = mtime
            logger.info(
                f"Reloaded {added} new rules from {self._rules_file} "
                f"(total active: {len(self._rules)})"
            )
        return added

    # -----------------------------------------------------------------
    # Main Mutation Loop (reads traffic log)
    # -----------------------------------------------------------------

    async def mutation_loop(
        self,
        traffic_log_path: str = "shared/raw_traffic.jsonl",
        poll_interval: float = 2.0,
    ) -> None:
        """Main async loop: read traffic log, mutate packets, inject.

        This loop absorbs the mutation logic that was previously inline
        in ``main.py``. It runs as an independent asyncio task.

        Every ``rule_reload_interval_s`` seconds, it checks for new rules
        from the Slow Loop.

        Args:
            traffic_log_path: Path to the JSONL traffic log.
            poll_interval: Seconds between traffic log polls.
        """
        log_path = Path(traffic_log_path)
        last_pos = 0
        rule_reload_counter = 0
        rule_reload_ticks = max(
            1, int(self._rule_reload_interval / poll_interval)
        )

        logger.info(
            f"Mutation loop started (poll={poll_interval}s, "
            f"rules_file={self._rules_file})"
        )

        try:
            while not self._paused and self.interceptor.is_running:
                # ── Periodic rule reload ─────────────────────────────
                rule_reload_counter += 1
                if rule_reload_counter >= rule_reload_ticks:
                    await self.reload_rules()
                    rule_reload_counter = 0

                # ── Read traffic log (non-blocking I/O) ────────────────
                if not log_path.exists():
                    await asyncio.sleep(poll_interval)
                    continue

                try:
                    lines = await asyncio.get_event_loop().run_in_executor(
                        None, self._read_log_lines, log_path, last_pos
                    )
                except OSError:
                    await asyncio.sleep(poll_interval)
                    continue

                if len(lines) <= last_pos:
                    await asyncio.sleep(poll_interval)
                    continue

                # ── Process new client→server non-mutated packets ──────
                for line in lines[last_pos:]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if (
                            record.get("direction") == "client_to_server"
                            and not record.get("is_mutated")
                        ):
                            raw_hex = record.get("payload", "")
                            if raw_hex and len(raw_hex) >= 8:
                                raw_data = bytes.fromhex(raw_hex)
                                await self.mutate(raw_data)
                    except (json.JSONDecodeError, ValueError):
                        continue

                last_pos = len(lines)

                # ── Stats ────────────────────────────────────────────
                stats = self.coverage_summary
                logger.info(
                    f"Stats: packets={stats['total_packets']} "
                    f"mutations={stats['total_mutations']} "
                    f"kills={stats['total_kills']} "
                    f"rules={stats['active_rules']} "
                    f"captured={self.interceptor.total_captured} "
                    f"injected={self.interceptor.total_injected}"
                )

                await asyncio.sleep(poll_interval)

        except asyncio.CancelledError:
            pass

        logger.info("Mutation loop stopped.")

    async def _read_log_lines(self, path: Path, from_pos: int) -> list[str]:
        """Read log file from position, return all lines (blocking helper for executor)."""
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()[from_pos:]

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
        applicable = [
            r for r in self._rules
            if r.offset_end <= len(packet) and r.offset_start < r.offset_end
        ]
        if not applicable:
            return self.random_byte_substitution(packet)

        rule = max(applicable, key=lambda r: r.priority)
        variant = self.apply_rule(packet, rule)

        # Track which rule generated this mutation
        self._last_injected_rule_id = rule.rule_id
        return variant

    def apply_rule(self, packet: bytes, rule: SemanticRule) -> Optional[bytes]:
        """Apply a single semantic rule to a packet.

        Dispatches to the Advanced Binary Mutation Arsenal operators
        based on ``rule.rule_type``:

        - ``BIT_FLIP``  → op_bit_flip (1–3 random bits)
        - ``BOUNDARY``   → op_integer_overflow or op_boundary_violation
        - ``STRUCTURAL`` → op_buffer_overflow, op_format_string, or
                           op_random_byte_injection
        - ``STATE``      → drop packet (50 %) or op_omission (50 %)

        OOB safety: ``safe_slice()`` zero-pads the buffer if the LLM
        hallucinates offsets beyond the packet length.

        Returns:
            Mutated bytes, or None if the rule drops the packet (STATE type).
        """
        # OOB-safe buffer — zero-pads if offsets exceed packet length
        buf = safe_slice(bytearray(packet), rule.offset_start, rule.offset_end)

        if rule.rule_type == RuleType.BIT_FLIP:
            buf = op_bit_flip(
                buf, rule.offset_start, rule.offset_end,
                rule.field_type, rule.constraints,
            )

        elif rule.rule_type == RuleType.BOUNDARY:
            if random.random() < 0.5:
                buf = op_integer_overflow(
                    buf, rule.offset_start, rule.offset_end,
                    rule.field_type, rule.constraints,
                )
            else:
                buf = op_boundary_violation(
                    buf, rule.offset_start, rule.offset_end,
                    rule.field_type, rule.constraints,
                )

        elif rule.rule_type == RuleType.STRUCTURAL:
            op = random.choice([
                op_buffer_overflow,
                op_format_string,
                op_random_byte_injection,
            ])
            buf = op(
                buf, rule.offset_start, rule.offset_end,
                rule.field_type, rule.constraints,
            )

        elif rule.rule_type == RuleType.STATE:
            # 50 % chance: drop the packet entirely, 50 %: truncate
            if random.random() < 0.5:
                return None
            buf = op_omission(
                buf, rule.offset_start, rule.offset_end,
                rule.field_type, rule.constraints,
            )

        # Track coverage
        self._fuzzed_offsets.add((rule.offset_start, rule.offset_end))

        # Restore preserved bytes (magic header prefix)
        if rule.preserve_bytes:
            buf[: len(rule.preserve_bytes)] = rule.preserve_bytes

        # Restore static values at specific offsets
        for offset, value in rule.static_values_to_keep.items():
            if 0 <= offset < len(buf):
                buf[offset] = value

        return bytes(buf)

    def _pick_boundary_value(self, rule: SemanticRule) -> int:
        """Pick a boundary value based on field type and constraints."""
        values = [0, (1 << (rule.field_length * 8)) - 1]

        if rule.constraints.min_value is not None:
            values.append(rule.constraints.min_value)
        if rule.constraints.max_value is not None:
            values.append(rule.constraints.max_value)

        if rule.constraints.invalid_values:
            values.extend(
                v for v in rule.constraints.invalid_values if isinstance(v, int)
            )

        return random.choice(values) if values else 0

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
    # Pause / Resume (called by CrashMonitor)
    # -----------------------------------------------------------------

    def pause(self) -> None:
        """Pause the mutation loop (called by CrashMonitor on crash)."""
        self._paused = True
        logger.warning("MutationEngine PAUSED")

    def resume(self) -> None:
        """Resume the mutation loop (called by CrashMonitor after reset)."""
        self._paused = False
        logger.info("MutationEngine RESUMED")

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def coverage_summary(self) -> dict:
        return {
            "total_mutations": self._total_mutations,
            "total_packets": self._total_packets,
            "total_kills": self._total_kills,
            "unique_offsets_fuzzed": len(self._fuzzed_offsets),
            "active_rules": len(self._rules),
        }
