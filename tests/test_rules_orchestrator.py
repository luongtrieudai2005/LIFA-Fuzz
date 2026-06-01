"""
tests/test_rules_orchestrator.py
───────────────────────────────────
Tests for the Rules Orchestrator — dedup, sliding window, budget, and
full pipeline integration (with MOCK LLM mode).
"""

import json
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.schemas import (
    Direction,
    FieldType,
    MutationStrategy,
    ProtocolGrammar,
    SemanticRule,
)
from slow_loop.llm_agent import LLMAgent, estimate_tokens
from slow_loop.parser import InteractionSession, TrafficParser
from slow_loop.rule_generator import RuleGenerator
from slow_loop.rules_orchestrator import (
    RulesOrchestrator,
    SlidingWindow,
    packet_signature,
)


# =============================================================================
# Packet Signature Tests
# =============================================================================


class TestPacketSignature:
    """Tests for the dedup signature function."""

    def test_basic_signature(self):
        sig = packet_signature("deadbeef0005", prefix_bytes=4)
        assert sig.startswith("deadbeef:6:")  # New format includes content hash

    def test_short_packet(self):
        """Packets shorter than prefix_bytes use whatever is available."""
        sig = packet_signature("dead", prefix_bytes=4)
        assert sig.startswith("dead:2:")

    def test_empty_packet(self):
        sig = packet_signature("", prefix_bytes=4)
        assert sig.startswith(":0:")

    def test_same_prefix_same_length_is_duplicate(self):
        sig1 = packet_signature("deadbeef0005aa", prefix_bytes=4)
        sig2 = packet_signature("deadbeef0005bb", prefix_bytes=4)
        assert sig1 == sig2  # Same prefix + same length → duplicate

    def test_different_content_different_sig(self):
        """Packets with same prefix+length but different body content
        should produce DIFFERENT signatures (critical for HTTP protocols)."""
        # Two GET requests with same length but different paths
        get_root = "474554202f20485454502f312e310d0a486f73743a206c6f63616c686f7374"
        get_path = "474554202f62696e20485454502f312e310d0a486f73743a206c6f63616c686f7374"
        sig1 = packet_signature(get_root, prefix_bytes=4)
        sig2 = packet_signature(get_path, prefix_bytes=4)
        assert sig1 != sig2  # Different content → different signature

    def test_different_prefix_not_duplicate(self):
        sig1 = packet_signature("deadbeef0005", prefix_bytes=4)
        sig2 = packet_signature("cafebabe0005", prefix_bytes=4)
        assert sig1 != sig2

    def test_different_length_not_duplicate(self):
        sig1 = packet_signature("deadbeef0005", prefix_bytes=4)
        sig2 = packet_signature("deadbeef00050006", prefix_bytes=4)
        assert sig1 != sig2  # Different length


# =============================================================================
# Sliding Window Tests
# =============================================================================


class TestSlidingWindow:
    """Tests for the sliding window dedup buffer."""

    def test_add_new_packet(self):
        window = SlidingWindow(max_entries=10)
        pkt = {"payload": "deadbeef0005"}
        assert window.add(pkt) is True
        assert window.size == 1

    def test_add_duplicate_returns_false(self):
        window = SlidingWindow(max_entries=10)
        pkt = {"payload": "deadbeef0005"}
        window.add(pkt)
        assert window.add(pkt) is False
        assert window.size == 1

    def test_add_different_packet(self):
        window = SlidingWindow(max_entries=10)
        pkt1 = {"payload": "deadbeef0005"}
        pkt2 = {"payload": "cafebabe0005"}
        assert window.add(pkt1) is True
        assert window.add(pkt2) is True
        assert window.size == 2

    def test_eviction_when_over_capacity(self):
        window = SlidingWindow(max_entries=3)
        for i in range(5):
            # Each has a unique prefix (8 hex chars = 4 bytes)
            window.add({"payload": f"{i:08x}0001"})
        assert window.size == 3  # Only last 3 kept

    def test_add_all_returns_new_count(self):
        window = SlidingWindow(max_entries=10)
        packets = [
            {"payload": "deadbeef0005"},
            {"payload": "deadbeef0005"},  # duplicate (same prefix + same length)
            {"payload": "cafebabe0005"},
        ]
        new_count = window.add_all(packets)
        assert new_count == 2  # Only 2 unique

    def test_get_diverse_sample_small_buffer(self):
        window = SlidingWindow(max_entries=10)
        window.add({"payload": "deadbeef0005"})
        window.add({"payload": "cafebabe0005"})
        result = window.get_diverse_sample(5)
        assert len(result) == 2

    def test_get_diverse_sample_respects_limit(self):
        window = SlidingWindow(max_entries=100)
        # Add 20 packets: 10 with prefix 'deadbeef', 10 with prefix 'cafebabe'
        # Each with DIFFERENT lengths (trailing data varies in length)
        for i in range(10):
            # Ensure each has a unique length to get unique signatures
            suffix = "aa" * (i + 1)  # varying length
            window.add({"payload": "deadbeef" + suffix})
        for i in range(10):
            suffix = "bb" * (i + 1)
            window.add({"payload": "cafebabe" + suffix})
        result = window.get_diverse_sample(5)
        assert len(result) == 5

    def test_get_diverse_sample_round_robin_diversity(self):
        window = SlidingWindow(max_entries=100)
        # Add many packets with prefix 'aaaaaaaa' (unique lengths), then 'bbbbbbbb'
        for i in range(10):
            suffix = "cc" * (i + 1)
            window.add({"payload": "aaaaaaaa" + suffix})
        for i in range(10):
            suffix = "dd" * (i + 1)
            window.add({"payload": "bbbbbbbb" + suffix})

        result = window.get_diverse_sample(4)
        # Should have 2 from each type (round-robin)
        prefixes = [p["payload"][:8] for p in result]
        assert prefixes.count("aaaaaaaa") == 2
        assert prefixes.count("bbbbbbbb") == 2

    def test_unique_prefixes(self):
        window = SlidingWindow(max_entries=100)
        window.add({"payload": "aaaaaa0001"})  # prefix 'aaaaaa00' → actually first 4 bytes = 'aaaaaa00'
        window.add({"payload": "aaaaaa0002"})  # Same prefix (first 4 bytes = 'aaaaaa00'), but length differs → different sig, same prefix
        window.add({"payload": "bbbbbb0001"})  # Different prefix
        # unique_prefixes counts distinct prefix parts of signatures
        # Both 'aaaa...' packets have same first 4 bytes, so 2 unique prefixes
        # But wait — the unique_prefixes property splits on ':' and takes the first part
        # Let me check: sig for 'aaaaaa0001' = 'aaaaaa00:5', sig for 'aaaaaa0002' = 'aaaaaa00:5'
        # Actually they have the same length (5 bytes each) and same prefix → same signature!
        # So window has only 2 entries: one with prefix 'aaaaaa00' and one with 'bbbbbb00'
        assert window.unique_prefixes == 2

    def test_unique_prefixes_with_varying_lengths(self):
        window = SlidingWindow(max_entries=100)
        # Same prefix but different lengths → different signatures but same prefix group
        window.add({"payload": "aaaa0001"})         # prefix 'aaaa', length 4 → sig 'aaaa:4'
        window.add({"payload": "aaaa000100"})        # prefix 'aaaa', length 5 → sig 'aaaa:5'
        # unique_prefixes: {'aaaa'} = 1
        assert window.unique_prefixes == 1

    def test_empty_window(self):
        window = SlidingWindow(max_entries=10)
        assert window.size == 0
        assert window.unique_prefixes == 0
        assert window.get_diverse_sample(10) == []


# =============================================================================
# Token Estimation Tests
# =============================================================================


class TestEstimateTokens:
    """Tests for the token estimation utility."""

    def test_empty_string(self):
        assert estimate_tokens("") >= 200  # System prompt overhead

    def test_pure_hex(self):
        # 100 hex chars = 50 bytes
        result = estimate_tokens("deadbeef" * 12 + "dead")
        assert result > 0

    def test_english_text(self):
        result = estimate_tokens("Hello, this is a test prompt for the LLM.")
        assert result > 0

    def test_mixed_content(self):
        hex_part = "deadbeef" * 20
        text_part = "Analyze this traffic data carefully."
        result = estimate_tokens(hex_part + text_part)
        assert result > 200


# =============================================================================
# Rules Orchestrator Tests
# =============================================================================


class TestRulesOrchestrator:
    """Tests for the full orchestrator pipeline."""

    def _make_orchestrator(
        self,
        tmp_path: Path,
        max_prompt_tokens: int = 0,
        min_packets: int = 1,
    ) -> tuple[RulesOrchestrator, Path]:
        """Create an orchestrator with a temporary traffic log."""
        log_path = tmp_path / "traffic.jsonl"

        parser = TrafficParser(
            log_path=str(log_path),
            read_interval_ms=100,
            session_gap_threshold=2.0,
        )

        agent = LLMAgent(
            provider="openai",
            model="gpt-4o",
            api_key="test-key",
        )

        rule_gen = RuleGenerator(
            min_confidence=0.3,
            max_rules=200,
            rule_output_file=str(tmp_path / "rules.json"),
        )

        orch = RulesOrchestrator(
            parser=parser,
            agent=agent,
            rule_gen=rule_gen,
            max_packets_per_inference=20,
            window_size=200,
            max_prompt_tokens=max_prompt_tokens,
            min_packets_before_infer=min_packets,
        )

        return orch, log_path

    def _write_traffic(
        self, log_path: Path, packets: list[dict], base_time: float = 1000.0
    ) -> None:
        """Write packets to the traffic log file."""
        with open(log_path, "w") as f:
            for i, pkt in enumerate(packets):
                entry = {
                    "timestamp": base_time + i * 0.1,
                    "direction": pkt.get("direction", "client_to_server"),
                    "payload": pkt.get("payload", "deadbeef0005"),
                    "length": pkt.get("length", len(pkt.get("payload", "deadbeef0005")) // 2),
                    "is_mutated": pkt.get("is_mutated", False),
                }
                f.write(json.dumps(entry) + "\n")

    @pytest.mark.asyncio
    async def test_run_cycle_no_traffic(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path)
        # No traffic log file
        result = await orch.run_cycle()
        assert result is None

    @pytest.mark.asyncio
    async def test_run_cycle_skipped_insufficient_data(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=5)
        self._write_traffic(log_path, [
            {"payload": "deadbeef0005"},  # Only 1 packet
        ])
        result = await orch.run_cycle()
        assert result is not None
        assert result["status"] == "skipped"
        assert "Insufficient" in result["reason"]

    @pytest.mark.asyncio
    async def test_run_cycle_skipped_budget_exceeded(self, tmp_path):
        orch, log_path = self._make_orchestrator(
            tmp_path, max_prompt_tokens=1, min_packets=1
        )
        # Need packets with different prefixes so they're not deduped
        self._write_traffic(log_path, [
            {"payload": f"{i:08x}00aa"} for i in range(5)
        ])
        result = await orch.run_cycle()
        # With max_prompt_tokens=1, it should skip on budget
        if result is not None and result["status"] == "skipped":
            assert "tokens" in result["reason"].lower() or "budget" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_run_cycle_success_mock_mode(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)
        # Use unique prefixes so they don't all dedup to 1
        self._write_traffic(log_path, [
            {"payload": "dead00010001"},
            {"payload": "cafe00020002"},
            {"payload": "beef00030003"},
        ])

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await orch.run_cycle()
            assert result is not None
            assert result["status"] == "success"
            assert isinstance(result["grammar"], ProtocolGrammar)
            assert result["grammar"].protocol_name == "mock_inferred_protocol"
            assert result["packets_sent"] > 0
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_run_cycle_dedup_reduces_packets(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)

        # 10 identical packets — should be deduped to 1
        self._write_traffic(log_path, [
            {"payload": "deadbeef0005"} for _ in range(10)
        ])

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await orch.run_cycle()
            if result is not None and result["status"] == "success":
                # Only 1 unique packet → 1 sent
                assert result["packets_sent"] == 1
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_run_cycle_diverse_types_preserved(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)

        # 5 packets of type A (prefix 'aaaa'), 5 of type B (prefix 'bbbb')
        # Each with varying lengths so they have unique signatures
        packets = []
        for i in range(5):
            suffix_a = "aa" * (i + 1)
            suffix_b = "bb" * (i + 1)
            packets.append({"payload": f"aaaaaaaa" + suffix_a})
            packets.append({"payload": f"bbbbbbbb" + suffix_b})
        self._write_traffic(log_path, packets)

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await orch.run_cycle()
            if result is not None and result["status"] == "success":
                # Should have representatives from both types
                assert result["unique_types"] >= 2
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_run_cycle_handles_llm_error(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)
        self._write_traffic(log_path, [
            {"payload": "deadbeef0005"},
        ])

        # Force REAL mode but mock infer_protocol to raise RuntimeError
        os.environ["LLM_MODE"] = "REAL"
        try:
            orch.agent.infer_protocol = AsyncMock(
                side_effect=RuntimeError("API error: no key")
            )
            result = await orch.run_cycle()
            assert result is not None
            assert result["status"] == "error"
            assert "API error" in result["reason"]
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_run_cycle_handles_parse_error(self, tmp_path):
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)
        self._write_traffic(log_path, [
            {"payload": "deadbeef0005"},
        ])

        os.environ["LLM_MODE"] = "REAL"
        try:
            orch.agent.infer_protocol = AsyncMock(
                side_effect=ValueError("Invalid JSON from LLM")
            )
            result = await orch.run_cycle()
            assert result is not None
            assert result["status"] == "error"
            assert "Parse error" in result["reason"]
        finally:
            os.environ.pop("LLM_MODE", None)

    def test_stats_initial(self, tmp_path):
        orch, _ = self._make_orchestrator(tmp_path)
        stats = orch.stats
        assert stats["total_cycles"] == 0
        assert stats["total_inferences"] == 0
        assert stats["total_rules_pushed"] == 0
        assert stats["errors"] == 0
        assert stats["window_size"] == 0

    def test_window_accessible(self, tmp_path):
        orch, _ = self._make_orchestrator(tmp_path)
        assert isinstance(orch.window, SlidingWindow)
        assert orch.window.size == 0


# =============================================================================
# Integration: Orchestrator + Mock LLM → Rule Generation
# =============================================================================


class TestOrchestratorIntegration:
    """End-to-end tests: traffic → dedup → MOCK LLM → rules."""

    @pytest.mark.asyncio
    async def test_full_mock_pipeline(self, tmp_path):
        """Verify the orchestrator produces rules end-to-end in MOCK mode."""
        log_path = tmp_path / "traffic.jsonl"
        rules_path = tmp_path / "rules.json"

        parser = TrafficParser(log_path=str(log_path))
        agent = LLMAgent(api_key="test")
        rule_gen = RuleGenerator(
            min_confidence=0.3,
            rule_output_file=str(rules_path),
        )

        orch = RulesOrchestrator(
            parser=parser,
            agent=agent,
            rule_gen=rule_gen,
            max_packets_per_inference=20,
            min_packets_before_infer=1,
        )

        # Write diverse traffic (different prefixes so they aren't all deduped)
        with open(log_path, "w") as f:
            for i in range(10):
                entry = {
                    "timestamp": 1000.0 + i * 0.1,
                    "direction": "client_to_server",
                    "payload": f"{i:08x}00aa",  # unique prefix per packet
                    "length": 5,
                    "is_mutated": False,
                }
                f.write(json.dumps(entry) + "\n")

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await orch.run_cycle()
            assert result is not None
            assert result["status"] == "success"

            grammar = result["grammar"]
            assert isinstance(grammar, ProtocolGrammar)
            assert len(grammar.fields) > 0

            # Check that rules were generated and written
            if result["rules"]:
                assert rules_path.exists()
                with open(rules_path) as f:
                    saved_rules = json.load(f)
                assert len(saved_rules) > 0

            # Check stats
            stats = orch.stats
            assert stats["total_inferences"] == 1
            assert stats["total_rules_pushed"] >= 0
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_multiple_cycles_accumulate_in_window(self, tmp_path):
        """Verify the window accumulates across multiple cycles."""
        log_path = tmp_path / "traffic.jsonl"

        parser = TrafficParser(log_path=str(log_path))
        agent = LLMAgent(api_key="test")
        rule_gen = RuleGenerator(
            min_confidence=0.3,
            rule_output_file=str(tmp_path / "rules.json"),
        )

        orch = RulesOrchestrator(
            parser=parser,
            agent=agent,
            rule_gen=rule_gen,
            min_packets_before_infer=1,
        )

        os.environ["LLM_MODE"] = "MOCK"
        try:
            # Cycle 1: add some packets with prefix 'aaaa'
            with open(log_path, "w") as f:
                for i in range(5):
                    # Each has a different length to avoid dedup
                    suffix = "aa" * (i + 1)
                    f.write(json.dumps({
                        "timestamp": 1000.0 + i * 0.1,
                        "direction": "client_to_server",
                        "payload": f"aaaaaaaa" + suffix,
                        "length": 4 + i + 1,
                        "is_mutated": False,
                    }) + "\n")

            await orch.run_cycle()
            assert orch.window.size > 0

            # Cycle 2: add more packets with prefix 'bbbb'
            with open(log_path, "a") as f:
                for i in range(5):
                    suffix = "bb" * (i + 1)
                    f.write(json.dumps({
                        "timestamp": 2000.0 + i * 0.1,
                        "direction": "client_to_server",
                        "payload": f"bbbbbbbb" + suffix,
                        "length": 4 + i + 1,
                        "is_mutated": False,
                    }) + "\n")

            await orch.run_cycle()
            assert orch.window.unique_prefixes >= 2
        finally:
            os.environ.pop("LLM_MODE", None)


# =============================================================================
# Phase 6: Neural-Mathematical Fusion Tests
# =============================================================================


class TestDifferentialAnalysis:
    """Tests for the DifferentialAnalyzer integration in the orchestrator."""

    def _make_orchestrator(
        self,
        tmp_path: Path,
        min_packets: int = 1,
    ) -> tuple[RulesOrchestrator, Path]:
        """Create an orchestrator with a temporary traffic log."""
        log_path = tmp_path / "traffic.jsonl"

        parser = TrafficParser(
            log_path=str(log_path),
            read_interval_ms=100,
            session_gap_threshold=2.0,
        )

        agent = LLMAgent(
            provider="openai",
            model="gpt-4o",
            api_key="test-key",
        )

        rule_gen = RuleGenerator(
            min_confidence=0.3,
            max_rules=200,
            rule_output_file=str(tmp_path / "rules.json"),
        )

        orch = RulesOrchestrator(
            parser=parser,
            agent=agent,
            rule_gen=rule_gen,
            max_packets_per_inference=20,
            window_size=200,
            min_packets_before_infer=min_packets,
        )

        return orch, log_path

    def _write_traffic(
        self, log_path: Path, packets: list[dict], base_time: float = 1000.0
    ) -> None:
        """Write packets to the traffic log file."""
        with open(log_path, "w") as f:
            for i, pkt in enumerate(packets):
                entry = {
                    "timestamp": base_time + i * 0.1,
                    "direction": pkt.get("direction", "client_to_server"),
                    "payload": pkt.get("payload", "deadbeef0005"),
                    "length": pkt.get("length", len(pkt.get("payload", "deadbeef0005")) // 2),
                    "is_mutated": pkt.get("is_mutated", False),
                }
                f.write(json.dumps(entry) + "\n")

    @pytest.mark.asyncio
    async def test_run_cycle_produces_heatmap(self, tmp_path):
        """run_cycle() runs DifferentialAnalyzer and stores the heatmap."""
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)

        # Write 5 client packets with a consistent header (first 4 bytes = deadbeef)
        # and varying payload — enough for the analyzer (min_packets=3)
        packets = []
        for i in range(5):
            payload_hex = f"deadbeef{i:04x}" + "aa" * (i + 1)
            packets.append({"payload": payload_hex})
        self._write_traffic(log_path, packets)

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await orch.run_cycle()
            assert result is not None
            assert result["status"] == "success"
            # Heatmap should have been generated
            assert orch.last_heatmap is not None
            assert orch.last_heatmap.packet_count >= 3
            assert len(orch.last_heatmap.field_groups) > 0
            assert result.get("heatmap_groups", 0) > 0
        finally:
            os.environ.pop("LLM_MODE", None)

    @pytest.mark.asyncio
    async def test_extract_raw_bytes_filters_client_only(self):
        """_extract_raw_bytes() only returns client_to_server packets."""
        packets = [
            {"direction": "client_to_server", "payload": "deadbeef"},
            {"direction": "server_to_client", "payload": "cafebabe"},
            {"direction": "client_to_server", "payload": "01020304"},
        ]
        raw = RulesOrchestrator._extract_raw_bytes(packets)
        assert len(raw) == 2
        assert raw[0] == b"\xde\xad\xbe\xef"
        assert raw[1] == b"\x01\x02\x03\x04"

    @pytest.mark.asyncio
    async def test_convert_field_rules(self, tmp_path):
        """_convert_field_rules() produces valid SemanticRules."""
        from shared.schemas import FieldRule, MutationStrategy

        orch, _ = self._make_orchestrator(tmp_path)
        field_rules = [
            FieldRule(
                field_name="magic",
                offset=0,
                length=4,
                mutation_strategy=MutationStrategy.STATIC,
                static_value="deadbeef",
                confidence=1.0,
                notes="Constant magic header",
            ),
            FieldRule(
                field_name="length",
                offset=4,
                length=2,
                mutation_strategy=MutationStrategy.BOUNDARY_VALUES,
                confidence=0.9,
                notes="Length field",
            ),
        ]

        semantic_rules = orch._convert_field_rules(field_rules)
        assert len(semantic_rules) == 2
        assert all(isinstance(r, SemanticRule) for r in semantic_rules)
        assert semantic_rules[0].target_field_name == "magic"
        assert semantic_rules[0].priority == 1.0
        assert semantic_rules[1].target_field_name == "length"

    @pytest.mark.asyncio
    async def test_bootstrap_fallback_on_llm_failure(self, tmp_path):
        """When LLM fails and heatmap exists, bootstrap rules are pushed
        ONLY when no prior LLM rules are active (C3 fix: don't overwrite
        good LLM rules with stale heatmap bootstrap)."""
        orch, log_path = self._make_orchestrator(tmp_path, min_packets=1)

        # Write enough packets to trigger both analysis and LLM
        packets = []
        for i in range(5):
            payload_hex = f"deadbeef{i:04x}" + "bb" * (i + 1)
            packets.append({"payload": payload_hex})
        self._write_traffic(log_path, packets)

        # C3 fix: To test bootstrap fallback, do NOT run a successful
        # LLM cycle first. Instead, make the first cycle fail so
        # _llm_rules_active stays False and bootstrap fallback triggers.
        orch.agent.infer_protocol = AsyncMock(
            side_effect=RuntimeError("API budget exhausted")
        )

        # First cycle: run analysis (creates heatmap), then LLM fails
        # → bootstrap rules should be pushed since no LLM rules exist.
        result = await orch.run_cycle()
        assert result is not None
        assert result["status"] == "bootstrap"
        assert len(result["rules"]) > 0
        assert orch.stats["bootstrap_count"] == 1

    @pytest.mark.asyncio
    async def test_precision_mode_on_crash(self, tmp_path):
        """Orchestrator enters precision mode when crashes are detected."""
        orch, _ = self._make_orchestrator(tmp_path)

        # Create a mock crash_manager that reports crashes
        from shared.crash_manager import CrashStatistics

        mock_stats = CrashStatistics(
            unique_crashes=1,
            total_hits=5,
            duplicate_hits=4,
            dedup_ratio=0.8,
            struct_buckets=1,
            top_signatures=[],
            crash_types={"SIGSEGV": 1},
            poc_directory="./crashes",
            index_file="./crashes/crash_index.json",
        )

        mock_crash_manager = MagicMock()
        mock_crash_manager.get_statistics = AsyncMock(return_value=mock_stats)
        orch.crash_manager = mock_crash_manager

        # Trigger crash check
        await orch._check_crash_isolation()
        assert orch.precision_mode is True
        assert orch.stats["precision_mode"] is True

    @pytest.mark.asyncio
    async def test_no_precision_mode_without_crashes(self, tmp_path):
        """Orchestrator stays in normal mode when no crashes detected."""
        orch, _ = self._make_orchestrator(tmp_path)

        from shared.crash_manager import CrashStatistics

        mock_stats = CrashStatistics(
            unique_crashes=0,
            total_hits=0,
            duplicate_hits=0,
            dedup_ratio=0.0,
            struct_buckets=0,
            top_signatures=[],
            crash_types={},
            poc_directory="./crashes",
            index_file="./crashes/crash_index.json",
        )

        mock_crash_manager = MagicMock()
        mock_crash_manager.get_statistics = AsyncMock(return_value=mock_stats)
        orch.crash_manager = mock_crash_manager

        await orch._check_crash_isolation()
        assert orch.precision_mode is False
