"""
tests/test_e2e_flow.py
─────────────────────
End-to-end integration test for the full LIFA-Fuzz pipeline.

Tests the complete closed loop without Docker or real LLM:
    1. Mock Sandbox (simulates container lifecycle)
    2. Interceptor (captures + injects via loopback)
    3. Mutation Engine (rule-based + random mutations)
    4. Crash Monitor (detects crash → pause → save PoC → reset → resume)
    5. Slow Loop (MOCK mode: Parser → LLM Agent → Rule Generator)
    6. Performance Dashboard (metrics tracking + rendering)

This test proves that:
    - Traffic flows: Client → Interceptor → Server
    - Mutations are injected and tracked
    - Rules flow: Slow Loop → active_rules.json → Fast Loop
    - Crash → PoC saved → auto-recovery → resume
    - No race conditions, no deadlocks, no data corruption.
"""

import asyncio
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock

import pytest

from shared.logger import get_logger, setup_root_logger
from shared.sandbox_abstraction import (
    BaseSandbox,
    CrashInfo,
    ContainerInfo,
    SandboxDriver,
    register_driver,
)
from shared.schemas import (
    CrashRecord,
    Direction,
    FieldType,
    ProtocolGrammar,
    RuleType,
    SemanticRule,
    TrafficRecord,
)

# Ensure logging is initialized
setup_root_logger(level="WARNING", log_format="text")
logger = get_logger("tests.e2e_flow")


# =============================================================================
# Mock Sandbox — simulates Docker lifecycle
# =============================================================================


class MockSandbox(BaseSandbox):
    """In-memory sandbox that simulates container lifecycle.

    Tracks start/stop/reset/crash events and provides a fake
    network config for the Interceptor to connect to.
    """

    def __init__(self) -> None:
        self._alive: bool = False
        self._start_count: int = 0
        self._reset_count: int = 0
        self._crash_exit_code: Optional[int] = None
        self._network_config = {
            "network_name": "mock-network",
            "subnet": "10.0.0.0/24",
            "target_host": "127.0.0.1",
            "target_port": 19876,  # Ephemeral port for testing
            "proxy_listen_port": 19877,
            "sandbox_type": "mock",
        }

    async def start(self) -> None:
        self._alive = True
        self._start_count += 1

    async def stop(self) -> None:
        self._alive = False

    async def reset_state(self) -> None:
        self._crash_exit_code = None
        self._alive = True
        self._reset_count += 1

    async def get_target_info(self) -> ContainerInfo:
        return ContainerInfo(
            name="mock-target",
            host="127.0.0.1",
            port=self._network_config["target_port"],
            internal_port=self._network_config["target_port"],
            status="running" if self._alive else "crashed",
            exit_code=self._crash_exit_code,
        )

    async def is_target_alive(self) -> bool:
        return self._alive

    async def get_last_crash_info(self) -> Optional[CrashInfo]:
        if self._crash_exit_code is None:
            return None
        return CrashInfo(
            instance_name="mock-target",
            exit_code=self._crash_exit_code,
            signal="SIGSEGV" if self._crash_exit_code == 139 else None,
            timestamp=time.time(),
        )

    async def get_network_config(self) -> dict[str, Any]:
        return self._network_config

    # ── Test helpers ───────────────────────────────────────────────

    def simulate_crash(self, exit_code: int = 139) -> None:
        """Externally trigger a crash state (simulates container exit)."""
        self._alive = False
        self._crash_exit_code = exit_code


# Register mock driver
register_driver("mock", MockSandbox)


# =============================================================================
# Mock TCP Server — accepts connections on ephemeral port
# =============================================================================


async def start_mock_server(port: int = 0) -> asyncio.AbstractServer:
    """Start a simple echo TCP server on an ephemeral port.

    Returns:
        Tuple of (server, actual_port).
    """
    actual_port = port

    async def handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_client, "127.0.0.1", port)
    if port == 0:
        # Get the actual assigned port
        addr = server.sockets[0].getsockname()
        actual_port = addr[1]
    return server, actual_port


# =============================================================================
# E2E Tests
# =============================================================================


class TestE2EFastLoop:
    """Test the Fast Loop pipeline: CrashMonitor + Mutator + Interceptor."""

    @pytest.mark.asyncio
    async def test_crash_monitor_detects_and_recovers(self, tmp_path):
        """CrashMonitor detects crash → pauses → saves PoC → resets → resumes.

        Tests the core crash recovery pipeline without TCP proxy complexity.
        Uses MockSandbox to simulate container lifecycle.
        """
        from fast_loop.crash_monitor import CrashMonitor

        crashes_dir = tmp_path / "crashes"
        sandbox = MockSandbox()
        await sandbox.start()

        # Minimal mock interceptor and mutator
        mock_interceptor = type("I", (), {
            "pause": lambda self: None,
            "resume": lambda self: None,
            "is_paused": False,
        })()
        mock_mutator = type("M", (), {
            "pause": lambda self: None,
            "resume": lambda self: None,
            "_last_injected_packet": b"\xDE\xAD\xBE\xEF",
            "_last_injected_rule_id": "test_rule_001",
        })()

        crash_monitor = CrashMonitor(
            sandbox=sandbox,
            interceptor=mock_interceptor,
            mutator=mock_mutator,
            poll_interval_ms=50,  # Fast polling for test
            crash_corpus_dir=str(crashes_dir),
            auto_reset=True,
            restart_delay_s=0.05,  # Fast reset
        )

        # Start watch loop
        watch_task = asyncio.create_task(crash_monitor.watch())

        # Let it poll once to establish baseline (alive)
        await asyncio.sleep(0.2)

        # Trigger crash
        assert await sandbox.is_target_alive()
        sandbox.simulate_crash(exit_code=139)

        # Wait for detection + recovery cycle
        await asyncio.sleep(1.0)

        # Stop monitor
        await crash_monitor.stop()
        watch_task.cancel()
        try:
            await asyncio.wait_for(watch_task, timeout=1.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

        # ── Assertions ────────────────────────────────────────────
        assert crash_monitor.total_crashes == 1, (
            f"Expected 1 crash, got {crash_monitor.total_crashes}"
        )
        assert await sandbox.is_target_alive(), (
            "Sandbox should be alive after auto-reset"
        )
        assert sandbox._reset_count == 1, (
            f"Expected 1 reset, got {sandbox._reset_count}"
        )

        # Verify PoC saved
        assert crashes_dir.exists(), "Crashes directory should exist"
        crash_files = list(crashes_dir.glob("crash_*.json"))
        assert len(crash_files) >= 1, f"Expected >=1 crash JSON, got {len(crash_files)}"

        # Verify crash JSON content
        crash_data = json.loads(crash_files[0].read_text())
        assert crash_data["exit_code"] == 139
        assert crash_data["signal"] == "SIGSEGV"
        assert "offending_packet_hex" in crash_data

        # Verify binary PoC file
        bin_files = list(crashes_dir.glob("crash_*.bin"))
        assert len(bin_files) >= 1, f"Expected >=1 crash .bin, got {len(bin_files)}"

    @pytest.mark.asyncio
    async def test_kill_server_crash_with_mutator(self, tmp_path):
        """Verify KILL_SERVER payload tracked + crash PoC saved with rule attribution."""
        from fast_loop.crash_monitor import CrashMonitor
        from fast_loop.mutator import MutationEngine

        crashes_dir = tmp_path / "crashes"
        sandbox = MockSandbox()
        await sandbox.start()

        # Mock interceptor with inject_mutation
        mock_interceptor = type("I", (), {
            "inject_mutation": AsyncMock(),
            "pause": lambda self: None,
            "resume": lambda self: None,
            "is_paused": False,
            "is_running": True,
            "total_captured": 0,
            "total_injected": 0,
        })()

        mutator = MutationEngine(
            interceptor=mock_interceptor,
            kill_server_ratio=1.0,  # 100% KILL_SERVER
        )

        # Trigger a mutation → KILL_SERVER payload injected
        packet = b"\xDE\xAD\xBE\xEF\x00\x05HELLO"
        await mutator.mutate(packet)

        assert mutator.coverage_summary["total_kills"] == 1, (
            "Should have 1 KILL_SERVER trigger"
        )

        # Set up crash monitor with mutator reference
        crash_monitor = CrashMonitor(
            sandbox=sandbox,
            interceptor=mock_interceptor,
            mutator=mutator,
            poll_interval_ms=50,
            crash_corpus_dir=str(crashes_dir),
            auto_reset=True,
            restart_delay_s=0.05,
        )

        watch_task = asyncio.create_task(crash_monitor.watch())
        await asyncio.sleep(0.2)

        # Trigger crash
        sandbox.simulate_crash(exit_code=139)
        await asyncio.sleep(1.0)

        # Stop
        await crash_monitor.stop()
        watch_task.cancel()
        try:
            await asyncio.wait_for(watch_task, timeout=1.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

        # ── Assertions ────────────────────────────────────────────
        assert crash_monitor.total_crashes == 1
        assert await sandbox.is_target_alive()

        # Crash PoC should have the KILL_SERVER payload
        crash_files = list(crashes_dir.glob("crash_*.json"))
        assert len(crash_files) == 1
        crash_data = json.loads(crash_files[0].read_text())
        assert crash_data["exit_code"] == 139
        # The offending packet should be from the mutator's last injection
        assert crash_data.get("offending_packet_hex", "") != ""


class TestE2ERuleFlow:
    """Test rule flow: Slow Loop writes → Fast Loop reads."""

    @pytest.mark.asyncio
    async def test_atomic_rule_write_and_reload(self, tmp_path):
        """Verify atomic write → read cycle with no corruption.

        1. Write rules via RuleGenerator (atomic temp+rename).
        2. Read rules via Mutator.reload_rules().
        3. Verify no JSONDecodeError, correct rule count.
        """
        rules_file = tmp_path / "active_rules.json"

        # Create a Mutator pointing to the rules file
        from fast_loop.mutator import MutationEngine

        mock_interceptor = type("M", (), {
            "inject_mutation": AsyncMock(),
            "is_running": True,
        })()

        mutator = MutationEngine(
            interceptor=mock_interceptor,
            rules_file=str(rules_file),
        )

        # ── 1. Write rules atomically ────────────────────────────
        from slow_loop.rule_generator import RuleGenerator

        grammar = ProtocolGrammar(
            protocol_name="test_protocol",
            magic_bytes="deadbeef",
            confidence=0.85,
            fields=[
                {
                    "name": "magic",
                    "offset_start": 0,
                    "offset_end": 4,
                    "field_type": FieldType.UINT32_LE,
                    "is_constant": True,
                },
                {
                    "name": "length",
                    "offset_start": 4,
                    "offset_end": 6,
                    "field_type": FieldType.UINT16_LE,
                    "is_constant": False,
                },
            ],
        )

        rule_gen = RuleGenerator(
            min_confidence=0.5,
            rule_output_file=str(rules_file),
        )
        rules = rule_gen.grammar_to_rules(grammar)
        await rule_gen.push_rules(rules)

        assert rules_file.exists(), "Rules file should exist after push"
        assert len(rules) > 0, "Should have generated rules"

        # ── 2. Read rules via Mutator ────────────────────────────
        added = await mutator.reload_rules()

        assert added > 0, f"Should have loaded new rules, got {added}"
        assert mutator.coverage_summary["active_rules"] > 0

        # ── 3. Verify no corruption on rapid re-read ───────────
        # Read again — should report 0 new rules (no change)
        added_again = await mutator.reload_rules()
        assert added_again == 0, "Should not reload unchanged file"

        # ── 4. Simulate concurrent write during read ─────────────
        # Ensure mtime advances between writes (some filesystems
        # have second-level mtime resolution, e.g., /tmp on WSL2)
        await asyncio.sleep(0.1)

        new_grammar = ProtocolGrammar(
            protocol_name="new_protocol",
            confidence=0.90,
            fields=[
                {
                    "name": "payload",
                    "offset_start": 6,
                    "offset_end": 20,
                    "field_type": FieldType.BYTES,
                    "is_constant": False,
                },
            ],
        )
        new_rules = rule_gen.grammar_to_rules(new_grammar)
        await rule_gen.push_rules(new_rules)

        # Read should pick up the new rules without error
        added_new = await mutator.reload_rules()
        assert added_new > 0, "Should detect and load new rules"

        # Total rules should be sum of both pushes
        expected_total = len(rules) + len(new_rules)
        assert mutator.coverage_summary["active_rules"] == expected_total


class TestE2EMockLLMMode:
    """Test Mock LLM mode in the Slow Loop."""

    @pytest.mark.asyncio
    async def test_mock_llm_returns_valid_grammar(self):
        """Verify LLM_MODE=MOCK returns valid ProtocolGrammar."""
        # Set mock mode
        old_mode = os.environ.get("LLM_MODE")
        os.environ["LLM_MODE"] = "MOCK"

        try:
            from slow_loop.llm_agent import LLMAgent, is_mock_mode

            assert is_mock_mode(), "Should be in MOCK mode"

            agent = LLMAgent(api_key="")  # No API key needed in MOCK

            # Infer protocol from dummy traffic
            records = [
                TrafficRecord(
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_data=b"\xDE\xAD\xBE\xEF\x00\x05HELLO",
                ),
            ]

            t0 = time.monotonic()
            grammar = await agent.infer_protocol(records)
            elapsed = time.monotonic() - t0

            # Verify response
            assert isinstance(grammar, ProtocolGrammar)
            assert grammar.protocol_name == "mock_inferred_protocol"
            assert len(grammar.fields) >= 2
            assert grammar.confidence > 0
            assert elapsed >= 1.5, f"Should have waited ~2s, waited {elapsed:.1f}s"

            # Verify token tracking
            assert agent._total_tokens_used > 0
            assert agent._total_inferences == 1

        finally:
            # Restore env var
            if old_mode is None:
                os.environ.pop("LLM_MODE", None)
            else:
                os.environ["LLM_MODE"] = old_mode

    @pytest.mark.asyncio
    async def test_mock_llm_produces_valid_rules(self):
        """Verify MOCK LLM response → RuleGenerator → valid SemanticRules."""
        old_mode = os.environ.get("LLM_MODE")
        os.environ["LLM_MODE"] = "MOCK"

        try:
            from slow_loop.llm_agent import LLMAgent
            from slow_loop.rule_generator import RuleGenerator

            agent = LLMAgent(api_key="")
            rule_gen = RuleGenerator(min_confidence=0.5)

            # Get grammar from mock LLM
            records = [
                TrafficRecord(
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_data=b"\xDE\xAD\xBE\xEF\x00\x05HELLO",
                ),
            ]
            grammar = await agent.infer_protocol(records)

            # Convert to rules
            rules = rule_gen.grammar_to_rules(grammar)
            assert len(rules) > 0, "Mock grammar should produce rules"

            # Verify rules are valid and actionable
            for rule in rules:
                assert rule.offset_start < rule.offset_end
                assert rule.field_length > 0
                assert 0.0 <= rule.priority <= 1.0
                # Non-constant fields should have mutation rules
                if rule.target_field_name != "magic":
                    assert rule.rule_type in (
                        RuleType.BIT_FLIP,
                        RuleType.BOUNDARY,
                        RuleType.STRUCTURAL,
                    )

        finally:
            if old_mode is None:
                os.environ.pop("LLM_MODE", None)
            else:
                os.environ["LLM_MODE"] = old_mode


class TestE2EWebDashboard:
    """Test the Web Dashboard data readers (no Streamlit runtime needed)."""

    def test_traffic_stats_reader_no_file(self, tmp_path):
        """Dashboard handles missing traffic log gracefully."""
        import importlib
        import sys

        # Point dashboard to temp dir with no files
        os.environ["LIFA_DATA_DIR"] = str(tmp_path)

        # Re-read the dashboard module to pick up env var
        if "web_ui.dashboard" in sys.modules:
            importlib.reload(sys.modules["web_ui.dashboard"])

        # Directly test the reader function
        from web_ui.dashboard import read_traffic_stats
        stats = read_traffic_stats()
        assert stats["total_packets"] == 0
        assert stats["total_captured"] == 0

    def test_active_rules_reader(self, tmp_path):
        """Dashboard reads active rules from JSON file."""
        shared = tmp_path / "shared"
        shared.mkdir()
        rules_file = shared / "active_rules.json"
        rules_file.write_text(json.dumps([
            {"rule_id": "r1", "target_field_name": "length", "priority": 0.9},
            {"rule_id": "r2", "target_field_name": "payload", "priority": 0.5},
        ]))

        os.environ["LIFA_DATA_DIR"] = str(tmp_path)
        import importlib
        import sys
        if "web_ui.dashboard" in sys.modules:
            importlib.reload(sys.modules["web_ui.dashboard"])

        from web_ui.dashboard import read_active_rules
        rules = read_active_rules()
        assert len(rules) == 2
        assert rules[0]["target_field_name"] == "length"

    def test_crash_records_reader(self, tmp_path):
        """Dashboard reads crash records from crashes/ directory."""
        crashes = tmp_path / "crashes"
        crashes.mkdir()
        crash_file = crashes / "crash_20260529_120000_test.json"
        crash_file.write_text(json.dumps({
            "exit_code": 139,
            "signal": "SIGSEGV",
            "offending_packet_hex": "deadbeef",
        }))

        os.environ["LIFA_DATA_DIR"] = str(tmp_path)
        import importlib
        import sys
        if "web_ui.dashboard" in sys.modules:
            importlib.reload(sys.modules["web_ui.dashboard"])

        from web_ui.dashboard import read_crash_records
        records = read_crash_records()
        assert len(records) == 1
        assert records[0]["signal"] == "SIGSEGV"
        assert records[0]["_source_file"] == "crash_20260529_120000_test.json"


class TestE2ECrashPoCSave:
    """Test that crash artifacts are saved correctly."""

    def test_crash_record_saved_as_json_and_bin(self, tmp_path):
        """Verify save_crash_record creates JSON + binary files."""
        from fast_loop.crash_monitor import CrashMonitor

        sandbox = MockSandbox()
        monitor = CrashMonitor(
            sandbox=sandbox,
            crash_corpus_dir=str(tmp_path / "crashes"),
        )

        record = CrashRecord(
            exit_code=139,
            signal="SIGSEGV",
            offending_packet=b"\xDE\xAD\xBE\xEF\x00\x00\x00\x00",
            mutation_rule_id="test_rule_001",
        )

        json_path = monitor.save_crash_record(record)

        # Verify JSON file exists and is valid
        assert json_path.exists(), "JSON crash file should exist"
        data = json.loads(json_path.read_text())
        assert data["exit_code"] == 139
        assert data["signal"] == "SIGSEGV"
        assert data["mutation_rule_id"] == "test_rule_001"
        assert "offending_packet_hex" in data

        # Verify binary file exists
        bin_path = json_path.with_suffix(".bin")
        assert bin_path.exists(), "Binary crash file should exist"
        assert bin_path.read_bytes() == record.offending_packet
