"""
tests/conftest.py
─────────────────
Shared pytest fixtures for the LIFA-Fuzz test suite.

Provides reusable fixtures for:
    - Sample traffic records
    - Sample semantic rules
    - Mock LLM responses
    - Temporary directories for log files
"""

import pytest
import asyncio
from pathlib import Path

from shared.schemas import (
    ActiveRuleSet,
    CrashRecord,
    Direction,
    FieldType,
    MutationConstraints,
    ProtocolGrammar,
    RuleType,
    SemanticRule,
    TrafficRecord,
)


# =============================================================================
# Fixtures: Traffic Records
# =============================================================================


@pytest.fixture
def sample_raw_packet() -> bytes:
    """A realistic-looking protocol packet: magic + length + payload."""
    # Magic: DEADBEEF, Length: 000B (11), Payload: "HELLO_WORLD"
    return bytes.fromhex("DEADBEEF0B00000048454C4C4F5F574F524C44")


@pytest.fixture
def sample_traffic_record(sample_raw_packet: bytes) -> TrafficRecord:
    """A single TrafficRecord with the sample packet."""
    return TrafficRecord(
        direction=Direction.CLIENT_TO_SERVER,
        raw_data=sample_raw_packet,
        session_id="test001",
    )


@pytest.fixture
def multiple_traffic_records(sample_raw_packet: bytes) -> list[TrafficRecord]:
    """A batch of traffic records for testing batch operations."""
    records = []
    for i in range(10):
        records.append(
            TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=sample_raw_packet,
                session_id=f"test_{i:03d}",
            )
        )
    return records


# =============================================================================
# Fixtures: Semantic Rules
# =============================================================================


@pytest.fixture
def sample_rule() -> SemanticRule:
    """A sample semantic rule targeting the length field."""
    return SemanticRule(
        rule_id="test_rule_001",
        rule_type=RuleType.BOUNDARY,
        offset_start=4,
        offset_end=6,
        target_field_name="header_length",
        field_type=FieldType.UINT16_LE,
        constraints=MutationConstraints(min_value=0, max_value=65535),
        preserve_bytes=b"\xDE\xAD\xBE\xEF",
        priority=0.8,
        description="Fuzz the 2-byte length field at offset 4",
    )


@pytest.fixture
def sample_active_rule_set(sample_rule: SemanticRule) -> ActiveRuleSet:
    """An ActiveRuleSet containing the sample rule."""
    rule_set = ActiveRuleSet()
    rule_set.add_rules([sample_rule])
    return rule_set


# =============================================================================
# Fixtures: Protocol Grammar
# =============================================================================


@pytest.fixture
def sample_grammar() -> ProtocolGrammar:
    """A sample inferred protocol grammar."""
    return ProtocolGrammar(
        protocol_name="test_protocol",
        description="A simple protocol with magic + length + payload",
        magic_bytes="DEADBEEF",
        total_header_size=6,
        confidence=0.85,
    )


# =============================================================================
# Fixtures: Crash Record
# =============================================================================


@pytest.fixture
def sample_crash_record(sample_raw_packet: bytes) -> CrashRecord:
    """A crash record for testing."""
    return CrashRecord(
        exit_code=139,
        offending_packet=sample_raw_packet,
    )


# =============================================================================
# Fixtures: Async
# =============================================================================


@pytest.fixture
def event_loop():
    """Provide a fresh event loop for each async test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Fixtures: Temp Dirs
# =============================================================================


@pytest.fixture
def tmp_log_dir(tmp_path: Path) -> Path:
    """Temporary directory for traffic log files."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def tmp_rules_file(tmp_path: Path) -> Path:
    """Temporary file path for rule set JSON."""
    return tmp_path / "rules.json"


@pytest.fixture
def tmp_traffic_log(tmp_path: Path) -> Path:
    """Temporary file path for traffic log."""
    return tmp_path / "traffic.log"
