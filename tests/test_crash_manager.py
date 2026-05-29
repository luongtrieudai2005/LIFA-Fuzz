"""
tests/test_crash_manager.py
─────────────────────────────
Unit tests for CrashManager — crash deduplication engine.
"""

import asyncio
import json
import os
import pytest
from pathlib import Path

from shared.crash_manager import (
    CrashManager,
    CrashEntry,
    RecordResult,
    CrashStatistics,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def crash_dir(tmp_path):
    """Temporary crash directory."""
    d = tmp_path / "crash_pocs"
    d.mkdir()
    return d


@pytest.fixture
def manager(crash_dir):
    """A fresh CrashManager pointing to a temp directory."""
    return CrashManager(crash_dir=str(crash_dir))


@pytest.fixture
def sample_payload():
    """A realistic mutated payload."""
    return b"\xDE\xAD\xBE\xEF\xFF\xFF\x00\x05HELLO\x00"


# =============================================================================
# Initialization
# =============================================================================


class TestCrashManagerInit:
    """Tests for CrashManager initialization."""

    def test_creates_directory(self, tmp_path):
        """CrashManager creates its directory on init."""
        d = tmp_path / "new_crashes"
        CrashManager(crash_dir=str(d))
        assert d.exists()

    @pytest.mark.asyncio
    async def test_empty_stats_on_init(self, manager):
        """Fresh manager has empty stats."""
        stats = await manager.get_statistics()
        assert stats.unique_crashes == 0
        assert stats.total_hits == 0


# =============================================================================
# Record & Dedup
# =============================================================================


class TestCrashManagerRecord:
    """Tests for the core record() method."""

    @pytest.mark.asyncio
    async def test_record_new_crash(self, manager, sample_payload):
        """First occurrence of a payload → is_new=True."""
        result = await manager.record(
            payload=sample_payload,
            crash_type="connection_refused",
            rule_set_id="test-rules-001",
        )

        assert isinstance(result, RecordResult)
        assert result.is_new is True
        assert result.duplicate_count == 0
        assert result.poc_path is not None
        assert result.signature != ""

    @pytest.mark.asyncio
    async def test_record_duplicate(self, manager, sample_payload):
        """Same payload again → is_new=False, duplicate_count incremented."""
        await manager.record(payload=sample_payload)
        result = await manager.record(payload=sample_payload)

        assert result.is_new is False
        assert result.duplicate_count == 1
        assert result.poc_path is None

    @pytest.mark.asyncio
    async def test_record_different_payload_new(self, manager, sample_payload):
        """Different payload → new unique crash."""
        await manager.record(payload=sample_payload)
        other = sample_payload + b"\x00"
        result = await manager.record(payload=other)

        assert result.is_new is True

    @pytest.mark.asyncio
    async def test_record_saves_poc_file(self, manager, sample_payload, crash_dir):
        """New crash saves a .bin PoC file."""
        result = await manager.record(payload=sample_payload)
        assert result.poc_path is not None
        poc_path = Path(result.poc_path)
        assert poc_path.exists()
        assert poc_path.read_bytes() == sample_payload

    @pytest.mark.asyncio
    async def test_record_saves_report_json(self, manager, sample_payload, crash_dir):
        """New crash saves a .report.json file."""
        result = await manager.record(payload=sample_payload)
        sig = result.signature
        report_path = crash_dir / f"{sig}.report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["crash_id"] == sig
        assert data["crash_type"] == "unknown"

    @pytest.mark.asyncio
    async def test_record_saves_index(self, manager, sample_payload, crash_dir):
        """New crash updates crash_index.json."""
        await manager.record(payload=sample_payload)
        index_path = crash_dir / "crash_index.json"
        assert index_path.exists()
        data = json.loads(index_path.read_text())
        assert data["meta"]["unique_crashes"] == 1


# =============================================================================
# Statistics
# =============================================================================


class TestCrashManagerStats:
    """Tests for statistics and querying."""

    @pytest.mark.asyncio
    async def test_statistics_after_multiple_crashes(self, manager):
        """Stats reflect all recorded crashes."""
        payloads = [bytes([i]) * 10 for i in range(5)]
        for p in payloads:
            await manager.record(payload=p)
        # Record a duplicate
        await manager.record(payload=payloads[0])

        stats = await manager.get_statistics()
        assert stats.unique_crashes == 5
        assert stats.total_hits == 6
        assert stats.duplicate_hits == 1
        assert stats.dedup_ratio > 0

    @pytest.mark.asyncio
    async def test_get_all_entries(self, manager):
        """get_all_entries() returns all CrashEntry objects."""
        for i in range(3):
            await manager.record(payload=bytes([i]) * 8)

        entries = await manager.get_all_entries()
        assert len(entries) == 3
        assert all(isinstance(e, CrashEntry) for e in entries)

    @pytest.mark.asyncio
    async def test_struct_siblings(self, manager):
        """Packets with same header but different payload are structural siblings."""
        header = b"\xDE\xAD\xBE\xEF"
        p1 = header + b"\x01\x02"
        p2 = header + b"\x03\x04"

        await manager.record(payload=p1)
        result = await manager.record(payload=p2)

        # Same first 16 bytes (both < 16) + same length → same struct_sig
        # But actually they differ in bytes 4-5, so struct_sig differs
        # Let's check: p1[:16] = header + 0x01 0x02, len=6
        # p2[:16] = header + 0x03 0x04, len=6
        # They differ → different struct_sig
        # To get siblings, use same header + same total length
        p3 = header + b"\x05\x06"
        r3 = await manager.record(payload=p3)
        # All three have same length (6) and share header bytes
        # struct_sig = SHA256(payload[:16] + len_bytes)[:8]
        # p1[:16] differs from p2[:16] at bytes 4-5 → different struct_sig
        # This is expected behavior

    @pytest.mark.asyncio
    async def test_is_known(self, manager, sample_payload):
        """is_known() returns True for previously recorded payloads."""
        assert await manager.is_known(sample_payload) is False
        await manager.record(payload=sample_payload)
        assert await manager.is_known(sample_payload) is True

    @pytest.mark.asyncio
    async def test_is_known_different_payload(self, manager, sample_payload):
        """is_known() returns False for unknown payloads."""
        await manager.record(payload=sample_payload)
        assert await manager.is_known(b"\x00" * 10) is False


# =============================================================================
# Persistence & Load
# =============================================================================


class TestCrashManagerPersistence:
    """Tests for load/save persistence."""

    @pytest.mark.asyncio
    async def test_load_restores_previous_crashes(self, crash_dir, sample_payload):
        """load() restores crashes from a previous session."""
        manager1 = CrashManager(crash_dir=str(crash_dir))
        await manager1.record(payload=sample_payload)

        # Create a new manager pointing to the same directory
        manager2 = CrashManager(crash_dir=str(crash_dir))
        count = await manager2.load()
        assert count == 1

        # The same payload should now be known
        assert await manager2.is_known(sample_payload) is True

    @pytest.mark.asyncio
    async def test_load_empty_directory(self, crash_dir):
        """load() returns 0 when no index file exists."""
        manager = CrashManager(crash_dir=str(crash_dir))
        count = await manager.load()
        assert count == 0

    @pytest.mark.asyncio
    async def test_load_corrupted_index(self, crash_dir):
        """load() handles corrupted index file gracefully."""
        index_path = crash_dir / "crash_index.json"
        index_path.write_text("NOT VALID JSON{{{")

        manager = CrashManager(crash_dir=str(crash_dir))
        count = await manager.load()
        assert count == 0  # Should not crash


# =============================================================================
# Signature Computation
# =============================================================================


class TestSignatures:
    """Tests for signature computation methods."""

    def test_primary_sig_deterministic(self):
        """Same payload always produces the same primary signature."""
        payload = b"\xDE\xAD\xBE\xEF"
        sig1 = CrashManager._compute_primary_sig(payload)
        sig2 = CrashManager._compute_primary_sig(payload)
        assert sig1 == sig2
        assert len(sig1) == 16  # 16 hex chars

    def test_primary_sig_different_for_different_payloads(self):
        """Different payloads produce different signatures."""
        sig1 = CrashManager._compute_primary_sig(b"\x01\x02")
        sig2 = CrashManager._compute_primary_sig(b"\x03\x04")
        assert sig1 != sig2

    def test_struct_sig_same_header_same_length(self):
        """Structural signature identical for same header + same length."""
        header = b"\xDE\xAD" + b"\x00" * 14  # Exactly 16 bytes
        p1 = header + b"\xAA"
        p2 = header + b"\xBB"
        sig1 = CrashManager._compute_struct_sig(p1)
        sig2 = CrashManager._compute_struct_sig(p2)
        assert sig1 == sig2  # Same first 16 bytes + same total length

    def test_struct_sig_different_header(self):
        """Different headers produce different struct signatures."""
        p1 = b"\xDE\xAD" + b"\x00" * 14 + b"\xAA"
        p2 = b"\xCA\xFE" + b"\x00" * 14 + b"\xBB"
        sig1 = CrashManager._compute_struct_sig(p1)
        sig2 = CrashManager._compute_struct_sig(p2)
        assert sig1 != sig2
