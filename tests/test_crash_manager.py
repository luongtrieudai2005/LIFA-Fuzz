"""
tests/test_crash_manager.py
─────────────────────────────
Unit tests for CrashManager — Two-Level Hybrid Structural Dedup engine.
"""

import asyncio
import hashlib
import json
import os
import random
import time
from collections import Counter

import pytest
from pathlib import Path

from shared.crash_manager import (
    CrashManager,
    CrashEntry,
    RecordResult,
    CrashStatistics,
    # Module-level signature functions
    compute_sigma1,
    compute_simple_fold,
    compute_sigma2,
    get_structural_key,
    batch_process_crashes,
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
        """Two payloads that share σ₂ but differ in σ₁ are structural siblings.

        64-byte layout (8 chunks × 8 bytes):
          chunk 0-2: header  (head24)
          chunk 3:   variable_a      ← swapped in p2
          chunk 4:   middle  (middle_8 at offset 32)
          chunk 5:   variable_b      ← swapped in p2
          chunk 6-7: tail

        Swapping chunks 3 & 5 keeps middle_8 identical and XOR fold
        identical (XOR is commutative) → same σ₂ but different σ₁.
        """
        header  = b"\x00" * 24
        chunk_a = b"\xAA" * 8
        middle  = b"\x11" * 8
        chunk_b = b"\xBB" * 8
        tail    = b"\x00" * 16

        p1 = header + chunk_a + middle + chunk_b + tail   # 64 bytes
        p2 = header + chunk_b + middle + chunk_a + tail   # chunks 3↔5

        assert p1 != p2

        r1 = await manager.record(payload=p1, crash_type="type_a")
        r2 = await manager.record(payload=p2, crash_type="type_a")

        assert r1.is_new is True
        assert r2.is_new is True
        assert r1.signature != r2.signature       # different σ₁
        assert r1.struct_sig == r2.struct_sig      # same σ₂ → siblings
        assert r1.signature in r2.struct_siblings

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

    @pytest.mark.asyncio
    async def test_load_migrates_old_v1_signatures(self, crash_dir):
        """load() migrates old 16-char v1 signatures to new 32-char v2 format.

        Simulates a crash_index.json written by the old SHA256[:16]-based code.
        The migration reads the .bin PoC file, recomputes v2 signatures, and
        renames the PoC + report files.
        """
        payload = b"\xDE\xAD\xBE\xEF" * 4  # 16 bytes
        old_sig = hashlib.sha256(payload).hexdigest()[:16]  # v1: 16 hex chars
        new_sig = hashlib.sha256(payload).digest()[:16].hex()  # v2: 32 hex chars

        # Write old-format PoC file
        old_poc = crash_dir / f"{old_sig}.bin"
        old_poc.write_bytes(payload)

        # Write old-format report file
        old_report = crash_dir / f"{old_sig}.report.json"
        old_report.write_text('{"crash_id": "' + old_sig + '"}')

        # Write old-format index with 16-char signature keys
        old_index = {
            "meta": {"unique_crashes": 1, "total_hits": 1},
            "crashes": {
                old_sig: {
                    "signature": old_sig,
                    "struct_sig": "deadbeef",  # old 8-char struct sig
                    "first_seen": "2025-01-01T00:00:00",
                    "last_seen": "2025-01-01T00:00:00",
                    "total_hits": 1,
                    "duplicate_count": 0,
                    "crash_type": "segfault",
                    "payload_length": len(payload),
                    "poc_path": f"{old_sig}.bin",
                    "report_path": f"{old_sig}.report.json",
                    "rule_set_id": None,
                    "notes": "",
                }
            },
        }
        (crash_dir / "crash_index.json").write_text(json.dumps(old_index))

        # Load and migrate
        manager = CrashManager(crash_dir=str(crash_dir))
        count = await manager.load()
        assert count == 1

        # Old .bin should be renamed to new sig
        assert not old_poc.exists()
        new_poc = crash_dir / f"{new_sig}.bin"
        assert new_poc.exists()
        assert new_poc.read_bytes() == payload

        # Old report renamed too
        assert not old_report.exists()
        new_report = crash_dir / f"{new_sig}.report.json"
        assert new_report.exists()

        # In-memory index uses new sig
        assert new_sig in manager._index
        assert old_sig not in manager._index

        # is_known works with v2 sig
        assert await manager.is_known(payload) is True


# =============================================================================
# Signature Computation — σ₁ (Primary)
# =============================================================================


class TestSigma1:
    """Tests for the primary signature (SHA256[0:16], 128-bit)."""

    def test_deterministic(self):
        """Same payload → same σ₁."""
        p = b"\xDE\xAD\xBE\xEF"
        assert compute_sigma1(p) == compute_sigma1(p)

    def test_returns_16_bytes(self):
        """σ₁ is exactly 16 bytes (128-bit)."""
        sig = compute_sigma1(b"test payload")
        assert isinstance(sig, bytes)
        assert len(sig) == 16

    def test_different_payloads_different_sig(self):
        """Different payloads → different σ₁."""
        assert compute_sigma1(b"\x01\x02") != compute_sigma1(b"\x03\x04")

    def test_empty_payload(self):
        """Empty payload produces a valid signature."""
        sig = compute_sigma1(b"")
        assert len(sig) == 16
        # SHA256("") is well-defined
        assert sig != b"\x00" * 16

    def test_manager_method_matches(self):
        """CrashManager._compute_primary_sig returns hex of compute_sigma1."""
        p = b"hello world"
        assert CrashManager._compute_primary_sig(p) == compute_sigma1(p).hex()

    def test_primary_sig_hex_length(self):
        """Manager returns 32 hex chars (16 bytes × 2)."""
        sig = CrashManager._compute_primary_sig(b"test")
        assert len(sig) == 32
        assert all(c in "0123456789abcdef" for c in sig)


# =============================================================================
# Signature Computation — simple_fold
# =============================================================================


class TestSimpleFold:
    """Tests for the simple_fold content fingerprint."""

    def test_short_payload_returns_self(self):
        """Payload < 32 bytes → returned as-is."""
        p = b"short"
        assert compute_simple_fold(p) == p

    def test_exactly_31_bytes(self):
        """31-byte payload → returned as-is."""
        p = bytes(range(31))
        assert compute_simple_fold(p) == p

    def test_exactly_32_bytes_returns_16(self):
        """32-byte payload → compressed to 16 bytes."""
        p = bytes(range(32))
        fold = compute_simple_fold(p)
        assert len(fold) == 16
        assert fold != p  # Not the original

    def test_long_payload_returns_16(self):
        """100-byte payload → compressed to 16 bytes."""
        p = bytes(range(100))
        fold = compute_simple_fold(p)
        assert len(fold) == 16

    def test_middle_8_at_correct_offset(self):
        """middle_8 comes from payload[n//2 : n//2+8]."""
        p = b"\x00" * 40
        # Midpoint = 20, so middle_8 = p[20:28] = 00s
        fold = compute_simple_fold(p)
        middle_8 = fold[:8]
        assert middle_8 == b"\x00" * 8

        # Now put distinctive bytes at midpoint
        p2 = b"\x00" * 20 + b"\xFF" * 8 + b"\x00" * 12
        fold2 = compute_simple_fold(p2)
        assert fold2[:8] == b"\xFF" * 8

    def test_xor_fold_basic(self):
        """XOR fold: two identical chunks cancel to zero."""
        # 32 bytes: chunk[0]=0x01*8, chunk[1]=0x01*8, chunk[2]=0x00*8, chunk[3]=0x00*8
        p = b"\x01" * 8 + b"\x01" * 8 + b"\x00" * 16
        fold = compute_simple_fold(p)
        xor_fold_bytes = fold[8:]  # last 8 bytes
        # XOR of chunk0 ⊕ chunk1 = 0x01⊕0x01 per byte = 0x00
        expected_xor = b"\x00" * 8
        assert xor_fold_bytes == expected_xor

    def test_xor_fold_with_remainder(self):
        """Last chunk < 8 bytes is zero-padded before XOR."""
        # 36 bytes: chunks at 0-7, 8-15, 16-23, 24-31, 32-35(+3 pad)
        p = b"\x00" * 32 + b"\xAB\xCD\xEF"
        fold = compute_simple_fold(p)
        xor_val = int.from_bytes(fold[8:], "big")
        # Only nonzero chunk: 0xAB_CD_EF_00_00_00_00_00 (padded)
        assert xor_val == 0xABCD_EF00_0000_0000

    def test_empty_payload(self):
        """Empty payload < 32 → returns empty bytes."""
        assert compute_simple_fold(b"") == b""

    def test_deterministic(self):
        """Same input → same output."""
        p = bytes(range(50))
        assert compute_simple_fold(p) == compute_simple_fold(p)


# =============================================================================
# Signature Computation — σ₂ (Structural)
# =============================================================================


class TestSigma2:
    """Tests for the structural signature (XXH64[…][0:6], 48-bit)."""

    def test_returns_6_bytes(self):
        """σ₂ is exactly 6 bytes (48-bit)."""
        sig = compute_sigma2(b"test payload")
        assert isinstance(sig, bytes)
        assert len(sig) == 6

    def test_deterministic(self):
        """Same payload → same σ₂."""
        p = b"\xDE\xAD\xBE\xEF" * 10
        assert compute_sigma2(p) == compute_sigma2(p)

    def test_different_payloads_usually_differ(self):
        """Completely different payloads → different σ₂ (probabilistic)."""
        sig1 = compute_sigma2(b"\x01" * 40)
        sig2 = compute_sigma2(b"\x02" * 40)
        assert sig1 != sig2

    def test_empty_payload(self):
        """Empty payload produces a valid 6-byte signature."""
        sig = compute_sigma2(b"")
        assert len(sig) == 6

    def test_get_structural_key_hex(self):
        """get_structural_key returns 12-char hex string."""
        key = get_structural_key(b"hello")
        assert isinstance(key, str)
        assert len(key) == 12
        assert all(c in "0123456789abcdef" for c in key)

    def test_get_structural_key_matches_compute(self):
        """get_structural_key == compute_sigma2().hex()."""
        p = b"test data here"
        assert get_structural_key(p) == compute_sigma2(p).hex()

    def test_manager_method_matches(self):
        """CrashManager._compute_struct_sig returns hex of compute_sigma2."""
        p = b"another test"
        assert CrashManager._compute_struct_sig(p) == compute_sigma2(p).hex()

    def test_same_header_24_same_length_different_tail(self):
        """Payloads sharing head24 + length + simple_fold → same σ₂.

        Swap chunks 3 & 5 (outside middle_8 region at bytes 32-39):
        same head24, same length, same middle_8, same XOR fold.
        """
        header  = b"\xAA" * 24
        chunk_a = b"\x11" * 8
        middle  = b"\x33" * 8
        chunk_b = b"\x22" * 8
        tail    = b"\x00" * 16

        p1 = header + chunk_a + middle + chunk_b + tail
        p2 = header + chunk_b + middle + chunk_a + tail  # swap 3↔5

        assert compute_sigma2(p1) == compute_sigma2(p2)
        assert compute_sigma1(p1) != compute_sigma1(p2)

    def test_different_length_different_sigma2(self):
        """Different payload lengths → different σ₂ (len_be32 differs)."""
        p1 = b"\x00" * 40
        p2 = b"\x00" * 48
        assert compute_sigma2(p1) != compute_sigma2(p2)

    def test_short_payload(self):
        """Payload < 24 bytes: head24 = payload, simple_fold = payload."""
        p = b"short"
        sig = compute_sigma2(p)
        assert len(sig) == 6  # Still produces valid σ₂


# =============================================================================
# Batch Processing
# =============================================================================


class TestBatchProcess:
    """Tests for batch_process_crashes()."""

    def test_empty_input(self):
        """Empty list → empty dict."""
        assert batch_process_crashes([]) == {}

    def test_exact_duplicates(self):
        """Identical payloads grouped under one σ₁ variant."""
        p = b"\xDE\xAD" * 20
        result = batch_process_crashes([p, p, p])

        assert len(result) == 1
        group = list(result.values())[0]
        assert group["total"] == 3
        assert group["unique_variants"] == 1

    def test_structural_siblings(self):
        """Different payloads with same σ₂ → same group, different variants."""
        header  = b"\xBB" * 24
        chunk_a = b"\x0A" * 8
        middle  = b"\x44" * 8
        chunk_b = b"\x0B" * 8
        tail    = b"\x00" * 16

        p1 = header + chunk_a + middle + chunk_b + tail
        p2 = header + chunk_b + middle + chunk_a + tail

        result = batch_process_crashes([p1, p2])

        assert len(result) == 1  # one σ₂ group
        group = list(result.values())[0]
        assert group["total"] == 2
        assert group["unique_variants"] == 2  # two different σ₁

    def test_different_structures_separate_groups(self):
        """Completely different payloads → separate σ₂ groups."""
        p1 = b"\x01" * 40
        p2 = b"\x02" * 40
        result = batch_process_crashes([p1, p2])

        assert len(result) == 2

    def test_max_5_representatives(self):
        """More than 5 unique variants → representatives capped at 5.

        Each variant has chunk3 = chunk5 = bytes([i])*8 → they cancel
        in XOR fold (i ⊕ i = 0), so all share the same σ₂.
        """
        header = b"\xCC" * 24
        middle = b"\x55" * 8
        tail   = b"\x00" * 16
        payloads = []
        for i in range(8):
            pair = bytes([i]) * 8   # same for chunk3 & chunk5 → XOR cancels
            p = header + pair + middle + pair + tail  # 64 bytes
            payloads.append(p)

        result = batch_process_crashes(payloads)
        assert len(result) == 1
        group = list(result.values())[0]
        assert group["unique_variants"] == 8
        assert len(group["representatives"]) == 5  # capped

    def test_mixed_duplicates_and_variants(self):
        """Mix of exact duplicates and structural siblings."""
        header  = b"\xDD" * 24
        chunk_a = b"\x10" * 8
        middle  = b"\x66" * 8
        chunk_b = b"\x20" * 8
        tail    = b"\x00" * 16

        p1 = header + chunk_a + middle + chunk_b + tail
        p2 = header + chunk_b + middle + chunk_a + tail

        result = batch_process_crashes([p1, p1, p2, p2, p2])

        assert len(result) == 1
        group = list(result.values())[0]
        assert group["total"] == 5
        assert group["unique_variants"] == 2

    def test_result_structure(self):
        """Result has correct structure with all required keys."""
        result = batch_process_crashes([b"\x00" * 40])
        assert len(result) == 1
        group = list(result.values())[0]
        assert "total" in group
        assert "unique_variants" in group
        assert "representatives" in group
        assert isinstance(group["representatives"], list)
        assert isinstance(group["representatives"][0], bytes)


# =============================================================================
# Collision Rate Estimation
# =============================================================================


class TestCollisionRate:
    """Statistical collision rate tests for σ₂ (48-bit)."""

    def test_sigma2_collision_rate_random(self):
        """With 1000 random 48-bit hashes, expect ≈0 collisions.

        Birthday bound for 48-bit: p ≈ n²/(2×2⁴⁸) = 10⁶/(2⁴⁹) ≈ 1.8e-9.
        With 1000 random payloads, collisions should be ~0.
        """
        random.seed(12345)
        keys = set()
        n = 1000
        for _ in range(n):
            p = bytes(random.randbytes(64))
            keys.add(get_structural_key(p))

        assert len(keys) >= n - 1  # Allow at most 1 collision (extremely unlikely)

    def test_sigma1_zero_collisions(self):
        """σ₁ (128-bit) should have zero collisions for 1000 random payloads."""
        random.seed(54321)
        sigs = set()
        n = 1000
        for _ in range(n):
            p = bytes(random.randbytes(32))
            sigs.add(compute_sigma1(p).hex())

        assert len(sigs) == n  # Zero collisions guaranteed at this scale


# =============================================================================
# Performance
# =============================================================================


class TestPerformance:
    """Throughput benchmarks — must exceed 10,000 crashes/sec."""

    def test_sigma_throughput(self):
        """Compute σ₁ + σ₂ for 10,000 payloads in under 1 second."""
        random.seed(99)
        payloads = [bytes(random.randbytes(64)) for _ in range(10_000)]

        start = time.perf_counter()
        for p in payloads:
            compute_sigma1(p)
            compute_sigma2(p)
        elapsed = time.perf_counter() - start

        rate = 10_000 / elapsed
        assert rate > 10_000, (
            f"Throughput {rate:.0f}/sec — below 10,000 target"
        )

    def test_batch_throughput(self):
        """batch_process_crashes handles 10,000 payloads in under 2 seconds."""
        random.seed(77)
        payloads = [bytes(random.randbytes(64)) for _ in range(10_000)]

        start = time.perf_counter()
        result = batch_process_crashes(payloads)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"Batch took {elapsed:.2f}s — too slow"
        assert len(result) > 0
