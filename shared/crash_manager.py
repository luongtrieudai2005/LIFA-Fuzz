"""
shared/crash_manager.py
------------------------
Crash Deduplication Engine for LIFA-Fuzz

PROBLEM:
    A single exploitable bug can generate 100,000+ crash events in a
    high-speed fuzzing session. Without deduplication, the crash directory
    fills up with identical PoC files, making triage impossible.

SOLUTION — Two-level deduplication:

    Level 1 (Primary):   SHA256(raw_payload)[0:16]  — 128-bit exact match
        The exact byte sequence that triggered the crash.
        Two packets that are byte-for-byte identical get the same signature.
        This is the FAST path — O(1) lookup after hashing.

    Level 2 (Secondary): XXH64(head24 ‖ len_be32 ‖ simple_fold(p))[0:6]  — 48-bit
        Lightweight hybrid structural signature that captures:
          - First 24 bytes  → protocol header / fixed fields
          - uint32_BE(|p|)  → payload length
          - simple_fold(p)  → content fingerprint (middle_8 + XOR fold)
        Two crashes are "structurally similar" if they share the same
        header structure, length, and overall content pattern.

FILE LAYOUT:
    crash_pocs/
    ├── crash_index.json        ← Master index (always up to date)
    ├── {sig}.bin               ← Raw binary PoC for crash replay
    └── {sig}.report.json       ← Human-readable crash metadata

CONCURRENCY:
    Protected by asyncio.Lock. The lock is held only during in-memory
    state updates and brief file I/O — never during the fuzzing hot loop.
    File writes are synchronous (crashes are rare events; blocking is OK).

USAGE:
    manager = CrashManager(crash_dir="crash_pocs")
    await manager.load()                     # Load existing index from disk

    result = await manager.record(
        payload      = mutated_bytes,
        rule_set_id  = active_rule_set.rule_set_id,
        crash_type   = "connection_refused",
    )
    if result.is_new:
        log.critical(f"NEW crash! PoC → {result.poc_path}")
    else:
        log.debug(f"Duplicate #{result.duplicate_count} of {result.signature}")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import xxhash
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.logger import get_logger
from shared.schemas import CrashReport

log = get_logger("shared.crash_manager")


# ===========================================================================
# Data classes
# ===========================================================================

@dataclass
class CrashEntry:
    """
    Persistent record of a single unique crash, stored in crash_index.json.

    One entry exists per UNIQUE signature regardless of how many times
    the identical packet triggered the crash.
    """
    signature:       str            # σ₁ hex — SHA256(payload)[0:16] → 32 hex chars
    struct_sig:      str            # σ₂ hex — XXH64(head24‖len_be32‖fold)[0:6] → 12 hex chars
    first_seen:      str            # ISO-8601 UTC
    last_seen:       str            # ISO-8601 UTC
    total_hits:      int            # Total times this signature appeared
    duplicate_count: int            # Hits after the first (= total_hits - 1)
    crash_type:      str
    payload_length:  int
    poc_path:        str            # Relative path to .bin file
    report_path:     str            # Relative path to .report.json file
    rule_set_id:     Optional[str]  # Active rule set at time of crash
    notes:           str = ""


@dataclass
class RecordResult:
    """
    Return value from CrashManager.record().
    Contains everything the caller needs to decide on follow-up actions.
    """
    is_new:          bool           # True only on the very first occurrence
    signature:       str            # Primary SHA256[:16] signature
    struct_sig:      str            # Secondary structural signature
    duplicate_count: int            # 0 if is_new=True
    poc_path:        Optional[str]  # Set if is_new=True; None for duplicates
    struct_siblings: list[str]      # Other signatures with same struct_sig
    crash_report:    Optional[CrashReport] = None   # Full Pydantic model if new


@dataclass
class CrashStatistics:
    """Aggregate statistics for the current session."""
    unique_crashes:      int
    total_hits:          int
    duplicate_hits:      int
    dedup_ratio:         float           # duplicate_hits / total_hits
    struct_buckets:      int             # Unique structural signatures
    top_signatures:      list[dict]      # Top 5 by hit count
    crash_types:         dict[str, int]  # crash_type → total hits per type
    poc_directory:       str
    index_file:          str
    first_crash_time:    Optional[str]   = None  # ISO-8601 of first unique crash


# ===========================================================================
# Signature Functions — Two-Level Hybrid Structural Dedup
# ===========================================================================
#
# σ₁ (Primary — exact match, 128-bit):
#     SHA256(payload)[0:16]
#     Guarantees zero false positives: byte-for-byte identical payloads only.
#
# σ₂ (Structural — similarity group, 48-bit):
#     XXH64( head24 ‖ uint32_BE(|p|) ‖ simple_fold(p) )[0:6]
#     Groups crashes by protocol header + length + content fingerprint.
#
# simple_fold(p):
#     |p| < 32 → p (full payload — too short to compress)
#     |p| ≥ 32 → middle_8(p) ‖ xor_fold(p)  → 16 bytes
#     Captures spatial locality (middle) + global integrity (XOR fold).
# ============================================================================

_MAX_STRUCTURAL_REPS = 5  # Max representative samples per σ₂ group


def compute_sigma1(payload: bytes) -> bytes:
    """Primary signature — SHA256(payload)[0:16], 128-bit.

    Collision probability is negligible for any realistic fuzzing session
    (birthday bound ≈ 2⁻⁶⁴ at 2³² unique crashes).  Full SHA256 is
    computed but only the first 16 bytes are kept to reduce storage.

    FIX: When payload is empty (no offending packet found), incorporate
    a timestamp so each empty-payload crash gets a unique signature.
    Without this, ALL crashes without packet attribution collide into
    a single "unique" crash, severely undercounting.

    Returns:
        16 raw bytes.
    """
    if not payload:
        import time as _time
        return hashlib.sha256(
            b"__empty_crash__" + str(_time.monotonic_ns()).encode()
        ).digest()[:16]
    return hashlib.sha256(payload).digest()[:16]


def compute_simple_fold(payload: bytes) -> bytes:
    """Content fingerprint for the structural signature.

    For short payloads (|p| < 32) the full content is returned — there
    isn't enough data to compress meaningfully.

    For longer payloads, two independent digests are combined:
      - middle_8: 8 bytes at offset |p|//2  (spatial locality — the
        mutation target often sits near the middle of a fuzzed packet)
      - xor_fold:  XOR of all 8-byte chunks (big-endian) across the
        entire payload.  Last chunk is zero-padded if < 8 bytes.
        Not positional by itself (XOR is commutative), but combined
        with middle_8 the full simple_fold IS position-sensitive.

    Returns:
        |p| < 32 → payload itself (variable length)
        |p| ≥ 32 → exactly 16 bytes (middle_8 ‖ xor_fold)
    """
    n = len(payload)
    if n < 32:
        return payload

    # Middle 8 bytes — captures the region around the mutation point
    mid = n // 2
    middle_8 = payload[mid:mid + 8]

    # XOR fold — iterate 8-byte chunks (big-endian)
    xor_fold = 0
    full_chunks = n // 8
    for i in range(full_chunks):
        xor_fold ^= int.from_bytes(payload[i * 8:(i + 1) * 8], "big")

    remainder = n % 8
    if remainder:
        last = payload[full_chunks * 8:] + b"\x00" * (8 - remainder)
        xor_fold ^= int.from_bytes(last, "big")

    return middle_8 + xor_fold.to_bytes(8, "big")


def compute_sigma2(payload: bytes) -> bytes:
    """Structural signature — XXH64(head24 ‖ len_be32 ‖ fold)[0:6], 48-bit.

    XXH64 is ~10× faster than SHA256 on short inputs, making this cheap
    enough for the hot loop.  The 48-bit output gives ≈ 2²⁴ collision
    birthday bound — more than enough to group a few thousand crashes.

    Components:
        head24    = payload[:24]     (protocol header / fixed fields)
        len_be32  = uint32_BE(|p|)   (payload length)
        fold      = simple_fold(p)   (content fingerprint)

    Returns:
        6 raw bytes.
    """
    head24   = payload[:24]
    len_be32 = len(payload).to_bytes(4, "big")
    fold     = compute_simple_fold(payload)
    return xxhash.xxh64(head24 + len_be32 + fold).digest()[:6]


def get_structural_key(payload: bytes) -> str:
    """Return σ₂ as a hex string (12 chars) — suitable as dict key."""
    return compute_sigma2(payload).hex()


def batch_process_crashes(crashes: list[bytes]) -> dict[str, dict]:
    """Two-level deduplication over a batch of crash payloads.

    Algorithm:
        1. Group all payloads by σ₂ (structural similarity)
        2. Within each σ₂ group, subgroup by σ₁ (exact match)
        3. Keep up to _MAX_STRUCTURAL_REPS representative payloads per group

    Args:
        crashes: List of raw crash payloads.

    Returns:
        {
            sigma2_hex: {
                "total":            int,          # total payloads in this group
                "unique_variants":  int,          # distinct σ₁ values
                "representatives":  list[bytes],  # ≤ 5 sample payloads
            },
            ...
        }
    """
    # Two-level grouping: σ₂ → σ₁ → [payloads]
    groups: dict[str, dict[str, list[bytes]]] = {}

    for payload in crashes:
        s2 = get_structural_key(payload)
        s1 = compute_sigma1(payload).hex()
        groups.setdefault(s2, {}).setdefault(s1, []).append(payload)

    # Collapse into result
    result: dict[str, dict] = {}
    for s2, exact_groups in groups.items():
        total = sum(len(v) for v in exact_groups.values())
        unique = len(exact_groups)
        reps = [v[0] for v in list(exact_groups.values())[:_MAX_STRUCTURAL_REPS]]
        result[s2] = {
            "total": total,
            "unique_variants": unique,
            "representatives": reps,
        }

    return result


# ===========================================================================
# Crash Manager
# ===========================================================================

class CrashManager:
    """
    Async-safe crash deduplication engine.

    Maintains an in-memory index (dict[signature → CrashEntry]) that is
    persisted to crash_index.json on every new unique crash.

    Thread safety: protected by asyncio.Lock; safe to call from any coroutine.

    Attributes:
        crash_dir:    Root directory for all crash artefacts.
        _index:       In-memory dict[primary_sig → CrashEntry].
        _struct_map:  In-memory dict[struct_sig → set[primary_sig]].
        _lock:        asyncio.Lock protecting all state mutations.
        _total_hits:  Total calls to record() (new + duplicates).
    """

    INDEX_FILENAME = "crash_index.json"

    def __init__(self, crash_dir: str = "crash_pocs") -> None:
        self.crash_dir:  Path         = Path(crash_dir)
        self._index:     dict[str, CrashEntry]       = {}
        self._struct_map: dict[str, set[str]]         = {}
        self._lock:      asyncio.Lock                 = asyncio.Lock()
        self._total_hits: int                         = 0

        self.crash_dir.mkdir(parents=True, exist_ok=True)
        log.info(
            "CrashManager initialized",
            extra={"context": {"crash_dir": str(self.crash_dir)}},
        )

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def load(self) -> int:
        """
        Load existing crash index from disk into memory.

        Call at application startup so that crashes from previous runs
        are not re-reported as new unique crashes.

        Returns:
            Number of previously recorded unique crashes loaded.
        """
        index_path = self.crash_dir / self.INDEX_FILENAME
        if not index_path.exists():
            log.info("No existing crash index found — starting fresh")
            return 0

        async with self._lock:
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)

                migrated = 0
                for sig, entry_dict in raw.get("crashes", {}).items():
                    # Schema migration: old entries used 16-char hex sigs (64-bit SHA256),
                    # new entries use 32-char hex sigs (128-bit SHA256[0:16]).
                    # Old struct_sig was 8 chars (SHA256-based), new is 12 chars (XXH64-based).
                    # Mismatched lengths mean old entries can never match new signatures,
                    # so we migrate them by recomputing from the PoC file on disk.
                    if len(sig) != 32:
                        poc_path = self.crash_dir / entry_dict.get("poc_path", "")
                        if poc_path.exists():
                            old_payload = poc_path.read_bytes()
                            new_sig = compute_sigma1(old_payload).hex()
                            new_struct = get_structural_key(old_payload)
                            entry_dict["signature"] = new_sig
                            entry_dict["struct_sig"] = new_struct
                            # Rename PoC + report files to new sig
                            new_poc = self.crash_dir / f"{new_sig}.bin"
                            new_rpt = self.crash_dir / f"{new_sig}.report.json"
                            if not new_poc.exists():
                                poc_path.rename(new_poc)
                            if (self.crash_dir / f"{sig}.report.json").exists():
                                (self.crash_dir / f"{sig}.report.json").rename(new_rpt)
                            entry_dict["poc_path"] = str(
                                new_poc.relative_to(self.crash_dir)
                            )
                            entry_dict["report_path"] = str(
                                new_rpt.relative_to(self.crash_dir)
                            )
                            sig = new_sig
                            migrated += 1
                        else:
                            # PoC file missing — skip stale entry
                            continue

                    entry = CrashEntry(**entry_dict)
                    # FIX: verify duplicate_count invariant on load.
                    # If corrupted, repair from total_hits.
                    if entry.duplicate_count != entry.total_hits - 1:
                        entry.duplicate_count = entry.total_hits - 1
                    self._index[sig] = entry
                    self._struct_map.setdefault(entry.struct_sig, set()).add(sig)

                self._total_hits = sum(e.total_hits for e in self._index.values())

                if migrated:
                    self._persist_index_sync()  # Rewrite with new-format keys
                    log.info(
                        "Migrated %d crash entries to v2 signature format",
                        migrated,
                    )

                log.info(
                    "Crash index loaded",
                    extra={"context": {
                        "unique": len(self._index),
                        "total_hits": self._total_hits,
                    }},
                )
                return len(self._index)

            except Exception as exc:
                log.error(
                    "Failed to load crash index",
                    extra={"context": {"err": str(exc)}},
                )
                return 0

    # -----------------------------------------------------------------------
    # Core API
    # -----------------------------------------------------------------------

    async def record(
        self,
        payload:      bytes,
        crash_type:   str   = "unknown",
        rule_set_id:  Optional[str] = None,
        notes:        str   = "",
    ) -> RecordResult:
        """
        Record a crash event and apply deduplication.

        Algorithm:
            1. Compute primary_sig   = SHA256(payload)[0:16] (128-bit)
            2. Compute struct_sig    = XXH64(head24‖len_be32‖fold)[0:6] (48-bit)
            3. If primary_sig in _index → duplicate: increment counter, return
            4. Else → new crash: save PoC, save report, update index + disk

        Args:
            payload:     The exact mutated bytes that triggered the crash.
            crash_type:  Classification string ("connection_refused", etc.).
            rule_set_id: UUID of the SemanticRuleSet active at crash time.
            notes:       Free-text annotation (e.g. stack trace snippet).

        Returns:
            RecordResult with is_new=True for unique crashes, False for dupes.
        """
        primary_sig = self._compute_primary_sig(payload)
        struct_sig  = self._compute_struct_sig(payload)

        async with self._lock:
            self._total_hits += 1

            # ---------------------------------------------------------------
            # Duplicate path (fast): update counter only
            # ---------------------------------------------------------------
            if primary_sig in self._index:
                entry = self._index[primary_sig]
                entry.duplicate_count += 1
                entry.total_hits      += 1
                entry.last_seen        = datetime.now(timezone.utc).isoformat()
                siblings = list(self._struct_map.get(struct_sig, set()) - {primary_sig})

                log.debug(
                    f"Duplicate crash [{primary_sig}] #{entry.total_hits}",
                    extra={"context": {
                        "sig":     primary_sig,
                        "type":    crash_type,
                        "dup_cnt": entry.duplicate_count,
                    }},
                )

                # Persist updated hit counts (non-blocking write every 100 dups)
                if entry.duplicate_count % 100 == 0:
                    self._persist_index_sync()

                return RecordResult(
                    is_new          = False,
                    signature       = primary_sig,
                    struct_sig      = struct_sig,
                    duplicate_count = entry.duplicate_count,
                    poc_path        = None,
                    struct_siblings = siblings,
                )

            # ---------------------------------------------------------------
            # New unique crash path
            # ---------------------------------------------------------------
            now = datetime.now(timezone.utc)

            poc_path    = self.crash_dir / f"{primary_sig}.bin"
            report_path = self.crash_dir / f"{primary_sig}.report.json"

            # Save raw binary PoC
            self._write_poc(poc_path, payload)

            # Build and save human-readable report
            crash_report = CrashReport(
                crash_id           = primary_sig,
                detected_at        = now,
                triggering_packet  = payload.hex(),
                active_rule_set_id = rule_set_id,
                crash_type         = crash_type,
                poc_file_path      = str(poc_path),
                notes              = notes,
            )
            self._write_report(report_path, crash_report)

            # Update in-memory index
            entry = CrashEntry(
                signature       = primary_sig,
                struct_sig      = struct_sig,
                first_seen      = now.isoformat(),
                last_seen       = now.isoformat(),
                total_hits      = 1,
                duplicate_count = 0,
                crash_type      = crash_type,
                payload_length  = len(payload),
                poc_path        = str(poc_path.relative_to(self.crash_dir)),
                report_path     = str(report_path.relative_to(self.crash_dir)),
                rule_set_id     = rule_set_id,
                notes           = notes,
            )
            self._index[primary_sig] = entry
            self._struct_map.setdefault(struct_sig, set()).add(primary_sig)

            # Persist index to disk immediately for every new crash
            self._persist_index_sync()

            siblings = list(self._struct_map.get(struct_sig, set()) - {primary_sig})
            is_structural_sibling = len(siblings) > 0

            log.critical(
                f"NEW unique crash [{primary_sig}]",
                extra={"context": {
                    "sig":          primary_sig,
                    "struct_sig":   struct_sig,
                    "type":         crash_type,
                    "payload_len":  len(payload),
                    "poc":          str(poc_path),
                    "siblings":     len(siblings),
                    "struct_new":   not is_structural_sibling,
                }},
            )

            return RecordResult(
                is_new          = True,
                signature       = primary_sig,
                struct_sig      = struct_sig,
                duplicate_count = 0,
                poc_path        = str(poc_path),
                struct_siblings = siblings,
                crash_report    = crash_report,
            )

    async def is_known(self, payload: bytes) -> bool:
        """
        Quick check: has this exact payload been seen before?
        O(1) after SHA256[0:16] computation — safe to call in the hot loop.
        """
        sig = self._compute_primary_sig(payload)
        async with self._lock:
            return sig in self._index

    async def get_statistics(self) -> CrashStatistics:
        """Return aggregate statistics for reporting / health checks."""
        async with self._lock:
            unique  = len(self._index)
            total   = self._total_hits
            dups    = total - unique
            ratio   = dups / total if total > 0 else 0.0
            buckets = len(self._struct_map)

            # Top 5 by hit count
            top5 = sorted(
                self._index.values(),
                key=lambda e: e.total_hits,
                reverse=True,
            )[:5]

            # Crash type distribution — counts total hits per type, not just
            # unique signatures. FIX: was counting unique signatures per type,
            # which understates actual crash frequency per type.
            types: dict[str, int] = {}
            for e in self._index.values():
                types[e.crash_type] = types.get(e.crash_type, 0) + e.total_hits

            return CrashStatistics(
                unique_crashes  = unique,
                total_hits      = total,
                duplicate_hits  = dups,
                dedup_ratio     = round(ratio, 4),
                struct_buckets  = buckets,
                top_signatures  = [
                    {
                        "sig":    e.signature,
                        "hits":   e.total_hits,
                        "type":   e.crash_type,
                        "first":  e.first_seen,
                    }
                    for e in top5
                ],
                crash_types     = types,
                poc_directory   = str(self.crash_dir),
                index_file      = str(self.crash_dir / self.INDEX_FILENAME),
                # FIX: precise first crash time from earliest CrashEntry,
                # not from coarse telemetry snapshot granularity.
                first_crash_time = (
                    min(e.first_seen for e in self._index.values())
                    if self._index else None
                ),
            )

    async def get_all_entries(self) -> list[CrashEntry]:
        """Return a snapshot of all known crash entries."""
        async with self._lock:
            return list(self._index.values())

    async def get_struct_siblings(self, payload: bytes) -> list[CrashEntry]:
        """
        Return all crashes that share the same structural signature.

        Useful for identifying whether a new crash is a VARIANT of a
        known bug (same header mutation, different payload) or truly novel.
        """
        struct_sig = self._compute_struct_sig(payload)
        async with self._lock:
            sigs    = self._struct_map.get(struct_sig, set())
            return [self._index[s] for s in sigs if s in self._index]

    # -----------------------------------------------------------------------
    # Signature Computation (delegates to module-level functions)
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_primary_sig(payload: bytes) -> str:
        """Primary dedup key: SHA256(payload)[0:16] → 32 hex chars (128-bit).

        Delegates to compute_sigma1() and converts to hex string.
        """
        return compute_sigma1(payload).hex()

    @staticmethod
    def _compute_struct_sig(payload: bytes) -> str:
        """Structural key: XXH64(head24‖len_be32‖fold)[0:6] → 12 hex chars (48-bit).

        Delegates to get_structural_key().
        """
        return get_structural_key(payload)

    # -----------------------------------------------------------------------
    # File I/O (synchronous — intentional, crashes are rare)
    # -----------------------------------------------------------------------

    def _write_poc(self, path: Path, payload: bytes) -> None:
        """Save raw binary PoC for replay / submission."""
        try:
            path.write_bytes(payload)
            log.debug(f"PoC saved", extra={"context": {"path": str(path), "size": len(payload)}})
        except OSError as exc:
            log.error(f"Failed to save PoC", extra={"context": {"err": str(exc)}})

    def _write_report(self, path: Path, report: CrashReport) -> None:
        """Save human-readable JSON crash report."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    report.model_dump(mode="json"),
                    f,
                    indent=2,
                    default=str,
                    ensure_ascii=False,
                )
        except OSError as exc:
            log.error(f"Failed to save crash report", extra={"context": {"err": str(exc)}})

    def _persist_index_sync(self) -> None:
        """
        Atomically write crash_index.json to disk.

        Uses a write-to-temp-then-rename pattern to prevent index
        corruption if the process is killed mid-write.
        """
        index_path = self.crash_dir / self.INDEX_FILENAME
        tmp_path   = index_path.with_suffix(".tmp")

        payload = {
            "meta": {
                "last_updated":    datetime.now(timezone.utc).isoformat(),
                "unique_crashes":  len(self._index),
                "total_hits":      self._total_hits,
                "struct_buckets":  len(self._struct_map),
            },
            "crashes": {
                sig: asdict(entry)
                for sig, entry in self._index.items()
            },
        }

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            os.replace(tmp_path, index_path)   # Atomic rename
        except OSError as exc:
            log.error(
                "Failed to persist crash index",
                extra={"context": {"err": str(exc)}},
            )
