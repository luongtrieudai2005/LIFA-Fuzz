"""
tests/test_adaptive_sampling_integration.py
─────────────────────────────────────────────
Integration tests for the EWMA Adaptive State Sampling system.

Verifies:
    1. _poll_adaptive_k() reads file correctly
    2. _should_recv() cycles at expected k interval
    3. _record_response_sample() skips when buffer large
    4. MutatorStats includes EWMA fields
    5. coverage_summary includes EWMA fields
    6. End-to-end: Slow Loop writes k → Fast Loop reads k
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fast_loop.mutator import MutationEngine, MutatorStats
from shared.schemas import (
    ActiveRuleSet,
    Direction,
    FieldRule,
    MutationStrategy,
    SeedSequence,
    TrafficRecord,
)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_engine(tmp_path: Path, **overrides) -> MutationEngine:
    """Create a MutationEngine with tmp paths for EWMA files."""
    defaults = {
        "target_host": "127.0.0.1",
        "target_port": 9999,
        "seed_queue": asyncio.Queue(),
        "k": 2,
        "max_eps": 0,
        "warmup_seconds": 0,
    }
    defaults.update(overrides)
    engine = MutationEngine(**defaults)
    # Override EWMA paths to tmp
    engine._adaptive_k_path = str(tmp_path / "adaptive_k.json")
    engine._response_buf_path = str(tmp_path / "response_buffer.jsonl")
    return engine


def _write_adaptive_k(tmp_path: Path, k: int, **extra: dict) -> None:
    """Write adaptive_k.json with given values."""
    data = {"current_k": k, "lambda_c": 0.0, "regime": "sparse", "updated_at": 1234.0}
    data.update(extra)
    p = tmp_path / "adaptive_k.json"
    p.write_text(json.dumps(data))
    # Ensure mtime advances — some filesystems have 1s granularity
    import time as _time
    _time.sleep(0.01)
    p.touch()


# ──────────────────────────────────────────────────────────────────────
# Test 1: _poll_adaptive_k reads file correctly
# ──────────────────────────────────────────────────────────────────────


def test_poll_adaptive_k_reads_file(tmp_path: Path) -> None:
    """_poll_adaptive_k should read current_k from the file."""
    engine = _make_engine(tmp_path)
    _write_adaptive_k(tmp_path, 42, lambda_c=0.5, regime="active")

    engine._poll_adaptive_k()
    assert engine._current_k == 42


def test_poll_adaptive_k_clamps_to_range(tmp_path: Path) -> None:
    """_poll_adaptive_k should clamp k to [1, 200]."""
    engine = _make_engine(tmp_path)

    # Too high → clamped to 200
    _write_adaptive_k(tmp_path, 500)
    engine._adaptive_k_mtime = 0  # force re-read
    engine._poll_adaptive_k()
    assert engine._current_k == 200

    # Zero → clamped to 1
    _write_adaptive_k(tmp_path, 0)
    engine._adaptive_k_mtime = 0  # force re-read
    engine._poll_adaptive_k()
    assert engine._current_k == 1

    # Negative → clamped to 1
    _write_adaptive_k(tmp_path, -5)
    engine._adaptive_k_mtime = 0  # force re-read
    engine._poll_adaptive_k()
    assert engine._current_k == 1


def test_poll_adaptive_k_missing_file(tmp_path: Path) -> None:
    """If adaptive_k.json doesn't exist, keep current _current_k."""
    engine = _make_engine(tmp_path)
    engine._current_k = 150
    # Don't write the file
    engine._poll_adaptive_k()
    assert engine._current_k == 150


def test_poll_adaptive_k_malformed_file(tmp_path: Path) -> None:
    """If the file has bad JSON, keep current _current_k."""
    engine = _make_engine(tmp_path)
    engine._current_k = 123
    (tmp_path / "adaptive_k.json").write_text("not json{{{")
    engine._poll_adaptive_k()
    assert engine._current_k == 123


def test_poll_adaptive_k_updates_stats(tmp_path: Path) -> None:
    """_poll_adaptive_k should update stats with EWMA telemetry."""
    engine = _make_engine(tmp_path)
    _write_adaptive_k(tmp_path, 42, lambda_c=0.75, regime="active")

    engine._poll_adaptive_k()
    assert engine._stats.current_k == 42
    assert engine._stats.ewma_lambda_c == 0.75
    assert engine._stats.ewma_regime == "active"


# ──────────────────────────────────────────────────────────────────────
# Test 2: _should_recv() cycles at expected k
# ──────────────────────────────────────────────────────────────────────


def test_should_recv_cycles_at_k10() -> None:
    """At k=10, _should_recv should return True every 10th call."""
    engine = _make_engine(Path("/tmp"))
    engine._current_k = 10
    engine._packet_counter = 0

    results = [engine._should_recv() for _ in range(30)]
    recv_at = [i + 1 for i, r in enumerate(results) if r]

    assert recv_at == [10, 20, 30], f"Expected recv at 10,20,30 — got {recv_at}"


def test_should_recv_at_k1() -> None:
    """At k=1, _should_recv should return True every call."""
    engine = _make_engine(Path("/tmp"))
    engine._current_k = 1
    engine._packet_counter = 0

    results = [engine._should_recv() for _ in range(10)]
    assert all(results)


def test_should_recv_at_k200() -> None:
    """At k=200, _should_recv should return True once in 200 calls."""
    engine = _make_engine(Path("/tmp"))
    engine._current_k = 200
    engine._packet_counter = 0

    results = [engine._should_recv() for _ in range(200)]
    assert sum(results) == 1
    assert results[-1] is True  # the 200th call


def test_should_recv_increments_packet_counter() -> None:
    """_should_recv should increment _packet_counter each call."""
    engine = _make_engine(Path("/tmp"))
    engine._packet_counter = 0

    for _ in range(5):
        engine._should_recv()

    assert engine._packet_counter == 5


# ──────────────────────────────────────────────────────────────────────
# Test 3: _record_response_sample
# ──────────────────────────────────────────────────────────────────────


def test_record_response_sample_writes(tmp_path: Path) -> None:
    """_record_response_sample should append a JSON line to the buffer."""
    engine = _make_engine(tmp_path)
    buf = tmp_path / "response_buffer.jsonl"
    assert not buf.exists()

    engine._record_response_sample(b"hello world!!")

    assert buf.exists()
    line = buf.read_text().strip()
    data = json.loads(line)
    assert "hex_prefix" in data
    assert data["length"] == 13


def test_record_response_sample_skips_large_buffer(tmp_path: Path) -> None:
    """_record_response_sample should skip if buffer is already large."""
    engine = _make_engine(tmp_path)
    buf = tmp_path / "response_buffer.jsonl"

    # Write a file larger than 80KB
    big_line = '{"hex_prefix":"aa","length":1,"ts":0.0}\n'
    buf.write_text(big_line * 2500)  # ~2500 lines, well over 80KB
    size_before = buf.stat().st_size
    assert size_before > 80_000

    engine._record_response_sample(b"test data here")
    size_after = buf.stat().st_size
    assert size_after == size_before, "Should not have appended to a large buffer"


def test_record_response_sample_no_crash_on_error(tmp_path: Path) -> None:
    """_record_response_sample should never crash the hot loop."""
    engine = _make_engine(tmp_path)
    engine._response_buf_path = "/nonexistent/path/buffer.jsonl"
    # Should silently fail, not raise
    engine._record_response_sample(b"test")


# ──────────────────────────────────────────────────────────────────────
# Test 4: MutatorStats EWMA fields
# ──────────────────────────────────────────────────────────────────────


def test_mutator_stats_ewma_defaults() -> None:
    """MutatorStats should have EWMA fields with safe defaults."""
    stats = MutatorStats()
    assert stats.current_k == 200
    assert stats.recv_sample_rate == 0.0
    assert stats.ewma_lambda_c == 0.0
    assert stats.ewma_regime == "sparse"


def test_mutator_stats_ewma_backward_compat() -> None:
    """Existing code creating MutatorStats() without EWMA args should work."""
    stats = MutatorStats(
        mode="dumb",
        total_sent=100,
        current_eps=50.0,
    )
    assert stats.current_k == 200  # default
    assert stats.recv_sample_rate == 0.0


# ──────────────────────────────────────────────────────────────────────
# Test 5: get_stats() and coverage_summary include EWMA
# ──────────────────────────────────────────────────────────────────────


def test_get_stats_includes_ewma(tmp_path: Path) -> None:
    """get_stats() should return EWMA telemetry."""
    engine = _make_engine(tmp_path)
    engine._current_k = 42
    engine._recv_count = 10
    engine._stats.total_sent = 100

    stats = engine.get_stats()
    assert stats.current_k == 42
    assert abs(stats.recv_sample_rate - 0.1) < 0.01


def test_coverage_summary_includes_ewma(tmp_path: Path) -> None:
    """coverage_summary should include EWMA fields."""
    engine = _make_engine(tmp_path)
    engine._current_k = 42
    engine._recv_count = 10
    engine._stats.total_sent = 100

    summary = engine.coverage_summary
    assert summary["current_k"] == 42
    assert abs(summary["recv_sample_rate"] - 0.1) < 0.01


# ──────────────────────────────────────────────────────────────────────
# Test 6: End-to-end — Slow Loop writes k → Fast Loop reads k
# ──────────────────────────────────────────────────────────────────────


def test_e2e_slow_loop_writes_fast_loop_reads(tmp_path: Path) -> None:
    """Simulate the full IPC flow: EWMAController writes → MutationEngine reads."""
    from slow_loop.ewma_controller import EWMAController

    # Slow Loop side
    ctrl = EWMAController(
        output_path=str(tmp_path / "adaptive_k.json"),
        response_buf_path=str(tmp_path / "response_buffer.jsonl"),
        theta=2.0,
        K_max=200,
        k_min=5,
    )

    # Write some response data (simulating Fast Loop samples)
    buf = tmp_path / "response_buffer.jsonl"
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 100, "ts": 0.0}
        for i in range(30)
    ]
    buf.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    # Slow Loop epoch
    k_written = ctrl.update(field_groups_count=8, epoch_duration_s=5.0)

    # Fast Loop side
    engine = _make_engine(tmp_path)
    engine._poll_adaptive_k()

    assert engine._current_k == k_written
    assert engine._current_k < 200  # coverage was detected


def test_e2e_multiple_epochs(tmp_path: Path) -> None:
    """Multiple EWMA epochs should converge the sampling interval."""
    from slow_loop.ewma_controller import EWMAController

    ctrl = EWMAController(
        output_path=str(tmp_path / "adaptive_k.json"),
        response_buf_path=str(tmp_path / "response_buffer.jsonl"),
        theta=2.0,
        K_max=200,
    )

    engine = _make_engine(tmp_path)

    # Epoch 1: high coverage
    buf = tmp_path / "response_buffer.jsonl"
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(50)
    ]
    buf.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    ctrl.update(field_groups_count=10, epoch_duration_s=2.0)
    engine._adaptive_k_mtime = 0
    engine._poll_adaptive_k()
    k1 = engine._current_k

    # Epochs 2-6: zero coverage (buffer was truncated by epoch 1)
    # Run several epochs to let lambda_c decay enough for k to change
    k_prev = k1
    for _ in range(5):
        ctrl.update(field_groups_count=0, epoch_duration_s=5.0)

    ctrl.update(field_groups_count=0, epoch_duration_s=5.0)
    engine._adaptive_k_mtime = 0
    engine._poll_adaptive_k()
    k_final = engine._current_k

    # k should have increased significantly as coverage decayed
    assert k_final > k1, f"k_final ({k_final}) should be > k1 ({k1}) after decay"
    assert k_final >= 60, f"k_final ({k_final}) should be >= 60 after sustained decay"
