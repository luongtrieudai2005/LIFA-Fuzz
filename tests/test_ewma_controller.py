"""
tests/test_ewma_controller.py
──────────────────────────────
Unit tests for slow_loop/ewma_controller.py — EWMA Adaptive Controller.

Verifies:
    1. Cold start: lambda_c=0 → k=K_max
    2. High coverage: proxy metrics push k down
    3. Response buffer truncated after read
    4. Epoch duration normalization
    5. k_min enforced
    6. Decay to K_max when no new coverage
    7. EWMA smoothing (hysteresis)
    8. Regime classification
    9. Atomic file writes
    10. Malformed buffer entries skipped
    11. lambda_c property
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

import pytest

from slow_loop.ewma_controller import EWMAController


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_controller(
    tmp_path: Path,
    delta: float = 0.1,
    theta: float = 2.0,
    K_max: int = 200,
    k_min: int = 5,
    weight_A: float = 0.3,
    weight_B: float = 0.7,
) -> EWMAController:
    """Create an EWMAController with tmp paths."""
    return EWMAController(
        output_path=str(tmp_path / "adaptive_k.json"),
        delta=delta,
        theta=theta,
        K_max=K_max,
        k_min=k_min,
        weight_A=weight_A,
        weight_B=weight_B,
        response_buf_path=str(tmp_path / "response_buffer.jsonl"),
    )


def _read_k(tmp_path: Path) -> int:
    """Read current_k from the output file."""
    p = tmp_path / "adaptive_k.json"
    if not p.exists():
        return 200
    data = json.loads(p.read_text())
    return data["current_k"]


def _write_response_buf(
    tmp_path: Path,
    entries: list[dict],
) -> None:
    """Write entries to the response buffer file."""
    buf = tmp_path / "response_buffer.jsonl"
    lines = []
    for e in entries:
        lines.append(json.dumps(e))
    buf.write_text("\n".join(lines) + "\n")


# ──────────────────────────────────────────────────────────────────────
# Test 1: Cold start — lambda_c=0 → k=K_max
# ──────────────────────────────────────────────────────────────────────


def test_cold_start_returns_k_max(tmp_path: Path) -> None:
    """When no coverage (delta_C=0), k should be K_max."""
    ctrl = _make_controller(tmp_path)
    k = ctrl.update(field_groups_count=0, epoch_duration_s=5.0)
    assert k == 200
    assert _read_k(tmp_path) == 200


def test_cold_start_file_has_correct_shape(tmp_path: Path) -> None:
    """The adaptive_k.json file should have all expected fields."""
    ctrl = _make_controller(tmp_path)
    ctrl.update(field_groups_count=0, epoch_duration_s=5.0)
    data = json.loads((tmp_path / "adaptive_k.json").read_text())
    assert "current_k" in data
    assert "lambda_c" in data
    assert "regime" in data
    assert "updated_at" in data


# ──────────────────────────────────────────────────────────────────────
# Test 2: High coverage pushes k down
# ──────────────────────────────────────────────────────────────────────


def test_high_coverage_reduces_k(tmp_path: Path) -> None:
    """With many new field groups + diverse responses, k should decrease."""
    ctrl = _make_controller(tmp_path, theta=2.0, K_max=200)

    # Write 50 unique responses to buffer
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 100, "ts": 0.0}
        for i in range(50)
    ]
    _write_response_buf(tmp_path, entries)

    k = ctrl.update(field_groups_count=5, epoch_duration_s=5.0)
    # delta_C = (0.3 * 5 + 0.7 * 50) / 5.0 = 7.3
    # lambda_c = 0.1 * 7.3 = 0.73
    # k = floor(200 / (1 + 2.0 * 0.73)) = floor(200 / 2.46) = 81
    assert 60 <= k <= 100, f"Expected k around 81, got {k}"


def test_response_buffer_is_primary_driver(tmp_path: Path) -> None:
    """Metric B (responses) should dominate when weight_B=0.7."""
    ctrl = _make_controller(tmp_path, weight_A=0.0, weight_B=1.0)

    # 20 unique responses, no field groups
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(20)
    ]
    _write_response_buf(tmp_path, entries)

    k = ctrl.update(field_groups_count=0, epoch_duration_s=2.0)
    # delta_C = 1.0 * 20 / 2.0 = 10.0
    # lambda_c = 0.1 * 10.0 = 1.0
    # k = floor(200 / (1 + 2.0 * 1.0)) = floor(200/3) = 66
    assert 55 <= k <= 75, f"Expected k around 66, got {k}"


# ──────────────────────────────────────────────────────────────────────
# Test 3: Response buffer truncated after read
# ──────────────────────────────────────────────────────────────────────


def test_response_buffer_truncated_after_update(tmp_path: Path) -> None:
    """After update(), the response buffer should be consumed (file removed).

    The rename-swap pattern renames the live file to .reading, processes it,
    then deletes the staging file. The live buffer no longer exists — data
    has been consumed. Any new Fast Loop writes will create a fresh file.
    """
    ctrl = _make_controller(tmp_path)
    buf = tmp_path / "response_buffer.jsonl"
    buf.write_text(
        '{"hex_prefix":"aabbccdd11223344","length":50,"ts":0.0}\n'
    )
    assert buf.exists()
    ctrl.update(field_groups_count=0, epoch_duration_s=1.0)
    # After consumption: original file is gone (renamed to .reading then deleted)
    assert not buf.exists()
    # No stale staging file left behind
    staging = tmp_path / "response_buffer.reading"
    assert not staging.exists()


def test_response_buffer_missing_is_fine(tmp_path: Path) -> None:
    """If response buffer doesn't exist, update should not crash."""
    ctrl = _make_controller(tmp_path)
    # No buffer file created
    k = ctrl.update(field_groups_count=10, epoch_duration_s=1.0)
    assert isinstance(k, int)


# ──────────────────────────────────────────────────────────────────────
# Test 4: Epoch duration normalization
# ──────────────────────────────────────────────────────────────────────


def test_epoch_duration_normalization(tmp_path: Path) -> None:
    """Different epoch durations with same delta produce different rates.

    Two controllers, same initial state. Controller A gets a short epoch,
    Controller B gets a long epoch with the same field_groups delta.
    Controller A should have lower k (more aggressive sampling).
    """
    ctrl_short = _make_controller(tmp_path / "short", weight_A=1.0, weight_B=0.0)
    ctrl_long = _make_controller(tmp_path / "long", weight_A=1.0, weight_B=0.0)

    # Same delta_C (10 new field groups), different epoch durations
    k_short = ctrl_short.update(field_groups_count=10, epoch_duration_s=1.0)
    k_long = ctrl_long.update(field_groups_count=10, epoch_duration_s=10.0)

    # Short epoch → higher rate → lower k (more aggressive sampling)
    assert k_short < k_long, (
        f"k_short ({k_short}) should be < k_long ({k_long}) "
        f"— shorter epoch = higher rate = lower k"
    )


# ──────────────────────────────────────────────────────────────────────
# Test 5: k_min enforced
# ──────────────────────────────────────────────────────────────────────


def test_k_min_enforced(tmp_path: Path) -> None:
    """Even with huge coverage signal, k should never go below k_min."""
    ctrl = _make_controller(tmp_path, theta=100.0, K_max=200, k_min=5)

    # Massive response diversity
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 100, "ts": 0.0}
        for i in range(200)
    ]
    _write_response_buf(tmp_path, entries)

    k = ctrl.update(field_groups_count=100, epoch_duration_s=1.0)
    assert k >= 5, f"k={k} should be >= k_min=5"


def test_k_min_default_is_5(tmp_path: Path) -> None:
    """Default k_min=5 should be enforced under extreme coverage."""
    ctrl = _make_controller(tmp_path, theta=10.0, K_max=200, k_min=5)
    k = ctrl.update(field_groups_count=50, epoch_duration_s=0.1)
    assert k >= 5


# ──────────────────────────────────────────────────────────────────────
# Test 6: Decay to K_max when no new coverage
# ──────────────────────────────────────────────────────────────────────


def test_coverage_decay_to_k_max(tmp_path: Path) -> None:
    """After many epochs with zero coverage, k should recover to K_max."""
    ctrl = _make_controller(tmp_path)

    # Initial spike
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(30)
    ]
    _write_response_buf(tmp_path, entries)
    k_spike = ctrl.update(field_groups_count=10, epoch_duration_s=1.0)
    assert k_spike < 200  # Confirm we actually went down

    # Decay: 50 epochs with zero coverage
    for _ in range(50):
        k = ctrl.update(field_groups_count=0, epoch_duration_s=10.0)

    # After sustained zero coverage, lambda_c should have decayed
    # lambda_c ≈ initial_lambda * (1-delta)^50
    # With delta=0.1, (0.9)^50 ≈ 0.00515 — very small
    assert k >= 180, f"After 50 zero-coverage epochs, k={k} should be near K_max=200"


# ──────────────────────────────────────────────────────────────────────
# Test 7: EWMA smoothing (hysteresis)
# ──────────────────────────────────────────────────────────────────────


def test_ewma_smooths_single_spike(tmp_path: Path) -> None:
    """A single large spike should be smoothed by EWMA — k doesn't jump
    as hard as a non-smoothed controller would."""
    ctrl = _make_controller(tmp_path, theta=2.0, K_max=200)

    # One big spike
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(100)
    ]
    _write_response_buf(tmp_path, entries)
    k1 = ctrl.update(field_groups_count=50, epoch_duration_s=1.0)

    # Immediately zero coverage — lambda_c decays but doesn't vanish
    k2 = ctrl.update(field_groups_count=0, epoch_duration_s=1.0)

    # k should recover but not instantly jump back to 200
    # (that would mean no hysteresis — chattering)
    assert k2 > k1, "After zero coverage, k should increase"
    assert k2 < 200, "EWMA should smooth — instant jump to 200 means no hysteresis"


# ──────────────────────────────────────────────────────────────────────
# Test 8: Regime classification
# ──────────────────────────────────────────────────────────────────────


def test_regime_classification(tmp_path: Path) -> None:
    """Verify regime labels in the output file."""
    ctrl = _make_controller(tmp_path, theta=2.0, K_max=200)

    # k=200 → "sparse"
    ctrl.update(field_groups_count=0, epoch_duration_s=5.0)
    data = json.loads((tmp_path / "adaptive_k.json").read_text())
    assert data["regime"] == "sparse"

    # Push k down significantly
    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(80)
    ]
    _write_response_buf(tmp_path, entries)
    ctrl.update(field_groups_count=30, epoch_duration_s=1.0)
    data = json.loads((tmp_path / "adaptive_k.json").read_text())
    # k should be low enough for "intensive" or "active"
    assert data["regime"] in ("intensive", "active")


# ──────────────────────────────────────────────────────────────────────
# Test 9: Atomic file writes
# ──────────────────────────────────────────────────────────────────────


def test_atomic_file_write(tmp_path: Path) -> None:
    """Verify that adaptive_k.json is valid JSON after write."""
    ctrl = _make_controller(tmp_path)
    ctrl.update(field_groups_count=5, epoch_duration_s=3.0)

    data = json.loads((tmp_path / "adaptive_k.json").read_text())
    assert isinstance(data, dict)
    assert isinstance(data["current_k"], int)
    assert isinstance(data["lambda_c"], float)
    assert isinstance(data["regime"], str)
    assert isinstance(data["updated_at"], float)


def test_no_stale_tmp_file(tmp_path: Path) -> None:
    """After write, no .tmp file should be left behind."""
    ctrl = _make_controller(tmp_path)
    ctrl.update(field_groups_count=0, epoch_duration_s=1.0)
    assert not (tmp_path / "adaptive_k.json.tmp").exists()


# ──────────────────────────────────────────────────────────────────────
# Test 10: Malformed response buffer entries are skipped
# ──────────────────────────────────────────────────────────────────────


def test_malformed_buffer_entries_skipped(tmp_path: Path) -> None:
    """Malformed lines in response buffer should be silently skipped."""
    ctrl = _make_controller(tmp_path)

    buf = tmp_path / "response_buffer.jsonl"
    lines = [
        '{"hex_prefix":"aabbccdd11223344","length":50,"ts":0.0}',  # valid
        'not-json-at-all',                                            # malformed
        '{"hex_prefix":"deadbeef","length":42,"ts":0.0}',           # valid
        '',                                                           # empty line
        '{"no_hex_prefix":true}',                                    # missing field
    ]
    buf.write_text("\n".join(lines) + "\n")

    k = ctrl.update(field_groups_count=0, epoch_duration_s=1.0)
    # Should not crash; 2 valid unique prefixes contribute to proxy_B
    assert isinstance(k, int)


# ──────────────────────────────────────────────────────────────────────
# Test 11: lambda_c property
# ──────────────────────────────────────────────────────────────────────


def test_lambda_c_property(tmp_path: Path) -> None:
    """The lambda_c property should reflect internal state."""
    ctrl = _make_controller(tmp_path)
    assert ctrl.lambda_c == 0.0  # initial

    entries = [
        {"hex_prefix": f"{i:016x}", "length": 50, "ts": 0.0}
        for i in range(10)
    ]
    _write_response_buf(tmp_path, entries)
    ctrl.update(field_groups_count=5, epoch_duration_s=1.0)
    assert ctrl.lambda_c > 0.0
