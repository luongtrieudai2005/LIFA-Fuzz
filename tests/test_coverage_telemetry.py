"""
tests/test_coverage_telemetry.py
────────────────────────────────
Unit tests for code coverage tracking:
    - TelemetryCollector.parse_lcov() with synthetic .info data
    - TelemetryCollector.find_latest_lcov()
    - Coverage in telemetry snapshots
    - Build coverage-instrumented binary
    - gcov .gcda generation
    - plot_coverage_comparison()
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from evaluation.telemetry_collector import TelemetryCollector


# =============================================================================
# Fixtures
# =============================================================================


SYNTHETIC_LCOV = """\
TN:
SF:vulnerable_server.c
FN:46,handle_connection
FN:99,main
FNDA:10,handle_connection
FNDA:5,main
FNF:2
FNH:2
BRDA:53,0,0,5
BRDA:53,0,1,0
BRDA:59,0,0,3
BRDA:59,0,1,2
BRDA:79,0,0,0
BRDA:79,0,1,0
BRDA:87,0,0,4
BRDA:87,0,1,1
BRDA:108,0,0,0
BRDA:108,0,1,0
BRDA:143,0,0,6
BRDA:143,0,1,5
DA:46,10
DA:50,10
DA:53,5
DA:59,5
DA:66,5
DA:69,10
DA:79,0
DA:87,5
DA:95,5
DA:99,5
DA:108,0
DA:115,5
DA:143,6
DA:150,6
DA:154,1
LF:15
LH:10
BRF:12
BRH:8
end_of_record
"""


@pytest.fixture
def synthetic_lcov_file(tmp_path):
    """Write synthetic lcov .info content to a temp file."""
    info_path = tmp_path / "coverage.info"
    info_path.write_text(SYNTHETIC_LCOV)
    return str(info_path)


# =============================================================================
# parse_lcov — known data
# =============================================================================


class TestParseLcov:
    """Test TelemetryCollector.parse_lcov() with synthetic data."""

    def test_known_lines_hit(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        # DA lines with count > 0: 46(10),50(10),53(5),59(5),66(5),69(10),
        # 87(5),95(5),99(5),115(5),143(6),150(6),154(1) = 13
        assert result["lines_hit"] == 13

    def test_known_lines_total(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        assert result["lines_total"] == 15  # 15 unique DA lines

    def test_known_line_coverage_pct(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        assert result["line_coverage_pct"] == round(13 / 15 * 100, 2)

    def test_known_branches_hit(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        # BRDA where taken != 0 and != "-":
        # 53,0,0=5✓ 59,0,0=3✓ 59,0,1=2✓ 87,0,0=4✓ 87,0,1=1✓ 143,0,0=6✓ 143,0,1=5✓ = 7
        assert result["branches_hit"] == 7

    def test_known_branches_total(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        assert result["branches_total"] == 12

    def test_known_branch_coverage_pct(self, synthetic_lcov_file):
        result = TelemetryCollector.parse_lcov(synthetic_lcov_file)
        assert result["branch_coverage_pct"] == round(7 / 12 * 100, 2)

    def test_empty_file_returns_zeros(self, tmp_path):
        info_path = tmp_path / "empty.info"
        info_path.write_text("")
        result = TelemetryCollector.parse_lcov(str(info_path))
        assert result["lines_hit"] == 0
        assert result["lines_total"] == 0
        assert result["branches_hit"] == 0
        assert result["branches_total"] == 0

    def test_missing_file_returns_zeros(self, tmp_path):
        result = TelemetryCollector.parse_lcov(str(tmp_path / "nonexistent.info"))
        assert result["lines_hit"] == 0
        assert result["lines_total"] == 0
        assert result["line_coverage_pct"] == 0.0

    def test_malformed_lines_skipped(self, tmp_path):
        info_path = tmp_path / "bad.info"
        info_path.write_text("garbage line\nDA:\nBRDA:invalid\nDA:abc,def\n")
        result = TelemetryCollector.parse_lcov(str(info_path))
        # No valid DA/BRDA lines → all zeros
        assert result["lines_hit"] == 0
        assert result["lines_total"] == 0

    def test_da_only_no_brda(self, tmp_path):
        info_path = tmp_path / "da_only.info"
        info_path.write_text("DA:1,5\nDA:2,0\nDA:3,3\n")
        result = TelemetryCollector.parse_lcov(str(info_path))
        assert result["lines_hit"] == 2  # lines 1 and 3 have count > 0
        assert result["lines_total"] == 3
        assert result["branches_hit"] == 0
        assert result["branches_total"] == 0

    def test_brda_zero_taken_not_counted(self, tmp_path):
        info_path = tmp_path / "zero_taken.info"
        info_path.write_text("BRDA:10,0,0,0\nBRDA:10,0,1,0\n")
        result = TelemetryCollector.parse_lcov(str(info_path))
        assert result["branches_hit"] == 0
        assert result["branches_total"] == 2

    def test_brda_dash_taken_not_counted(self, tmp_path):
        info_path = tmp_path / "dash_taken.info"
        info_path.write_text("BRDA:10,0,0,-\nBRDA:10,0,1,5\n")
        result = TelemetryCollector.parse_lcov(str(info_path))
        assert result["branches_hit"] == 1
        assert result["branches_total"] == 2


# =============================================================================
# find_latest_lcov
# =============================================================================


class TestFindLatestLcov:
    """Test TelemetryCollector.find_latest_lcov()."""

    def test_newest_file_selected(self, tmp_path):
        # Create two .info files with different mtimes
        old = tmp_path / "old.info"
        new = tmp_path / "new.info"
        old.write_text("DA:1,1\n")
        new.write_text("DA:1,2\n")
        # Ensure different mtime
        os.utime(str(old), (time.time() - 100, time.time() - 100))
        result = TelemetryCollector.find_latest_lcov(str(tmp_path))
        assert result == str(new)

    def test_no_files_returns_none(self, tmp_path):
        result = TelemetryCollector.find_latest_lcov(str(tmp_path))
        assert result is None

    def test_single_file_returned(self, tmp_path):
        f = tmp_path / "only.info"
        f.write_text("DA:1,1\n")
        result = TelemetryCollector.find_latest_lcov(str(tmp_path))
        assert result == str(f)

    def test_nonexistent_dir_returns_none(self, tmp_path):
        result = TelemetryCollector.find_latest_lcov(str(tmp_path / "nope"))
        assert result is None


# =============================================================================
# Snapshot coverage integration
# =============================================================================


class TestSnapshotCoverage:
    """Test that coverage data appears in telemetry snapshots."""

    @pytest.mark.asyncio
    async def test_snapshot_includes_coverage(self, tmp_path, synthetic_lcov_file):
        """When coverage_info_path is set and file exists, snapshot has code_coverage."""
        out_path = tmp_path / "telemetry.jsonl"
        collector = TelemetryCollector(
            output_path=str(out_path),
            baseline_label="X",
            coverage_info_path=synthetic_lcov_file,
        )
        # Mock components
        mock_interceptor = MagicMock()
        mock_interceptor.total_captured = 0
        mock_interceptor.total_injected = 0
        mock_mutator = MagicMock()
        mock_mutator.coverage_summary = {}

        collector._interceptor = mock_interceptor
        collector._mutator = mock_mutator
        collector._crash_manager = None
        collector._agent = None
        collector._start_time = time.monotonic()
        collector._last_snapshot_time = time.monotonic()

        await collector._write_snapshot()

        with open(out_path) as f:
            record = json.loads(f.readline())

        assert "code_coverage" in record
        assert record["code_coverage"]["lines_hit"] == 13
        assert record["code_coverage"]["lines_total"] == 15

    @pytest.mark.asyncio
    async def test_snapshot_no_coverage_without_file(self, tmp_path):
        """Without coverage_info_path, no code_coverage key in snapshot."""
        out_path = tmp_path / "telemetry.jsonl"
        collector = TelemetryCollector(
            output_path=str(out_path),
            baseline_label="X",
        )
        mock_interceptor = MagicMock()
        mock_interceptor.total_captured = 0
        mock_interceptor.total_injected = 0
        mock_mutator = MagicMock()
        mock_mutator.coverage_summary = {}

        collector._interceptor = mock_interceptor
        collector._mutator = mock_mutator
        collector._crash_manager = None
        collector._agent = None
        collector._start_time = time.monotonic()
        collector._last_snapshot_time = time.monotonic()

        await collector._write_snapshot()

        with open(out_path) as f:
            record = json.loads(f.readline())

        assert "code_coverage" not in record


# =============================================================================
# Build & gcov integration
# =============================================================================


class TestBuildAndGcov:
    """Test that the coverage binary builds and generates .gcda."""

    def test_makefile_coverage_target(self):
        """make coverage builds vulnerable_server_cov."""
        dummy_dir = Path(__file__).resolve().parent / "dummy_targets"
        result = subprocess.run(
            ["make", "-C", str(dummy_dir), "coverage"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, f"make coverage failed: {result.stderr}"
        assert (dummy_dir / "vulnerable_server_cov").exists()

    def test_gcov_generates_gcda(self):
        """Running cov binary and killing with SIGTERM generates .gcda."""
        dummy_dir = Path(__file__).resolve().parent / "dummy_targets"
        cov_bin = dummy_dir / "vulnerable_server_cov"
        if not cov_bin.exists():
            pytest.skip("vulnerable_server_cov not built")

        # Clean old .gcda files
        for gcda in dummy_dir.glob("*.gcda"):
            gcda.unlink()

        # Kill any stale process on our port from a previous test run
        port = 19879
        try:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    try:
                        os.kill(int(pid_str.strip()), 9)
                    except (ProcessLookupError, PermissionError, ValueError):
                        pass
                time.sleep(0.3)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        proc = subprocess.Popen(
            [str(cov_bin), str(port)],
            cwd=str(dummy_dir),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.5)

            # Send a SIGTERM for clean shutdown (flushes .gcda)
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            raise AssertionError("vulnerable_server_cov did not exit after SIGTERM")
        finally:
            # Belt-and-suspenders: ensure no orphan on the port
            try:
                result = subprocess.run(
                    ["lsof", "-ti", f":{port}"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip():
                    for pid_str in result.stdout.strip().split("\n"):
                        try:
                            os.kill(int(pid_str.strip()), 9)
                        except (ProcessLookupError, PermissionError, ValueError):
                            pass
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        gcda_files = list(dummy_dir.glob("*.gcda"))
        assert len(gcda_files) >= 1, "No .gcda files generated after clean exit"


# =============================================================================
# Plot
# =============================================================================


class TestPlotCoverage:
    """Test plot_coverage_comparison() generates a PNG."""

    def test_plot_generates_png(self, tmp_path):
        """plot_coverage_comparison produces a PNG file."""
        from evaluation.plot_generator import plot_coverage_comparison

        coverage_data = {
            "A": {"lines_hit": 45, "lines_total": 200, "line_coverage_pct": 22.5,
                  "branches_hit": 15, "branches_total": 80, "branch_coverage_pct": 18.75},
            "B": {"lines_hit": 95, "lines_total": 200, "line_coverage_pct": 47.5,
                  "branches_hit": 35, "branches_total": 80, "branch_coverage_pct": 43.75},
            "C": {"lines_hit": 135, "lines_total": 200, "line_coverage_pct": 67.5,
                  "branches_hit": 52, "branches_total": 80, "branch_coverage_pct": 65.0},
        }
        out = str(tmp_path / "coverage_test.png")
        result = plot_coverage_comparison(coverage_data, output_path=out)
        assert Path(result).exists()
        assert Path(result).stat().st_size > 0
