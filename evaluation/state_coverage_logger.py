"""
evaluation/state_coverage_logger.py
────────────────────────────────────
CSV Telemetry Logger for State-Coverage Expansion (Step 3).

Writes timestamped snapshots of state coverage metrics to a CSV file
at regular intervals. Each baseline (A, B, C) writes to its own file
(e.g., ``state_coverage_stats_C.csv``) for clean comparative plotting.

CSV Format:
    timestamp,executions,unique_code_branches,unique_states,unique_state_edges

Usage:
    # Production (main.py) — default filename:
    logger = StateCoverageLogger()
    logger.init_file()
    logger.write_snapshot(executions=1000, ...)

    # Evaluation — per-baseline isolation:
    logger = StateCoverageLogger(output_path="logs/state_coverage_stats_C.csv")
    logger.init_file()

Design:
    - Simple append mode — no locks needed (single-writer from state_writer_task).
    - Atomic init: only writes header if file is empty/missing.
    - Hardcoded defaults: no config.yaml section required.
"""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Optional

from shared.logger import get_logger

log = get_logger("evaluation.state_coverage_logger")


# =============================================================================
# State Coverage Logger
# =============================================================================


class StateCoverageLogger:
    """Background CSV logger for state coverage telemetry.

    Writes one row per snapshot interval with the following columns:
        timestamp             — Unix epoch (float, 1 decimal).
        executions            — Total mutation engine sends.
        unique_code_branches  — Unique mutation offset signatures.
        unique_states         — Unique FTP status codes observed.
        unique_state_edges    — Unique (code, cmd, code) transitions.

    Args:
        output_path: Path to the CSV file.
        interval_s:  Minimum seconds between writes (default 10.0).
    """

    CSV_HEADER: list[str] = [
        "timestamp",
        "executions",
        "unique_code_branches",
        "unique_states",
        "unique_state_edges",
    ]

    def __init__(
        self,
        output_path: str = "logs/state_coverage_stats.csv",
        interval_s: float = 10.0,
    ) -> None:
        self.output_path = Path(output_path)
        self.interval_s = interval_s
        self._last_write_time: float = 0.0
        self._snapshot_count: int = 0

    # -----------------------------------------------------------------
    # File Initialization
    # -----------------------------------------------------------------

    def init_file(self) -> None:
        """Write CSV header if the file doesn't exist or is empty.

        Safe to call multiple times — idempotent.
        """
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.output_path.exists() or self.output_path.stat().st_size == 0:
            with open(self.output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self.CSV_HEADER)
            log.info(f"CSV logger initialized: {self.output_path}")

    # -----------------------------------------------------------------
    # Snapshot Write
    # -----------------------------------------------------------------

    def write_snapshot(
        self,
        executions: int,
        unique_code_branches: int,
        unique_states: int,
        unique_state_edges: int,
    ) -> None:
        """Append one telemetry row to the CSV file.

        Respects the configured ``interval_s`` — skips writes that are
        too close together (prevents duplicate rows from overlapping
        state_writer_task cycles).

        Args:
            executions:            Total mutation sends.
            unique_code_branches:  Unique mutation offset signatures.
            unique_states:         Unique FTP status codes seen.
            unique_state_edges:    Unique state transition edges.
        """
        now = time.time()

        # Throttle: skip if last write was too recent
        if self._last_write_time > 0 and (now - self._last_write_time) < self.interval_s:
            return

        row = [
            f"{now:.1f}",
            executions,
            unique_code_branches,
            unique_states,
            unique_state_edges,
        ]

        try:
            with open(self.output_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(row)
            self._last_write_time = now
            self._snapshot_count += 1
        except OSError as exc:
            log.warning(f"Failed to write CSV snapshot: {exc}")

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def snapshot_count(self) -> int:
        """Number of snapshots written so far."""
        return self._snapshot_count

    @property
    def last_write_time(self) -> float:
        """Unix timestamp of the last successful write."""
        return self._last_write_time
