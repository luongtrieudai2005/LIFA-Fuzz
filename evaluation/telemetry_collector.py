"""
evaluation/telemetry_collector.py
──────────────────────────────────
Real-time telemetry collection for academic benchmarking.

Periodically snapshots metrics from running Fast/Slow Loop components
and appends structured JSONL records for later analysis and plotting.

Snapshot Interval: 10 seconds (configurable)
Output Format:     JSONL (one JSON object per line)

Metrics Collected:
    - Timestamp & Elapsed Time
    - Executions Per Second (EPS)
    - Total Mutations & Packets Captured
    - Crash counts (total & unique via CrashManager)
    - Token usage & budget
    - Active rules count
    - Precision mode status
    - Coverage (unique offsets fuzzed)
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fast_loop.interceptor import Interceptor
    from fast_loop.mutator import MutationEngine
    from shared.crash_manager import CrashManager
    from slow_loop.llm_agent import LLMAgent


# =============================================================================
# Telemetry Collector
# =============================================================================


class TelemetryCollector:
    """Periodically snapshots metrics from running pipeline components.

    Usage:
        collector = TelemetryCollector(
            output_path="evaluation/results/baseline_A/telemetry.jsonl",
            baseline_label="A",
        )
        await collector.start(interceptor, mutator, crash_manager, agent)
        # ... pipeline runs ...
        await collector.stop()

    The collector runs a background task that writes one JSONL line
    every ``snapshot_interval_s`` seconds.
    """

    def __init__(
        self,
        output_path: str,
        baseline_label: str = "X",
        snapshot_interval_s: float = 10.0,
    ) -> None:
        self.output_path = Path(output_path)
        self.baseline_label = baseline_label
        self.snapshot_interval_s = snapshot_interval_s

        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Component references (set by start())
        self._interceptor: Optional[Any] = None
        self._mutator: Optional[Any] = None
        self._crash_manager: Optional[Any] = None
        self._agent: Optional[Any] = None

        # Background task
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._start_time: float = 0.0

        # Accumulated counters for EPS calculation
        self._last_injected: int = 0
        self._last_snapshot_time: float = 0.0

    async def start(
        self,
        interceptor: Any,
        mutator: Any,
        crash_manager: Optional[Any] = None,
        agent: Optional[Any] = None,
    ) -> None:
        """Start the background telemetry collection loop.

        Args:
            interceptor:    The Interceptor instance (for packet counts).
            mutator:        The MutationEngine instance (for mutation counts).
            crash_manager:  Optional CrashManager (for crash dedup stats).
            agent:          Optional LLMAgent (for token usage).
        """
        self._interceptor = interceptor
        self._mutator = mutator
        self._crash_manager = crash_manager
        self._agent = agent
        self._running = True
        self._start_time = time.monotonic()
        self._last_snapshot_time = self._start_time
        self._last_injected = 0

        self._task = asyncio.create_task(
            self._collection_loop(), name="telemetry_collector"
        )

    async def stop(self) -> None:
        """Stop the collection loop and write final snapshot."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        # Write final snapshot
        if self._interceptor is not None:
            await self._write_snapshot(final=True)

    async def _collection_loop(self) -> None:
        """Background loop: snapshot metrics every N seconds."""
        try:
            while self._running:
                await asyncio.sleep(self.snapshot_interval_s)
                if self._running:
                    await self._write_snapshot()
        except asyncio.CancelledError:
            pass

    async def _write_snapshot(self, final: bool = False) -> None:
        """Collect metrics from all components and append to JSONL."""
        now = time.monotonic()
        elapsed = now - self._start_time

        # Calculate EPS (injected since last snapshot)
        current_injected = self._interceptor.total_injected if self._interceptor else 0
        dt = now - self._last_snapshot_time
        eps = (current_injected - self._last_injected) / dt if dt > 0 else 0.0
        self._last_injected = current_injected
        self._last_snapshot_time = now

        # Mutation engine stats
        mut_stats = {}
        if self._mutator:
            try:
                mut_stats = self._mutator.coverage_summary
            except Exception:
                pass

        # Crash stats
        crash_data = {
            "total_crashes": 0,
            "unique_crashes": 0,
            "dedup_ratio": 0.0,
        }
        if self._crash_manager:
            try:
                cs = await self._crash_manager.get_statistics()
                crash_data = {
                    "total_crashes": cs.total_hits,
                    "unique_crashes": cs.unique_crashes,
                    "dedup_ratio": round(cs.dedup_ratio, 4),
                }
            except Exception:
                pass

        # Agent stats (token usage)
        agent_data = {
            "token_usage": 0,
            "token_budget": 0,
            "total_inferences": 0,
        }
        if self._agent:
            try:
                agent_stats = self._agent.stats
                agent_data = {
                    "token_usage": agent_stats.get("session_tokens_used", 0),
                    "token_budget": agent_stats.get("session_budget", 0),
                    "total_inferences": agent_stats.get("total_inferences", 0),
                }
            except Exception:
                pass

        # Precision mode
        precision_mode = False
        try:
            if self._mutator and hasattr(self._mutator, "_orchestrator_precision"):
                precision_mode = bool(self._mutator._orchestrator_precision)
        except Exception:
            pass

        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(elapsed, 2),
            "baseline": self.baseline_label,
            "eps": round(eps, 2),
            "total_mutations": mut_stats.get("total_mutations", 0),
            "total_packets_captured": self._interceptor.total_captured
                                     if self._interceptor else 0,
            "total_packets_injected": current_injected,
            "total_crashes": crash_data["total_crashes"],
            "unique_crashes": crash_data["unique_crashes"],
            "dedup_ratio": crash_data["dedup_ratio"],
            "token_usage": agent_data["token_usage"],
            "token_budget": agent_data["token_budget"],
            "total_inferences": agent_data["total_inferences"],
            "active_rules": mut_stats.get("active_rules", 0),
            "precision_mode": precision_mode,
            "coverage_offsets": mut_stats.get("unique_offsets_fuzzed", 0),
            "final": final,
        }

        # Append to JSONL file
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")

    async def write_summary(self) -> dict:
        """Compute and write a summary of the collected telemetry.

        Returns:
            Summary dict with aggregate statistics.
        """
        snapshots = []
        if self.output_path.exists():
            with open(self.output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            snapshots.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        if not snapshots:
            return {"baseline": self.baseline_label, "error": "no data"}

        summary = {
            "baseline": self.baseline_label,
            "duration_s": snapshots[-1].get("elapsed_s", 0),
            "total_snapshots": len(snapshots),
            "avg_eps": sum(s.get("eps", 0) for s in snapshots) / len(snapshots),
            "max_eps": max(s.get("eps", 0) for s in snapshots),
            "total_mutations": snapshots[-1].get("total_mutations", 0),
            "total_crashes": snapshots[-1].get("total_crashes", 0),
            "unique_crashes": snapshots[-1].get("unique_crashes", 0),
            "first_crash_elapsed_s": None,
            "total_token_usage": snapshots[-1].get("token_usage", 0),
            "total_inferences": snapshots[-1].get("total_inferences", 0),
            "final_active_rules": snapshots[-1].get("active_rules", 0),
        }

        # Find time to first crash
        for s in snapshots:
            if s.get("unique_crashes", 0) > 0:
                summary["first_crash_elapsed_s"] = s.get("elapsed_s")
                break

        # Write summary file
        summary_path = self.output_path.parent / "summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        return summary


# =============================================================================
# Standalone Synthetic Telemetry Generator (for plot testing)
# =============================================================================


def generate_synthetic_telemetry(
    output_path: str,
    baseline: str,
    duration_s: int = 300,
    interval_s: int = 10,
    eps_base: float = 400.0,
    eps_noise: float = 50.0,
    crash_start_s: Optional[int] = None,
    crash_rate: float = 0.01,
    total_unique_crashes: int = 0,
    token_rate: float = 0.0,
    seed: int = 42,
) -> None:
    """Generate synthetic telemetry data for testing plot generation.

    Args:
        output_path:   Path to write JSONL telemetry.
        baseline:      Baseline label ("A", "B", "C").
        duration_s:    Total experiment duration.
        interval_s:    Snapshot interval.
        eps_base:      Base EPS value.
        eps_noise:     Random noise amplitude on EPS.
        crash_start_s: When the first crash appears (None = no crashes).
        crash_rate:    Probability of new unique crash per snapshot.
        total_unique_crashes: Max unique crashes.
        token_rate:    Token usage growth per snapshot.
        seed:          Random seed for reproducibility.
    """
    import random
    random.seed(seed)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    total_mutations = 0
    unique_crashes = 0
    token_usage = 0

    with open(output_path, "w") as f:
        for t in range(interval_s, duration_s + 1, interval_s):
            eps = max(0, eps_base + random.gauss(0, eps_noise))
            total_mutations += int(eps * interval_s)

            # Crash discovery
            if crash_start_s and t >= crash_start_s:
                if random.random() < crash_rate and unique_crashes < total_unique_crashes:
                    unique_crashes += 1

            token_usage += int(token_rate)

            snapshot = {
                "timestamp": f"2026-01-01T00:{t // 60:02d}:{t % 60:02d}Z",
                "elapsed_s": t,
                "baseline": baseline,
                "eps": round(eps, 2),
                "total_mutations": total_mutations,
                "total_packets_captured": total_mutations // 5,
                "total_packets_injected": total_mutations,
                "total_crashes": unique_crashes + random.randint(0, 2),
                "unique_crashes": unique_crashes,
                "dedup_ratio": round(random.uniform(0.3, 0.7), 4),
                "token_usage": token_usage,
                "token_budget": 100000,
                "total_inferences": token_usage // 500 if token_rate > 0 else 0,
                "active_rules": random.randint(0, 15),
                "precision_mode": unique_crashes > 0 and random.random() < 0.3,
                "coverage_offsets": random.randint(10, 60),
                "final": t == duration_s,
            }
            f.write(json.dumps(snapshot) + "\n")
