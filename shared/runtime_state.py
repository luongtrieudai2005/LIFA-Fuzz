"""
shared/runtime_state.py
────────────────────────
Pipeline runtime state — Pydantic models and atomic write/read helpers.

This module defines the data contract between the running pipeline
(main.py + run_slow_loop.py) and the Streamlit dashboard (web_ui/).

Files produced:
    shared/runtime_state.json    — aggregated state from all components
    shared/slow_loop_state.json  — slow loop subprocess state

Write pattern:
    Atomic temp + rename — identical to RuleGenerator.push_rules().
    On Linux, rename() is atomic within a single filesystem, so the
    dashboard never sees a partial write.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from shared.logger import get_logger

log = get_logger("shared.runtime_state")

# Default file paths (overridable for testing)
RUNTIME_STATE_FILE = Path("shared/runtime_state.json")
SLOW_LOOP_STATE_FILE = Path("shared/slow_loop_state.json")


# =============================================================================
# Sub-Models
# =============================================================================


class TargetState(BaseModel):
    """Target server status."""
    alive: Optional[bool] = None
    sandbox_driver: str = "docker"
    host: str = ""
    port: int = 0


class ClientState(BaseModel):
    """Client subprocess status."""
    alive: Optional[bool] = None
    pid: Optional[int] = None


class InterceptorState(BaseModel):
    """Interceptor proxy status."""
    captured: int = 0
    injected: int = 0
    active_connections: int = 0
    paused: bool = False


class MutatorState(BaseModel):
    """Mutation engine status."""
    mode: str = "dumb"
    k: int = 2
    current_eps: float = 0.0
    total_sent: int = 0
    total_accepted: int = 0
    total_rejected: int = 0
    total_crashes: int = 0
    total_timeout: int = 0
    investigation_mode: bool = False
    rule_set_version: int = 0
    active_rule_count: int = 0


class SlowLoopState(BaseModel):
    """Slow loop daemon status."""
    alive: Optional[bool] = None
    pid: Optional[int] = None
    last_cycle_time: str = ""
    total_cycles: int = 0
    total_inferences: int = 0
    total_rules_pushed: int = 0
    last_error: str = ""


class RuleSetState(BaseModel):
    """Active rule set metadata."""
    version: int = 0
    protocol_name: str = "unknown"
    confidence: float = 0.0
    total_rules: int = 0


class EvaluationState(BaseModel):
    """Evaluation campaign state — written by evaluation_runner.py.

    Provides the dashboard with campaign-level progress information:
    which baseline is running, how long it takes, ETA, etc.
    """
    campaign_active: bool = False
    baseline_id: str = ""                   # "A", "B", "C"
    baseline_label: str = ""                # "baseline_A_random"
    baseline_description: str = ""          # "Pure Random Fuzzing"
    total_baselines: int = 3
    baseline_index: int = 0                 # 0-based index
    baseline_duration_s: int = 0            # Configured duration per baseline
    baseline_elapsed_s: float = 0.0         # Seconds elapsed in current baseline
    target: str = ""                        # "lighttpd" or "lifa"
    sandbox_driver: str = ""                # "firecracker" or "docker"


# =============================================================================
# Top-Level Model
# =============================================================================


class PipelineState(BaseModel):
    """Complete pipeline runtime state — written by main.py every 2 seconds.

    Read by the Streamlit dashboard to render the Pipeline Status panel.
    All sub-models default to zero/empty values so partial state is valid.
    """

    timestamp: float = 0.0
    uptime_seconds: float = 0.0
    pipeline_status: str = "stopped"

    target: TargetState = TargetState()
    client: ClientState = ClientState()
    interceptor: InterceptorState = InterceptorState()
    mutator: MutatorState = MutatorState()
    slow_loop: SlowLoopState = SlowLoopState()
    rule_set: RuleSetState = RuleSetState()
    evaluation: EvaluationState = EvaluationState()

    unique_crashes: int = 0
    total_crash_hits: int = 0


# =============================================================================
# Atomic Write / Read Helpers
# =============================================================================


def _atomic_write_json(data: dict, path: Path) -> None:
    """Write a dict as JSON using atomic temp + rename.

    On Linux, rename() within a single filesystem is atomic — the reader
    sees either the old file or the complete new file, never a partial write.

    Args:
        data: Dict to serialize as JSON.
        path: Target file path.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        tmp.rename(path)
        # Force mtime update (rename can preserve source mtime on some FS)
        path.touch()
    except OSError as e:
        log.debug(f"Atomic write failed for {path}: {e}")
        # Clean up temp file
        try:
            tmp = path.with_suffix(".tmp")
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        except OSError:
            pass


def write_runtime_state(state: PipelineState, path: Path = RUNTIME_STATE_FILE) -> None:
    """Write the aggregated pipeline state to disk."""
    _atomic_write_json(state.model_dump(mode="json"), path)


def read_runtime_state(path: Path = RUNTIME_STATE_FILE) -> Optional[PipelineState]:
    """Read the pipeline state file. Returns None if missing or corrupt."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return PipelineState.model_validate(data)
    except (json.JSONDecodeError, OSError, Exception):
        return None


def write_slow_loop_state(data: dict, path: Path = SLOW_LOOP_STATE_FILE) -> None:
    """Write slow loop subprocess state to disk.

    Called by run_slow_loop.py after each cycle.
    """
    _atomic_write_json(data, path)


def read_slow_loop_state(path: Path = SLOW_LOOP_STATE_FILE) -> Optional[dict]:
    """Read slow loop state file. Returns None if missing or corrupt.

    Returns a plain dict (not a model) since the caller only needs
    to merge it into the aggregated PipelineState.
    """
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
