"""
web_ui/logic/readers.py
───────────────────────
Data I/O layer for the LIFA-Fuzz Dashboard.

NO Streamlit dependency — pure data reading and computation.
Used by the presentation layer to feed data into the UI.

Data Sources:
    - shared/raw_traffic.jsonl    → packet/mutation counts
    - shared/active_rules.json    → active SemanticRules
    - crashes/                    → crash PoC artifacts
    - shared/llm_last_inference.json → latest LLM prompt/response
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("LIFA_DATA_DIR", "."))
TRAFFIC_LOG = DATA_DIR / "shared" / "raw_traffic.jsonl"
RULES_FILE = DATA_DIR / "shared" / "active_rules.json"
CRASHES_DIR = DATA_DIR / "crashes"
LLM_LOG = DATA_DIR / "shared" / "llm_last_inference.json"

# EPS history buffer size (stored in Streamlit session_state)
EPS_HISTORY_LEN = 120  # ~10 min at 5s refresh


# ---------------------------------------------------------------------------
# Data Readers
# ---------------------------------------------------------------------------


def read_traffic_stats() -> dict[str, Any]:
    """Scan the JSONL traffic log and return packet counts.

    Also merges mutator stats from runtime_state.json when available.
    The MutationEngine sends directly to the target (bypassing the
    Interceptor), so the traffic log only captures Interceptor-relayed
    packets. We use runtime_state.json's mutator.total_sent as the
    authoritative injection count.
    """
    total = 0
    captured = 0
    injected = 0
    client_pkts = 0
    server_pkts = 0
    mutated_pkts = 0
    latest_ts: float | None = None

    if TRAFFIC_LOG.exists():
        try:
            with open(TRAFFIC_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        total += 1
                        ts = rec.get("timestamp", 0)
                        if ts and (latest_ts is None or ts > latest_ts):
                            latest_ts = ts

                        if rec.get("is_mutated"):
                            injected += 1
                            mutated_pkts += 1
                        else:
                            captured += 1

                        d = rec.get("direction", "")
                        if "client" in d:
                            client_pkts += 1
                        elif "server" in d:
                            server_pkts += 1

                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    # Override injection count from runtime_state.json (authoritative source)
    # The mutator sends directly to target, so its total_sent > log count
    if RUNTIME_STATE.exists():
        try:
            state = json.loads(RUNTIME_STATE.read_text(encoding="utf-8"))
            mut_total_sent = state.get("mutator", {}).get("total_sent", 0)
            if mut_total_sent > injected:
                injected = mut_total_sent
            # Also use runtime_state timestamp if fresher than traffic log
            rt_ts = state.get("timestamp", 0)
            if rt_ts and (latest_ts is None or rt_ts > latest_ts):
                latest_ts = rt_ts
        except (json.JSONDecodeError, OSError):
            pass

    return {
        "total_packets": total,
        "total_captured": captured,
        "total_injected": injected,
        "client_packets": client_pkts,
        "server_packets": server_pkts,
        "mutated_packets": mutated_pkts,
        "latest_timestamp": latest_ts,
    }


def read_active_rules() -> list[dict]:
    """Load active rules from the shared JSON file."""
    if not RULES_FILE.exists():
        return []
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def read_crash_records() -> list[dict]:
    """Load all crash records from the crashes directory.

    FIX: supports BOTH naming conventions:
    - CrashMonitor: crash_YYYYMMDD_HHMMSS_<uuid>.json
    - CrashManager: <sha256_sig>.report.json
    """
    if not CRASHES_DIR.exists():
        return []
    records = []
    # Match both CrashMonitor (crash_*.json) and CrashManager (*.report.json)
    for json_file in sorted(
        list(CRASHES_DIR.glob("crash_*.json"))
        + list(CRASHES_DIR.glob("*.report.json")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            data["_source_file"] = json_file.name
            records.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return records


def delete_crash_artifacts(source_filename: str) -> bool:
    """Delete a crash record (.json + .bin) from the crashes directory.

    Args:
        source_filename: The ``_source_file`` value attached by
            ``read_crash_records()`` (e.g.
            ``"crash_20260530_084800_abc.json"``).

    Returns:
        True if at least one file was deleted, False otherwise.
    """
    deleted = False
    json_path = CRASHES_DIR / source_filename
    bin_path = CRASHES_DIR / source_filename.replace(".json", ".bin")

    for path in (json_path, bin_path):
        try:
            if path.exists():
                path.unlink()
                deleted = True
        except OSError:
            pass
    return deleted


def delete_all_crashes() -> int:
    """Delete ALL crash artifacts (.json + .bin) from the crashes directory.

    Returns:
        Number of files deleted.
    """
    count = 0
    for pattern in ("crash_*.json", "crash_*.bin", "*.report.json"):
        for path in CRASHES_DIR.glob(pattern):
            try:
                path.unlink()
                count += 1
            except OSError:
                pass
    return count


def read_llm_insights() -> dict[str, str]:
    """Read the latest LLM inference log (if available)."""
    if not LLM_LOG.exists():
        return {"prompt": "Waiting for first inference...", "response": ""}
    try:
        return json.loads(LLM_LOG.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"prompt": "Error reading LLM log", "response": ""}


# ---------------------------------------------------------------------------
# Computed Metrics
# ---------------------------------------------------------------------------


RUNTIME_STATE = DATA_DIR / "shared" / "runtime_state.json"


def read_pipeline_status() -> dict[str, Any]:
    """Read the pipeline runtime state file.

    Returns a dict with pipeline component status, or a minimal
    'not running' dict if the file is missing or stale (>30s old).
    """
    if not RUNTIME_STATE.exists():
        return {"pipeline_status": "not_running"}
    try:
        state = json.loads(RUNTIME_STATE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"pipeline_status": "error"}
    # Staleness check: >30s = stopped
    ts = state.get("timestamp", 0)
    if ts and time.time() - ts > 30:
        state["pipeline_status"] = "stopped"
    return state


def infer_pipeline_status(stats: dict) -> str:
    """Infer whether the fuzzing pipeline is running.

    Checks both traffic log timestamps and runtime_state.json freshness.
    """
    # First check runtime_state.json — the authoritative source
    if RUNTIME_STATE.exists():
        try:
            state = json.loads(RUNTIME_STATE.read_text(encoding="utf-8"))
            ps = state.get("pipeline_status", "")
            if ps in ("running", "degraded"):
                ts = state.get("timestamp", 0)
                if ts and time.time() - ts < 30:
                    return "running"
                elif ts and time.time() - ts < 120:
                    return "idle"
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback: check traffic log freshness
    ts = stats.get("latest_timestamp")
    if ts is None:
        return "stopped"
    age = time.time() - ts
    if age < 30:
        return "running"
    elif age < 120:
        return "idle"
    return "stopped"


def compute_eps(stats: dict, prev_stats: dict, elapsed_s: float) -> float:
    """Compute current EPS (injections per second).

    FIX: clamp to [0, 100000] to prevent negative EPS on counter reset
    and infinite EPS on near-zero elapsed time.
    """
    if elapsed_s < 0.1:  # Minimum 100ms to avoid spike
        return 0.0
    new_injected = stats["total_injected"] - prev_stats.get("total_injected", 0)
    if new_injected < 0:
        return 0.0  # Counter reset — don't show negative
    eps = new_injected / elapsed_s
    return min(eps, 100_000.0)  # Upper bound sanity clamp


# ---------------------------------------------------------------------------
# Evaluation State
# ---------------------------------------------------------------------------

BASELINE_ORDER = ["A", "B", "C"]


def read_evaluation_state() -> dict[str, Any]:
    """Read evaluation campaign state and compute derived progress metrics.

    Returns a dict with evaluation progress info, or minimal inactive
    dict when no evaluation is running.
    """
    if not RUNTIME_STATE.exists():
        return {"campaign_active": False}

    try:
        state = json.loads(RUNTIME_STATE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"campaign_active": False}

    ev = state.get("evaluation", {})
    if not ev or not ev.get("campaign_active"):
        return {"campaign_active": False}

    # Staleness check — same logic as read_pipeline_status
    ts = state.get("timestamp", 0)
    if ts and time.time() - ts > 30:
        return {"campaign_active": False, "stale": True}

    baseline_id = ev.get("baseline_id", "?")
    baseline_duration = ev.get("baseline_duration_s", 0)
    baseline_elapsed = ev.get("baseline_elapsed_s", 0)
    total_baselines = ev.get("total_baselines", 3)
    baseline_index = ev.get("baseline_index", 0)

    # Derived metrics
    progress_pct = min(100.0, (baseline_elapsed / baseline_duration * 100)) if baseline_duration > 0 else 0
    remaining_s = max(0, baseline_duration - baseline_elapsed)
    total_elapsed_s = baseline_index * baseline_duration + baseline_elapsed
    total_duration_s = total_baselines * baseline_duration
    total_remaining_s = max(0, total_duration_s - total_elapsed_s)
    overall_pct = min(100.0, (total_elapsed_s / total_duration_s * 100)) if total_duration_s > 0 else 0

    # ETA
    now = time.time()
    eta_current = now + remaining_s
    eta_campaign = now + total_remaining_s

    return {
        "campaign_active": True,
        "baseline_id": baseline_id,
        "baseline_label": ev.get("baseline_label", ""),
        "baseline_description": ev.get("baseline_description", ""),
        "total_baselines": total_baselines,
        "baseline_index": baseline_index,
        "baseline_duration_s": baseline_duration,
        "baseline_elapsed_s": baseline_elapsed,
        "remaining_s": remaining_s,
        "progress_pct": progress_pct,
        "total_elapsed_s": total_elapsed_s,
        "total_remaining_s": total_remaining_s,
        "total_duration_s": total_duration_s,
        "overall_pct": overall_pct,
        "eta_current": eta_current,
        "eta_campaign": eta_campaign,
        "target": ev.get("target", ""),
        "sandbox_driver": ev.get("sandbox_driver", ""),
    }
