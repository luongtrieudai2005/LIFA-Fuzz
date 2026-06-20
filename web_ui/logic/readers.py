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
# Defined up-front: read_traffic_stats() (below) and the pipeline/evaluation
# readers all reference it. Previously it was defined ~150 lines after its
# first use, which only worked by accident via module-global late binding
# and would NameError if any reader ran during import.
RUNTIME_STATE = DATA_DIR / "shared" / "runtime_state.json"

# EPS history buffer size (stored in Streamlit session_state)
EPS_HISTORY_LEN = 120  # ~10 min at 5s refresh


def _crash_search_dirs() -> list[Path]:
    """All directories that may hold crash artifacts.

    Production (main.py) writes to ``./crashes/``; evaluation_runner writes to
    per-baseline ``evaluation/results/<baseline>/crashes/``. Search both so
    the dashboard reflects crashes regardless of which path produced them
    (otherwise the crash table shows empty during/after an eval campaign).
    """
    dirs: list[Path] = [CRASHES_DIR]
    eval_results = DATA_DIR / "evaluation" / "results"
    if eval_results.is_dir():
        dirs.extend(sorted(p for p in eval_results.glob("*/crashes") if p.is_dir()))
    # de-dup by resolved path while preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for d in dirs:
        try:
            key = str(d.resolve())
        except OSError:
            key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


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
    # Also read response breakdown (accepted/rejected/timeout/crash)
    total_accepted = 0
    total_rejected_rs = 0
    total_timeout = 0
    total_crashes_rs = 0

    if RUNTIME_STATE.exists():
        try:
            state = json.loads(RUNTIME_STATE.read_text(encoding="utf-8"))
            mut_state = state.get("mutator", {})
            mut_total_sent = mut_state.get("total_sent", 0)
            if mut_total_sent > injected:
                injected = mut_total_sent
            # Response breakdown
            total_accepted = mut_state.get("total_accepted", 0)
            total_rejected_rs = mut_state.get("total_rejected", 0)
            total_timeout = mut_state.get("total_timeout", 0)
            # FIX: crash count comes from the DETECTION counters, not the
            # send-side mutator.total_crashes. The send-side counter only
            # increments when a send returns PacketStatus.CRASH; crashes
            # detected by CrashMonitor liveness polling (the common case,
            # incl. all kernel_panic/ASAN crashes) never touch it, so it
            # stays 0 and the dashboard showed 0 despite real crashes.
            # Prefer evaluation.unique_crashes (crash_manager dedup) →
            # evaluation.total_crash_hits (CrashMonitor liveness), both
            # written by main.py and evaluation_runner; fall back to the
            # send-side counter for older state files.
            eval_state = state.get("evaluation", {})
            total_crashes_rs = (
                eval_state.get("unique_crashes")
                or eval_state.get("total_crash_hits")
                or mut_state.get("total_crashes", 0)
            )
            # Also use runtime_state timestamp if fresher than traffic log
            rt_ts = state.get("timestamp", 0)
            if rt_ts and (latest_ts is None or rt_ts > latest_ts):
                latest_ts = rt_ts
        except (json.JSONDecodeError, OSError):
            pass

    # FIX: the crash count header must never show fewer crashes than the
    # crash table below it. runtime_state.json is overwritten each run, so a
    # stale state file (e.g. a 0-crash run) can report 0 while crash
    # artifacts from an earlier run still sit on disk. Floor the count at the
    # number of crash records actually found on disk so header and table stay
    # consistent regardless of which run last wrote state.
    try:
        on_disk = len(read_crash_records())
    except Exception:
        on_disk = 0
    if on_disk > total_crashes_rs:
        total_crashes_rs = on_disk

    return {
        "total_packets": total,
        "total_captured": captured,
        "total_injected": injected,
        "client_packets": client_pkts,
        "server_packets": server_pkts,
        "mutated_packets": mutated_pkts,
        "latest_timestamp": latest_ts,
        "total_accepted": total_accepted,
        "total_rejected": total_rejected_rs,
        "total_timeout": total_timeout,
        "total_crashes": total_crashes_rs,
    }


def _resolve_rules_file() -> Path:
    """Resolve the active-rules file path the engine actually writes to.

    The rule-file location is configurable in config.yaml
    (slow_loop.rule_generator.rule_output_file, falling back to
    fast_loop.rule_watcher.rules_file). The engine is typically configured
    to write to ``/tmp/lifa_rules.json`` — NOT ``shared/active_rules.json``.
    This mirrors ``fast_loop/mutator.py:_load_rules_path_from_config()`` so
    the dashboard reads the SAME file the engine reads; otherwise the
    "Active Rules" metric card always shows 0 (the old default file is
    never written).

    Config is read from ``DATA_DIR/config.yaml`` (the deployment the
    dashboard monitors). If absent — e.g. a stripped data dir or a test
    tmp_path — fall back to the default ``shared/active_rules.json`` under
    DATA_DIR.
    """
    try:
        import yaml as _yaml

        cfg = DATA_DIR / "config.yaml"
        if cfg.exists():
            data = _yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
            rg = (data.get("slow_loop") or {}).get("rule_generator") or {}
            p = rg.get("rule_output_file")
            if not p:
                rw = (data.get("fast_loop") or {}).get("rule_watcher") or {}
                p = rw.get("rules_file")
            if p:
                rp = Path(p)
                return rp if rp.is_absolute() else DATA_DIR / rp
    except Exception:
        pass
    return RULES_FILE  # default: DATA_DIR/shared/active_rules.json


def read_active_rules() -> list[dict]:
    """Load active rules from the shared JSON file.

    Handles two formats:
      - A flat list: [{...}, {...}, ...]
      - A dict with "rules" key: {"rules": [{...}, ...], "protocol_name": ...}

    Reads the path resolved by :func:`_resolve_rules_file` (config-aware),
    so it picks up the same file the mutation engine uses.
    """
    rules_file = _resolve_rules_file()
    if not rules_file.exists():
        return []
    try:
        with open(rules_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "rules" in data:
            return data["rules"] if isinstance(data["rules"], list) else []
        return []
    except (json.JSONDecodeError, OSError):
        return []


def read_active_rule_count(rules: list[dict] | None = None) -> int:
    """Authoritative active-rule count for the metric card.

    Primary source: the length of the rules list read from the rule file
    (config-resolved — same path the engine writes). Fallback: when the
    rule file is missing or empty, use the live engine count reported in
    ``runtime_state.json`` (``rule_set.total_rules``, then
    ``mutator.active_rule_count``). This guarantees the metric never reads
    0 while the engine actually has rules loaded — e.g. right after a run
    when ``/tmp/lifa_rules.json`` has been cleaned up but the last
    ``runtime_state.json`` snapshot still reflects the active rule set.
    """
    if rules:
        return len(rules)
    try:
        if RUNTIME_STATE.exists():
            with open(RUNTIME_STATE, "r", encoding="utf-8") as f:
                rs = json.load(f)
            rule_set = rs.get("rule_set") or {}
            n = rule_set.get("total_rules")
            if isinstance(n, int) and n > 0:
                return n
            mutator = rs.get("mutator") or {}
            n = mutator.get("active_rule_count")
            if isinstance(n, int) and n > 0:
                return n
    except (json.JSONDecodeError, OSError):
        pass
    return 0


def _safe_mtime(p: Path) -> float:
    """Safe mtime that returns 0 if file is deleted mid-scan."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def read_crash_records() -> list[dict]:
    """Load all crash records from the crashes directory.

    FIX: supports BOTH naming conventions:
    - CrashMonitor: crash_YYYYMMDD_HHMMSS_<uuid>.json
    - CrashManager: <sha256_sig>.report.json

    FIX: searches every crash dir — production ``./crashes/`` AND each
    per-baseline ``evaluation/results/<baseline>/crashes/`` — so the table
    shows crashes from an eval campaign, not just a main.py run.
    """
    records = []
    files = []
    for d in _crash_search_dirs():
        if not d.is_dir():
            continue
        # Match both CrashMonitor (crash_*.json) and CrashManager (*.report.json)
        files.extend(d.glob("crash_*.json"))
        files.extend(d.glob("*.report.json"))
    for json_file in sorted(files, key=_safe_mtime, reverse=True):
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

    FIX: searches every crash dir (production + per-baseline eval) for the
    file by name, since the artifact may live in either.
    """
    deleted = False
    for d in _crash_search_dirs():
        json_path = d / source_filename
        bin_path = d / source_filename.replace(".json", ".bin")
        for path in (json_path, bin_path):
            try:
                if path.exists():
                    path.unlink()
                    deleted = True
            except OSError:
                pass
    return deleted


def delete_all_crashes() -> int:
    """Delete ALL crash artifacts (.json + .bin) from every crashes directory.

    Returns:
        Number of files deleted.
    """
    count = 0
    for d in _crash_search_dirs():
        if not d.is_dir():
            continue
        for pattern in ("crash_*.json", "crash_*.bin", "*.report.json"):
            for path in d.glob(pattern):
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

    Returns 0.0 on the first refresh (no previous sample to delta against).
    Previously, an empty ``prev_stats`` made the delta equal the entire
    accumulated injection count, so the very first chart point spiked to the
    100k clamp — a wildly misleading headline number for a pipeline that had
    been fuzzing for minutes before the dashboard opened.
    """
    if elapsed_s < 0.1:  # Minimum 100ms to avoid spike
        return 0.0
    # No prior sample → we cannot compute a rate; emit 0 and let the next
    # cycle establish a real delta.
    if "total_injected" not in prev_stats:
        return 0.0
    new_injected = stats["total_injected"] - prev_stats["total_injected"]
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
