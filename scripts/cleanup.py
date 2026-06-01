#!/usr/bin/env python3
"""
scripts/cleanup.py
──────────────────
LIFA-Fuzz Cleanup & Archival Pipeline.

Handles three concerns:
    1. Archive previous campaign results (results, plots, logs, core dumps)
    2. Kill orphaned resources (Firecracker VMs, Docker containers, TAPs)
    3. Clean shared state files between runs

Usage:
    # Full cleanup: archive + kill orphans + clean shared state
    python3 scripts/cleanup.py

    # Only archive results (don't touch running processes)
    python3 scripts/cleanup.py --archive-only

    # Skip confirmation prompt
    python3 scripts/cleanup.py --force

    # Specify target/driver for archive naming
    python3 scripts/cleanup.py --target lifa --driver firecracker
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Project root (one level up from scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Paths
EVAL_DIR = PROJECT_ROOT / "evaluation"
RESULTS_DIR = EVAL_DIR / "results"
PLOTS_DIR = EVAL_DIR / "plots"
ARCHIVE_DIR = EVAL_DIR / "archive"
CRASHES_DIR = PROJECT_ROOT / "crashes"
SHARED_DIR = PROJECT_ROOT / "shared"

# Resources
DOCKER_CONTAINERS = ["lifa-target-server", "lifa-lighttpd-server"]
SHARED_STATE_FILES = [
    "runtime_state.json",
    "raw_traffic.jsonl",
    "active_rules.json",
    "slow_loop_state.json",
    "last_known_grammar.json",
    "llm_last_inference.json",
]


# =============================================================================
# 1. Archival
# =============================================================================


def archive_previous_results(
    target: str = "unknown",
    driver: str = "unknown",
) -> Path | None:
    """Archive previous campaign results into a timestamped directory.

    Moves:
        - evaluation/results/   → archive/<target>_<driver>_<ts>/results/
        - evaluation/plots/     → archive/<target>_<driver>_<ts>/plots/
        - evaluation/*.log      → archive/<target>_<driver>_<ts>/logs/
        - crashes/              → archive/<target>_<driver>_<ts>/crashes/
        - core.* (project root) → archive/<target>_<driver>_<ts>/core_dumps/

    Args:
        target: Target name (lifa, lighttpd) for archive folder naming.
        driver:  Driver name (docker, firecracker) for archive folder naming.

    Returns:
        Path to the archive directory, or None if nothing to archive.
    """
    # Check if there's anything to archive
    has_results = RESULTS_DIR.exists() and any(RESULTS_DIR.iterdir())
    has_plots = PLOTS_DIR.exists() and any(PLOTS_DIR.iterdir())
    has_logs = bool(list(EVAL_DIR.glob("*.log")))
    has_crashes = CRASHES_DIR.exists() and any(CRASHES_DIR.iterdir())
    core_files = list(PROJECT_ROOT.glob("core.*"))
    has_cores = len(core_files) > 0

    if not any([has_results, has_plots, has_logs, has_crashes, has_cores]):
        print("  ℹ Nothing to archive — workspace is clean.")
        return None

    # Create archive directory
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%Hh%Mm")
    archive_name = f"{target}_{driver}_{ts}"
    archive_path = ARCHIVE_DIR / archive_name
    archive_path.mkdir(parents=True, exist_ok=True)

    print(f"  📦 Archiving previous results → {archive_path.relative_to(PROJECT_ROOT)}")

    # 1a. Results
    if has_results:
        dest = archive_path / "results"
        shutil.move(str(RESULTS_DIR), str(dest))
        print(f"     ✓ results/")
        # Recreate empty results dir for next run
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1b. Plots
    if has_plots:
        dest = archive_path / "plots"
        shutil.move(str(PLOTS_DIR), str(dest))
        print(f"     ✓ plots/")
        PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1c. Campaign logs
    log_files = list(EVAL_DIR.glob("*.log"))
    if log_files:
        log_dest = archive_path / "logs"
        log_dest.mkdir(parents=True, exist_ok=True)
        for lf in log_files:
            shutil.move(str(lf), str(log_dest / lf.name))
        print(f"     ✓ {len(log_files)} log file(s)")

    # 1d. Crashes (project root)
    if has_crashes:
        dest = archive_path / "crashes"
        shutil.move(str(CRASHES_DIR), str(dest))
        print(f"     ✓ crashes/")
        CRASHES_DIR.mkdir(parents=True, exist_ok=True)

    # 1e. Core dumps (project root)
    if core_files:
        core_dest = archive_path / "core_dumps"
        core_dest.mkdir(parents=True, exist_ok=True)
        for cf in core_files:
            shutil.move(str(cf), str(core_dest / cf.name))
        print(f"     ✓ {len(core_files)} core dump(s)")

    print(f"  📦 Archive complete.")
    return archive_path


# =============================================================================
# 2. Orphaned Resource Cleanup
# =============================================================================


def cleanup_orphaned_resources() -> None:
    """Kill orphaned processes, containers, and network devices.

    Handles:
        - Firecracker VM processes
        - Docker containers (lifa-target-server, lifa-lighttpd-server)
        - TAP network devices (tap-lifa0)
        - Unix socket files (/tmp/firecracker-lifa.sock)
        - Port 8001 bindings
    """
    print("  🧹 Cleaning orphaned resources...")

    # 2a. Kill orphaned Firecracker VMs
    try:
        result = subprocess.run(
            ["pkill", "-f", "firecracker.*api-sock"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            print("     ✓ Killed orphaned Firecracker VM(s)")
    except Exception:
        pass

    # 2b. Remove orphaned Docker containers
    for container in DOCKER_CONTAINERS:
        try:
            result = subprocess.run(
                ["docker", "rm", "-f", container],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                print(f"     ✓ Removed Docker container: {container}")
        except Exception:
            pass

    # 2c. Remove TAP device
    try:
        result = subprocess.run(
            ["ip", "link", "del", "tap-lifa0"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            print("     ✓ Removed TAP device: tap-lifa0")
    except Exception:
        pass

    # 2d. Remove Unix sockets
    socket_path = Path("/tmp/firecracker-lifa.sock")
    if socket_path.exists():
        socket_path.unlink()
        print("     ✓ Removed socket: /tmp/firecracker-lifa.sock")

    # 2e. Free port 8001
    try:
        result = subprocess.run(
            ["fuser", "-k", "8001/tcp"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            print("     ✓ Freed port 8001")
    except Exception:
        pass

    print("  🧹 Orphan cleanup complete.")


# =============================================================================
# 3. Shared State Cleanup
# =============================================================================


def cleanup_shared_state() -> None:
    """Delete shared state files (JSON/JSONL) but keep the directory."""
    print("  🧹 Cleaning shared state...")
    cleaned = 0
    for name in SHARED_STATE_FILES:
        p = SHARED_DIR / name
        if p.exists():
            p.unlink()
            cleaned += 1
    if cleaned:
        print(f"     ✓ Removed {cleaned} shared state file(s)")
    else:
        print("     ℹ No shared state files to clean")
    print("  🧹 Shared state cleanup complete.")


# =============================================================================
# 4. Full Cleanup
# =============================================================================


def full_cleanup(
    target: str = "unknown",
    driver: str = "unknown",
) -> None:
    """Run the complete cleanup pipeline: archive → orphans → shared state."""
    print("\n" + "=" * 50)
    print("  LIFA-Fuzz Cleanup Pipeline")
    print("=" * 50)

    archive_previous_results(target=target, driver=driver)
    cleanup_orphaned_resources()
    cleanup_shared_state()

    print("\n  ✅ Full cleanup complete.\n")


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LIFA-Fuzz Cleanup & Archival Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/cleanup.py                           # full cleanup
  python3 scripts/cleanup.py --archive-only            # only archive
  python3 scripts/cleanup.py --force                   # skip confirmation
  python3 scripts/cleanup.py --target lifa --driver firecracker
        """,
    )
    parser.add_argument(
        "--archive-only", action="store_true",
        help="Only archive results (don't kill processes)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--target", default="unknown",
        help="Target name for archive folder (default: unknown)",
    )
    parser.add_argument(
        "--driver", default="unknown",
        help="Driver name for archive folder (default: unknown)",
    )
    args = parser.parse_args()

    # Confirmation
    if not args.force:
        print("This will archive old results and clean up resources.")
        resp = input("Continue? [y/N] ").strip().lower()
        if resp != "y":
            print("Aborted.")
            return

    if args.archive_only:
        archive_previous_results(target=args.target, driver=args.driver)
    else:
        full_cleanup(target=args.target, driver=args.driver)


if __name__ == "__main__":
    main()
