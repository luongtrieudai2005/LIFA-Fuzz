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

    # Wipe ALL archived campaigns (frees disk, discards history)
    python3 scripts/cleanup.py --clear-archive

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


# Core-dump file patterns produced by crashing ASAN targets.
# The kernel writes ``core.<pid>`` (core_pattern=core) into the crashing
# process's CWD, which for host-side test targets is the project root and
# for Firecracker campaigns ends up copied into archive dirs. ASAN already
# emits a richer report, so these raw cores are pure clutter.
CORE_PATTERNS: tuple[str, ...] = ("core", "core.[0-9]*", "*.core", "core.*")

# Directories we never sweep for cores (generated/vendored, not ours).
_CORE_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".venv", "venv", ".git", "__pycache__", ".pytest_cache",
    ".idea", ".vscode", "node_modules",
})


def _iter_core_files(
    root: Path,
    *,
    exclude_dirs: frozenset[str] = _CORE_EXCLUDE_DIRS,
    skip_archive: bool = True,
) -> list[Path]:
    """Recursively find core-dump files under ``root``.

    Walks the whole tree but prunes vendored/generated dirs. When
    ``skip_archive`` is True, ``evaluation/archive`` is also pruned so we
    don't re-move already-archived campaign cores into a new archive
    (nested archive churn).

    Args:
        root:          Directory to scan.
        exclude_dirs:  Directory basenames to skip at any depth.
        skip_archive:  Also skip ``evaluation/archive``.

    Returns:
        Sorted list of core-file Paths.
    """
    hits: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs
            and not (skip_archive and Path(dirpath, d) == EVAL_DIR / "archive")
        ]
        for fname in filenames:
            # Match core / core.<pid> / *.core without fnmatch overhead
            is_core = (
                fname == "core"
                or fname.startswith("core.")
                or fname.endswith(".core")
            )
            if is_core:
                hits.append(Path(dirpath, fname))
    return sorted(hits)


def purge_core_dumps(
    root: Path = PROJECT_ROOT,
    *,
    skip_archive: bool = True,
) -> int:
    """Delete every core-dump file under ``root`` (recursive).

    This is the "triet tieu tan goc" safety net: even with ASAN
    ``disable_coredump=1`` and ``ulimit -c 0`` set at process start, a
    stray core can still land on disk (e.g. a target spawned before the
    limits took effect, or an external process). Running this as part of
    the standard prep step guarantees a clean tree before each campaign.

    Args:
        root:          Root directory to sweep.
        skip_archive:  Leave ``evaluation/archive`` untouched (preserve
                       historic campaign cores) when True.

    Returns:
        Number of core files deleted.
    """
    cores = _iter_core_files(root, skip_archive=skip_archive)
    if not cores:
        print("  ℹ No core dumps found — tree is clean.")
        return 0

    total_bytes = 0
    for cf in cores:
        try:
            total_bytes += cf.stat().st_size
            cf.unlink()
        except OSError as exc:
            print(f"  ⚠ Could not delete {cf}: {exc}")

    print(
        f"  🗑️ Purged {len(cores)} core dump(s) "
        f"({total_bytes / 1048576:.1f} MB) from working tree"
    )
    return len(cores)


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

    Core dumps are NOT archived here — they are purged (deleted) by
    ``purge_core_dumps()`` in ``full_cleanup``, since for ASAN targets the
    ASAN report is strictly richer than a raw core and the user opted to
    eliminate cores entirely.

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

    if not any([has_results, has_plots, has_logs, has_crashes]):
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

    print(f"  📦 Archive complete.")
    return archive_path


def clear_archive(*, force: bool = False) -> int:
    """Delete every archived campaign under ``evaluation/archive``.

    This is the missing counterpart to ``archive_previous_results()``: the
    archival step only ever *adds* timestamped folders, so without a pruning
    step the archive grows without bound. ``clear_archive`` wipes the whole
    archive directory (preserving the empty directory itself so the next
    archival still works) — useful when the accumulated history is no longer
    needed and the disk footprint matters.

    Core dumps archived inside campaign folders are deleted along with
    everything else; this intentionally overrides the ``skip_archive``
    protection that ``purge_core_dumps()`` applies to live sweeps, because
    here the caller has explicitly asked to discard archived history.

    Safety mirrors the rest of ``cleanup.py``'s destructive flows:
    - Prints the list of folders to delete and their total size, then asks
      ``[y/N]`` — unless ``force=True`` (set by ``--force``).
    - A no-op when the archive is already empty.

    Args:
        force: Skip the interactive confirmation prompt.

    Returns:
        Number of archived campaign folders deleted.
    """
    if not ARCHIVE_DIR.exists():
        print("  ℹ Archive directory does not exist — nothing to clear.")
        return 0

    # Each archived campaign is a directory <target>_<driver>_<ts>.
    campaigns = sorted(
        (p for p in ARCHIVE_DIR.iterdir() if p.is_dir()),
        key=lambda p: p.name,
    )
    if not campaigns:
        print("  ℹ Archive is empty — nothing to clear.")
        return 0

    # Compute total size per campaign for the confirmation summary.
    def _dir_size(path: Path) -> int:
        return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())

    total_bytes = sum(_dir_size(c) for c in campaigns)

    print(f"  🗑️ Clearing archive: {len(campaigns)} campaign(s) "
          f"({total_bytes / 1048576:.1f} MB) under "
          f"{ARCHIVE_DIR.relative_to(PROJECT_ROOT)}")
    for c in campaigns:
        print(f"     • {c.name}")

    if not force:
        resp = input("  Delete ALL of the above? This cannot be undone. [y/N] ").strip().lower()
        if resp != "y":
            print("  Aborted — archive left untouched.")
            return 0

    deleted = 0
    for c in campaigns:
        try:
            shutil.rmtree(c)
            deleted += 1
        except OSError as exc:
            print(f"  ⚠ Could not delete {c.name}: {exc}")

    print(f"  🗑️ Cleared {deleted}/{len(campaigns)} campaign(s) from archive.")
    return deleted


# =============================================================================
# 2. Orphaned Resource Cleanup
# =============================================================================


def cleanup_orphaned_resources(free_port_8001: bool = True) -> None:
    """Kill orphaned processes, containers, and network devices.

    Handles:
        - Firecracker VM processes
        - Docker containers (lifa-target-server, lifa-lighttpd-server)
        - TAP network devices (tap-lifa0)
        - Unix socket files (/tmp/firecracker-lifa.sock)
        - Port 8001 bindings

    Args:
        free_port_8001: When True, run ``fuser -k 8001/tcp`` to free the
            port. **Set False when the caller is the process that owns
            port 8001** (e.g. the evaluation runner, whose interceptor
            binds 8001 in-process) — otherwise fuser SIGKILLs the runner
            itself. At campaign start (no in-process owner yet) keep True.
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
    # SKIPPED when the caller owns port 8001 (in-process interceptor) —
    # fuser -k would SIGKILL the caller itself.
    if not free_port_8001:
        print("     ⊘ Skip fuser -k 8001/tcp (caller owns the port)")
    else:
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
    """Run the complete cleanup pipeline: archive → purge cores → orphans → shared state.

    This is the standard **prep step before each campaign**: it guarantees a
    clean workspace (no stale results, no stray cores, no orphaned VMs, no
    leftover shared state) so the next run starts from a known-good baseline.
    Run it via ``python3 scripts/cleanup.py --force``.
    """
    print("\n" + "=" * 50)
    print("  LIFA-Fuzz Cleanup Pipeline")
    print("=" * 50)

    archive_previous_results(target=target, driver=driver)
    purge_core_dumps()
    cleanup_orphaned_resources()
    cleanup_shared_state()

    print("\n  ✅ Full cleanup complete — workspace ready for next run.\n")


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
  python3 scripts/cleanup.py --clear-archive           # wipe all archives
  python3 scripts/cleanup.py --clear-archive --force   # wipe, no prompt
  python3 scripts/cleanup.py --force                   # skip confirmation
  python3 scripts/cleanup.py --target lifa --driver firecracker
        """,
    )
    parser.add_argument(
        "--archive-only", action="store_true",
        help="Only archive results (don't kill processes)",
    )
    parser.add_argument(
        "--clear-archive", action="store_true",
        help="Wipe ALL archived campaigns under evaluation/archive/ "
             "(discards history, frees disk). Confirms unless --force.",
    )
    parser.add_argument(
        "--cores-only", action="store_true",
        help="Only purge stray core dumps recursively (quick clean)",
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

    # --cores-only is a safe, targeted action (deletes only stray core dumps,
    # leaves results/crashes/state untouched) — no confirmation needed.
    if args.cores_only:
        purge_core_dumps()
        return

    # --clear-archive discards ALL archived campaign history. It carries its
    # own confirmation prompt (inside clear_archive) unless --force is given,
    # because unlike archival it is strictly destructive and unrecoverable.
    if args.clear_archive:
        clear_archive(force=args.force)
        return

    # Confirmation for the heavier archive/full flows (they move results and
    # kill processes).
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
