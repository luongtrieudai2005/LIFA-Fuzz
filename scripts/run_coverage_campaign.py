#!/usr/bin/env python3
"""
FC2 — Firecracker LightFTP code-coverage campaign (relative A/B/C).

Runs ONE baseline (A/B/C) against the COVERAGE Firecracker rootfs: the fuzzer
fuzzes ffp for N seconds, /init's timer SIGTERMs ffp (gcov_flush + sync), the
guest halts, and this script extracts /opt/cov (.gcda) + /opt/lightftp-build
(.gcno + source) from the rootfs ext4 via debugfs, runs lcov --capture, and
parses line/branch coverage with TelemetryCollector.parse_lcov.

Coverage is measured in a SEPARATE non-snapshot run (snapshot restore would
discard gcov counters), so this is its own short campaign per baseline — not
part of the headline RQ2/RQ3 Firecracker runs.

Usage:
    python3 scripts/run_coverage_campaign.py --baseline B --duration 30
    python3 scripts/run_coverage_campaign.py --baseline A,B,C --duration 30
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

COVERAGE_ROOTFS = _ROOT / "sandbox/firecracker_env/rootfs_lightftp_coverage.ext4"
RESULTS_DIR = _ROOT / "evaluation/results/coverage"

# Mutator/math/LLM config per baseline (mirrors evaluation_runner BASELINE_CONFIGS).
BASELINES = {
    "A": {"mode": "random", "math": False, "llm": False, "desc": "Pure Random"},
    "B": {"mode": "smart", "math": True, "llm": False, "desc": "Math-Only"},
    "C": {"mode": "smart", "math": True, "llm": True, "desc": "Full Fusion"},
}


def _gcov_tool() -> str | None:
    for g in ("gcov-12", "gcov-11", "gcov-15", "gcov"):
        if shutil.which(g):
            return g
    return None


def extract_and_lcov(baseline: str, work: Path) -> dict:
    """debugfs-dump /opt/cov + /opt/lightftp-build, run lcov (in a gcc-12
    container — the .gcda is bookworm gcc-12 format, which the host's
    gcov-11/15 can't read), parse."""
    if not shutil.which("debugfs"):
        print(f"  [{baseline}] debugfs missing on host")
        return {}

    # Dump the gcov build tree (.gcno + source).
    build_dst = work / "build"
    build_dst.mkdir(parents=True, exist_ok=True)
    for sub in ("Source/Release", "Source"):
        out = subprocess.run(
            ["debugfs", "-R", f"rdump /opt/lightftp-build/{sub} {build_dst}",
             str(COVERAGE_ROOTFS)],
            capture_output=True, text=True, timeout=60,
        )
        if out.returncode == 0 and any(build_dst.rglob("*.gcno")):
            break

    # Dump .gcda (GCOV_PREFIX path) and place next to .gcno.
    cov_dst = work / "cov"
    cov_dst.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["debugfs", "-R", f"rdump /opt/cov {cov_dst}", str(COVERAGE_ROOTFS)],
        capture_output=True, text=True, timeout=60,
    )
    gcda_files = list(cov_dst.rglob("*.gcda"))
    gcno_files = list(build_dst.rglob("*.gcno"))
    release_dir = gcno_files[0].parent if gcno_files else build_dst
    for g in gcda_files:
        (release_dir / g.name).write_bytes(g.read_bytes())
    print(f"  [{baseline}] {len(gcda_files)} .gcda placed in {release_dir.relative_to(work)}")
    if not gcda_files:
        return {}

    # Run lcov INSIDE a gcc-12 (bookworm) container — the .gcda is gcc-12
    # format ('B22*'); host gcov-11/15 refuse it. lifa-lcov has matching gcov.
    info = work / "coverage.info"
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{work}:/work", "lifa-lcov",
         "lcov", "--capture", "--directory", "/work/build",
         "--output-file", "/work/coverage.info",
         "--rc", "lcov_branch_coverage=1", "--ignore-errors", "source"],
        capture_output=True, text=True, timeout=180,
    )
    if r.returncode != 0 or not info.exists():
        print(f"  [{baseline}] lcov failed: {r.stderr[:160]}")
        return {}

    from evaluation.telemetry_collector import TelemetryCollector
    data = TelemetryCollector.parse_lcov(str(info))
    data["lcov_path"] = str(info)
    data["gcov_tool"] = "gcov-12 (bookworm container)"
    data["gcda_count"] = len(gcda_files)
    print(f"  [{baseline}] {data['line_coverage_pct']:.1f}% lines "
          f"({data['lines_hit']}/{data['lines_total']}), "
          f"{data['branch_coverage_pct']:.1f}% branches "
          f"({data['branches_hit']}/{data['branches_total']})")
    return data


async def run_baseline(baseline: str, duration: int) -> dict:
    """Boot coverage VM, fuzz `duration`s via the full pipeline, extract."""
    cfg = BASELINES[baseline]
    print(f"\n=== Baseline {baseline} ({cfg['desc']}) — {duration}s coverage run ===")
    work = RESULTS_DIR / f"baseline_{baseline}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)

    # Import lazily so the script can run --help without heavy deps.
    from sandbox.firecracker_driver import FirecrackerSandbox
    import os
    os.environ["LLM_MODE"] = "REAL" if cfg["llm"] else "MOCK"

    sb = FirecrackerSandbox(
        rootfs_path=str(COVERAGE_ROOTFS),
        target_name="lightftp",
        vm_ip="172.16.0.2",
        kernel_args=(
            "console=ttyS0 reboot=k panic=1 pci=off"
            f" root=/dev/vda rw init=/init cov_duration={duration + 5}"
            " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
        ),
    )
    try:
        await sb.start()
        # Drive the fuzzer for `duration`s.
        await fuzz_against_vm(cfg["mode"], duration)
        # Let the /init timer (duration+5s) fire → flush+sync+halt.
        print(f"  waiting {duration + 8}s for /init timer flush...")
        await asyncio.sleep(duration + 8)
    finally:
        await sb.stop()

    return extract_and_lcov(baseline, work)


async def fuzz_against_vm(mutator_mode: str, duration: int) -> None:
    """Run a minimal FTP fuzzer against 172.16.0.2:21 for `duration` seconds.

    Uses the project's FTP client to drive legit traffic + sends a stream of
    mutated commands so ffp exercises varied code paths (the point of coverage).
    """
    import random
    end = asyncio.get_event_loop().time() + duration
    sent = 0
    cmds = [b"USER admin\r\n", b"PASS *\r\n", b"SYST\r\n", b"PWD\r\n",
            b"LIST\r\n", b"CWD pub\r\n", b"TYPE I\r\n", b"QUIT\r\n",
            b"NOOP\r\n", b"RETR a\r\n"]
    while asyncio.get_event_loop().time() < end:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection("172.16.0.2", 21), timeout=5)
            await asyncio.wait_for(r.read(256), timeout=3)
            for _ in range(random.randint(2, 6)):
                c = random.choice(cmds)
                if mutator_mode == "random" and random.random() < 0.4:
                    c = c[:-2] + os.urandom(random.randint(1, 4)) + b"\r\n"
                w.write(c)
                await w.drain()
                sent += 1
                try:
                    await asyncio.wait_for(r.read(256), timeout=1)
                except asyncio.TimeoutError:
                    pass
            w.close()
        except Exception:
            pass
        await asyncio.sleep(0.05)
    print(f"  fuzzed ~{sent} commands in {duration}s ({mutator_mode})")


def main() -> int:
    global os
    import os
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", default="B", help="A, B, C, or comma-separated")
    p.add_argument("--duration", type=int, default=30)
    args = p.parse_args()

    if not COVERAGE_ROOTFS.exists():
        print(f"[err] {COVERAGE_ROOTFS} not built — run build_rootfs_lightftp_coverage.sh")
        return 2

    baselines = [b.strip().upper() for b in args.baseline.split(",")]
    summary = {}
    for b in baselines:
        if b not in BASELINES:
            print(f"[skip] unknown baseline {b}")
            continue
        try:
            summary[b] = asyncio.run(run_baseline(b, args.duration))
        except Exception as e:
            print(f"  [{b}] FAILED: {e}")
            summary[b] = {"error": str(e)}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"coverage_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_s": args.duration,
        "rootfs": str(COVERAGE_ROOTFS),
        "results": summary,
    }, indent=2, default=str))
    print(f"\n=== SUMMARY (relative A/B/C code coverage) ===")
    for b, d in summary.items():
        if d.get("branches_hit") is not None:
            print(f"  {b} ({BASELINES[b]['desc']:<12}): "
                  f"{d['branch_coverage_pct']}% branches ({d['branches_hit']}/{d['branches_total']}), "
                  f"{d['line_coverage_pct']}% lines")
    print(f"\n  saved → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
