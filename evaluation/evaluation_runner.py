"""
evaluation/evaluation_runner.py
─────────────────────────────────
Orchestrates running LIFA-Fuzz under 3 baseline configurations for
a fixed duration, collecting telemetry for each.

Baseline Configurations:
    A (Pure Random):  Math OFF, LLM OFF — pure random bit-flip fuzzing
    B (Math-Only):    Math ON,  LLM OFF — bootstrap rules from DifferentialAnalyzer
    C (Full Fusion):  Math ON,  LLM ON  — complete Neural-Mathematical Fusion Loop

Usage:
    # Run all baselines for 5 minutes each:
    python -m evaluation.evaluation_runner --duration 300

    # Quick smoke test (1 minute):
    python -m evaluation.evaluation_runner --duration 60

    # Single baseline:
    python -m evaluation.evaluation_runner --baseline B --duration 120

Output:
    evaluation/results/
    ├── baseline_A_random/
    │   ├── telemetry.jsonl
    │   └── summary.json
    ├── baseline_B_math/
    │   ├── telemetry.jsonl
    │   └── summary.json
    ├── baseline_C_full/
    │   ├── telemetry.jsonl
    │   └── summary.json
    └── comparison.json         ← Side-by-side comparison of all baselines
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from evaluation.telemetry_collector import TelemetryCollector
from dotenv import load_dotenv

RESULTS_DIR = Path(__file__).parent / "results"

BASELINE_CONFIGS = {
    "A": {
        "label": "baseline_A_random",
        "description": "Pure Random Fuzzing (no AI, no math)",
        "mutator_mode": "random",
        "math_enabled": False,
        "llm_enabled": False,
        "color": "#e74c3c",  # Red
    },
    "B": {
        "label": "baseline_B_math",
        "description": "Math-Only (DifferentialAnalyzer bootstrap rules)",
        "mutator_mode": "smart",
        "math_enabled": True,
        "llm_enabled": False,
        "color": "#3498db",  # Blue
    },
    "C": {
        "label": "baseline_C_full",
        "description": "Full LIFA-Fuzz (Neural-Mathematical Fusion)",
        "mutator_mode": "smart",
        "math_enabled": True,
        "llm_enabled": True,
        "color": "#2ecc71",  # Green
    },
}


# =============================================================================
# Pipeline Construction (mirrors main.py but with telemetry injection)
# =============================================================================


async def run_single_baseline(
    baseline_id: str,
    duration_s: int,
    sandbox_driver: str = "docker",
    kill_server_ratio: float = 0.0,
    target: str = "lifa",
    total_baselines: int = 3,
    baseline_index: int = 0,
) -> dict[str, Any]:
    """Run LIFA-Fuzz under one baseline configuration for a fixed duration.

    Args:
        baseline_id:     "A", "B", or "C".
        duration_s:      How long to run this baseline (seconds).
        sandbox_driver:  Sandbox backend ("docker" or "firecracker").
        kill_server_ratio: Fraction of KILL_SERVER test payloads (0 for benchmarking).
        target:          Target server: "lifa" (vulnerable_server) or
                         "lighttpd" (real-world HTTP server).
        total_baselines: Total number of baselines in the campaign.
        baseline_index:  0-based index of this baseline in the campaign.

    Returns:
        Summary dict with aggregate metrics.
    """
    config = BASELINE_CONFIGS[baseline_id]
    baseline_dir = RESULTS_DIR / config["label"]
    baseline_dir.mkdir(parents=True, exist_ok=True)

    telemetry_path = baseline_dir / "telemetry.jsonl"
    # Clear previous telemetry
    if telemetry_path.exists():
        telemetry_path.unlink()

    # Clean shared state
    _reset_shared_state()

    # Set LLM mode based on config
    if config["llm_enabled"]:
        os.environ["LLM_MODE"] = os.environ.get("LLM_MODE", "MOCK")
    else:
        os.environ["LLM_MODE"] = "MOCK"  # Always MOCK when LLM disabled

    # ── Target configuration ─────────────────────────────────────────
    TARGET_CONFIGS = {
        "lifa": {
            "image": "lifa-fuzz-server:latest",
            "build_context": "sandbox/target",
            "port": 9000,
            "container": "lifa-target-server",
            "client_script": "sandbox/client/client.py",
        },
        "lighttpd": {
            "image": "lifa-lighttpd-cov:latest",
            "build_context": "tests/dummy_targets/real_targets/lighttpd",
            "port": 8080,
            "container": "lifa-lighttpd-server",
            "client_script": "sandbox/client/http_client.py",
        },
    }
    tcfg = TARGET_CONFIGS.get(target)
    if tcfg is None:
        raise ValueError(f"Unknown target '{target}'. Choose: {list(TARGET_CONFIGS.keys())}")

    # Firecracker target-specific rootfs and kernel config
    FIRECRACKER_TARGET_CONFIGS = {
        "lifa": {
            "rootfs_path": "sandbox/firecracker_env/rootfs.ext4",
            "kernel_args": (
                "console=ttyS0 reboot=k panic=1 pci=off"
                " root=/dev/vda rw"
                " init=/bin/vulnerable_server"
                " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
            ),
            "target_port": 9000,
        },
        "lighttpd": {
            "rootfs_path": "sandbox/firecracker_env/rootfs_lighttpd.ext4",
            "kernel_args": (
                "console=ttyS0 reboot=k panic=1 pci=off"
                " root=/dev/vda rw"
                " init=/init"
                " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
            ),
            "target_port": 9000,  # lighttpd listens on 9000 inside the VM (matches lighttpd.conf)
        },
    }

    image_display = tcfg["image"] if sandbox_driver == "docker" else "MicroVM (rootfs)"
    print(f"\n{'=' * 60}")
    print(f"  Baseline {baseline_id}: {config['description']}")
    print(f"  Duration: {duration_s}s  |  Mode: {config['mutator_mode']}")
    print(f"  Driver: {sandbox_driver}  |  Target: {target}")
    print(f"  Image: {image_display}")
    print(f"  Math: {config['math_enabled']}  |  LLM: {config['llm_enabled']}")
    print(f"{'=' * 60}")

    background_tasks: list[asyncio.Task] = []
    slow_loop_proc = None
    sandbox = None
    client_proc = None
    interceptor = None

    # ── Signal handler for graceful cleanup on kill ───────────
    import signal as _signal
    _baseline_shutdown = asyncio.Event()

    def _baseline_sig_handler(sig: int, frame: Any) -> None:
        print(f"\n  ⚠ Received signal {sig} — shutting down baseline {baseline_id}...")
        _baseline_shutdown.set()

    _signal.signal(_signal.SIGINT, _baseline_sig_handler)
    _signal.signal(_signal.SIGTERM, _baseline_sig_handler)

    try:
        # ── 1. Sandbox ────────────────────────────────────────────
        from shared.sandbox_abstraction import BaseSandbox, get_driver
        import sandbox.docker_driver  # noqa: F401
        import sandbox.firecracker_driver  # noqa: F401

        driver_cls = get_driver(sandbox_driver)

        if sandbox_driver == "docker":
            sandbox: BaseSandbox = driver_cls(
                target_image_tag=tcfg["image"],
                target_container=tcfg["container"],
                target_internal_port=tcfg["port"],
                build_context=tcfg["build_context"],
            )
        else:
            # Firecracker: select rootfs + kernel_args by target
            fc_cfg = FIRECRACKER_TARGET_CONFIGS[target]
            sandbox = driver_cls(
                rootfs_path=fc_cfg["rootfs_path"],
                kernel_args=fc_cfg["kernel_args"],
                target_port=fc_cfg["target_port"],
            )

        await sandbox.start()
        net_config = await sandbox.get_network_config()
        target_host = net_config["target_host"]
        target_port = net_config["target_port"]
        await asyncio.sleep(2)

        if not await sandbox.is_target_alive():
            raise RuntimeError("Target server is not alive after startup")

        # ── 2. Interceptor ──────────────────────────────────────────
        from fast_loop.interceptor import Interceptor

        traffic_log = "shared/raw_traffic.jsonl"
        Path(traffic_log).parent.mkdir(parents=True, exist_ok=True)
        Path(traffic_log).unlink(missing_ok=True)

        interceptor = Interceptor(
            listen_host="0.0.0.0",
            listen_port=8001,
            upstream_host=target_host,
            upstream_port=target_port,
            traffic_log_path=traffic_log,
        )

        await interceptor.start()
        serve_task = asyncio.create_task(
            interceptor.serve_forever(), name="interceptor_serve"
        )
        background_tasks.append(serve_task)

        # ── 3. Client Subprocess ──────────────────────────────────
        from fast_loop.client_process import ClientSubprocess

        client_proc = ClientSubprocess(
            script_path=tcfg["client_script"],
            target_host="127.0.0.1",
            target_port=8001,
        )
        await client_proc.start()
        client_watch_task = asyncio.create_task(
            client_proc.watch(check_interval=5.0), name="client_watchdog"
        )
        background_tasks.append(client_watch_task)

        # ── 4. Mutation Engine ─────────────────────────────────────
        from fast_loop.mutator import MutationEngine

        seed_queue: asyncio.Queue = asyncio.Queue()

        # ── Target-specific seed injection ──────────────────────────
        if target == "lighttpd":
            from shared.schemas import Direction, TrafficRecord
            # Inject diverse HTTP seeds so the mutator has good starting material
            http_seeds = [
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                b"username=admin&password=test",
                b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n"
                b"Range: bytes=0-1023\r\nConnection: close\r\n\r\n",
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            ]
            for seed_data in http_seeds:
                await seed_queue.put(TrafficRecord(
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_data=seed_data,
                ))

        mutator = MutationEngine(
            target_host=target_host,
            target_port=target_port,
            seed_queue=seed_queue,
            k=2,
            max_eps=5000,              # Lift throttle for evaluation
            connection_timeout=0.2,    # Fast localhost
            recv_timeout=0.01,         # 10ms fallback
            no_recv=True,              # Skip response — crash monitored separately
        )

        # ── 5. Crash Monitor ──────────────────────────────────────
        from fast_loop.crash_monitor import CrashMonitor
        from shared.crash_manager import CrashManager

        crashes_dir = baseline_dir / "crashes"
        crashes_dir.mkdir(parents=True, exist_ok=True)

        crash_manager = CrashManager(crash_dir=str(crashes_dir))
        await crash_manager.load()

        crash_monitor = CrashMonitor(
            sandbox=sandbox,
            interceptor=interceptor,
            mutator=mutator,
            poll_interval_ms=500,
            crash_corpus_dir=str(crashes_dir),
            auto_reset=True,
            restart_delay_s=2.0,
            crash_manager=crash_manager,  # FIX: wire crash_manager so telemetry reports crashes
        )

        watch_task = asyncio.create_task(
            crash_monitor.watch(), name="crash_monitor_watch"
        )
        background_tasks.append(watch_task)

        # ── 6. Mutation Loop ───────────────────────────────────────
        mutation_task = asyncio.create_task(
            mutator.run(),
            name="mutation_loop",
        )
        background_tasks.append(mutation_task)

        # ── 6b. Seed Feeder ──────────────────────────────────────
        from shared.schemas import Direction, TrafficRecord

        async def _feed_seed_queue() -> None:
            """Read JSONL traffic log and push C2S seeds into the mutator queue."""
            last_pos = 0
            import json as _json
            while True:
                try:
                    p = Path(traffic_log)
                    if not p.exists():
                        await asyncio.sleep(1.0)
                        continue
                    with open(p) as f:
                        lines = f.readlines()
                    for line in lines[last_pos:]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = _json.loads(line)
                        except _json.JSONDecodeError:
                            continue
                        if (
                            rec.get("direction") == "client_to_server"
                            and not rec.get("is_mutated")
                        ):
                            raw_hex = rec.get("payload", rec.get("raw_hex", ""))
                            if raw_hex and len(raw_hex) >= 8:
                                tr = TrafficRecord(
                                    direction=Direction.CLIENT_TO_SERVER,
                                    raw_data=bytes.fromhex(raw_hex),
                                )
                                await seed_queue.put(tr)
                    last_pos = len(lines)
                except Exception:
                    pass
                await asyncio.sleep(1.0)

        seed_feeder_task = asyncio.create_task(
            _feed_seed_queue(), name="seed_feeder"
        )
        background_tasks.append(seed_feeder_task)

        # ── 7. Slow Loop (only for Baseline C with LLM) ────────────
        agent = None
        if config["llm_enabled"] or config["math_enabled"]:
            # Start slow loop subprocess for rule generation
            # For Baseline B (math-only), the orchestrator still runs
            # to produce bootstrap rules from the analyzer
            from slow_loop.llm_agent import LLMAgent
            agent = LLMAgent(
                provider=os.environ.get("LLM_PROVIDER", "openai"),
                model=os.environ.get("LLM_MODEL", "gpt-4o"),
                api_key=os.environ.get(
                    os.environ.get("LLM_API_KEY_ENV", "OPENAI_API_KEY"), "test"
                ),
                api_base=os.environ.get("LLM_API_BASE", ""),
            )

            if config["llm_enabled"]:
                # Full slow loop subprocess
                slow_loop_proc = await _start_slow_loop_subprocess()
            else:
                # Math-only: run orchestrator in-process for bootstrap rules
                math_task = asyncio.create_task(
                    _run_math_only_loop(
                        traffic_log, agent, mutator, crash_manager
                    ),
                    name="math_bootstrap_loop",
                )
                background_tasks.append(math_task)

        # ── 8. Telemetry Collector ─────────────────────────────────
        collector = TelemetryCollector(
            output_path=str(telemetry_path),
            baseline_label=baseline_id,
            snapshot_interval_s=10.0,
        )
        await collector.start(interceptor, mutator, crash_manager, agent)

        # ── 8b. Runtime State Writer (feeds the Dashboard) ────────
        # Writes shared/runtime_state.json every 2s so the Streamlit
        # dashboard can show live status during evaluation campaigns.
        from shared.runtime_state import (
            PipelineState, TargetState, ClientState, InterceptorState,
            MutatorState, SlowLoopState, RuleSetState, EvaluationState,
            write_runtime_state, RUNTIME_STATE_FILE,
        )

        async def _eval_state_writer() -> None:
            """Background task: write runtime state for dashboard."""
            while True:
                try:
                    target_alive = await sandbox.is_target_alive()
                    ms = mutator.get_stats()
                    state = PipelineState(
                        timestamp=time.time(),
                        uptime_seconds=time.monotonic() - start,
                        pipeline_status="running" if target_alive else "degraded",
                        target=TargetState(
                            alive=target_alive,
                            sandbox_driver=sandbox_driver,
                            host=target_host,
                            port=target_port,
                        ),
                        client=ClientState(
                            alive=client_proc.is_alive if client_proc else None,
                            pid=client_proc.pid if client_proc else None,
                        ),
                        interceptor=InterceptorState(
                            captured=interceptor.total_captured,
                            injected=ms.total_sent,
                            active_connections=interceptor.active_connections,
                            paused=interceptor.is_paused,
                        ),
                        mutator=MutatorState(
                            mode=ms.mode,
                            k=2,
                            current_eps=ms.current_eps,
                            total_sent=ms.total_sent,
                            total_accepted=ms.total_accepted,
                            total_rejected=ms.total_rejected,
                            total_crashes=ms.total_crashes,
                            investigation_mode=ms.investigation_mode,
                            rule_set_version=ms.rule_set_version,
                        ),
                        slow_loop=SlowLoopState(
                            alive=(slow_loop_proc is not None and slow_loop_proc.poll() is None),
                            pid=slow_loop_proc.pid if slow_loop_proc else None,
                            total_cycles=0,
                            total_inferences=0,
                            total_rules_pushed=0,
                            last_error="",
                        ),
                        evaluation=EvaluationState(
                            campaign_active=True,
                            baseline_id=baseline_id,
                            baseline_label=config["label"],
                            baseline_description=config["description"],
                            total_baselines=total_baselines,
                            baseline_index=baseline_index,
                            baseline_duration_s=duration_s,
                            baseline_elapsed_s=time.monotonic() - start,
                            target=target,
                            sandbox_driver=sandbox_driver,
                        ),
                        unique_crashes=0,
                        total_crash_hits=crash_monitor.total_crashes,
                    )
                    # Try to get unique crash count
                    try:
                        cs = await crash_manager.get_statistics()
                        state.unique_crashes = cs.unique_crashes
                        state.total_crash_hits = cs.total_hits
                    except Exception:
                        pass
                    write_runtime_state(state, RUNTIME_STATE_FILE)
                except Exception:
                    pass
                await asyncio.sleep(2.0)

        state_writer_task = asyncio.create_task(
            _eval_state_writer(), name="eval_state_writer"
        )
        background_tasks.append(state_writer_task)

        # ── 9. Run for fixed duration ──────────────────────────────
        print(f"  Running baseline {baseline_id} for {duration_s}s...")
        start = time.monotonic()

        # Progress reporting
        while (time.monotonic() - start) < duration_s and not _baseline_shutdown.is_set():
            elapsed = time.monotonic() - start
            remaining = duration_s - elapsed
            if int(elapsed) % 30 == 0 and elapsed > 0:
                # MutationEngine sends directly to target (bypasses Interceptor),
                # so we use mutator's total_sent as the authoritative count.
                ms = mutator.get_stats()
                injected = ms.total_sent
                eps = ms.current_eps if ms.current_eps > 0 else (injected / elapsed if elapsed > 0 else 0)
                crashes = crash_monitor.total_crashes
                print(
                    f"  [{elapsed:.0f}s/{duration_s}s] "
                    f"EPS={eps:.0f}  injected={injected}  crashes={crashes}"
                )
            await asyncio.sleep(1.0)

        # ── 10. Stop and collect results ───────────────────────────
        print(f"  Baseline {baseline_id} complete. Collecting final metrics...")
        await collector.stop()
        summary = await collector.write_summary()

        # Final stats
        final_stats = mutator.coverage_summary
        summary["final_mutations"] = final_stats["total_mutations"]
        summary["final_rules"] = final_stats["active_rules"]
        summary["final_coverage"] = final_stats["unique_offsets_fuzzed"]

        # Save summary
        with open(baseline_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)

        print(f"  → Summary: {summary}")
        return summary

    except Exception as e:
        print(f"  ERROR in baseline {baseline_id}: {e}")
        import traceback
        traceback.print_exc()
        return {"baseline": baseline_id, "error": str(e)}

    finally:
        # ── Cleanup ────────────────────────────────────────────────
        for task in background_tasks:
            if not task.done():
                task.cancel()
        for task in background_tasks:
            try:
                await asyncio.wait_for(task, timeout=3.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        try:
            if client_proc is not None:
                await client_proc.stop()
        except Exception:
            pass

        try:
            if interceptor is not None:
                await interceptor.stop()
        except Exception:
            pass

        # Collect gcov coverage BEFORE sandbox.stop() removes the container
        try:
            if sandbox is not None:
                coverage_data = await _collect_gcov_coverage(
                    baseline_dir, sandbox, target=target,
                    sandbox_driver=sandbox_driver,
                )
                if coverage_data:
                    # Append coverage to summary.json
                    summary_path = baseline_dir / "summary.json"
                    if summary_path.exists():
                        with open(summary_path) as f:
                            summary = json.load(f)
                        summary["coverage"] = coverage_data
                        with open(summary_path, "w") as f:
                            json.dump(summary, f, indent=2, default=str)
        except Exception as e:
            print(f"  ⚠ Coverage collection failed: {e}")

        try:
            if sandbox is not None:
                await sandbox.stop()
        except Exception:
            pass

        if slow_loop_proc:
            try:
                slow_loop_proc.terminate()
                slow_loop_proc.wait(timeout=5)
            except Exception:
                pass

        # Reset LLM_MODE
        os.environ.pop("LLM_MODE", None)


# =============================================================================
# Helper Functions
# =============================================================================


def _reset_shared_state() -> None:
    """Clean shared files between baseline runs.

    Removes all persistent state so each baseline starts from a
    clean slate — no cross-contamination of rules, grammars, or
    telemetry from previous runs.
    """
    for path in [
        "shared/raw_traffic.jsonl",
        "shared/active_rules.json",
        "shared/llm_last_inference.json",
        # Rules file (from config.yaml rule_generator.rule_output_file)
        "/tmp/lifa_rules.json",
        # Slow-loop subprocess state (total_inferences, etc.)
        "shared/slow_loop_state.json",
        # Persistent grammar cache (survives LLMAgent restarts)
        "shared/last_known_grammar.json",
        # Dashboard runtime state
        "shared/runtime_state.json",
    ]:
        p = Path(path)
        if p.exists():
            p.unlink()


async def _collect_gcov_coverage(
    baseline_dir: Path,
    sandbox: Any = None,
    target: str = "lifa",
    sandbox_driver: str = "docker",
) -> dict[str, Any]:
    """Collect gcov code coverage data after a baseline run.

    Works with the dummy target (host-run) or Docker-based target.
    Requires ``lcov`` installed on the host. Gracefully degrades if
    lcov is unavailable.

    Args:
        baseline_dir: Where to store coverage artifacts.
        sandbox:      Optional sandbox instance (for Docker gcda extraction).
        target:       Target server ("lifa" or "lighttpd") — determines gcda
                       search paths inside the container.
        sandbox_driver: "docker" or "firecracker". Coverage is skipped for
                       Firecracker (no docker cp access to VM filesystem).

    Returns:
        Coverage dict from TelemetryCollector.parse_lcov(), or empty dict.
    """
    import subprocess as sp
    from evaluation.telemetry_collector import TelemetryCollector

    # Check if lcov is available
    try:
        sp.run(
            ["lcov", "--version"],
            capture_output=True, timeout=10, check=True,
        )
    except (FileNotFoundError, sp.CalledProcessError, sp.TimeoutExpired):
        print("  ⚠ lcov not installed — skipping coverage collection. "
              "Install with: sudo apt install lcov")
        return {}

    # Firecracker VMs have no mechanism to extract .gcda files.
    # Coverage collection requires docker cp, which only works with containers.
    if sandbox_driver == "firecracker":
        print("  ℹ Coverage collection skipped — not available for Firecracker driver")
        return {}

    coverage_dir = baseline_dir / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)

    work_dir = coverage_dir / "gcov_work"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Collect .gcda files — search paths differ by target
    if sandbox is not None and hasattr(sandbox, "target_container"):
        container_name = sandbox.target_container

        # Collect coverage for lighttpd target
        if target == "lighttpd":
            try:
                import subprocess as sp
                # Step 1: SIGINT (signal 2) to flush gcov .gcda files
                sp.run(
                    ["docker", "exec", container_name, "kill", "-2", "1"],
                    capture_output=True, timeout=10,
                )
                await asyncio.sleep(2)  # Wait for gcov flush
                print("  ✓ Sent SIGINT to lighttpd (PID 1) — gcov buffers flushed")

                # Step 2: Copy gcno+gcda from stopped container (docker cp works on stopped)
                for src in [
                    f"{container_name}:/tmp/lighttpd-1.4.55/src/.",
                    f"{container_name}:/tmp/lighttpd-1.4.55/.",
                ]:
                    sp.run(
                        ["docker", "cp", src, str(work_dir)],
                        capture_output=True, timeout=30,
                    )
                gcda_files = list(work_dir.rglob("*.gcda"))
                if gcda_files:
                    print(f"  ✓ Copied {len(gcda_files)} .gcda files from container")

                    # Step 3: Run lcov on HOST with gcov-11 (matching container's GCC)
                    info_path = coverage_dir / "coverage.info"
                    lcov_result = sp.run(
                        ["lcov", "--capture",
                         "--directory", str(work_dir),
                         "--output-file", str(info_path),
                         "--gcov-tool", "gcov-11",
                         "--rc", "lcov_branch_coverage=1",
                         "--ignore-errors", "source"],
                        capture_output=True, text=True, timeout=60,
                    )
                    if lcov_result.returncode == 0:
                        print(f"  ✓ lcov --capture succeeded (gcov-11)")
                        # Parse coverage.info and return structured data
                        coverage_data = TelemetryCollector.parse_lcov(str(info_path))
                        coverage_data["lcov_path"] = str(info_path)
                        print(
                            f"  ✓ Coverage: {coverage_data['line_coverage_pct']:.1f}% lines "
                            f"({coverage_data['lines_hit']}/{coverage_data['lines_total']}), "
                            f"{coverage_data['branch_coverage_pct']:.1f}% branches "
                            f"({coverage_data['branches_hit']}/{coverage_data['branches_total']})"
                        )
                        return coverage_data
                    else:
                        print(f"  ⚠ lcov failed: {lcov_result.stderr[:200]}")
                else:
                    print("  ℹ No .gcda files found after SIGTERM")
            except Exception as e:
                print(f"  ⚠ Coverage collection failed: {e}")
                return {}

        # For non-lighttpd targets, use original docker cp approach
        if target != "lighttpd":
            gcda_search_paths = [
                f"{container_name}:/app/.",
            ]
            for src_path in gcda_search_paths:
                try:
                    result = sp.run(
                        ["docker", "cp", src_path, str(work_dir)],
                        capture_output=True, timeout=30,
                    )
                    if result.returncode == 0:
                        break  # First successful copy is enough
                except Exception:
                    continue
    else:
        # Host-based (dummy target): find .gcda files recursively
        for gcda in Path(".").rglob("*.gcda"):
            dest = work_dir / gcda.relative_to(".")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(gcda), str(dest))

    # Check we actually got data (search recursively for subdirs)
    gcda_files = list(work_dir.rglob("*.gcda"))
    if not gcda_files:
        print("  ℹ No .gcda files found — no coverage data to collect")
        return {}

    # Run lcov --capture
    info_path = coverage_dir / "coverage.info"
    try:
        result = sp.run(
            ["lcov", "--capture", "--directory", str(work_dir),
             "--output-file", str(info_path), "--rc", "lcov_branch_coverage=1",
             "--ignore-errors", "version,empty"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            print(f"  ⚠ lcov --capture failed: {result.stderr[:200]}")
            return {}
    except (FileNotFoundError, sp.TimeoutExpired) as e:
        print(f"  ⚠ lcov execution error: {e}")
        return {}

    # Run genhtml for visual report
    html_dir = coverage_dir / "html"
    try:
        sp.run(
            ["genhtml", str(info_path), "--output-directory", str(html_dir),
             "--branch-coverage"],
            capture_output=True, text=True, timeout=60,
        )
    except (FileNotFoundError, sp.TimeoutExpired):
        pass  # Non-critical — HTML report is optional

    # Parse and return structured data
    coverage_data = TelemetryCollector.parse_lcov(str(info_path))
    coverage_data["lcov_path"] = str(info_path)
    coverage_data["html_report"] = str(html_dir / "index.html") if html_dir.exists() else None

    print(
        f"  ✓ Coverage: {coverage_data['line_coverage_pct']:.1f}% lines "
        f"({coverage_data['lines_hit']}/{coverage_data['lines_total']}), "
        f"{coverage_data['branch_coverage_pct']:.1f}% branches "
        f"({coverage_data['branches_hit']}/{coverage_data['branches_total']})"
    )

    return coverage_data


async def _start_slow_loop_subprocess():
    """Start the slow loop as a subprocess (Baseline C).

    Redirects stdout/stderr to a log file so errors are visible.
    Performs a health check after 5s to catch immediate crashes.
    """
    import subprocess as sp

    script = _project_root / "run_slow_loop.py"
    if not script.exists():
        print("  ⚠ run_slow_loop.py not found — Baseline C will run without LLM")
        return None
    try:
        # Redirect to log file instead of PIPE (which silently swallows errors)
        slow_loop_log = _project_root / "logs" / "slow_loop_subprocess.log"
        slow_loop_log.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(slow_loop_log, "w")

        proc = sp.Popen(
            [sys.executable, str(script), "--config", "config.yaml"],
            stdout=log_fh,
            stderr=sp.STDOUT,  # Merge stderr into stdout → log file
            cwd=str(_project_root),
        )

        # Close file handle in parent — child process inherited the fd
        log_fh.close()

        # Health check: wait 5s, see if it died immediately
        await asyncio.sleep(5.0)
        if proc.poll() is not None:
            # Process already exited — read log for error
            try:
                error_output = slow_loop_log.read_text()[-2000:]
            except Exception:
                error_output = "(could not read log)"
            print(
                f"  ⚠ Slow loop subprocess died (rc={proc.returncode}) "
                f"within 5s:\n{error_output}"
            )
            return None

        print(f"  ✓ Slow loop subprocess started (PID={proc.pid})")
        print(f"    Log: {slow_loop_log}")
        return proc
    except Exception as e:
        print(f"  ⚠ Failed to start slow loop subprocess: {e}")
        return None


async def _run_math_only_loop(
    traffic_log: str,
    agent: Any,
    mutator: Any,
    crash_manager: Any,
    poll_interval: float = 15.0,
) -> None:
    """Background loop that runs DifferentialAnalyzer and pushes bootstrap rules.

    This is Baseline B: math-only, no LLM calls.
    """
    from slow_loop.parser import TrafficParser
    from slow_loop.differential_analyzer import DifferentialAnalyzer
    from slow_loop.rules_orchestrator import RulesOrchestrator
    from slow_loop.rule_generator import RuleGenerator

    analyzer = DifferentialAnalyzer()
    # Create parser ONCE so incremental reads track position correctly
    parser = TrafficParser(log_path=traffic_log, read_interval_ms=1000)

    while True:
        await asyncio.sleep(poll_interval)
        try:
            # Check if traffic log has enough data
            log_path = Path(traffic_log)
            if not log_path.exists() or log_path.stat().st_size == 0:
                continue

            sessions = await parser.read_log()
            if not sessions:
                continue

            # Extract raw packets
            all_packets = []
            for session in sessions:
                all_packets.extend(session.packets)

            raw_bytes = []
            for pkt in all_packets:
                if pkt.get("direction") == "client_to_server":
                    hex_data = pkt.get("payload", "")
                    if hex_data:
                        try:
                            raw_bytes.append(bytes.fromhex(hex_data))
                        except ValueError:
                            continue

            if len(raw_bytes) < analyzer.min_packets:
                continue

            # Run analyzer → bootstrap rules
            heatmap = analyzer.analyze(raw_bytes)
            field_rules = heatmap.to_field_rules()

            if field_rules:
                import hashlib
                from shared.schemas import SemanticRule, RuleType, MutationStrategy
                rules = []
                for fr in field_rules:
                    end = fr.offset + fr.length if fr.length > 0 else 65535
                    # Map strategy to rule type
                    strategy_map = {
                        MutationStrategy.STATIC: RuleType.STRUCTURAL,
                        MutationStrategy.BOUNDARY_VALUES: RuleType.BOUNDARY,
                        MutationStrategy.BIT_FLIP: RuleType.BIT_FLIP,
                        MutationStrategy.RANDOM_BYTES: RuleType.STRUCTURAL,
                        MutationStrategy.CALCULATED: RuleType.BOUNDARY,
                    }
                    rt = strategy_map.get(fr.mutation_strategy, RuleType.BIT_FLIP)
                    # C2 fix: deterministic rule_id based on field content
                    # so the same field always gets the same ID → dedup works.
                    rule_id = hashlib.sha256(
                        f"{fr.offset}:{end}:{fr.mutation_strategy.value}".encode()
                    ).hexdigest()[:12]
                    rule = SemanticRule(
                        rule_id=rule_id,
                        rule_type=rt,
                        target_field_name=fr.field_name,
                        mutation_type=rt,
                        offset_start=fr.offset,
                        offset_end=end,
                        priority=fr.confidence,
                        description=fr.notes or "Bootstrap rule from DifferentialAnalyzer",
                    )
                    rules.append(rule)

                # Direct push to mutator (primary delivery mechanism)
                from shared.schemas import ActiveRuleSet as _ARS
                rule_set_payload = _ARS(
                    protocol_name="math_bootstrap",
                    rules=rules,
                )
                await mutator.update_rule_set(rule_set_payload)

                # Write rules to file for mutator file poller (backup path)
                # MUST match the path read by MutationEngine._load_rules_path_from_config()
                rules_path = Path(mutator._rules_file)
                rules_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = rules_path.with_suffix(".tmp")
                with open(tmp, "w") as f:
                    json.dump(
                        [r.model_dump(mode="json") for r in rules],
                        f, indent=2, default=str,
                    )
                tmp.rename(rules_path)

        except asyncio.CancelledError:
            break
        except Exception:
            continue


# =============================================================================
# Comparison & Reporting
# =============================================================================


def write_comparison(baselines: list[str] = None) -> dict:
    """Write a side-by-side comparison of all completed baselines."""
    if baselines is None:
        baselines = list(BASELINE_CONFIGS.keys())

    comparison = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baselines": {},
    }

    for bid in baselines:
        config = BASELINE_CONFIGS[bid]
        summary_path = RESULTS_DIR / config["label"] / "summary.json"
        if summary_path.exists():
            with open(summary_path) as f:
                comparison["baselines"][bid] = json.load(f)
        else:
            comparison["baselines"][bid] = {"status": "not_run"}

    # Write comparison file
    comp_path = RESULTS_DIR / "comparison.json"
    with open(comp_path, "w") as f:
        json.dump(comparison, f, indent=2, default=str)

    return comparison


# =============================================================================
# CLI
# =============================================================================


async def main():
    parser = argparse.ArgumentParser(
        description="LIFA-Fuzz Evaluation Runner — Academic Benchmarking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m evaluation.evaluation_runner --duration 300   # 5 min per baseline
  python -m evaluation.evaluation_runner --baseline A --duration 60  # Quick test
        """,
    )
    parser.add_argument(
        "--duration", type=int, default=300,
        help="Duration per baseline in seconds (default: 300)",
    )
    parser.add_argument(
        "--baseline", choices=["A", "B", "C", "all"], default="all",
        help="Which baseline to run (default: all)",
    )
    parser.add_argument(
        "--driver", choices=["docker", "firecracker"], default="docker",
        help="Sandbox driver (default: docker)",
    )
    parser.add_argument(
        "--target", default="lifa", choices=["lifa", "lighttpd"],
        help="Target server: lifa (vulnerable_server) or lighttpd (real-world HTTP)",
    )

    args = parser.parse_args()

    baselines = list(BASELINE_CONFIGS.keys()) if args.baseline == "all" else [args.baseline]

    # ── Pre-run cleanup: archive old results, kill orphans ────────
    from scripts.cleanup import (
        archive_previous_results,
        cleanup_orphaned_resources,
    )
    cleanup_orphaned_resources()
    archive_previous_results(target=args.target, driver=args.driver)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  LIFA-Fuzz Academic Benchmarking Suite                  ║")
    print(f"║  Baselines: {', '.join(baselines):<44s}║")
    print(f"║  Duration:   {args.duration}s per baseline{' ' * (34 - len(str(args.duration)))}║")
    print(f"║  Target:     {args.target:<44s}║")
    print(f"║  Output:     {str(RESULTS_DIR):<44s}║")
    print("╚══════════════════════════════════════════════════════════╝")

    results = {}
    for i, bid in enumerate(baselines):
        summary = await run_single_baseline(
            baseline_id=bid,
            duration_s=args.duration,
            sandbox_driver=args.driver,
            target=args.target,
            total_baselines=len(baselines),
            baseline_index=i,
        )
        results[bid] = summary

        # Wait between baselines for cleanup
        if bid != baselines[-1]:
            print("\n  Waiting 10s for cleanup...")
            await asyncio.sleep(10)

    # Write comparison
    comparison = write_comparison(baselines)

    # Print final comparison table
    print("\n" + "=" * 70)
    print("  BENCHMARK RESULTS COMPARISON")
    print("=" * 70)
    print(f"  {'Baseline':<10} {'EPS':>8} {'Crashes':>10} {'Unique':>8} {'TTC':>8} {'Tokens':>8}")
    print("  " + "-" * 56)
    for bid, data in comparison["baselines"].items():
        if "error" in data:
            print(f"  {bid:<10} ERROR: {data['error']}")
        else:
            ttc = data.get('first_crash_elapsed_s')
            ttc_str = f"{ttc:.0f}" if ttc is not None else "N/A"
            print(
                f"  {bid:<10} "
                f"{data.get('avg_eps', 0):>8.1f} "
                f"{data.get('total_crashes', 0):>10} "
                f"{data.get('unique_crashes', 0):>8} "
                f"{ttc_str:>8} "
                f"{data.get('total_token_usage', 0):>8}"
            )
    print("=" * 70)
    print(f"\n  Results saved to: {RESULTS_DIR}")
    print(f"  Generate plots:   python -m evaluation.plot_generator")


if __name__ == "__main__":
    load_dotenv(override=False)
    asyncio.run(main())
