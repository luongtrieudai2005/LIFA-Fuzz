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
) -> dict[str, Any]:
    """Run LIFA-Fuzz under one baseline configuration for a fixed duration.

    Args:
        baseline_id:     "A", "B", or "C".
        duration_s:      How long to run this baseline (seconds).
        sandbox_driver:  Sandbox backend ("docker" or "firecracker").
        kill_server_ratio: Fraction of KILL_SERVER test payloads (0 for benchmarking).

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

    print(f"\n{'=' * 60}")
    print(f"  Baseline {baseline_id}: {config['description']}")
    print(f"  Duration: {duration_s}s  |  Mode: {config['mutator_mode']}")
    print(f"  Math: {config['math_enabled']}  |  LLM: {config['llm_enabled']}")
    print(f"{'=' * 60}")

    # Set LLM mode based on config
    if config["llm_enabled"]:
        os.environ["LLM_MODE"] = os.environ.get("LLM_MODE", "MOCK")
    else:
        os.environ["LLM_MODE"] = "MOCK"  # Always MOCK when LLM disabled

    background_tasks: list[asyncio.Task] = []
    slow_loop_proc = None

    try:
        # ── 1. Sandbox ────────────────────────────────────────────
        from shared.sandbox_abstraction import BaseSandbox, get_driver
        import sandbox.docker_driver  # noqa: F401

        driver_cls = get_driver(sandbox_driver)
        sandbox: BaseSandbox = driver_cls()

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
            script_path="sandbox/client/client.py",
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

        mutator = MutationEngine(
            interceptor=interceptor,
            mode=config["mutator_mode"],
            mutations_per_packet=5,
            kill_server_ratio=kill_server_ratio,
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
        )

        watch_task = asyncio.create_task(
            crash_monitor.watch(), name="crash_monitor_watch"
        )
        background_tasks.append(watch_task)

        # ── 6. Mutation Loop ───────────────────────────────────────
        mutation_task = asyncio.create_task(
            mutator.mutation_loop(
                traffic_log_path=traffic_log,
                poll_interval=2.0,
            ),
            name="mutation_loop",
        )
        background_tasks.append(mutation_task)

        # ── 7. Slow Loop (only for Baseline C with LLM) ────────────
        agent = None
        if config["llm_enabled"] or config["math_enabled"]:
            # Start slow loop subprocess for rule generation
            # For Baseline B (math-only), the orchestrator still runs
            # to produce bootstrap rules from the analyzer
            from slow_loop.llm_agent import LLMAgent
            agent = LLMAgent(
                provider="openai",
                model="gpt-4o",
                api_key=os.environ.get("OPENAI_API_KEY", "test"),
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

        # ── 9. Run for fixed duration ──────────────────────────────
        print(f"  Running baseline {baseline_id} for {duration_s}s...")
        start = time.monotonic()

        # Progress reporting
        while (time.monotonic() - start) < duration_s:
            elapsed = time.monotonic() - start
            remaining = duration_s - elapsed
            if int(elapsed) % 30 == 0 and elapsed > 0:
                injected = interceptor.total_injected
                eps = injected / elapsed if elapsed > 0 else 0
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
            await client_proc.stop()
        except Exception:
            pass

        try:
            await interceptor.stop()
        except Exception:
            pass

        try:
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
    """Clean shared files between baseline runs."""
    for path in [
        "shared/raw_traffic.jsonl",
        "shared/active_rules.json",
        "shared/llm_last_inference.json",
    ]:
        p = Path(path)
        if p.exists():
            p.unlink()


async def _start_slow_loop_subprocess():
    """Start the slow loop as a subprocess (Baseline C)."""
    import subprocess as sp

    script = _project_root / "run_slow_loop.py"
    if not script.exists():
        return None
    try:
        proc = sp.Popen(
            [sys.executable, str(script), "--config", "config.yaml"],
            stdout=sp.PIPE, stderr=sp.PIPE,
            cwd=str(_project_root),
        )
        return proc
    except Exception:
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

    while True:
        await asyncio.sleep(poll_interval)
        try:
            # Check if traffic log has enough data
            log_path = Path(traffic_log)
            if not log_path.exists() or log_path.stat().st_size == 0:
                continue

            parser = TrafficParser(log_path=traffic_log, read_interval_ms=1000)
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
                    rule = SemanticRule(
                        rule_type=rt,
                        target_field_name=fr.field_name,
                        mutation_type=rt,
                        offset_start=fr.offset,
                        offset_end=end,
                        priority=fr.confidence,
                        description=fr.notes or "Bootstrap rule from DifferentialAnalyzer",
                    )
                    rules.append(rule)

                # Write rules to shared file for mutator to pick up
                rules_path = Path("shared/active_rules.json")
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

    args = parser.parse_args()

    baselines = list(BASELINE_CONFIGS.keys()) if args.baseline == "all" else [args.baseline]

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  LIFA-Fuzz Academic Benchmarking Suite                  ║")
    print(f"║  Baselines: {', '.join(baselines):<44s}║")
    print(f"║  Duration:   {args.duration}s per baseline{' ' * (34 - len(str(args.duration)))}║")
    print(f"║  Output:     {str(RESULTS_DIR):<44s}║")
    print("╚══════════════════════════════════════════════════════════╝")

    results = {}
    for bid in baselines:
        summary = await run_single_baseline(
            baseline_id=bid,
            duration_s=args.duration,
            sandbox_driver=args.driver,
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
            print(
                f"  {bid:<10} "
                f"{data.get('avg_eps', 0):>8.1f} "
                f"{data.get('total_crashes', 0):>10} "
                f"{data.get('unique_crashes', 0):>8} "
                f"{data.get('first_crash_elapsed_s', 'N/A'):>8} "
                f"{data.get('total_token_usage', 0):>8}"
            )
    print("=" * 70)
    print(f"\n  Results saved to: {RESULTS_DIR}")
    print(f"  Generate plots:   python -m evaluation.plot_generator")


if __name__ == "__main__":
    asyncio.run(main())
