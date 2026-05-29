"""
main.py
────────
LIFA-Fuzz Master Orchestrator — boots the FULL pipeline.

Spins up:
    1. Docker Sandbox (target server only)
    2. Interceptor (async MitM proxy between client and target)
    3. Client Subprocess (local process connecting to Interceptor)
	    4. Mutation Engine (captures packets, injects mutations)
    5. Crash Monitor (watches for target crashes, auto-recovers)
    6. Slow Loop Daemon (Parser → LLM → Rule Generator, as subprocess)

Visual monitoring is handled by the Streamlit Web Dashboard:
    docker compose -f sandbox/docker-compose.yml up web_dashboard
    → http://localhost:8501

Usage:
    # FREE Mock Mode — no API key needed:
    LLM_MODE=MOCK python main.py

    # REAL Mode — requires API key:
    OPENAI_API_KEY=sk-... python main.py

    # Production (no test payloads):
    python main.py --no-kill-server

    # Stop and cleanup:
    python main.py --stop

Architecture:
    All Fast Loop components run in a single asyncio event loop.
    The Slow Loop runs as a separate subprocess (independent lifecycle,
    independent failure domain — a hung LLM call never blocks the
    Fast Loop).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from shared.logger import get_logger, setup_root_logger, shutdown_logging
from shared.sandbox_abstraction import BaseSandbox, get_driver

# Import sandbox drivers so they self-register via register_driver()
import sandbox.docker_driver  # noqa: F401 — registers "docker" driver

# Setup logging before anything else
setup_root_logger(level="INFO", log_format="json")
logger = get_logger("lifa_fuzz.main")

# Global flag for graceful shutdown
_shutdown_event: Optional[asyncio.Event] = None


# =============================================================================
# Slow Loop Subprocess Manager
# =============================================================================


async def start_slow_loop(
    config_path: str = "config.yaml",
) -> Optional[subprocess.Popen]:
    """Launch the Slow Loop daemon as a subprocess.

    The Slow Loop runs independently — it reads the traffic log produced
    by the Fast Loop and writes rules to shared/active_rules.json.
    It has its own event loop and lifecycle.

    Args:
        config_path: Path to config.yaml for the Slow Loop.

    Returns:
        The subprocess handle, or None if launch failed.
    """
    slow_loop_script = Path(__file__).parent / "run_slow_loop.py"
    if not slow_loop_script.exists():
        logger.warning(
            "run_slow_loop.py not found — Slow Loop will not run. "
            "Rules must be provided manually in shared/active_rules.json"
        )
        return None

    try:
        proc = subprocess.Popen(
            [sys.executable, str(slow_loop_script), "--config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(__file__).parent),
        )
        logger.info(f"Slow Loop daemon started (PID={proc.pid})")
        return proc
    except FileNotFoundError:
        logger.warning("Python interpreter not found for Slow Loop")
        return None
    except OSError as e:
        logger.error(f"Failed to start Slow Loop: {e}")
        return None


def stop_slow_loop(proc: Optional[subprocess.Popen]) -> None:
    """Stop the Slow Loop subprocess gracefully."""
    if proc is None:
        return
    logger.info(f"Stopping Slow Loop (PID={proc.pid})...")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Slow Loop did not exit in time — killing")
            proc.kill()
            proc.wait(timeout=3)
        logger.info("Slow Loop stopped")
    except Exception as e:
        logger.error(f"Error stopping Slow Loop: {e}")


# =============================================================================
# Main Pipeline
# =============================================================================


async def run_pipeline(
    driver_name: str = "docker",
    kill_server_ratio: float = 0.01,
) -> None:
    """Start the full LIFA-Fuzz pipeline.

    Boots: Sandbox → Interceptor → Mutator → Crash Monitor → Slow Loop.
    All visual monitoring is handled by the separate Web Dashboard.
    """
    global _shutdown_event
    _shutdown_event = asyncio.Event()

    # Track background tasks for clean shutdown
    background_tasks: list[asyncio.Task] = []
    slow_loop_proc: Optional[subprocess.Popen] = None

    try:
        # ── 1. Sandbox ────────────────────────────────────────────
        driver_cls = get_driver(driver_name)
        logger.info(f"Using sandbox driver: {driver_cls.__name__}")

        sandbox: BaseSandbox = driver_cls()

        logger.info("Starting LIFA-Fuzz pipeline")
        await sandbox.start()

        net_config = await sandbox.get_network_config()
        target_host = net_config["target_host"]
        target_port = net_config["target_port"]

        # Wait for containers to stabilize
        await asyncio.sleep(2)
        assert await sandbox.is_target_alive(), "Target is not alive!"

        # ── 2. Interceptor ──────────────────────────────────────────
        from fast_loop.interceptor import Interceptor

        traffic_log = "shared/raw_traffic.jsonl"
        traffic_log_path = Path(traffic_log)
        traffic_log_path.parent.mkdir(parents=True, exist_ok=True)
        traffic_log_path.unlink(missing_ok=True)

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
            target_port=8001,  # Interceptor's listen port
        )
        await client_proc.start()
        client_watch_task = asyncio.create_task(
            client_proc.watch(check_interval=5.0),
            name="client_watchdog",
        )
        background_tasks.append(client_watch_task)

        # ── 4. Mutation Engine ─────────────────────────────────────
        from fast_loop.mutator import MutationEngine

        mutator = MutationEngine(
            interceptor=interceptor,
            mode="smart",
            mutations_per_packet=5,
            kill_server_ratio=kill_server_ratio,
        )

        # ── 5. Crash Monitor ──────────────────────────────────────
        from fast_loop.crash_monitor import CrashMonitor

        crashes_dir = Path("./crashes")
        crashes_dir.mkdir(parents=True, exist_ok=True)

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

        # ── 7. Slow Loop Daemon ────────────────────────────────────
        llm_mode = os.environ.get("LLM_MODE", "REAL").upper()
        slow_loop_proc = await start_slow_loop()

        # ── Startup Banner ─────────────────────────────────────────
        logger.info(
            "LIFA-Fuzz RUNNING",
            extra={"context": {
                "traffic_log": traffic_log,
                "target": f"{target_host}:{target_port}",
                "proxy": "0.0.0.0:8001",
                "client_pid": client_proc.pid,
                "crashes_dir": str(crashes_dir),
                "kill_server_ratio": kill_server_ratio,
                "llm_mode": llm_mode,
                "slow_loop_pid": slow_loop_proc.pid if slow_loop_proc else None,
                "dashboard": "http://localhost:8501",
            }},
        )

        # ── 7. Main Loop (stats + shutdown wait) ───────────────────
        stats_interval = 10.0
        last_stats_time = time.monotonic()

        while not _shutdown_event.is_set():
            await asyncio.sleep(1.0)

            # Periodic stats log (JSON structured — machine-parseable)
            now = time.monotonic()
            if now - last_stats_time >= stats_interval:
                stats = mutator.coverage_summary
                logger.info(
                    "Fuzzing stats",
                    extra={"context": {
                        "eps": round(
                            interceptor.total_injected / max(1, now - time.monotonic() + stats_interval), 1
                        ),
                        "packets_captured": interceptor.total_captured,
                        "packets_injected": interceptor.total_injected,
                        "mutations": stats["total_mutations"],
                        "kills": stats["total_kills"],
                        "active_rules": stats["active_rules"],
                        "crashes": crash_monitor.total_crashes,
                    }},
                )
                last_stats_time = now

    except asyncio.CancelledError:
        pass

    finally:
        # ── Graceful Shutdown ──────────────────────────────────────
        logger.info("Shutting down LIFA-Fuzz...")

        # 1. Signal shutdown
        if _shutdown_event:
            _shutdown_event.set()

        # 2. Cancel all background tasks
        for task in background_tasks:
            if not task.done():
                task.cancel()
        for task in background_tasks:
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        # 3. Final stats
        try:
            stats = mutator.coverage_summary
            logger.info(
                "Final stats",
                extra={"context": {
                    "total_packets": stats["total_packets"],
                    "total_mutations": stats["total_mutations"],
                    "total_kills": stats["total_kills"],
                    "unique_offsets": stats["unique_offsets_fuzzed"],
                    "active_rules": stats["active_rules"],
                    "total_crashes": crash_monitor.total_crashes,
                    "total_captured": interceptor.total_captured,
                    "total_injected": interceptor.total_injected,
                }},
            )
        except Exception:
            pass

        # 4. Stop components in reverse order
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

        # 5. Stop Slow Loop subprocess
        stop_slow_loop(slow_loop_proc)

        # 6. Flush logs
        shutdown_logging()
        logger.info("Cleanup complete. Goodbye!")


# =============================================================================
# Signal Handling
# =============================================================================


def _signal_handler(sig, frame):
    """Handle Ctrl+C for graceful shutdown."""
    logger.info("Received SIGINT, shutting down...")
    if _shutdown_event:
        _shutdown_event.set()


# =============================================================================
# CLI Entry Points
# =============================================================================


async def stop_and_cleanup(driver_name: str = "docker") -> None:
    """Stop sandbox and cleanup containers."""
    driver_cls = get_driver(driver_name)
    sandbox: BaseSandbox = driver_cls()
    await sandbox.stop()
    logger.info("Cleanup complete.")


def main():
    parser = argparse.ArgumentParser(
        description="LIFA-Fuzz Master Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Free Mock Mode (no API key needed):
  LLM_MODE=MOCK python main.py

  # Real Mode with OpenAI:
  OPENAI_API_KEY=sk-... python main.py

  # Production (no test payloads):
  python main.py --no-kill-server

  # Dashboard (separate terminal):
  docker compose -f sandbox/docker-compose.yml up web_dashboard
  → http://localhost:8501

  # Cleanup:
  python main.py --stop
        """,
    )
    parser.add_argument(
        "--driver",
        choices=["docker", "firecracker"],
        default="docker",
        help="Sandbox backend driver (default: docker)",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop and cleanup without running",
    )
    parser.add_argument(
        "--no-kill-server",
        action="store_true",
        help="Disable KILL_SERVER payloads (for production fuzzing)",
    )

    args = parser.parse_args()

    signal.signal(signal.SIGINT, _signal_handler)

    kill_server_ratio = 0.0 if args.no_kill_server else 0.01

    if args.stop:
        asyncio.run(stop_and_cleanup(args.driver))
    else:
        asyncio.run(run_pipeline(
            driver_name=args.driver,
            kill_server_ratio=kill_server_ratio,
        ))


if __name__ == "__main__":
    main()
