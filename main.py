"""
main.py
────────
LIFA-Fuzz Orchestrator — boots the full pipeline for local testing.

Spins up:
    1. Docker Sandbox (client + target server)
    2. Interceptor (async MitM proxy between client and target)
    3. Mutation Engine (captures packets, injects mutations)
    4. Crash Monitor (watches for target crashes)

Usage:
    # Start everything (Docker backend):
    python main.py

    # Start with a specific backend:
    python main.py --driver docker

    # Stop and cleanup:
    python main.py --stop
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from pathlib import Path

from shared.logger import get_logger, setup_root_logger
from shared.sandbox_abstraction import BaseSandbox, get_driver

# Setup logging before anything else
setup_root_logger(level="DEBUG", log_format="text")
logger = get_logger("lifa_fuzz.main")

# Global flag for graceful shutdown
_shutdown_event: Optional[asyncio.Event] = None


async def run_pipeline(driver_name: str = "docker") -> None:
    """Start the full LIFA-Fuzz pipeline."""
    global _shutdown_event
    _shutdown_event = asyncio.Event()

    # 1. Import and instantiate the sandbox driver
    driver_cls = get_driver(driver_name)
    logger.info(f"Using sandbox driver: {driver_cls.__name__}")

    sandbox: BaseSandbox = driver_cls()

    # 2. Start the sandbox
    logger.info("=" * 60)
    logger.info("Starting LIFA-Fuzz Pipeline")
    logger.info("=" * 60)

    logger.info("[Step 1] Starting sandbox...")
    await sandbox.start()
    logger.info("[Step 1] Sandbox started successfully")

    # Get network config from sandbox
    net_config = await sandbox.get_network_config()
    target_host = net_config["target_host"]
    target_port = net_config["target_port"]

    # Wait a moment for containers to stabilize
    logger.info("Waiting for containers to stabilize...")
    await asyncio.sleep(2)
    assert await sandbox.is_target_alive(), "Target is not alive!"

    # 3. Start the Interceptor
    from fast_loop.interceptor import Interceptor

    traffic_log = "/tmp/lifa_traffic.log"
    # Clear old log
    Path(traffic_log).unlink(missing_ok=True)

    interceptor = Interceptor(
        listen_host="0.0.0.0",
        listen_port=8001,
        upstream_host=target_host,
        upstream_port=target_port,
        traffic_log_path=traffic_log,
    )

    await interceptor.start()
    asyncio.create_task(interceptor.serve_forever())
    logger.info("[Step 2] Interceptor started on port 8001")

    # 4. Start the Mutation Engine
    from fast_loop.mutator import MutationEngine

    mutator = MutationEngine(
        interceptor=interceptor,
        mode="smart",
        mutations_per_packet=5,
        kill_server_ratio=0.01,  # 1% KILL_SERVER
    )

    logger.info("[Step 3] Mutation Engine started")

    # 5. Start the Crash Monitor
    from fast_loop.crash_monitor import CrashMonitor

    crash_monitor = CrashMonitor(
        sandbox=sandbox,
        poll_interval_ms=500,
        crash_corpus_dir="./crashes",
        auto_reset=True,
    )
    asyncio.create_task(crash_monitor.watch())
    logger.info("[Step 4] Crash Monitor started")

    # 6. Start the mutation loop (reads traffic log, mutates, injects)
    logger.info("[Step 5] Starting mutation loop...")
    logger.info("")
    logger.info("=" * 60)
    logger.info("LIFA-Fuzz is RUNNING. Press Ctrl+C to stop.")
    logger.info(f"  Traffic log: {traffic_log}")
    logger.info(f"  Target: {target_host}:{target_port}")
    logger.info(f"  Proxy: 0.0.0.0:8001")
    logger.info(f"  KILL_SERVER ratio: 1%")
    logger.info("=" * 60)
    logger.info("")

    try:
        # Mutation loop: poll traffic log, generate mutations, inject
        last_pos = 0
        while not _shutdown_event.is_set():
            await asyncio.sleep(2.0)  # Check every 2 seconds

            # Read new entries from traffic log
            log_path = Path(traffic_log)
            if not log_path.exists():
                continue

            try:
                with open(log_path, "r") as f:
                    lines = f.readlines()
            except OSError:
                continue

            if len(lines) <= last_pos:
                continue

            # Process new non-mutated packets (client → server only)
            for line in lines[last_pos:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    # Only mutate original client→server traffic (not mutations, not responses)
                    if (
                        record.get("direction") == "client_to_server"
                        and not record.get("is_mutated")
                    ):
                        raw_hex = record.get("raw_data", "")
                        if raw_hex and len(raw_hex) >= 8:
                            raw_data = bytes.fromhex(raw_hex)
                            await mutator.mutate(raw_data)
                except (json.JSONDecodeError, ValueError):
                    continue

            last_pos = len(lines)

            # Print stats
            stats = mutator.coverage_summary
            logger.info(
                f"Stats: packets={stats['total_packets']} "
                f"mutations={stats['total_mutations']} "
                f"kills={stats['total_kills']} "
                f"captured={interceptor.total_captured} "
                f"injected={interceptor.total_injected}"
            )

    except asyncio.CancelledError:
        pass
    finally:
        # Shutdown
        logger.info("")
        logger.info("=" * 60)
        logger.info("Shutting down LIFA-Fuzz...")
        logger.info("=" * 60)

        stats = mutator.coverage_summary
        logger.info(f"Final stats:")
        logger.info(f"  Total packets processed: {stats['total_packets']}")
        logger.info(f"  Total mutations injected: {stats['total_mutations']}")
        logger.info(f"  KILL_SERVER triggers: {stats['total_kills']}")
        logger.info(f"  Unique offsets fuzzed: {stats['unique_offsets_fuzzed']}")
        logger.info(f"  Total captured: {interceptor.total_captured}")

        await interceptor.stop()
        await sandbox.stop()
        logger.info("Cleanup complete.")


def _signal_handler(sig, frame):
    """Handle Ctrl+C for graceful shutdown."""
    logger.info("Received SIGINT, shutting down...")
    if _shutdown_event:
        _shutdown_event.set()


async def stop_and_cleanup(driver_name: str = "docker") -> None:
    """Stop sandbox and cleanup containers."""
    driver_cls = get_driver(driver_name)
    sandbox: BaseSandbox = driver_cls()
    await sandbox.stop()
    logger.info("Cleanup complete.")


def main():
    parser = argparse.ArgumentParser(description="LIFA-Fuzz Orchestrator")
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
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _signal_handler)

    if args.stop:
        asyncio.run(stop_and_cleanup(args.driver))
    else:
        asyncio.run(run_pipeline(args.driver))


if __name__ == "__main__":
    main()
