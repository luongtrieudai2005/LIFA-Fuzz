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
    7. Streamlit Dashboard (auto-started at http://localhost:8501)

Usage:
    # FREE Mock Mode — no API key needed:
    LLM_MODE=MOCK python main.py

    # REAL Mode — requires API key:
    OPENAI_API_KEY=sk-... python main.py

    # Production (no test payloads):
    python main.py --no-kill-server

    # Headless (no dashboard):
    python main.py --no-dashboard

    # Stop and cleanup:
    python main.py --stop

Architecture:
    All Fast Loop components run in a single asyncio event loop.
    The Slow Loop and Dashboard run as separate subprocesses
    (independent lifecycles, independent failure domains —
    a hung LLM call or dashboard crash never blocks the Fast Loop).
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
from shared.runtime_state import (
    PipelineState, TargetState, ClientState, InterceptorState,
    MutatorState, SlowLoopState, RuleSetState,
    write_runtime_state, read_slow_loop_state, RUNTIME_STATE_FILE,
)
from dotenv import load_dotenv

# Import sandbox drivers so they self-register via register_driver()
import sandbox.docker_driver  # noqa: F401 — registers "docker" driver
import sandbox.firecracker_driver  # noqa: F401 — registers "firecracker" driver (Phase 4)

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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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
# Dashboard Subprocess Manager
# =============================================================================


def _find_streamlit() -> Optional[str]:
    """Locate the streamlit executable in the current Python environment.

    Returns:
        Absolute path to the streamlit binary, or None if not found.
    """
    # 1. Check in the same bin/ directory as the current interpreter
    python_bin = Path(sys.executable).parent
    candidate = python_bin / "streamlit"
    if candidate.exists():
        return str(candidate)

    # 2. Try python -m streamlit (works even if no standalone binary)
    return None


def start_dashboard(port: int = 8501) -> Optional[subprocess.Popen]:
    """Launch the Streamlit dashboard as a background subprocess.

    The dashboard reads from shared files (runtime_state.json,
    active_rules.json, crashes/) — fully stateless, no IPC needed.

    Args:
        port: Port to serve the dashboard on (default 8501).

    Returns:
        The subprocess handle, or None if launch failed.
    """
    dashboard_script = Path(__file__).parent / "web_ui" / "app.py"
    if not dashboard_script.exists():
        logger.warning(
            "web_ui/app.py not found — dashboard will not start"
        )
        return None

    # Build command: prefer `streamlit run`, fall back to `python -m streamlit`
    streamlit_bin = _find_streamlit()
    if streamlit_bin:
        cmd = [
            streamlit_bin, "run", str(dashboard_script),
            "--server.port", str(port),
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
        ]
    else:
        cmd = [
            sys.executable, "-m", "streamlit", "run", str(dashboard_script),
            "--server.port", str(port),
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
        ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).parent),
        )
        logger.info(
            f"Dashboard started (PID={proc.pid}) → http://localhost:{port}"
        )
        return proc
    except FileNotFoundError:
        logger.warning(
            "streamlit not found — install with: pip install streamlit"
        )
        return None
    except OSError as e:
        logger.error(f"Failed to start dashboard: {e}")
        return None


def stop_dashboard(proc: Optional[subprocess.Popen]) -> None:
    """Stop the dashboard subprocess gracefully."""
    if proc is None:
        return
    logger.info(f"Stopping dashboard (PID={proc.pid})...")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Dashboard did not exit in time — killing")
            proc.kill()
            proc.wait(timeout=3)
        logger.info("Dashboard stopped")
    except Exception as e:
        logger.error(f"Error stopping dashboard: {e}")


# =============================================================================
# Runtime State Writer (background task — feeds the dashboard)
# =============================================================================


async def _state_writer_task(
    sandbox: BaseSandbox,
    interceptor: Any,
    client_proc: Any,
    mutator: Any,
    crash_monitor: Any,
    crash_manager: Any,
    slow_loop_proc: Optional[subprocess.Popen],
    driver_name: str,
    target_host: str,
    target_port: int,
    start_time: float,
    shutdown_event: asyncio.Event,
) -> None:
    """Background task: aggregate state from all components every 2s.

    Writes shared/runtime_state.json for the dashboard to read.
    Each component read is wrapped in its own try/except so one
    failure does not prevent the others from being written.

    Step 3: Also writes CSV telemetry snapshots every ~10s for
    state coverage plotting (logs/state_coverage_stats.csv).
    """
    state_path = RUNTIME_STATE_FILE

    # Step 3: CSV logger for state coverage telemetry
    _csv_logger = None
    _csv_write_interval = 10.0  # seconds between CSV snapshots
    _last_csv_write = 0.0

    while not shutdown_event.is_set():
        try:
            now = time.time()
            uptime = time.monotonic() - start_time

            # ── Target ────────────────────────────────────────────────
            target_alive = None
            try:
                target_alive = await sandbox.is_target_alive()
            except Exception:
                pass

            target = TargetState(
                alive=target_alive,
                sandbox_driver=driver_name,
                host=target_host,
                port=target_port,
            )

            # ── Client ────────────────────────────────────────────────
            client_alive = None
            client_pid = None
            try:
                client_alive = client_proc.is_alive
                client_pid = client_proc.pid
            except Exception:
                pass

            client = ClientState(alive=client_alive, pid=client_pid)

            # ── Interceptor ───────────────────────────────────────────
            # NOTE: MutationEngine sends directly to the target (bypasses
            # the Interceptor), so interceptor.total_injected is always 0.
            # We use mutator's total_sent as the authoritative injection count.
            captured = active_conns = 0
            injected = 0
            paused = False
            try:
                captured = interceptor.total_captured
                active_conns = interceptor.active_connections
                paused = interceptor.is_paused
            except Exception:
                pass
            try:
                injected = mutator._stats.total_sent
            except Exception:
                pass

            interceptor_state = InterceptorState(
                captured=captured,
                injected=injected,
                active_connections=active_conns,
                paused=paused,
            )

            # ── Mutator ───────────────────────────────────────────────
            try:
                ms = mutator.get_stats()
                mutator_state = MutatorState(
                    mode=ms.mode,
                    k=mutator.k,
                    current_eps=ms.current_eps,
                    total_sent=ms.total_sent,
                    total_accepted=ms.total_accepted,
                    total_rejected=ms.total_rejected,
                    total_crashes=ms.total_crashes,
                    total_timeout=ms.total_timeout,
                    investigation_mode=ms.investigation_mode,
                    rule_set_version=ms.rule_set_version,
                    active_rule_count=ms.active_rule_count,
                )
            except Exception:
                mutator_state = MutatorState()

            # ── Slow Loop ─────────────────────────────────────────────
            sl_alive = None
            sl_pid = None
            try:
                if slow_loop_proc is not None:
                    sl_alive = slow_loop_proc.poll() is None
                    sl_pid = slow_loop_proc.pid
            except Exception:
                pass

            # Merge state from slow_loop_state.json (written by subprocess)
            sl_data = read_slow_loop_state()
            if sl_data:
                slow_loop_state = SlowLoopState(
                    alive=sl_alive if sl_alive is not None else sl_data.get("alive"),
                    pid=sl_pid or sl_data.get("pid"),
                    last_cycle_time=sl_data.get("last_cycle_time", ""),
                    total_cycles=sl_data.get("total_cycles", 0),
                    total_inferences=sl_data.get("total_inferences", 0),
                    total_rules_pushed=sl_data.get("total_rules_pushed", 0),
                    last_error=sl_data.get("last_error", ""),
                )
            else:
                slow_loop_state = SlowLoopState(alive=sl_alive, pid=sl_pid)

            # ── Crash Manager ─────────────────────────────────────────
            unique_crashes = 0
            total_hits = 0
            try:
                if crash_manager is not None:
                    crash_stats = await crash_manager.get_statistics()
                    unique_crashes = crash_stats.unique_crashes
                    total_hits = crash_stats.total_hits
            except Exception:
                pass

            # ── Rule Set ──────────────────────────────────────────────
            rule_set = RuleSetState()
            try:
                rules_path = Path("shared/active_rules.json")
                if rules_path.exists():
                    raw = json.loads(rules_path.read_text(encoding="utf-8"))
                    rules_list = raw if isinstance(raw, list) else raw.get("rules", [])
                    rule_set = RuleSetState(
                        version=mutator_state.rule_set_version,
                        total_rules=len(rules_list),
                    )
                    # Try to extract protocol/confidence from orchestrator data
            except Exception:
                pass

            # ── Assemble & write ──────────────────────────────────────
            pipeline_status = "running" if target_alive else "degraded"

            state = PipelineState(
                timestamp=now,
                uptime_seconds=uptime,
                pipeline_status=pipeline_status,
                target=target,
                client=client,
                interceptor=interceptor_state,
                mutator=mutator_state,
                slow_loop=slow_loop_state,
                rule_set=rule_set,
                unique_crashes=unique_crashes,
                total_crash_hits=total_hits,
            )
            write_runtime_state(state, state_path)

            # ── Step 3: CSV Telemetry (every ~10s) ────────────────────
            if uptime - _last_csv_write >= _csv_write_interval:
                try:
                    if _csv_logger is None:
                        from evaluation.state_coverage_logger import StateCoverageLogger
                        _csv_logger = StateCoverageLogger()
                        _csv_logger.init_file()
                    cs = mutator.coverage_summary
                    _csv_logger.write_snapshot(
                        executions=cs["total_mutations"],
                        unique_code_branches=cs["unique_offsets_fuzzed"],
                        unique_states=cs.get("unique_states", 0),
                        unique_state_edges=cs.get("unique_state_edges", 0),
                    )
                    _last_csv_write = uptime
                except Exception:
                    pass  # CSV failure must not crash the state writer

        except Exception as e:
            logger.warning(f"State writer error: {e}")

        await asyncio.sleep(2.0)


# =============================================================================
# Main Pipeline
# =============================================================================


async def run_pipeline(
    driver_name: str = "docker",
    kill_server_ratio: float = 0.01,
    config: Optional[dict[str, Any]] = None,
    no_dashboard: bool = False,
    dashboard_port: int = 8501,
) -> None:
    """Start the full LIFA-Fuzz pipeline.

    Boots: Sandbox → Interceptor → Mutator → Crash Monitor → Slow Loop → Dashboard.
    """
    global _shutdown_event
    _shutdown_event = asyncio.Event()

    # Load config (passed from main() or loaded fresh for standalone use)
    _cfg = config or {}
    if not _cfg:
        _config_path = Path("config.yaml")
        if _config_path.exists():
            try:
                import yaml
                with open(_config_path, encoding="utf-8") as f:
                    _cfg = yaml.safe_load(f) or {}
            except Exception:
                pass

    # Track background tasks for clean shutdown
    background_tasks: list[asyncio.Task] = []
    slow_loop_proc: Optional[subprocess.Popen] = None
    dashboard_proc: Optional[subprocess.Popen] = None
    pipeline_start_time = time.monotonic()

    try:
        # ── 1. Sandbox ────────────────────────────────────────────
        driver_cls = get_driver(driver_name)
        logger.info(f"Using sandbox driver: {driver_cls.__name__}")

        # Pre-flight check for Firecracker: /dev/kvm must be accessible
        if driver_name == "firecracker":
            kvm_path = Path("/dev/kvm")
            if not kvm_path.exists():
                logger.error(
                    "Firecracker requires KVM but /dev/kvm is missing. "
                    "Enable KVM in your hypervisor/VM settings, or revert "
                    "to the Docker driver:  --driver docker"
                )
                raise RuntimeError(
                    "/dev/kvm not found — Firecracker requires hardware "
                    "virtualization support.  Revert with --driver docker."
                )
            if not os.access(str(kvm_path), os.R_OK | os.W_OK):
                logger.error(
                    "/dev/kvm exists but this user lacks read/write access. "
                    "Fix with:  sudo chmod 666 /dev/kvm  "
                    "or add yourself to the kvm group.  "
                    "Alternatively, revert with --driver docker"
                )
                raise RuntimeError(
                    "/dev/kvm not accessible (permission denied). "
                    "Revert with --driver docker."
                )
            logger.info("KVM available — Firecracker driver ready")

        sandbox: BaseSandbox = driver_cls()

        # For Firecracker: pass config parameters to the driver
        # so it selects the correct rootfs and target provisioning.
        if driver_name == "firecracker":
            fc_cfg = _cfg.get("sandbox", {}).get("firecracker", {})
            # Update driver attributes from config before start()
            for key, val in fc_cfg.items():
                if hasattr(sandbox, key) and not key.startswith("_"):
                    try:
                        setattr(sandbox, key, val)
                    except (AttributeError, TypeError):
                        pass
            # Re-apply target-aware defaults (rootfs_path, kernel_args, target_port)
            # now that target_name is set from config
            sandbox._apply_target_defaults()

        logger.info("Starting LIFA-Fuzz pipeline")
        await sandbox.start()

        net_config = await sandbox.get_network_config()
        target_host = net_config["target_host"]
        target_port = net_config["target_port"]

        # Wait for containers to stabilize
        await asyncio.sleep(2)
        alive = await sandbox.is_target_alive()
        if not alive:
            raise RuntimeError(
                "Target server is not alive after startup. "
                "Check sandbox logs for errors."
            )

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

        # Select client script based on target protocol
        # "lightftp" → FTP client, everything else → default LIFA binary client
        fc_cfg = _cfg.get("sandbox", {}).get("firecracker", {})
        target_name = fc_cfg.get("target_name", "vulnerable_server")
        if target_name == "lightftp":
            client_script = "sandbox/client/ftp_client.py"
            logger.info("Using FTP client for LightFTP target")
        else:
            client_script = "sandbox/client/client.py"
            logger.info("Using default LIFA binary protocol client")

        client_proc = ClientSubprocess(
            script_path=client_script,
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

        seed_queue: asyncio.Queue = asyncio.Queue()

        mutator = MutationEngine(
            target_host=target_host,
            target_port=target_port,
            seed_queue=seed_queue,
            k=2,
            max_eps=1000,
        )

        # ── 5. Crash Monitor ──────────────────────────────────────
        from fast_loop.crash_monitor import CrashMonitor
        from shared.crash_manager import CrashManager

        crashes_dir = Path("./crashes")
        crashes_dir.mkdir(parents=True, exist_ok=True)

        crash_manager = CrashManager(crash_dir=str(crashes_dir))

        crash_monitor = CrashMonitor(
            sandbox=sandbox,
            interceptor=interceptor,
            mutator=mutator,
            crash_manager=crash_manager,
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
            mutator.run(),
            name="mutation_loop",
        )
        background_tasks.append(mutation_task)

        # ── 6b. Seed Feeder (Sequence-Aware) ──────────────────────
        # Adapter: read JSONL traffic log → group by session_id → push
        # SeedSequence objects into seed_queue for the MutationEngine.
        from shared.schemas import Direction, SeedSequence, TrafficRecord

        async def _feed_seed_queue() -> None:
            """Read JSONL traffic log, group C2S packets by session_id,
            and push SeedSequence objects into the mutator queue.

            Session buffering: packets accumulate per session_id until the
            session is idle for > session_timeout seconds, then the whole
            sequence is flushed as one SeedSequence.
            """
            last_pos = 0
            last_byte_offset = 0
            last_size = 0
            session_timeout = 2.0   # seconds before flushing a session buffer
            # session_id → {"packets": [TrafficRecord, ...], "last_seen": float}
            session_buffers: dict[str, dict] = {}

            while not _shutdown_event.is_set():
                try:
                    p = Path(traffic_log)
                    if not p.exists():
                        await asyncio.sleep(1.0)
                        continue
                    cur_size = p.stat().st_size
                    # Detect file rotation/truncation — reset position
                    if cur_size < last_size:
                        last_byte_offset = 0
                        session_buffers.clear()
                    last_size = cur_size

                    new_lines = []
                    with open(p, "r", encoding="utf-8") as f:
                        f.seek(last_byte_offset)
                        new_lines = f.readlines()
                        last_byte_offset = f.tell()

                    now = time.time()
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if (
                            rec.get("direction") == "client_to_server"
                            and not rec.get("is_mutated")
                        ):
                            raw_hex = rec.get("payload", rec.get("raw_hex", ""))
                            # FIX: accept all non-empty payloads (was >= 8 hex
                            # chars = 4 bytes, dropping legitimate 1-3 byte
                            # protocol packets like ACKs and status bytes).
                            if raw_hex and len(raw_hex) >= 2:
                                sid = rec.get("session_id", "")
                                tr = TrafficRecord(
                                    direction=Direction.CLIENT_TO_SERVER,
                                    raw_data=bytes.fromhex(raw_hex),
                                    session_id=sid,
                                    timestamp=rec.get("timestamp", time.time()),
                                )
                                if sid:
                                    # Buffer by session for sequence grouping
                                    buf = session_buffers.setdefault(
                                        sid,
                                        {"packets": [], "last_seen": now},
                                    )
                                    buf["packets"].append(tr)
                                    buf["last_seen"] = now
                                else:
                                    # No session_id — emit as single-packet sequence
                                    await seed_queue.put(
                                        SeedSequence(packets=[tr])
                                    )

                    # Flush session buffers that have been idle too long
                    expired = [
                        sid
                        for sid, buf in session_buffers.items()
                        if now - buf["last_seen"] >= session_timeout
                        and buf["packets"]
                    ]
                    for sid in expired:
                        buf = session_buffers.pop(sid)
                        await seed_queue.put(
                            SeedSequence(
                                session_id=sid,
                                packets=buf["packets"],
                            )
                        )

                except Exception as e:
                    logger.debug(f"Seed feeder error (non-fatal): {e}")
                await asyncio.sleep(1.0)

            # Final flush: emit any remaining buffered sessions on shutdown
            for sid, buf in list(session_buffers.items()):
                if buf["packets"]:
                    try:
                        await seed_queue.put(
                            SeedSequence(session_id=sid, packets=buf["packets"])
                        )
                    except Exception as e:
                        logger.debug(f"Seed feeder final flush error: {e}")
            session_buffers.clear()

        seed_feeder_task = asyncio.create_task(
            _feed_seed_queue(), name="seed_feeder"
        )
        background_tasks.append(seed_feeder_task)

        # ── 7. Slow Loop Daemon ────────────────────────────────────
        llm_mode = os.environ.get("LLM_MODE", "REAL").upper()
        slow_loop_proc = await start_slow_loop()

        # ── 7a. Dashboard ──────────────────────────────────────────
        if not no_dashboard:
            dashboard_proc = start_dashboard(port=dashboard_port)
        else:
            logger.info("Dashboard disabled (--no-dashboard flag)")

        # ── 7b. Runtime State Writer ───────────────────────────────
        # Background task: aggregates state from all components every 2s
        # and writes shared/runtime_state.json for the dashboard.
        state_writer = asyncio.create_task(
            _state_writer_task(
                sandbox=sandbox,
                interceptor=interceptor,
                client_proc=client_proc,
                mutator=mutator,
                crash_monitor=crash_monitor,
                crash_manager=crash_manager,
                slow_loop_proc=slow_loop_proc,
                driver_name=driver_name,
                target_host=target_host,
                target_port=target_port,
                start_time=pipeline_start_time,
                shutdown_event=_shutdown_event,
            ),
            name="state_writer",
        )
        background_tasks.append(state_writer)

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
                "dashboard_pid": dashboard_proc.pid if dashboard_proc else None,
                "dashboard": f"http://localhost:{dashboard_port}",
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
                ms = mutator.get_stats()
                logger.info(
                    "Fuzzing stats",
                    extra={"context": {
                        "eps": ms.current_eps,
                        "packets_captured": interceptor.total_captured,
                        "packets_injected": ms.total_sent,
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
            ms = mutator.get_stats()
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
                    "total_injected": ms.total_sent,
                }},
            )
        except Exception as e:
            logger.debug(f"Could not collect final stats: {e}")

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

        # 6. Stop Dashboard subprocess
        stop_dashboard(dashboard_proc)

        # 7. Flush logs
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
    # Load .env file first (manual env vars take precedence)
    load_dotenv(override=False)

    # Load config for default sandbox driver
    import yaml
    _config_path = Path("config.yaml")
    _cfg: dict[str, Any] = {}
    if _config_path.exists():
        try:
            with open(_config_path, encoding="utf-8") as f:
                _cfg = yaml.safe_load(f) or {}
        except Exception:
            pass
    _default_driver = _cfg.get("sandbox", {}).get("driver", "docker")

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

  # Headless (no dashboard):
  python main.py --no-dashboard

  # Custom dashboard port:
  python main.py --dashboard-port 9000

  # Cleanup:
  python main.py --stop
        """,
    )
    parser.add_argument(
        "--driver",
        choices=["docker", "firecracker"],
        default=_default_driver,
        help=f"Sandbox backend driver (default: {_default_driver}, from config.yaml)",
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
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Do not auto-start the Streamlit dashboard",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8501,
        help="Dashboard port (default: 8501)",
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
            config=_cfg,
            no_dashboard=args.no_dashboard,
            dashboard_port=args.dashboard_port,
        ))


if __name__ == "__main__":
    main()
