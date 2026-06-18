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


def _load_llm_agent_config(config_path: str = "config.yaml") -> dict[str, Any]:
    """Load the ``slow_loop.llm_agent`` block from ``config.yaml``.

    Baseline C builds its LLMAgent IN-PROCESS (via ``_run_fusion_loop``),
    not through ``run_slow_loop.py``, so it must read the same canonical
    config the daemon uses. Previously the agent was built from ad-hoc
    ``LLM_*`` env vars whose names did not match ``.env`` (it read
    ``LLM_API_BASE`` while ``.env`` defines ``OPENAI_API_BASE``), leaving
    ``api_base`` empty and routing every call to the default OpenAI
    endpoint with a GLM model name → all calls failed → silent bootstrap
    fallback. ``config.yaml`` is the single source of truth here.
    """
    try:
        import yaml

        path = _project_root / config_path
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        block = cfg.get("slow_loop", {}).get("llm_agent", {}) or {}
        # H2 fix: an empty/missing block means baseline C would build its agent
        # from all-``.get(default)`` values (provider=openai, model=gpt-4o,
        # api_base="") → every call fails → silent bootstrap fallback → C
        # silently degrades to B and the A/B/C comparison is invalid with no
        # error signal. Surface this loudly instead of returning {}.
        if not block:
            print(
                "WARNING: slow_loop.llm_agent block missing/empty in "
                f"{config_path} — baseline C cannot use the REAL LLM and will "
                "degrade to math-only (≈ baseline B). Fix the config before "
                "trusting a C result.",
                file=sys.stderr,
            )
        return block
    except Exception as exc:
        # H2 fix: do NOT swallow this silently. A malformed config used to
        # return {} here, silently defeating baseline C.
        print(
            f"ERROR: failed to load slow_loop.llm_agent from {config_path} "
            f"({exc!r}) — baseline C will degrade to math-only (≈ baseline B).",
            file=sys.stderr,
        )
        return {}


def _apply_core_suppression() -> None:
    """Prevent host-side core dumps from ASAN target crashes.

    Sets ``RLIMIT_CORE`` to 0 for this process (inherited by every spawned
    child target) and merges ``disable_coredump=1`` into ``ASAN_OPTIONS``.
    Both are no-ops on systems where core dumps are already off, and never
    silence ASAN's own textual report — only the redundant raw ``core.<pid>``
    files that would otherwise litter the project root.
    """
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError, ImportError):
        # Some sandboxes/CI forbid lowering rlimit — best effort only.
        pass

    existing = os.environ.get("ASAN_OPTIONS", "")
    if "disable_coredump" not in existing:
        os.environ["ASAN_OPTIONS"] = ":".join(
            p for p in (existing, "disable_coredump=1") if p
        )

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
    coverage: bool = False,
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

    # Set LLM mode based on config.
    # Baseline C (llm_enabled) MUST run in REAL mode. The previous code did
    # ``os.environ.get("LLM_MODE", "MOCK")`` which only kept an ambient value
    # and otherwise defaulted to MOCK — so unless the operator had manually
    # exported LLM_MODE=REAL, baseline C silently ran MOCK, produced a fixed
    # dummy grammar unrelated to the real traffic, and effectively degraded
    # to bootstrap (math) rules. Force REAL here deterministically.
    if config["llm_enabled"]:
        os.environ["LLM_MODE"] = "REAL"
    else:
        os.environ["LLM_MODE"] = "MOCK"  # Always MOCK when LLM disabled

    # ── Target configuration ─────────────────────────────────────────
    TARGET_CONFIGS = {
        "lifa": {
            "image": "lifa-target-server:latest",
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
        "lightftp": {
            "image": "lifa-lightftp-complete:latest",  # not used with firecracker
            "build_context": "sandbox/firecracker_env",
            "port": 21,
            "container": "lifa-lightftp-server",
            "client_script": "sandbox/client/ftp_client.py",
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
        "lightftp": {
            "rootfs_path": "sandbox/firecracker_env/rootfs_lightftp.ext4",
            "kernel_args": (
                "console=ttyS0 reboot=k panic=1 pci=off"
                " root=/dev/vda rw"
                " init=/init"
                " ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"
            ),
            "target_port": 21,  # FTP standard port
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

    # Track whether Slow Loop is running in-process (Baseline B/C fusion)
    # so the state writer can report correct SlowLoopState to the dashboard.
    _slow_loop_in_process = False

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
            if coverage and target == "lightftp":
                # Coverage mode: use the gcov-instrumented rootfs + a cov_duration
                # kernel arg so /init's watchdog SIGTERMs ffp (→ __gcov_dump+sync)
                # right after the campaign, before stop().
                rootfs = "sandbox/firecracker_env/rootfs_lightftp_coverage.ext4"
                # Reset from pristine so each baseline starts with NO .gcda (gcov
                # counters are ADDITIVE — without a reset, baseline N inherits
                # N-1's coverage and every comparison is contaminated). Pristine
                # is REQUIRED — fail hard if missing rather than silently run on
                # a stale (contaminated) rootfs.
                pristine = "sandbox/firecracker_env/rootfs_lightftp_coverage_pristine.ext4"
                if not Path(pristine).exists():
                    raise RuntimeError(
                        f"[coverage] pristine rootfs missing: {pristine}. "
                        f"Run scripts/build_rootfs_lightftp_coverage.sh then "
                        f"`cp rootfs_lightftp_coverage.ext4 rootfs_lightftp_coverage_pristine.ext4`. "
                        f"Aborting — running without it would contaminate the measurement."
                    )
                import shutil as _sh
                print(f"  [coverage] resetting rootfs from pristine master")
                _sh.copyfile(pristine, rootfs)
                # cov_duration measured from VM boot; fuzz starts T_start
                # later (boot+snapshot). +20 covers slow boots so the timer
                # never fires mid-fuzz (would truncate coverage).
                kernel_args = fc_cfg["kernel_args"] + f" cov_duration={duration_s + 20}"
            else:
                rootfs = fc_cfg["rootfs_path"]
                kernel_args = fc_cfg["kernel_args"]
            sandbox = driver_cls(
                rootfs_path=rootfs,
                kernel_args=kernel_args,
                target_port=fc_cfg["target_port"],
                target_name=target,  # Pass target name for driver-level defaults
                mem_size_mb=fc_cfg.get("mem_size_mb", 512),
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
        elif target == "lifa":
            from shared.schemas import Direction, SeedSequence, TrafficRecord
            import struct as _struct
            # ── LIFA v2 seed injection (8-byte header, state machine) ──
            # Protocol v2: MAGIC(4) + VERSION(0x01) + opcode(1) + len_le16(2) + payload.
            # CRITICAL: PROCESS_DATA is the vulnerable opcode but is SILENTLY
            # REJECTED (ERR_BAD_STATE) unless the connection is in AUTHENTICATED
            # state. A single PING transitions INIT → AUTH. So a crash requires
            # the SEQUENCE [new conn] → PING → PROCESS_DATA(overflow) sent in
            # the SAME TCP session. We therefore inject multi-packet
            # SeedSeences (prefix=PING, target=PROCESS). The mutator's
            # `_execute_sequence` replays the prefix verbatim before fuzzing
            # the target — exactly the auth-ordering the fuzzer must learn.
            #
            # PURE-DISCOVERY mode: PROCESS payloads stay well under the 64-byte
            # buffer (8B / 15B), so the mutator must GROW the payload itself
            # (buffer_overflow / payload_extend) to trigger the bug. This proves
            # autonomous discovery, not a fed PoC.
            MAGIC = b"LIFA"
            VERSION = 0x01
            OP_PING, OP_PROCESS = 0x01, 0x02
            import os as _os

            def _pkt(opcode: int, payload: bytes = b"") -> bytes:
                return MAGIC + bytes([VERSION, opcode]) + _struct.pack("<H", len(payload)) + payload

            # PROCESS payloads use RANDOM bytes (not bytes(range(N))). A fixed
            # ramp makes byte 0 of the payload constant (always 0x00) across
            # samples, which the analyzer misclassifies as a static separator
            # and splits the payload field. Random bytes give every offset
            # variance → the payload is one variable-length tail field.
            # Payloads stay short (≤ 15 B, well under the 64 B buffer) so the
            # fuzzer must GROW them itself — pure discovery, not a fed PoC.
            lifa_seed_sessions = [
                # (prefix packets, target packet)
                ([_pkt(OP_PING, b"PONG")],                  _pkt(OP_PROCESS, _os.urandom(8))),
                ([_pkt(OP_PING, b"SEQ00001")],              _pkt(OP_PROCESS, _os.urandom(15))),
                # STATUS in the prefix enriches the state signal the LLM sees
                # (state_byte 0x00→0x01 after PING), but is optional.
                ([_pkt(OP_PING, b"hello"), _pkt(0x03)],     _pkt(OP_PROCESS, _os.urandom(12))),
            ]
            for prefix_pkts, target_pkt in lifa_seed_sessions:
                packets = [
                    TrafficRecord(direction=Direction.CLIENT_TO_SERVER, raw_data=p)
                    for p in (prefix_pkts + [target_pkt])
                ]
                await seed_queue.put(SeedSequence(packets=packets, protocol_hint="LIFA"))
        elif target == "lightftp":
            # BLACK-BOX: do NOT inject hardcoded FTP seeds. The state oracle is
            # the REAL client (ftp_client.py) whose traffic the Interceptor
            # captures → the SeedFeeder groups it into multi-packet sessions →
            # _execute_sequence replays the prefix (auth) + fuzzes the target.
            # Injecting "USER admin"/"PASS admin" here would hardcode protocol
            # knowledge (the very black-box violation we refactored out).
            # If the corpus ends up single-packet-dominated, the fix is in the
            # FEEDER (real traffic), not here.
            pass

        # Target-specific mutator tuning
        # Firecracker + FTP: need generous timeouts (FTP banner + command
        # response arrive asynchronously over the TAP bridge).
        _is_fc_ftp = (sandbox_driver == "firecracker" and target == "lightftp")
        # Resolve ProtocolModule: env var override (ablation uses this to force
        # null/ftp cleanly) else auto-resolve (lightftp→ftp case-study, else
        # null = pure black-box core). WITHOUT this, MutationEngine defaulted to
        # NullModule → no FTP state tracking → the "stuck at 220" diagnostic was
        # blind (chains all empty). See scripts/ablation_generic_vs_module.py.
        import os as _os
        _protocol_module = _os.environ.get("LIFA_PROTOCOL_MODULE")
        if not _protocol_module:
            _protocol_module = "ftp" if target == "lightftp" else "null"
        # Register the FTP module so get_protocol_module("ftp") resolves — the
        # module name is only in the shared registry after fast_loop.ftp_module
        # is imported (its register_protocol_module call runs at import). Without
        # this, "ftp" silently fell back to NullModule → extract_state_code
        # returned "" → SEQ chains all empty → no state tracking → blind.
        if _protocol_module == "ftp":
            import fast_loop.ftp_module  # noqa: F401 (registers "ftp")
        elif _protocol_module == "lifa":
            import fast_loop.lifa_module  # noqa: F401 (registers "lifa")

        mutator = MutationEngine(
            target_host=target_host,
            target_port=target_port,
            seed_queue=seed_queue,
            k=2,
            max_eps=5000,
            connection_timeout=1.0 if _is_fc_ftp else 0.2,
            recv_timeout=0.5 if _is_fc_ftp else 0.01,
            no_recv=False,
            protocol_module=_protocol_module,
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
            # Coverage mode: disable snapshot-restore (auto_reset) — a snapshot
            # load discards gcov counters, so coverage would only reflect the
            # post-last-reset segment. In coverage mode we let crashes stand.
            auto_reset=not coverage,
            restart_delay_s=2.0,
            crash_manager=crash_manager,  # FIX: wire crash_manager so telemetry reports crashes
            # Phase 1: confirm each crash by replaying the frozen attribution
            # window on a clean target, so PoC artifacts actually reproduce.
            confirm_crashes=True,
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
        from shared.schemas import Direction, TrafficRecord, SeedSequence

        async def _feed_seed_queue() -> None:
            """Read JSONL traffic log and push C2S seeds into the mutator queue.

            Groups C2S packets by session_id into multi-packet SeedSequence
            (ported from main.py). WITHOUT grouping, each packet becomes a
            single-packet seed → the mutator fuzzes each on a fresh connection
            (no prefix, no state setup) → stateful protocols (FTP auth) never
            reached → "stuck at greeting". Grouping makes the real client
            traffic the state oracle (black-box: no protocol knowledge here).
            """
            last_byte_offset = 0
            import json as _json
            import time as _time
            session_buffers: dict[str, dict] = {}
            session_timeout = 2.0  # s — flush a session after this idle gap
            while True:
                try:
                    p = Path(traffic_log)
                    if not p.exists():
                        await asyncio.sleep(1.0)
                        continue
                    # H1 fix: incremental byte-seek read. f.readlines() on the
                    # FULL file every poll was an OOM time-bomb over a 12h run
                    # (raw_traffic.jsonl grows ~1.6 GiB/4h @200EPS, far more at
                    # higher EPS). Seek to the last byte read, read only new
                    # lines, remember the new offset. Mirrors main.py's feeder.
                    try:
                        file_size = p.stat().st_size
                    except OSError:
                        file_size = 0
                    if last_byte_offset > file_size:
                        # File shrank — interceptor rotated/truncated it.
                        # Restart from the start so we don't miss traffic.
                        last_byte_offset = 0
                    with open(p) as f:
                        f.seek(last_byte_offset)
                        new_lines = f.readlines()
                        last_byte_offset = f.tell()
                    now = _time.time()
                    for line in new_lines:
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
                            if raw_hex and len(raw_hex) >= 2:
                                sid = rec.get("session_id", "")
                                tr = TrafficRecord(
                                    direction=Direction.CLIENT_TO_SERVER,
                                    raw_data=bytes.fromhex(raw_hex),
                                    session_id=sid,
                                    timestamp=rec.get("timestamp", now),
                                )
                                if sid:
                                    buf = session_buffers.setdefault(
                                        sid, {"packets": [], "last_seen": now})
                                    buf["packets"].append(tr)
                                    buf["last_seen"] = now
                                else:
                                    await seed_queue.put(SeedSequence(packets=[tr]))
                    # Flush sessions idle past the timeout → multi-packet seeds.
                    expired = [
                        sid for sid, buf in session_buffers.items()
                        if now - buf["last_seen"] >= session_timeout and buf["packets"]
                    ]
                    for sid in expired:
                        buf = session_buffers.pop(sid)
                        await seed_queue.put(
                            SeedSequence(session_id=sid, packets=buf["packets"]))
                    # last_byte_offset is advanced by f.tell() above (H1 fix);
                    # no line-count bookkeeping needed.
                except Exception:
                    pass
                await asyncio.sleep(1.0)

        seed_feeder_task = asyncio.create_task(
            _feed_seed_queue(), name="seed_feeder"
        )
        background_tasks.append(seed_feeder_task)

        # ── 7. Slow Loop (only for Baseline B/C) ────────────
        agent = None
        if config["llm_enabled"]:
            # Baseline C: create LLM agent for full Neural-Mathematical Fusion.
            # Build from config.yaml's slow_loop.llm_agent block — the same
            # canonical config run_slow_loop.py uses — so provider/model/
            # api_base/enable_thinking match the daemon exactly. Only the API
            # key value comes from the environment (looked up via api_key_env).
            llm_cfg = _load_llm_agent_config()
            api_key_env = llm_cfg.get("api_key_env", "OPENAI_API_KEY")
            api_key = os.environ.get(
                api_key_env, os.environ.get("OPENAI_API_KEY", "")
            )
            from slow_loop.llm_agent import LLMAgent
            agent = LLMAgent(
                provider=llm_cfg.get("provider", "openai"),
                model=llm_cfg.get("model", "gpt-4o"),
                api_key=api_key,
                api_base=llm_cfg.get("api_base", ""),
                max_tokens=llm_cfg.get("max_tokens", 4096),
                temperature=llm_cfg.get("temperature", 0.2),
                timeout_seconds=llm_cfg.get("timeout_seconds", 60),
                max_retries=llm_cfg.get("max_retries", 3),
                cache_file=llm_cfg.get(
                    "cache_file", "shared/last_known_grammar.json"
                ),
                context_window=llm_cfg.get("context_window", 128_000),
            )
            # CRITICAL: GLM-5-Turbo via Z.ai consumes all tokens for
            # reasoning_content and returns empty .content unless thinking
            # is disabled. Authoritative value lives in config.yaml.
            agent.enable_thinking = llm_cfg.get("enable_thinking", False)

            if not api_key and agent.provider != "ollama":
                print(
                    "  ⚠ WARNING: LLM enabled (baseline C) but no API key found "
                    f"(env var '{api_key_env}'). Calls will fail and the loop "
                    "will fall back to bootstrap rules."
                )
            print(
                f"  LLM agent: provider={agent.provider} model={agent.model} "
                f"api_base={agent.api_base or '(default)'} "
                f"enable_thinking={agent.enable_thinking}"
            )

        if config["llm_enabled"]:
            # Full fusion: run slow loop IN-PROCESS (not subprocess!)
            # This ensures rules are pushed directly to the mutator
            # via await mutator.update_rule_set() instead of relying
            # on fragile file-based IPC.
            _slow_loop_in_process = True
            fusion_task = asyncio.create_task(
                _run_fusion_loop(
                    traffic_log, agent, mutator, crash_manager
                ),
                name="fusion_loop",
            )
            background_tasks.append(fusion_task)
        elif config["math_enabled"]:
            # Baseline B: math-only — no LLM agent needed.
            # The DifferentialAnalyzer produces rules directly.
            _slow_loop_in_process = True
            math_task = asyncio.create_task(
                _run_math_only_loop(
                    traffic_log, mutator, crash_manager
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

        # ── 8a. Step 3: State Coverage CSV Logger ──────────────────
        # Per-baseline CSV file for coverage comparison plots.
        from evaluation.state_coverage_logger import StateCoverageLogger
        csv_logger = StateCoverageLogger(
            output_path=f"logs/state_coverage_stats_{baseline_id}.csv",
            interval_s=10.0,
        )
        csv_logger.init_file()

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
                            total_timeout=ms.total_timeout,
                            investigation_mode=ms.investigation_mode,
                            rule_set_version=ms.rule_set_version,
                            active_rule_count=ms.active_rule_count,
                        ),
                        rule_set=RuleSetState(
                            version=ms.rule_set_version,
                            protocol_name="fuzzing",
                            confidence=0.0,
                            total_rules=ms.active_rule_count,
                        ),
                        slow_loop=SlowLoopState(
                            alive=(
                                _slow_loop_in_process
                                or (slow_loop_proc is not None and slow_loop_proc.poll() is None)
                            ),
                            pid=slow_loop_proc.pid if slow_loop_proc else None,
                            total_cycles=0,
                            total_inferences=0,
                            total_rules_pushed=ms.active_rule_count,
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

            # Step 3: Write state coverage CSV snapshot every ~10s
            if int(elapsed) > 0 and int(elapsed) % 10 == 0:
                try:
                    cs = mutator.coverage_summary
                    csv_logger.write_snapshot(
                        executions=cs["total_mutations"],
                        unique_code_branches=cs["unique_offsets_fuzzed"],
                        unique_states=cs.get("unique_states", 0),
                        unique_state_edges=cs.get("unique_state_edges", 0),
                    )
                except Exception:
                    pass

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

        # Honest crash breakdown: total detected events, unique crash SITES
        # (σ₃ dedup — distinct vulnerabilities), and how many of those unique
        # sites were REPRODUCED by replay on a clean target. Reporting all
        # three separately keeps the RQ3 numbers transparent: a reader can see
        # how many crashes were merely detected vs. confirmed reproducible.
        try:
            cs = await crash_manager.get_statistics()
            summary["crash_total_detected"] = cs.total_hits
            summary["crash_unique_sites"] = cs.unique_crashes
            summary["crash_reproduced_sites"] = cs.reproduced_crashes
        except Exception:
            pass

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
        # Wrap ENTIRE cleanup in a hard 45s deadline. If any step hangs
        # (litellm thread, aiohttp session close, Docker daemon unresponsive),
        # the deadline fires and we continue to the next baseline (or exit).
        import time as _cleanup_time
        _cleanup_deadline = _cleanup_time.monotonic() + 45.0

        print(f"  ⏭ Baseline {baseline_id} done — cleaning up...", flush=True)

        for task in background_tasks:
            if not task.done():
                task.cancel()
        for task in background_tasks:
            if _cleanup_time.monotonic() > _cleanup_deadline:
                print(f"  ⚠ Cleanup deadline exceeded — skipping remaining tasks", flush=True)
                break
            try:
                _remaining = max(1.0, _cleanup_deadline - _cleanup_time.monotonic())
                await asyncio.wait_for(task, timeout=min(3.0, _remaining))
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass

        if _cleanup_time.monotonic() <= _cleanup_deadline:
            try:
                if client_proc is not None:
                    await asyncio.wait_for(client_proc.stop(), timeout=5.0)
            except (Exception, asyncio.TimeoutError):
                pass

            try:
                if interceptor is not None:
                    await asyncio.wait_for(interceptor.stop(), timeout=5.0)
            except (Exception, asyncio.TimeoutError):
                pass

        # Collect gcov coverage ONLY in --coverage mode. In crash-finding mode
        # (auto_reset/snapshot) gcov counters are discarded on every snapshot
        # restore, so coverage is unmeasurable — and reading the coverage rootfs
        # here would report STALE .gcda from a previous run (a fake number).
        try:
            if sandbox is not None and coverage:
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
                # Bounded: a VM/container that won't tear down must not hold
                # the whole campaign hostage (it would prevent the next
                # baseline from ever starting).
                await asyncio.wait_for(sandbox.stop(), timeout=15.0)
        except asyncio.TimeoutError:
            print("  ⚠ sandbox.stop() timed out after 15s — forcing orphan cleanup")
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

    # Firecracker: extract .gcda from the gcov-instrumented rootfs via debugfs,
    # then run lcov inside a gcc-12 (bookworm) container (the .gcda is gcc-12
    # 'B22*' format; host gcov-11/15 refuse it). Only the coverage rootfs has
    # /opt/cov — the production rootfs has no gcov instrumentation.
    if sandbox_driver == "firecracker":
        import shutil as _sh
        rootfs = "sandbox/firecracker_env/rootfs_lightftp_coverage.ext4"
        if not _sh.which("debugfs") or not Path(rootfs).exists():
            print("  ℹ Firecracker coverage needs debugfs + the coverage rootfs — skipping")
            return {}
        coverage_dir = baseline_dir / "coverage"
        work = coverage_dir / "gcov_work"
        work.mkdir(parents=True, exist_ok=True)
        build_dst = work / "build"
        build_dst.mkdir(parents=True, exist_ok=True)
        try:
            # Dump .gcno + source, then .gcda, place .gcda next to .gcno.
            for sub in ("Source/Release", "Source"):
                sp.run(["debugfs", "-R", f"rdump /opt/lightftp-build/{sub} {build_dst}",
                        rootfs], capture_output=True, timeout=60)
                if any(build_dst.rglob("*.gcno")):
                    break
            cov_dst = work / "cov"
            cov_dst.mkdir(parents=True, exist_ok=True)
            sp.run(["debugfs", "-R", f"rdump /opt/cov {cov_dst}", rootfs],
                   capture_output=True, timeout=60)
            gcda = list(cov_dst.rglob("*.gcda"))
            gcno = list(build_dst.rglob("*.gcno"))
            rel = gcno[0].parent if gcno else build_dst
            for g in gcda:
                (rel / g.name).write_bytes(g.read_bytes())
            if not gcda:
                print("  ℹ Firecracker: no .gcda flushed (timer didn't fire?) — skipping")
                return {}
            info = work / "coverage.info"
            r = sp.run(
                ["docker", "run", "--rm", "-v", f"{work}:/work", "lifa-lcov",
                 "lcov", "--capture", "--directory", "/work/build",
                 "--output-file", "/work/coverage.info",
                 "--rc", "lcov_branch_coverage=1", "--ignore-errors", "source"],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode != 0 or not info.exists():
                print(f"  ⚠ Firecracker lcov failed: {r.stderr[:160]}")
                return {}
            data = TelemetryCollector.parse_lcov(str(info))
            data["lcov_path"] = str(info)
            data["gcov_tool"] = "gcov-12 (bookworm container)"
            data["gcda_count"] = len(gcda)
            print(f"  ✓ Firecracker coverage: {data['line_coverage_pct']:.1f}% lines "
                  f"({data['lines_hit']}/{data['lines_total']}), "
                  f"{data['branch_coverage_pct']:.1f}% branches "
                  f"({data['branches_hit']}/{data['branches_total']})")
            return data
        except Exception as e:
            print(f"  ⚠ Firecracker coverage extraction failed: {e}")
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

        # Collect coverage for lightftp target (gcov-instrumented build,
        # built via Dockerfile.lightftp-coverage which keeps /tmp/LightFTP).
        if target == "lightftp":
            try:
                import shutil
                # gcov tool must be compatible with the gcc that built fftp
                # (builder is bookworm = gcc-12). Host may lack gcov-12, so try
                # candidates in order of preference; first available wins.
                _GCOV_CANDIDATES = ["gcov-12", "gcov-11", "gcov-15", "gcov"]
                gcov_tool = next(
                    (g for g in _GCOV_CANDIDATES if shutil.which(g)), None
                )
                if gcov_tool is None:
                    print("  ⚠ No gcov tool found on host — skipping lightftp coverage")
                    return {}

                # Step 1: SIGINT (signal 2) to flush gcov .gcda files.
                # fftp is PID 1 (exec'd by /init).
                sp.run(
                    ["docker", "exec", container_name, "kill", "-2", "1"],
                    capture_output=True, timeout=10,
                )
                await asyncio.sleep(2)  # Wait for gcov flush
                print(f"  ✓ Sent SIGINT to fftp (PID 1) — gcov buffers flushed")

                # Step 2: Copy .gcda+.gcno (object dir) and source from container.
                # fftp writes .gcda to the absolute build path baked in at
                # compile time: /tmp/LightFTP/Source/Release/*.gcda
                for src in [
                    f"{container_name}:/tmp/LightFTP/Source/Release/.",
                    f"{container_name}:/tmp/LightFTP/Source/.",
                ]:
                    sp.run(
                        ["docker", "cp", src, str(work_dir)],
                        capture_output=True, timeout=30,
                    )
                gcda_files = list(work_dir.rglob("*.gcda"))
                if not gcda_files:
                    print("  ℹ No .gcda files found after SIGINT — ensure the "
                          "runtime image keeps /tmp/LightFTP (coverage variant)")
                    return {}
                print(f"  ✓ Copied {len(gcda_files)} .gcda files from container")

                # Step 3: Run lcov on HOST with a compatible gcov tool.
                info_path = coverage_dir / "coverage.info"
                lcov_result = sp.run(
                    ["lcov", "--capture",
                     "--directory", str(work_dir),
                     "--output-file", str(info_path),
                     "--gcov-tool", gcov_tool,
                     "--rc", "lcov_branch_coverage=1",
                     "--ignore-errors", "source,mismatch"],
                    capture_output=True, text=True, timeout=60,
                )
                if lcov_result.returncode == 0:
                    print(f"  ✓ lcov --capture succeeded ({gcov_tool})")
                    coverage_data = TelemetryCollector.parse_lcov(str(info_path))
                    coverage_data["lcov_path"] = str(info_path)
                    coverage_data["gcov_tool"] = gcov_tool
                    print(
                        f"  ✓ Coverage: {coverage_data['line_coverage_pct']:.1f}% lines "
                        f"({coverage_data['lines_hit']}/{coverage_data['lines_total']}), "
                        f"{coverage_data['branch_coverage_pct']:.1f}% branches "
                        f"({coverage_data['branches_hit']}/{coverage_data['branches_total']})"
                    )
                    return coverage_data
                else:
                    print(f"  ⚠ lcov failed ({gcov_tool}): {lcov_result.stderr[:200]}")
                    return {}
            except Exception as e:
                print(f"  ⚠ lightftp coverage collection failed: {e}")
                return {}

        # For other targets, use original docker cp approach
        if target not in ("lighttpd", "lightftp"):
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
            env=os.environ.copy(),  # propagate LIFA_PROTOCOL_MODULE → slow loop
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


# M4 fix: the math-only and fusion background loops previously swallowed
# every exception with a bare ``except Exception: continue``. A persistent
# failure (e.g. update_rule_set raising after a refactor) would silently
# produce zero rules for the whole baseline, degrading B/C to A with no signal.
# Log the first occurrence of each unique error so the run isn't blind.
_logged_loop_errors: set[str] = set()


def _log_loop_error(loop_name: str, exc: BaseException) -> None:
    key = f"{loop_name}:{type(exc).__name__}:{str(exc)[:80]}"
    if key in _logged_loop_errors:
        return
    _logged_loop_errors.add(key)
    print(
        f"WARNING: {loop_name} raised {type(exc).__name__}: {exc} "
        "(suppressed to keep the loop alive; logged once per unique error — "
        "if this repeats the baseline may be degraded).",
        file=sys.stderr,
    )


async def _run_math_only_loop(
    traffic_log: str,
    mutator: Any,
    crash_manager: Any,
    poll_interval: float = 5.0,
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

            print(
                f"  [math-only] Analyzed {len(raw_bytes)} packets → "
                f"{len(heatmap.field_groups)} groups, "
                f"{len(field_rules)} field_rules"
            )

            if field_rules:
                # Use RulesOrchestrator._convert_field_rules() which correctly
                # handles: STATIC → preserve_bytes, SKIP filtering,
                # dictionary_values transfer, and field_type inference.
                # C2 fix: _convert_field_rules is now a @staticmethod (pure
                # function, no instance state) — call it directly on the class
                # instead of the fragile __new__() hack that would silently
                # AttributeError if the method ever touched self.
                rules = RulesOrchestrator._convert_field_rules(field_rules)

                # Assign deterministic rule_ids so the same field always gets
                # the same ID → dedup works across math-only cycles.
                import hashlib
                for rule in rules:
                    rule.rule_id = hashlib.sha256(
                        f"{rule.offset_start}:{rule.offset_end}:{rule.rule_type.value}".encode()
                    ).hexdigest()[:12]

                # Direct push to mutator (primary delivery mechanism)
                from shared.schemas import ActiveRuleSet as _ARS
                rule_set_payload = _ARS(
                    protocol_name="math_bootstrap",
                    rules=rules,
                )
                await mutator.update_rule_set(rule_set_payload)
                print(
                    f"  [math-only] Pushed {len(rules)} rules to mutator "
                    f"(first 3: {[r.target_field_name for r in rules[:3]]})"
                )
                # No file write — direct push is authoritative in-process.
                # Writing the file would make _poll_rules_file() re-push with
                # default metadata (protocol_name="inferred", confidence=0%)
                # and overwrite this good push.

        except asyncio.CancelledError:
            break
        except Exception as exc:
            _log_loop_error("math-only loop (baseline B)", exc)
            continue


async def _run_fusion_loop(
    traffic_log: str,
    agent: Any,
    mutator: Any,
    crash_manager: Any,
    poll_interval: float = 5.0,
) -> None:
    """Background loop for Baseline C: math bootstrap + LLM inference.

    Runs the full RulesOrchestrator pipeline in-process, pushing rules
    directly to the mutator via await mutator.update_rule_set().
    This avoids the broken subprocess IPC that caused 0 rules in C.
    """
    from slow_loop.parser import TrafficParser
    from slow_loop.differential_analyzer import DifferentialAnalyzer
    from slow_loop.rules_orchestrator import RulesOrchestrator
    from slow_loop.rule_generator import RuleGenerator

    rule_gen = RuleGenerator(min_confidence=0.5, max_rules=200)
    parser = TrafficParser(log_path=traffic_log, read_interval_ms=2000)

    # Phase 3 / TASK 4: read force-inference thresholds from config.yaml so the
    # in-process campaign path honours the same force_inference keys as the
    # run_slow_loop.py daemon (single source of truth). Falls back to 600s /
    # 20000 mutations. NOTE: re_infer_interval_s=30 below is the dominant
    # cadence driver (fires first); force_inference is a starvation backstop.
    try:
        import yaml as _yaml
        with open(_project_root / "config.yaml", encoding="utf-8") as _f:
            _sl_cfg = (_yaml.safe_load(_f) or {}).get("slow_loop", {}) or {}
    except Exception:
        _sl_cfg = {}
    _force_cfg = _sl_cfg.get("force_inference", {}) or {}

    orchestrator = RulesOrchestrator(
        parser=parser,
        agent=agent,
        rule_gen=rule_gen,
        max_packets_per_inference=20,
        window_size=200,
        min_packets_before_infer=2,
        crash_manager=crash_manager,
        re_infer_interval_s=30.0,
        force_inference_time_s=_force_cfg.get("time_threshold_s", 600.0),
        force_inference_mutations=_force_cfg.get("mutation_threshold", 20000),
    )

    while True:
        await asyncio.sleep(poll_interval)
        try:
            result = await orchestrator.run_cycle()

            if result is not None and result.get("status") == "success":
                rules = result.get("rules", [])
                grammar = result.get("grammar")
                if rules and grammar:
                    from shared.schemas import ActiveRuleSet as _ARS
                    rule_set = _ARS(
                        protocol_name=grammar.protocol_name,
                        rules=rules,
                    )
                    await mutator.update_rule_set(rule_set)
                    # NOTE: we deliberately do NOT also write to the rules
                    # file here. The direct update_rule_set() above is the
                    # source of truth in this in-process eval loop. Writing
                    # the file too would make the mutator's _poll_rules_file()
                    # re-read it and re-push an ActiveRuleSet rebuilt with
                    # default metadata (protocol_name="inferred",
                    # confidence=0%), overwriting this good push — visible
                    # as the rule set oscillating FTP→inferred, confidence
                    # dropping to 0%.

            elif result is not None and result.get("status") == "bootstrap":
                rules = result.get("rules", [])
                if rules:
                    from shared.schemas import ActiveRuleSet as _ARS
                    rule_set = _ARS(
                        protocol_name="bootstrap_fusion",
                        rules=rules,
                    )
                    await mutator.update_rule_set(rule_set)
                    # No file write here either — same reason as the success
                    # branch above (direct push is authoritative in-process).

        except asyncio.CancelledError:
            break
        except Exception as exc:
            _log_loop_error("fusion loop (baseline C)", exc)
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
# Dashboard subprocess management
# =============================================================================


def _start_dashboard(port: int = 8501) -> Optional[object]:
    """Launch the Streamlit dashboard as a background subprocess.

    Returns the subprocess handle, or None if launch failed.
    """
    import subprocess as sp
    from pathlib import Path

    dashboard_script = _project_root / "web_ui" / "app.py"
    if not dashboard_script.exists():
        print("  ⚠ web_ui/app.py not found — dashboard skipped")
        return None

    # Find streamlit binary
    python_bin = Path(sys.executable).parent
    streamlit_bin = python_bin / "streamlit"

    if streamlit_bin.exists():
        cmd = [
            str(streamlit_bin), "run", str(dashboard_script),
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
        # Kill any stale dashboard on the same port first (silent conflict
        # would make the new process exit immediately with no error output).
        import subprocess as _sp
        try:
            _sp.run(
                ["fuser", "-k", f"{port}/tcp"],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass  # fuser may not be available

        proc = sp.Popen(
            cmd,
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
            cwd=str(_project_root),
        )
        # Health check: wait up to 8s for Streamlit to start serving HTTP.
        import urllib.request
        for _ in range(16):
            if proc.poll() is not None:
                print(f"  ⚠ Dashboard process exited early (rc={proc.returncode})")
                return None
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=0.5
                )
                print(f"  ✓ Dashboard started (PID={proc.pid}) → http://localhost:{port}")
                return proc
            except Exception:
                time.sleep(0.5)
        print(f"  ⚠ Dashboard started but health check timed out (PID={proc.pid})")
        return proc
    except FileNotFoundError:
        print("  ⚠ streamlit not found — install with: pip install streamlit")
        return None
    except OSError as e:
        print(f"  ⚠ Failed to start dashboard: {e}")
        return None


def _stop_dashboard(proc) -> None:
    """Stop the dashboard subprocess gracefully."""
    if proc is None:
        return
    import subprocess as sp
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        print("  ✓ Dashboard stopped")
    except Exception:
        pass


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
        "--coverage", action="store_true",
        help="Coverage mode: use the gcov-instrumented LightFTP rootfs, "
             "disable snapshot auto-reset (so gcov counters accumulate over "
             "the whole run), and extract real line/branch coverage post-run. "
             "Only for --driver firecracker --target lightftp.",
    )
    parser.add_argument(
        "--baseline", default="all",
        help="Which baseline(s) to run: A, B, C, all, or comma-separated "
             "like B,C (default: all). Runs in the given order.",
    )
    parser.add_argument(
        "--driver", choices=["docker", "firecracker"], default="firecracker",
        help="Sandbox driver (default: firecracker)",
    )
    parser.add_argument(
        "--target", default="lifa", choices=["lifa", "lighttpd", "lightftp"],
        help="Target server: lifa, lightttpd, or lightftp",
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

    # Parse --baseline: "all", a single letter (A/B/C), or a comma-separated
    # subset like "B,C" / "A,C". Preserve the requested order and de-dup.
    _valid = set(BASELINE_CONFIGS.keys())
    if args.baseline == "all":
        baselines = list(BASELINE_CONFIGS.keys())
    else:
        requested = [b.strip().upper() for b in args.baseline.split(",") if b.strip()]
        invalid = [b for b in requested if b not in _valid]
        if invalid:
            parser.error(
                f"Invalid --baseline value(s): {invalid}. "
                f"Choose from {sorted(_valid)}, 'all', or a comma-separated subset."
            )
        # de-dup while preserving order
        seen: set[str] = set()
        baselines = [b for b in requested if not (b in seen or seen.add(b))]
        if not baselines:
            parser.error("--baseline resolved to no baselines.")

    # ── Pre-run cleanup: archive old results, kill orphans ────────
    from scripts.cleanup import (
        archive_previous_results,
        cleanup_orphaned_resources,
    )
    cleanup_orphaned_resources()
    archive_previous_results(target=args.target, driver=args.driver)

    # ── Start dashboard subprocess ────────────────────────────────
    dashboard_proc = None
    if not args.no_dashboard:
        dashboard_proc = _start_dashboard(port=args.dashboard_port)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  LIFA-Fuzz Academic Benchmarking Suite                  ║")
    print(f"║  Baselines: {', '.join(baselines):<44s}║")
    print(f"║  Duration:   {args.duration}s per baseline{' ' * (34 - len(str(args.duration)))}║")
    print(f"║  Target:     {args.target:<44s}║")
    print(f"║  Output:     {str(RESULTS_DIR):<44s}║")
    print("╚══════════════════════════════════════════════════════════╝")

    results = {}
    # Hard cap per baseline: run duration + generous grace for teardown. This
    # GUARANTEES the campaign advances to the next baseline even if a baseline's
    # finally cleanup or the next baseline's sandbox boot hangs — otherwise the
    # whole B,C run can freeze after B finishes and never reach C. The grace is
    # well beyond normal teardown (sandbox.stop 15s + sleep 10s + boot 15s),
    # so it only trips on a genuine hang, and the baseline's summary is already
    # written before its finally runs, so no data is lost.
    _GRACE_S = 300
    _baseline_hard_timeout = args.duration + _GRACE_S
    for i, bid in enumerate(baselines):
        print(f"\n  ▶ Starting baseline {bid} "
              f"(hard cap {_baseline_hard_timeout}s = {args.duration}s run + {_GRACE_S}s grace)")
        try:
            summary = await asyncio.wait_for(
                run_single_baseline(
                    baseline_id=bid,
                    duration_s=args.duration,
                    sandbox_driver=args.driver,
                    target=args.target,
                    total_baselines=len(baselines),
                    baseline_index=i,
                    coverage=getattr(args, "coverage", False),
                ),
                timeout=_baseline_hard_timeout,
            )
        except asyncio.TimeoutError:
            print(
                f"\n  ⚠ Baseline {bid} exceeded hard timeout "
                f"({_baseline_hard_timeout}s) — forcing advance to next baseline. "
                f"Summary (if written before hang) is preserved on disk."
            )
            summary = {"baseline": bid, "error": "baseline_hard_timeout"}
        results[bid] = summary

        # Wait between baselines for cleanup
        if bid != baselines[-1]:
            print(f"\n  ⏭ Baseline {bid} done — cleaning up before next baseline...")
            # Kill orphaned VMs / containers / TAP devices / Firecracker sockets
            # left behind by this baseline so the next one starts clean.
            # free_port_8001=False because THIS process owns port 8001 (the
            # interceptor binds it in-process) — fuser -k would SIGKILL us.
            # The interceptor.stop() in the baseline's finally already freed
            # the port; the VM/TAP/socket orphans are what we still need to catch.
            t0 = time.monotonic()
            cleanup_orphaned_resources(free_port_8001=False)
            print(f"  ⏭ Inter-baseline cleanup took {time.monotonic() - t0:.1f}s, "
                  f"sleeping 10s, then starting next baseline.")
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

    # ── Stop dashboard ────────────────────────────────────────────
    if dashboard_proc:
        _stop_dashboard(dashboard_proc)

    # All work is done — force-exit immediately. litellm spawns a non-daemon
    # LoggingWorker thread + asyncio cleanup can hang indefinitely. We have the
    # results (comparison printed, files written); nothing useful remains.
    import os as _os
    print("  ✅ Campaign complete — exiting.")
    _os._exit(0)


if __name__ == "__main__":
    load_dotenv(override=False)

    # ── Suppress core dumps (eliminate clutter at the source) ──────────
    # ASAN targets (LightFTP, dummy vulnerable_server) abort() on crash and
    # the kernel writes core.<pid> into the crashing process's CWD = project
    # root. ASAN already prints a richer report than a raw core, so we (1)
    # drop the host RLIMIT_CORE to 0 and (2) set ASAN_OPTIONS=disable_coredump=1
    # so any ASAN-instrumented child the runner spawns never dumps a core.
    # Existing/stray cores are cleaned by ``scripts/cleanup.py --cores-only``.
    _apply_core_suppression()

    # Ensure CWD is project root — all relative paths (sandbox/,
    # shared/, etc.) depend on this. Running from evaluation/ breaks them.
    os.chdir(str(_project_root))
    asyncio.run(main())
