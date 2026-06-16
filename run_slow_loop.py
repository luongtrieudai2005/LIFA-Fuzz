#!/usr/bin/env python3
"""
run_slow_loop.py
─────────────────
LIFA-Fuzz Slow Loop Orchestrator — background daemon.

Watches the shared traffic log for new data, periodically invoking the
Parser → LLM Agent → Rule Generator pipeline, and writing SemanticRules
to the shared rules file for Fast Loop pickup.

Pipeline:
    shared/raw_traffic.jsonl  (written by Interceptor)
        │
        ▼  TrafficParser.read_log()
    list[InteractionSession]
        │
        ▼  TrafficParser.format_for_llm()
    dict  (structured LLM payload)
        │
        ▼  LLMAgent.infer_protocol()
    ProtocolGrammar
        │
        ▼  RuleGenerator.grammar_to_rules()
    list[SemanticRule]
        │
        ▼  RuleGenerator.push_rules()
    shared/active_rules.json  (polled by Fast Loop)

Usage:
    # Start the daemon (uses config.yaml defaults):
    python run_slow_loop.py

    # Custom traffic log path:
    python run_slow_loop.py --traffic-log shared/raw_traffic.jsonl

    # Custom poll interval and minimum packets:
    python run_slow_loop.py --interval 15 --min-packets 10

    # Custom config file:
    python run_slow_loop.py --config /path/to/config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from dotenv import load_dotenv
from shared.logger import get_logger, setup_root_logger
from shared.schemas import ProtocolGrammar, SemanticRule
from shared.crash_manager import CrashManager
from shared.runtime_state import write_slow_loop_state, SLOW_LOOP_STATE_FILE
from slow_loop.parser import TrafficParser
from slow_loop.llm_agent import LLMAgent
from slow_loop.rule_generator import RuleGenerator
from slow_loop.rules_orchestrator import RulesOrchestrator


# =============================================================================
# Configuration Helpers
# =============================================================================


def load_config(config_path: str = "config.yaml") -> dict[str, Any]:
    """Load and return the YAML configuration, or an empty dict if absent."""
    path = Path(config_path)
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        # Non-fatal — defaults will be used
        print(f"[warn] Failed to load config from {config_path}: {e}", file=sys.stderr)
        return {}


def resolve_traffic_log(config: dict[str, Any]) -> str:
    """Determine the traffic log path from config or fall back to default."""
    try:
        return config.get("fast_loop", {}).get("traffic_log", {}).get(
            "path", "shared/raw_traffic.jsonl"
        )
    except (AttributeError, TypeError):
        return "shared/raw_traffic.jsonl"


# =============================================================================
# Slow Loop State Persistence
# =============================================================================


def _write_slow_loop_state(
    orchestrator: RulesOrchestrator,
    agent: LLMAgent,
    alive: bool = True,
) -> None:
    """Write current slow loop status to shared/slow_loop_state.json.

    Called after each cycle so the main pipeline (and dashboard) can
    see slow loop health without shared object references.
    """
    orch_stats = orchestrator.stats
    data = {
        "timestamp": time.time(),
        "pid": os.getpid(),
        "alive": alive,
        "last_cycle_time": (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if orch_stats.get("total_cycles", 0) > 0
            else ""
        ),
        "total_cycles": orch_stats.get("total_cycles", 0),
        "total_inferences": orch_stats.get("total_inferences", 0),
        "total_rules_pushed": orch_stats.get("total_rules_pushed", 0),
        "last_error": orch_stats.get("last_error", ""),
    }
    write_slow_loop_state(data, SLOW_LOOP_STATE_FILE)


# =============================================================================
# Main Daemon Loop
# =============================================================================


async def run_slow_loop(
    traffic_log_path: str = "shared/raw_traffic.jsonl",
    rules_output_path: str = "shared/active_rules.json",
    poll_interval_s: float = 10.0,
    min_packets: int = 5,
    config_path: str = "config.yaml",
) -> None:
    """Run the Slow Loop daemon.

    Watches the traffic log for new data, periodically:
    1. Invokes the Traffic Parser to read and group packets.
    2. Sends parsed sessions to the LLM Agent for protocol inference.
    3. Converts inferred grammar into SemanticRule objects.
    4. Writes rules to the shared rules file.
    """
    logger = get_logger("slow_loop.orchestrator")

    # ── Load configuration ────────────────────────────────────────────
    config = load_config(config_path)
    if traffic_log_path == "shared/raw_traffic.jsonl":
        traffic_log_path = resolve_traffic_log(config)

    llm_cfg = config.get("slow_loop", {}).get("llm_agent", {})
    parser_cfg = config.get("slow_loop", {}).get("parser", {})
    rule_cfg = config.get("slow_loop", {}).get("rule_generator", {})
    slow_loop_cfg = config.get("slow_loop", {})

    min_packets = parser_cfg.get("min_samples_before_infer", min_packets)
    rules_output = rule_cfg.get("rule_output_file", rules_output_path)

    # ── Banner ────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  LIFA-Fuzz Slow Loop Daemon")
    logger.info("=" * 60)
    logger.info(f"  Traffic log:   {traffic_log_path}")
    logger.info(f"  Rules output:  {rules_output}")
    logger.info(f"  Poll interval: {poll_interval_s}s")
    logger.info(f"  Min packets:   {min_packets}")
    logger.info(f"  LLM mode:      {llm_cfg.get('mode', os.environ.get('LLM_MODE', 'REAL'))}")
    logger.info(f"  LLM provider:  {llm_cfg.get('provider', 'openai')}")
    logger.info(f"  LLM model:     {llm_cfg.get('model', 'gpt-4o')}")
    logger.info(f"  LLM api_base:  {llm_cfg.get('api_base', '') or '(default)'}")
    logger.info("=" * 60)

    # ── Config-driven LLM mode ────────────────────────────────────────
    llm_mode = llm_cfg.get("mode", os.environ.get("LLM_MODE", "REAL"))
    os.environ["LLM_MODE"] = llm_mode.upper()

    # ── Initialize components ─────────────────────────────────────────
    parser = TrafficParser(
        log_path=traffic_log_path,
        read_interval_ms=parser_cfg.get("read_interval_ms", 5000),
        session_gap_threshold=2.0,
    )

    # API key from environment
    api_key_env = llm_cfg.get("api_key_env", "OPENAI_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    agent = LLMAgent(
        provider=llm_cfg.get("provider", "openai"),
        model=llm_cfg.get("model", "gpt-4o"),
        api_key=api_key,
        api_base=llm_cfg.get("api_base", ""),
        max_tokens=llm_cfg.get("max_tokens", 4096),
        temperature=llm_cfg.get("temperature", 0.2),
        timeout_seconds=llm_cfg.get("timeout_seconds", 60),
        max_retries=llm_cfg.get("max_retries", 3),
        session_budget_tokens=llm_cfg.get("session_budget_tokens", 0),
        session_budget_usd=llm_cfg.get("session_budget_usd", 0),
        cache_file=llm_cfg.get("cache_file", "shared/last_known_grammar.json"),
        circuit_retry_after_s=llm_cfg.get("circuit_retry_after_s", 300),
        context_window=llm_cfg.get("context_window", 128_000),
        prompt_truncation_strategy=llm_cfg.get("prompt_truncation_strategy", "truncate"),
    )
    # H1 fix: default to False (matches LLMAgent.__init__ and the eval path).
    # GLM models with enable_thinking=True route all tokens to reasoning_content
    # and return an empty .content → every call fails → silent bootstrap
    # fallback. A config that omits this key must NOT silently flip the bit to
    # True; opt in explicitly instead.
    agent.enable_thinking = llm_cfg.get("enable_thinking", False)

    # Cross-validate enable_thinking for cost-sensitive models
    if agent.enable_thinking and "glm" in agent.model.lower():
        logger.warning(
            "enable_thinking=True with GLM model — this may cause "
            "all tokens to be consumed by reasoning_content. "
            "Set enable_thinking: false in config.yaml"
        )

    rule_gen = RuleGenerator(
        min_confidence=rule_cfg.get("min_confidence", 0.5),
        max_rules=rule_cfg.get("max_rules", 200),
        rule_output_file=rules_output,
    )

    # ── Crash Manager (crash deduplication & isolation) ────────────────
    crash_cfg = config.get("slow_loop", {}).get("crash_manager", {})
    crash_dir = crash_cfg.get("crash_dir", "./crashes")
    crash_manager = CrashManager(crash_dir=crash_dir)
    loaded_crashes = await crash_manager.load()
    if loaded_crashes > 0:
        logger.info(f"  Loaded {loaded_crashes} existing crash records")

    # ── EWMA Adaptive Controller (coordinates Fast Loop recv() sampling) ──
    ewma_cfg = config.get("slow_loop", {}).get("ewma_controller", {})
    ewma_enabled = ewma_cfg.get("enabled", True)
    ewma_controller = None
    if ewma_enabled:
        from slow_loop.ewma_controller import EWMAController
        ewma_controller = EWMAController(
            output_path=ewma_cfg.get("output_path", "shared/adaptive_k.json"),
            delta=ewma_cfg.get("delta", 0.1),
            theta=ewma_cfg.get("theta", 2.0),
            K_max=ewma_cfg.get("K_max", 200),
            k_min=ewma_cfg.get("k_min", 5),
            weight_A=ewma_cfg.get("weight_A", 0.3),
            weight_B=ewma_cfg.get("weight_B", 0.7),
            response_buf_path=ewma_cfg.get(
                "response_buf_path", "shared/response_buffer.jsonl"
            ),
        )
        logger.info(
            f"  EWMA Controller: enabled (theta={ewma_controller.theta}, "
            f"K_max={ewma_controller.K_max}, k_min={ewma_controller.k_min})"
        )
    else:
        logger.info("  EWMA Controller: disabled")

    # ── Orchestrator (wraps Parser → dedup → Math → LLM → RuleGen) ──
    orchestrator = RulesOrchestrator(
        parser=parser,
        agent=agent,
        rule_gen=rule_gen,
        max_packets_per_inference=parser_cfg.get("max_samples_per_batch", 20),
        window_size=200,
        max_prompt_tokens=llm_cfg.get("max_prompt_tokens", 0),
        min_packets_before_infer=min_packets,
        crash_manager=crash_manager,
        ab_mode=slow_loop_cfg.get("ab_mode", "llm"),
        ewma_controller=ewma_controller,
        re_infer_interval_s=slow_loop_cfg.get("re_infer_interval_s", 300.0),
        force_inference_time_s=slow_loop_cfg.get("force_inference", {}).get(
            "time_threshold_s", 600.0
        ),
        force_inference_mutations=slow_loop_cfg.get("force_inference", {}).get(
            "mutation_threshold", 20000
        ),
    )

    # ── Shutdown signal ──────────────────────────────────────────────
    shutdown_event = asyncio.Event()

    def _signal_handler(sig: int, frame: Any) -> None:
        logger.info("Received shutdown signal (SIGINT/SIGTERM)")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    logger.info("Slow Loop ready — waiting for traffic data...")

    # ── Main daemon loop ──────────────────────────────────────────────
    consecutive_empty_reads = 0
    cycle_count = 0

    try:
        while not shutdown_event.is_set():
            try:
                # Run one orchestrator cycle (read → dedup → Math → LLM → rules)
                result = await orchestrator.run_cycle()
                cycle_count += 1

                if result is not None:
                    consecutive_empty_reads = 0

                    if result["status"] == "success":
                        grammar = result["grammar"]
                        rules = result["rules"]
                        logger.info(
                            f"Cycle result: protocol='{grammar.protocol_name}', "
                            f"fields={len(grammar.fields)}, "
                            f"rules={len(rules)}, "
                            f"packets_sent={result['packets_sent']}, "
                            f"heatmap_groups={result.get('heatmap_groups', 0)}"
                        )
                    elif result["status"] == "bootstrap":
                        logger.info(
                            f"Cycle result: BOOTSTRAP FALLBACK — "
                            f"{len(result['rules'])} heatmap rules pushed "
                            f"(LLM unavailable)"
                        )
                    elif result["status"] == "skipped":
                        logger.debug(
                            f"Cycle skipped: {result['reason']}"
                        )
                    elif result["status"] == "error":
                        logger.error(
                            f"Cycle error: {result['reason']}"
                        )
                        # Persist state BEFORE backoff so dashboard sees the error
                        _write_slow_loop_state(orchestrator, agent, alive=True)
                        # Back off longer on API errors
                        await asyncio.sleep(min(poll_interval_s * 3, 120))
                        continue

                    # ── Periodic crash stats ──────────────────────────
                    if cycle_count % 6 == 0:
                        try:
                            crash_stats = await crash_manager.get_statistics()
                            if crash_stats.unique_crashes > 0:
                                logger.info(
                                    f"Crash stats: unique={crash_stats.unique_crashes}, "
                                    f"total={crash_stats.total_hits}, "
                                    f"dedup_ratio={crash_stats.dedup_ratio:.2%}"
                                )
                        except Exception:
                            pass

                    # ── Precision mode warning ─────────────────────────
                    if orchestrator.precision_mode:
                        logger.info(
                            "  ⚠ PRECISION MODE ACTIVE (k=1) — "
                            "single-field mutations for crash isolation"
                        )
                else:
                    consecutive_empty_reads += 1
                    if consecutive_empty_reads % 6 == 0:
                        # Log every ~60s of no data
                        logger.debug("No new traffic data — still watching...")

                # Wait before next cycle
                # Persist state so main pipeline & dashboard can see us
                _write_slow_loop_state(orchestrator, agent, alive=True)
                await asyncio.sleep(poll_interval_s)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in slow loop: {e}", exc_info=True)
                # Persist state so dashboard doesn't show stale data
                try:
                    _write_slow_loop_state(orchestrator, agent, alive=True)
                except Exception:
                    pass
                await asyncio.sleep(5.0)

    finally:
        # ── Shutdown: mark slow loop as dead ────────────────────────
        _write_slow_loop_state(orchestrator, agent, alive=False)

        # ── Shutdown summary ──────────────────────────────────────────
        orch_stats = orchestrator.stats
        logger.info("")
        logger.info("=" * 60)
        logger.info("  Slow Loop Daemon — Shutting Down")
        logger.info("=" * 60)
        logger.info(f"  Total cycles:       {orch_stats['total_cycles']}")
        logger.info(f"  Total inferences:   {orch_stats['total_inferences']}")
        logger.info(f"  Total rules pushed: {orch_stats['total_rules_pushed']}")
        logger.info(f"  Skipped (budget):   {orch_stats['skipped_budget']}")
        logger.info(f"  Skipped (data):     {orch_stats['skipped_insufficient_data']}")
        logger.info(f"  Errors:             {orch_stats['errors']}")
        logger.info(f"  LLM stats:          {agent.stats}")
        logger.info(f"  Rule gen stats:     {rule_gen.stats}")
        logger.info("=" * 60)


# =============================================================================
# CLI Entry Point
# =============================================================================


def main() -> None:
    """Parse CLI arguments and launch the daemon."""
    # Load .env file first (manual env vars take precedence)
    load_dotenv(override=False)

    parser = argparse.ArgumentParser(
        description="LIFA-Fuzz Slow Loop Daemon — "
        "Parser → LLM → Rule Generator pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_slow_loop.py
  python run_slow_loop.py --traffic-log shared/raw_traffic.jsonl
  python run_slow_loop.py --interval 15 --min-packets 10
  python run_slow_loop.py --config /path/to/config.yaml
        """,
    )
    parser.add_argument(
        "--traffic-log",
        default="",
        help="Path to the traffic log JSONL file (default: from config.yaml)",
    )
    parser.add_argument(
        "--rules-output",
        default="shared/active_rules.json",
        help="Path to write generated rules JSON (default: shared/active_rules.json)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.0,
        help="Poll interval in seconds (default: from config.yaml, fallback 10)",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=0,
        help="Minimum packets before LLM inference (default: from config.yaml, fallback 5)",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    args = parser.parse_args()

    # Setup logging before anything else
    setup_root_logger(level="DEBUG", log_format="text")

    # Load config for defaults
    config = load_config(args.config)

    # Resolve defaults from config if CLI args not set
    traffic_log = args.traffic_log or resolve_traffic_log(config)
    interval = args.interval or config.get("slow_loop", {}).get(
        "parser", {}
    ).get("read_interval_ms", 10000) / 1000.0
    min_packets = args.min_packets or config.get("slow_loop", {}).get(
        "parser", {}
    ).get("min_samples_before_infer", 5)

    try:
        asyncio.run(
            run_slow_loop(
                traffic_log_path=traffic_log,
                rules_output_path=args.rules_output,
                poll_interval_s=interval,
                min_packets=min_packets,
                config_path=args.config,
            )
        )
    except KeyboardInterrupt:
        print("\nInterrupted — shutting down.")


if __name__ == "__main__":
    main()
