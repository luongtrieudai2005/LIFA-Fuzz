#!/usr/bin/env python3
"""
RQ1 — REAL LLM inference (GLM-5-Turbo via Z.ai) on protocol grammar.

Smoke test: single REAL inference on synthetic LIFA traffic, evaluated
against the LIFA ground truth. Confirms the API path works and gives a
first REAL F1 number (vs the MOCK F1=0.857 in the report).

Wiring mirrors run_slow_loop.py exactly (provider/model/api_key/api_base/
enable_thinking from config.yaml), so the result is representative of the
real Slow-Loop inference — not a hand-rolled client.

Usage:
    python3 scripts/rq1_real.py                 # single REAL inference
    python3 scripts/rq1_real.py --self-consistent  # N=5 majority vote
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Project root on path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv
load_dotenv(override=False)

import yaml  # noqa: E402

from evaluation.rq1_accuracy import evaluate_grammar_accuracy, _generate_lifa_traffic  # noqa: E402
from evaluation.ground_truth import LIFA_GROUND_TRUTH  # noqa: E402
from evaluation.ftp_ground_truth import FTP_GROUND_TRUTH, get_ftp_ground_truth_summary  # noqa: E402
from slow_loop.llm_agent import LLMAgent  # noqa: E402


def _generate_ftp_traffic():
    """Generate TrafficRecords of realistic FTP control commands (RFC 959)."""
    from shared.schemas import TrafficRecord, Direction

    # Realistic FTP session commands (hex form for the parser/LLM).
    packets = [
        b"USER anonymous\r\n",
        b"PASS user@example.com\r\n",
        b"SYST\r\n",
        b"PWD\r\n",
        b"TYPE I\r\n",
        b"PASV\r\n",
        b"LIST\r\n",
        b"CWD pub\r\n",
        b"RETR readme.txt\r\n",
        b"QUIT\r\n",
    ]
    return [
        TrafficRecord(direction=Direction.CLIENT_TO_SERVER,
                      raw_data=p, is_mutated=False)
        for p in packets
    ]


def build_agent_from_config(config_path: str = "config.yaml") -> LLMAgent:
    """Build a REAL-mode LLMAgent exactly as run_slow_loop.py does."""
    with open(config_path) as f:
        config = yaml.safe_load(f)
    llm_cfg = config.get("slow_loop", {}).get("llm_agent", {})

    # Respect config's LLM_MODE (default REAL) — do NOT force MOCK.
    llm_mode = llm_cfg.get("mode", "REAL").upper()
    import os
    os.environ["LLM_MODE"] = llm_mode

    api_key_env = llm_cfg.get("api_key_env", "OPENAI_API_KEY")
    api_key = os.environ.get(api_key_env, "")
    if not api_key:
        sys.exit(f"[error] {api_key_env} not set — cannot run REAL inference")

    agent = LLMAgent(
        provider=llm_cfg.get("provider", "openai"),
        model=llm_cfg.get("model", "gpt-4o"),
        api_key=api_key,
        api_base=llm_cfg.get("api_base", ""),
        max_tokens=llm_cfg.get("max_tokens", 4096),
        temperature=llm_cfg.get("temperature", 0.2),
        timeout_seconds=llm_cfg.get("timeout_seconds", 60),
        max_retries=llm_cfg.get("max_retries", 3),
        context_window=llm_cfg.get("context_window", 128_000),
    )
    agent.enable_thinking = llm_cfg.get("enable_thinking", True)
    print(f"[config] mode={llm_mode} model={agent.model} "
          f"api_base={agent.api_base[:40]}... enable_thinking={agent.enable_thinking}")
    return agent


async def run(use_self_consistent: bool, protocol: str, n: int = 5) -> None:
    agent = build_agent_from_config()

    if protocol == "ftp":
        traffic = _generate_ftp_traffic()
        ground_truth = FTP_GROUND_TRUTH
        gt_label = "FTP (RFC 959, independent)"
    else:
        traffic = _generate_lifa_traffic()
        ground_truth = LIFA_GROUND_TRUTH
        gt_label = "LIFA (author-designed, simple)"

    print(f"\n[run] {'self-consistency N=' + str(n) if use_self_consistent else 'single'} "
          f"REAL inference on {len(traffic)} {protocol.upper()} packets "
          f"(GT: {gt_label})...")
    if use_self_consistent:
        grammar = await agent.infer_protocol_self_consistent(traffic, n_samples=n)
    else:
        grammar = await agent.infer_protocol(traffic)

    result = evaluate_grammar_accuracy(grammar, ground_truth=ground_truth)

    print("\n" + "=" * 60)
    print(f"  RQ1 REAL LLM — {protocol.upper()} grammar inference")
    print("=" * 60)
    print(f"  Precision: {result.precision:.2%}   Recall: {result.recall:.2%}   "
          f"F1: {result.f1_score:.2%}")
    print(f"  TP={result.true_positives} FP={result.false_positives} "
          f"FN={result.false_negatives}")
    print(f"  Offset acc: {result.offset_accuracy:.2%} | "
          f"Type acc: {result.type_accuracy:.2%} | "
          f"Strategy acc: {result.strategy_accuracy:.2%}")
    print("  Inferred fields:")
    for f in grammar.fields:
        print(f"    - {f.name:<14} [{f.offset_start},{f.offset_end}) "
              f"type={f.field_type.value} strat={f.mutation_strategy.value}")
    print("  Per-field match:")
    for d in result.field_details:
        m = d["match"]
        mk = {"TP": "✓", "FP": "✗", "FN": "✗"}[m]
        print(f"    {mk} {m}: GT={d.get('ground_truth') or '—':<12} "
              f"Inf={d.get('inferred') or '—':<12}")

    # Save
    out_dir = Path("evaluation/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"rq1_real_{protocol}_{'sc'+str(n) if use_self_consistent else 'single'}"
    out_path = out_dir / f"{tag}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": "REAL",
            "protocol": protocol,
            "method": "self_consistent" if use_self_consistent else "single",
            "model": agent.model,
            "ground_truth": (get_ftp_ground_truth_summary() if protocol == "ftp"
                             else "LIFA"),
            "metrics": result.to_dict(),
            "inferred_fields": [
                {"name": f.name, "offset": [f.offset_start, f.offset_end],
                 "type": f.field_type.value, "strategy": f.mutation_strategy.value}
                for f in grammar.fields
            ],
        }, f, indent=2, default=str)
    print(f"\n  saved → {out_path}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--self-consistent", action="store_true",
                   help="Use self-consistency N=5 (majority vote)")
    p.add_argument("--n", type=int, default=5)
    p.add_argument("--protocol", choices=["lifa", "ftp"], default="ftp",
                   help="Protocol to infer (default: ftp — independent GT)")
    args = p.parse_args()
    asyncio.run(run(args.self_consistent, args.protocol, args.n))
