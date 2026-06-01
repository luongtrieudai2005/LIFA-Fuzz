"""
tests/bench_mutator_eps.py
──────────────────────────
EPS benchmark — verifies scheduler changes do not degrade throughput.

Compares three configurations:
    A) Old:      k=2, use_weighted=False, adaptive_k=False, warmup_seconds=0
    B) New:      k=2, use_weighted=True,  adaptive_k=True,  warmup_seconds=0
    C) New+Warm: k=2, use_weighted=True,  adaptive_k=True,  warmup_seconds=5

Expected: EPS degradation in B and C vs A should be < 5%.

Usage:
    python -m tests.bench_mutator_eps
"""

import asyncio
import time
from dataclasses import dataclass

from fast_loop.mutator import MutationEngine
from shared.schemas import (
    ActiveRuleSet,
    FieldRule,
    MutationStrategy,
    RuleType,
    SeedSequence,
    SemanticRule,
)


@dataclass
class BenchResult:
    config_name: str
    total_sent: int
    elapsed_s: float
    eps: float
    mode: str
    k_used: int


def _make_test_rules(n_fields: int = 5) -> ActiveRuleSet:
    """Create a 5-field ActiveRuleSet for benchmarking."""
    rules = []
    strategies = [
        MutationStrategy.BOUNDARY_VALUES,
        MutationStrategy.DICTIONARY,
        MutationStrategy.RANDOM_BYTES,
        MutationStrategy.BIT_FLIP,
        MutationStrategy.INCREMENT,
    ]
    for i in range(n_fields):
        rules.append(SemanticRule(
            rule_id=f"rule_{i}",
            rule_type=RuleType.BIT_FLIP,
            target_field_name=f"field_{i}",
            offset_start=i * 4,
            offset_end=i * 4 + 4,
            priority=0.8,
        ))
    return ActiveRuleSet(
        rules=rules,
        protocol_name="bench",
        overall_confidence=0.85,
    )


async def _run_bench(config_name: str, duration_s: float = 10.0, **engine_kwargs) -> BenchResult:
    """Run the mutation engine for `duration_s` seconds and measure EPS."""

    seed_queue = asyncio.Queue()

    # Pre-populate seed queue
    from shared.schemas import Direction, TrafficRecord
    for _ in range(100):
        seed_queue.put_nowait(SeedSequence(packets=[
            TrafficRecord(
                direction=Direction.CLIENT_TO_SERVER,
                raw_data=b"\x00" * 20,
            ),
        ]))

    # Merge defaults with per-config overrides
    engine_params = dict(
        target_host="127.0.0.1",
        target_port=0,  # Will fail to connect — but we measure build speed
        seed_queue=seed_queue,
        max_eps=0,  # unlimited
        no_recv=True,
        warmup_seconds=0,
    )
    engine_params.update(engine_kwargs)

    engine = MutationEngine(**engine_params)

    # Push rules so we're not in DUMB mode
    await engine.update_rule_set(_make_test_rules())

    start = time.monotonic()
    sent = 0
    deadline = start + duration_s

    # Simulate the hot loop — just build mutants (skip actual TCP send)
    while time.monotonic() < deadline:
        # Drain seeds
        while not seed_queue.empty():
            try:
                seed_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        # Replenish seeds
        for _ in range(10):
            seed_queue.put_nowait(SeedSequence(packets=[
                TrafficRecord(
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_data=b"\x00" * 20,
                ),
            ]))

        await engine._drain_seeds()
        seq = engine._pick_seed()
        target = engine._split_sequence(seq)
        _ = await engine._build_mutant(target.target_seed)
        sent += 1

    elapsed = time.monotonic() - start
    eps = sent / elapsed if elapsed > 0 else 0

    stats = engine.get_stats()
    return BenchResult(
        config_name=config_name,
        total_sent=sent,
        elapsed_s=round(elapsed, 2),
        eps=round(eps, 1),
        mode=stats.mode,
        k_used=stats.k_this_round,
    )


async def main():
    """Run all three benchmark configurations."""
    configs = [
        ("A) Old (static k=2, uniform)", dict(
            k=2, use_weighted=False, adaptive_k=False,
        )),
        ("B) New (adaptive k, weighted)", dict(
            k=2, use_weighted=True, adaptive_k=True,
        )),
        ("C) New+Warmup", dict(
            k=2, use_weighted=True, adaptive_k=True, warmup_seconds=5,
        )),
    ]

    bench_duration = 5.0  # seconds per config
    print(f"\n{'='*70}")
    print(f"  LIFA-Fuzz EPS Benchmark — {bench_duration}s per configuration")
    print(f"{'='*70}\n")

    results: list[BenchResult] = []
    for name, kwargs in configs:
        print(f"  Running: {name}...")
        result = await _run_bench(name, duration_s=bench_duration, **kwargs)
        results.append(result)
        print(f"    Done: {result.eps:.1f} EPS ({result.total_sent} packets)\n")

    # Print comparison table
    print(f"\n{'='*70}")
    print(f"  RESULTS")
    print(f"{'='*70}")
    print(f"\n  {'Config':<35} {'EPS':>8} {'Sent':>8} {'k':>4}")
    print(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*4}")

    baseline_eps = results[0].eps
    for r in results:
        delta = ((r.eps - baseline_eps) / baseline_eps * 100) if baseline_eps > 0 else 0
        delta_str = f"({delta:+.1f}%)" if r.config_name != results[0].config_name else "(baseline)"
        print(f"  {r.config_name:<35} {r.eps:>8.1f} {r.total_sent:>8} {r.k_used:>4} {delta_str}")

    # Check degradation (negative = regression, positive = improvement)
    all_pass = True
    for r in results[1:]:
        delta = ((r.eps - baseline_eps) / baseline_eps * 100) if baseline_eps > 0 else 0
        if delta < -5:
            print(f"\n  ✗ FAIL: {r.config_name} shows {abs(delta):.1f}% EPS regression (> 5%)")
            all_pass = False
        elif delta >= 0:
            print(f"  ✓ {r.config_name}: {delta:+.1f}% (improvement — no regression)")
        else:
            print(f"  ✓ {r.config_name}: {delta:+.1f}% (within 5% threshold)")

    if all_pass:
        print(f"\n  ✓ ALL CONFIGURATIONS PASS — no EPS regression detected")
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
