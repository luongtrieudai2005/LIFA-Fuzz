"""
evaluation/rq1_accuracy.py
───────────────────────────
RQ1: Grammar Inference Accuracy — Precision, Recall, F1-Score.

Compares a ProtocolGrammar (inferred by LLM / DifferentialAnalyzer)
against the ground truth LIFA protocol structure.

Evaluation Methodology:
    For each ground truth field, we check whether the inferred grammar
    contains a field that overlaps at the correct offset range. We allow
    a tolerance of ±1 byte on each boundary to account for common
    off-by-one variations in LLM output.

    Metrics:
        - Precision = TP / (TP + FP)  — how many inferred fields are correct
        - Recall    = TP / (TP + FN)  — how many true fields were found
        - F1-Score  = harmonic mean of Precision and Recall

    A field is a True Positive if:
        1. Its offset range overlaps with a ground truth field
        2. The overlap covers at least 50% of the smaller field's span

Usage:
    # Evaluate a ProtocolGrammar:
    from evaluation.rq1_accuracy import evaluate_grammar_accuracy
    result = evaluate_grammar_accuracy(grammar)

    # Run full RQ1 experiment (Mock LLM → grammar → evaluate):
    python -m evaluation.rq1_accuracy
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensure project root is on path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from evaluation.ground_truth import (
    GroundTruthField,
    LIFA_GROUND_TRUTH,
    get_ground_truth_summary,
)
from shared.schemas import ProtocolGrammar, InferredField

RESULTS_DIR = Path(__file__).parent / "results"


# =============================================================================
# Field Matching
# =============================================================================


def _ranges_overlap(
    a_start: int, a_end: int,
    b_start: int, b_end: int,
) -> int:
    """Return the number of overlapping bytes between two ranges.

    Uses -1 to represent "extends to end of packet".
    """
    # Handle variable-length (-1 = open-ended)
    if a_end == -1 and b_end == -1:
        # Both variable → they overlap from max(start) onward
        return max(0, min(a_end if a_end != -1 else 1000,
                          b_end if b_end != -1 else 1000) - max(a_start, b_start))
    if a_end == -1:
        overlap_end = b_end
    elif b_end == -1:
        overlap_end = a_end
    else:
        overlap_end = min(a_end, b_end)

    overlap_start = max(a_start, b_start)
    return max(0, overlap_end - overlap_start)


def _field_span(f: Any) -> int:
    """Return the byte span of a field (offset_end - offset_start)."""
    end = f.offset_end if f.offset_end != -1 else 65535
    return max(1, end - f.offset_start)


def match_inferred_to_ground(
    inferred_fields: list[InferredField],
    ground_truth: list[GroundTruthField] = LIFA_GROUND_TRUTH,
    boundary_tolerance: int = 1,
    min_overlap_ratio: float = 0.5,
) -> dict[str, Any]:
    """Match inferred fields to ground truth fields.

    Returns a dict with:
        - matches: list of (inferred_idx, ground_idx) pairs
        - unmatched_inferred: indices of FP fields
        - unmatched_ground: indices of FN fields
        - field_details: per-field comparison details
    """
    matched_ground: set[int] = set()
    matched_inferred: set[int] = set()
    matches: list[tuple[int, int]] = []
    field_details: list[dict] = []

    for i, inf_field in enumerate(inferred_fields):
        best_j = -1
        best_overlap = 0

        for j, gt_field in enumerate(ground_truth):
            if j in matched_ground:
                continue

            # Check offset proximity with tolerance
            start_close = abs(inf_field.offset_start - gt_field.offset_start) <= boundary_tolerance

            # Check overlap
            overlap = _ranges_overlap(
                inf_field.offset_start,
                inf_field.offset_end if inf_field.offset_end != -1 else -1,
                gt_field.offset_start,
                gt_field.offset_end,
            )

            inf_span = _field_span(inf_field)
            gt_span = _field_span(gt_field)
            min_span = min(inf_span, gt_span)

            overlap_ratio = overlap / min_span if min_span > 0 else 0

            # Match requires: close start offset OR significant overlap
            if (start_close or overlap_ratio >= min_overlap_ratio) and overlap > best_overlap:
                best_j = j
                best_overlap = overlap

        if best_j >= 0:
            matched_ground.add(best_j)
            matched_inferred.add(i)
            matches.append((i, best_j))

            gt = ground_truth[best_j]
            field_details.append({
                "ground_truth": gt.name,
                "inferred": inf_field.name,
                "gt_offset": f"[{gt.offset_start},{gt.offset_end})",
                "inf_offset": f"[{inf_field.offset_start},{inf_field.offset_end})",
                "match": "TP",
                "offset_correct": inf_field.offset_start == gt.offset_start,
                "type_match": inf_field.field_type.value == gt.wire_type
                              or (gt.wire_type == "bytes" and inf_field.field_type.value in ("bytes", "string")),
                "strategy_match": inf_field.mutation_strategy.value == gt.semantic_role
                                  or (gt.semantic_role == "variable" and inf_field.mutation_strategy.value in ("random_bytes", "bit_flip")),
            })
        else:
            field_details.append({
                "ground_truth": None,
                "inferred": inf_field.name,
                "gt_offset": None,
                "inf_offset": f"[{inf_field.offset_start},{inf_field.offset_end})",
                "match": "FP",
                "offset_correct": False,
                "type_match": False,
                "strategy_match": False,
            })

    # Unmatched ground truth = False Negatives
    for j, gt in enumerate(ground_truth):
        if j not in matched_ground:
            field_details.append({
                "ground_truth": gt.name,
                "inferred": None,
                "gt_offset": f"[{gt.offset_start},{gt.offset_end})",
                "inf_offset": None,
                "match": "FN",
                "offset_correct": False,
                "type_match": False,
                "strategy_match": False,
            })

    return {
        "matches": matches,
        "unmatched_inferred": [i for i in range(len(inferred_fields)) if i not in matched_inferred],
        "unmatched_ground": [j for j in range(len(ground_truth)) if j not in matched_ground],
        "field_details": field_details,
    }


# =============================================================================
# Accuracy Metrics
# =============================================================================


@dataclass
class AccuracyResult:
    """RQ1 accuracy metrics for protocol grammar inference."""
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    false_positives: int
    false_negatives: int
    total_ground_fields: int
    total_inferred_fields: int
    field_details: list[dict] = field(default_factory=list)
    offset_accuracy: float = 0.0  # Fraction of TP fields with exact offset
    type_accuracy: float = 0.0    # Fraction of TP fields with correct type
    strategy_accuracy: float = 0.0  # Fraction of TP fields with correct strategy

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "total_ground_fields": self.total_ground_fields,
            "total_inferred_fields": self.total_inferred_fields,
            "offset_accuracy": round(self.offset_accuracy, 4),
            "type_accuracy": round(self.type_accuracy, 4),
            "strategy_accuracy": round(self.strategy_accuracy, 4),
            "field_details": self.field_details,
        }

    def __str__(self) -> str:
        return (
            f"Precision={self.precision:.2%}  "
            f"Recall={self.recall:.2%}  "
            f"F1={self.f1_score:.2%}  "
            f"(TP={self.true_positives} FP={self.false_positives} "
            f"FN={self.false_negatives})"
        )


def evaluate_grammar_accuracy(
    grammar: ProtocolGrammar,
    ground_truth: list[GroundTruthField] = LIFA_GROUND_TRUTH,
    boundary_tolerance: int = 1,
) -> AccuracyResult:
    """Evaluate a ProtocolGrammar against the ground truth.

    Args:
        grammar: The inferred protocol grammar from LLM/DifferentialAnalyzer.
        ground_truth: The true protocol fields (default: LIFA protocol).
        boundary_tolerance: Allowed offset mismatch in bytes.

    Returns:
        AccuracyResult with P/R/F1 and per-field details.
    """
    matching = match_inferred_to_ground(
        grammar.fields, ground_truth, boundary_tolerance
    )

    tp = len(matching["matches"])
    fp = len(matching["unmatched_inferred"])
    fn = len(matching["unmatched_ground"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Per-match accuracy
    tp_details = [d for d in matching["field_details"] if d["match"] == "TP"]
    offset_acc = sum(1 for d in tp_details if d["offset_correct"]) / len(tp_details) if tp_details else 0.0
    type_acc = sum(1 for d in tp_details if d["type_match"]) / len(tp_details) if tp_details else 0.0
    strat_acc = sum(1 for d in tp_details if d["strategy_match"]) / len(tp_details) if tp_details else 0.0

    return AccuracyResult(
        precision=precision,
        recall=recall,
        f1_score=f1,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        total_ground_fields=len(ground_truth),
        total_inferred_fields=len(grammar.fields),
        field_details=matching["field_details"],
        offset_accuracy=offset_acc,
        type_accuracy=type_acc,
        strategy_accuracy=strat_acc,
    )


# =============================================================================
# Experiment Runner
# =============================================================================


async def run_rq1_experiment(
    output_path: Optional[str] = None,
    use_mock: bool = True,
) -> AccuracyResult:
    """Run a full RQ1 experiment: infer grammar → evaluate accuracy.

    Args:
        output_path: Path to write results JSON. None = auto.
        use_mock: Use MOCK LLM mode for free testing.

    Returns:
        AccuracyResult with metrics.
    """
    if use_mock:
        os.environ["LLM_MODE"] = "MOCK"

    try:
        from slow_loop.llm_agent import LLMAgent
        from slow_loop.parser import TrafficParser

        # Generate sample traffic matching the LIFA protocol
        sample_packets = _generate_lifa_traffic()

        # Build prompt and infer grammar
        agent = LLMAgent(api_key="test")
        grammar = await agent.infer_protocol(sample_packets)

    finally:
        if use_mock:
            os.environ.pop("LLM_MODE", None)

    # Evaluate
    result = evaluate_grammar_accuracy(grammar)

    # Save results
    if output_path is None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = str(RESULTS_DIR / "rq1_accuracy.json")

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "MOCK" if use_mock else "REAL",
        "ground_truth": get_ground_truth_summary(),
        "inferred_grammar": {
            "protocol_name": grammar.protocol_name,
            "fields_count": len(grammar.fields),
            "confidence": grammar.confidence,
            "fields": [
                {
                    "name": f.name,
                    "offset": f"[{f.offset_start},{f.offset_end})",
                    "type": f.field_type.value,
                    "strategy": f.mutation_strategy.value,
                    "is_constant": f.is_constant,
                }
                for f in grammar.fields
            ],
        },
        "metrics": result.to_dict(),
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    return result


def _generate_lifa_traffic():
    """Generate sample TrafficRecords matching the LIFA protocol."""
    from shared.schemas import TrafficRecord, Direction

    magic = b"LIFA"
    records = []
    for i in range(8):
        if i % 2 == 0:
            # PING packet
            payload = f"SEQ{i:03d}".encode()
            pkt = magic + bytes([0x01, len(payload)]) + payload
        else:
            # PROCESS_DATA packet (safe payload, 8-15 bytes)
            data_len = 8 + (i % 8)
            payload = bytes(range(data_len))
            pkt = magic + bytes([0x02, len(payload)]) + payload

        records.append(TrafficRecord(
            direction=Direction.CLIENT_TO_SERVER,
            raw_data=pkt,
            is_mutated=False,
        ))
    return records


# =============================================================================
# CLI
# =============================================================================


if __name__ == "__main__":
    print("=" * 60)
    print("  RQ1: Protocol Grammar Inference Accuracy Evaluation")
    print("=" * 60)
    print(f"  Ground Truth: LIFA Binary Protocol ({len(LIFA_GROUND_TRUTH)} fields)")
    print(f"  Protocol: {get_ground_truth_summary()}")
    print()

    result = asyncio.run(run_rq1_experiment())

    print("  Results:")
    print(f"    Precision:  {result.precision:.2%}")
    print(f"    Recall:     {result.recall:.2%}")
    print(f"    F1-Score:   {result.f1_score:.2%}")
    print(f"    TP={result.true_positives}  FP={result.false_positives}  FN={result.false_negatives}")
    print(f"    Offset Accuracy:   {result.offset_accuracy:.2%}")
    print(f"    Type Accuracy:     {result.type_accuracy:.2%}")
    print(f"    Strategy Accuracy: {result.strategy_accuracy:.2%}")
    print()
    print("  Per-field details:")
    for d in result.field_details:
        match_type = d["match"]
        gt = d.get("ground_truth") or "(none)"
        inf = d.get("inferred") or "(none)"
        marker = {"TP": "✓", "FP": "✗", "FN": "✗"}[match_type]
        print(f"    {marker} {match_type}: GT={gt:<12} Inf={inf:<12} "
              f"offset={d.get('inf_offset') or d.get('gt_offset')}")
    print()
    print("=" * 60)
