"""
tests/test_evaluation.py
─────────────────────────
Unit tests for the Phase 7 Evaluation Framework.

Tests cover:
    - Ground truth definition validation
    - RQ1 accuracy evaluation (P/R/F1)
    - Telemetry collector (JSONL output)
    - Plot generator (synthetic data → PNG)
"""

import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Ensure project root on path
import sys
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from evaluation.ground_truth import (
    LIFA_GROUND_TRUTH,
    LIFA_MAGIC_HEX,
    LIFA_HEADER_SIZE,
    get_ground_truth_summary,
)
from evaluation.rq1_accuracy import (
    evaluate_grammar_accuracy,
    match_inferred_to_ground,
    AccuracyResult,
)
from evaluation.telemetry_collector import (
    TelemetryCollector,
    generate_synthetic_telemetry,
)
from shared.schemas import (
    InferredField,
    ProtocolGrammar,
    FieldType,
    MutationStrategy,
    Direction,
    TrafficRecord,
)


# =============================================================================
# Ground Truth Tests
# =============================================================================


class TestGroundTruth:
    """Tests for the LIFA protocol ground truth definition."""

    def test_has_5_fields(self):
        """Ground truth defines exactly 5 protocol fields (v2: +version)."""
        assert len(LIFA_GROUND_TRUTH) == 5

    def test_field_names(self):
        """Field names match the vulnerable server v2 protocol."""
        names = [f.name for f in LIFA_GROUND_TRUTH]
        assert names == ["magic", "version", "opcode", "length", "payload"]

    def test_magic_is_static(self):
        """Magic field is marked as static with correct hex value."""
        magic = LIFA_GROUND_TRUTH[0]
        assert magic.semantic_role == "static"
        assert magic.static_hex == LIFA_MAGIC_HEX
        assert magic.offset_start == 0
        assert magic.offset_end == 4

    def test_version_is_static(self):
        """Version field (v2) at offset [4,5), static 0x01."""
        version = LIFA_GROUND_TRUTH[1]
        assert version.semantic_role == "static"
        assert version.offset_start == 4
        assert version.offset_end == 5
        assert version.wire_type == "uint8"
        assert version.static_hex == "01"

    def test_opcode_is_enum(self):
        """Opcode field at [5,6) with 4 valid values (v2 opcodes)."""
        opcode = LIFA_GROUND_TRUTH[2]
        assert opcode.semantic_role == "enum"
        assert opcode.offset_start == 5
        assert opcode.offset_end == 6
        assert 0x01 in opcode.valid_values
        assert 0x02 in opcode.valid_values
        assert 0x03 in opcode.valid_values
        assert 0x04 in opcode.valid_values

    def test_length_field(self):
        """Length field at [6,8), uint16_le (v2 widened length)."""
        length = LIFA_GROUND_TRUTH[3]
        assert length.semantic_role == "length"
        assert length.offset_start == 6
        assert length.offset_end == 8
        assert length.wire_type == "uint16_le"

    def test_payload_is_variable(self):
        """Payload field extends to end of packet (-1), starting at byte 8."""
        payload = LIFA_GROUND_TRUTH[4]
        assert payload.semantic_role == "variable"
        assert payload.offset_start == 8
        assert payload.offset_end == -1
        assert payload.length == -1

    def test_header_size(self):
        """Header size is 8 bytes (magic + version + opcode + length_le16)."""
        assert LIFA_HEADER_SIZE == 8

    def test_get_summary(self):
        """get_ground_truth_summary() returns a valid dict."""
        summary = get_ground_truth_summary()
        assert summary["protocol"] == "LIFA Binary Protocol"
        assert len(summary["fields"]) == 5
        assert "vulnerability" in summary


# =============================================================================
# RQ1 Accuracy Tests
# =============================================================================


class TestRQ1Accuracy:
    """Tests for the RQ1 accuracy evaluator."""

    def _make_grammar(self, fields: list[dict]) -> ProtocolGrammar:
        """Helper: create a ProtocolGrammar from field dicts."""
        inferred_fields = []
        for fd in fields:
            inferred_fields.append(InferredField(
                name=fd["name"],
                offset_start=fd["offset_start"],
                offset_end=fd["offset_end"],
                field_type=FieldType(fd.get("field_type", "bytes")),
                mutation_strategy=MutationStrategy(fd.get("strategy", "random_bytes")),
                is_constant=fd.get("is_constant", False),
            ))
        return ProtocolGrammar(
            protocol_name="test",
            fields=inferred_fields,
            confidence=0.8,
        )

    def test_perfect_match(self):
        """Perfect grammar inference → P=1.0, R=1.0, F1=1.0."""
        grammar = self._make_grammar([
            {"name": "magic",   "offset_start": 0, "offset_end": 4,
             "field_type": "bytes", "strategy": "static", "is_constant": True},
            {"name": "version", "offset_start": 4, "offset_end": 5,
             "field_type": "uint8", "strategy": "static", "is_constant": True},
            {"name": "opcode",  "offset_start": 5, "offset_end": 6,
             "field_type": "uint8", "strategy": "dictionary"},
            {"name": "length",  "offset_start": 6, "offset_end": 8,
             "field_type": "uint16_le", "strategy": "boundary_values"},
            {"name": "payload", "offset_start": 8, "offset_end": -1,
             "field_type": "bytes", "strategy": "random_bytes"},
        ])

        result = evaluate_grammar_accuracy(grammar)
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1_score == 1.0
        assert result.true_positives == 5
        assert result.false_positives == 0
        assert result.false_negatives == 0

    def test_missing_field(self):
        """Missing the length field → lower recall."""
        grammar = self._make_grammar([
            {"name": "magic",   "offset_start": 0, "offset_end": 4, "strategy": "static"},
            {"name": "version", "offset_start": 4, "offset_end": 5, "strategy": "static"},
            {"name": "opcode",  "offset_start": 5, "offset_end": 6, "strategy": "dictionary"},
            {"name": "payload", "offset_start": 8, "offset_end": -1, "strategy": "random_bytes"},
        ])

        result = evaluate_grammar_accuracy(grammar)
        assert result.true_positives == 4
        assert result.false_negatives == 1  # Missing length field
        assert result.recall == 0.8

    def test_extra_field(self):
        """Extra inferred field → lower precision."""
        grammar = self._make_grammar([
            {"name": "magic",     "offset_start": 0,  "offset_end": 4,  "strategy": "static"},
            {"name": "version",   "offset_start": 4,  "offset_end": 5,  "strategy": "static"},
            {"name": "opcode",    "offset_start": 5,  "offset_end": 6,  "strategy": "dictionary"},
            {"name": "length",    "offset_start": 6,  "offset_end": 8,  "strategy": "boundary_values"},
            {"name": "payload",   "offset_start": 8,  "offset_end": -1, "strategy": "random_bytes"},
            {"name": "checksum",  "offset_start": 20, "offset_end": 24, "strategy": "calculated"},
        ])

        result = evaluate_grammar_accuracy(grammar)
        assert result.false_positives == 1  # Extra checksum field
        assert result.precision < 1.0

    def test_offset_tolerance(self):
        """Fields within ±1 byte tolerance still match."""
        grammar = self._make_grammar([
            {"name": "magic",  "offset_start": 0, "offset_end": 4, "strategy": "static"},
            {"name": "version","offset_start": 4, "offset_end": 5, "strategy": "static"},
            {"name": "opcode", "offset_start": 6, "offset_end": 7, "strategy": "dictionary"},  # off by 1
            {"name": "length", "offset_start": 6, "offset_end": 8, "strategy": "boundary_values"},
        ])

        result = evaluate_grammar_accuracy(grammar, boundary_tolerance=1)
        # With tolerance=1, opcode at [6,7) should still match ground truth opcode at [5,6)
        assert result.true_positives >= 3

    def test_no_fields_at_all(self):
        """Empty grammar → 0 TP, all FN."""
        grammar = ProtocolGrammar(protocol_name="empty", fields=[], confidence=0.0)
        result = evaluate_grammar_accuracy(grammar)
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.true_positives == 0
        assert result.false_negatives == 5

    def test_result_to_dict(self):
        """AccuracyResult serializes cleanly."""
        grammar = self._make_grammar([
            {"name": "magic", "offset_start": 0, "offset_end": 4, "strategy": "static"},
        ])
        result = evaluate_grammar_accuracy(grammar)
        d = result.to_dict()
        assert "precision" in d
        assert "f1_score" in d
        assert "field_details" in d
        json.dumps(d)  # Should not raise


# =============================================================================
# Telemetry Collector Tests
# =============================================================================


class TestTelemetryCollector:
    """Tests for the telemetry collector."""

    @pytest.mark.asyncio
    async def test_collector_writes_jsonl(self, tmp_path):
        """Collector writes snapshot JSONL lines."""
        output = tmp_path / "telemetry.jsonl"

        # Mock components
        interceptor = MagicMock()
        interceptor.total_captured = 100
        interceptor.total_injected = 50

        mutator = MagicMock()
        mutator.coverage_summary = {
            "total_mutations": 50,
            "total_packets": 20,
            "total_kills": 0,
            "unique_offsets_fuzzed": 15,
            "active_rules": 3,
        }

        crash_manager = MagicMock()
        crash_stats = MagicMock()
        crash_stats.total_hits = 2
        crash_stats.unique_crashes = 1
        crash_stats.dedup_ratio = 0.5
        crash_manager.get_statistics = AsyncMock(return_value=crash_stats)

        collector = TelemetryCollector(
            output_path=str(output),
            baseline_label="test",
            snapshot_interval_s=0.3,
        )

        # Wire up components manually and write snapshots directly
        collector._interceptor = interceptor
        collector._mutator = mutator
        collector._crash_manager = crash_manager
        collector._start_time = asyncio.get_event_loop().time()
        collector._last_snapshot_time = collector._start_time
        collector._last_injected = 0

        # Write 3 snapshots
        await collector._write_snapshot()
        interceptor.total_injected = 150  # Simulate traffic
        await asyncio.sleep(0.01)
        await collector._write_snapshot()
        interceptor.total_injected = 300
        await asyncio.sleep(0.01)
        await collector._write_snapshot(final=True)

        assert output.exists()
        content = output.read_text().strip()
        assert len(content) > 0, "Telemetry file is empty"
        lines = [l for l in content.split("\n") if l.strip()]
        assert len(lines) == 3
        for line in lines:
            data = json.loads(line)
            assert "elapsed_s" in data
            assert "eps" in data
            assert "baseline" in data
            assert data["baseline"] == "test"

    @pytest.mark.asyncio
    async def test_write_summary(self, tmp_path):
        """write_summary() produces aggregate stats."""
        output = tmp_path / "telemetry.jsonl"
        # Write some synthetic data
        with open(output, "w") as f:
            for t in [10, 20, 30]:
                f.write(json.dumps({
                    "elapsed_s": t, "eps": 400 + t, "baseline": "test",
                    "unique_crashes": 0, "total_crashes": 0,
                }) + "\n")

        collector = TelemetryCollector(
            output_path=str(output), baseline_label="test",
        )
        summary = await collector.write_summary()

        assert summary["baseline"] == "test"
        assert summary["total_snapshots"] == 3
        assert "avg_eps" in summary

    def test_generate_synthetic_telemetry(self, tmp_path):
        """Synthetic telemetry generator creates valid JSONL."""
        output = str(tmp_path / "synth.jsonl")
        generate_synthetic_telemetry(
            output_path=output,
            baseline="A",
            duration_s=60,
            interval_s=10,
            eps_base=400,
            crash_start_s=30,
            total_unique_crashes=2,
        )

        assert Path(output).exists()
        with open(output) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == 6  # 60s / 10s = 6 snapshots
        for line in lines:
            data = json.loads(line)
            assert data["baseline"] == "A"
            assert "eps" in data


# =============================================================================
# Plot Generator Tests
# =============================================================================


class TestPlotGenerator:
    """Tests for plot generation."""

    def test_plots_from_synthetic(self, tmp_path):
        """Plot generator creates PNG files from synthetic data."""
        from evaluation.plot_generator import (
            plot_eps_over_time,
            plot_cumulative_crashes,
            plot_accuracy_bars,
            load_all_baselines,
        )
        from evaluation import plot_generator

        # Generate synthetic data in tmp results dir
        synth_dir = tmp_path / "results"
        for baseline_id, dir_name in [("A", "baseline_A_random"), ("B", "baseline_B_math"), ("C", "baseline_C_full")]:
            bd = synth_dir / dir_name
            bd.mkdir(parents=True)
            generate_synthetic_telemetry(
                output_path=str(bd / "telemetry.jsonl"),
                baseline=baseline_id,
                duration_s=60,
                eps_base=[350, 420, 400][["A", "B", "C"].index(baseline_id)],
                crash_start_s=[40, 20, 10][["A", "B", "C"].index(baseline_id)],
                total_unique_crashes=[1, 2, 4][["A", "B", "C"].index(baseline_id)],
            )

        # Override results dir temporarily
        orig_results = plot_generator.RESULTS_DIR
        plot_generator.RESULTS_DIR = synth_dir
        plots_dir = tmp_path / "plots"
        plots_dir.mkdir()

        try:
            data = load_all_baselines()
            assert len(data) == 3

            p1 = plot_eps_over_time(data, output_path=str(plots_dir / "rq2.png"))
            assert Path(p1).exists()
            assert Path(p1).stat().st_size > 1000  # Non-trivial PNG

            p2 = plot_cumulative_crashes(data, output_path=str(plots_dir / "rq3.png"))
            assert Path(p2).exists()

            p3 = plot_accuracy_bars(output_path=str(plots_dir / "rq1.png"))
            assert Path(p3).exists()

        finally:
            plot_generator.RESULTS_DIR = orig_results


# =============================================================================
# RQ1 Experiment Integration Test
# =============================================================================


class TestRQ1Experiment:
    """Integration test: full RQ1 experiment with MOCK LLM."""

    @pytest.mark.asyncio
    async def test_run_rq1_experiment(self):
        """run_rq1_experiment() produces accuracy metrics."""
        from evaluation.rq1_accuracy import run_rq1_experiment

        os.environ["LLM_MODE"] = "MOCK"
        try:
            result = await run_rq1_experiment()
            assert isinstance(result, AccuracyResult)
            assert 0 <= result.precision <= 1.0
            assert 0 <= result.recall <= 1.0
            assert 0 <= result.f1_score <= 1.0
        finally:
            os.environ.pop("LLM_MODE", None)
