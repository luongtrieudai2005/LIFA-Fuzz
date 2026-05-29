"""
evaluation
──────────
Automated Academic Benchmarking & Metrics Suite for LIFA-Fuzz.

Research Questions:
    RQ1 (Accuracy):            How precisely does LIFA-Fuzz infer protocol grammar?
    RQ2 (Throughput):          Does the async architecture maintain high EPS?
    RQ3 (Vulnerability Discovery): Does full fusion find crashes faster?

Components:
    ground_truth         — Canonical LIFA protocol definition
    rq1_accuracy         — Precision/Recall/F1 grammar evaluation
    telemetry_collector  — Real-time metrics snapshot (10s JSONL)
    evaluation_runner    — 3-baseline experiment orchestrator
    plot_generator       — Paper-ready PNG plots from telemetry data
"""
