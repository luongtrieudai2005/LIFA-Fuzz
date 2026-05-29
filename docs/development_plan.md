# Development Plan

> Step-by-step implementation roadmap for LIFA-Fuzz.
> Use this as your daily checklist. Each phase builds on the previous one.

---

## Phase 1: Sandbox Setup (Week 1) — ✅ DONE

**Goal:** Working sandbox with clean abstraction layer.

### Checklist

- [x] **1.1** Create `shared/sandbox_abstraction.py` — `BaseSandbox` abstract class.
- [x] **1.2** Create `sandbox/docker_driver.py` — `DockerSandbox(BaseSandbox)`.
- [x] **1.3** Create `sandbox/target/Dockerfile` — compile vulnerable C server.
- [x] **1.4** Create `sandbox/target/vulnerable_server.c` — LIFA protocol with stack buffer overflow.
- [x] **1.5** Create `sandbox/client/client.py` — honest TCP client sending LIFA traffic.
- [x] **1.6** Create `sandbox/docker-compose.yml` — network + containers.
- [x] **1.7** Verify traffic flows end-to-end.
- [x] **1.8** Verify crash detection: kill server → Docker reports exit code.
- [x] **1.9** Verify `reset_state()`: crash → detect → restart → resume.

---

## Phase 2: Fast Loop — Interceptor & Mutation Engine (Week 2-3) — ✅ DONE

**Goal:** TCP proxy that captures traffic, mutates packets, and detects crashes.

### 2A: Interceptor

- [x] **2.1** Implement `fast_loop/interceptor.py` — asyncio TCP proxy.
- [x] **2.2** Add packet capture + JSONL traffic logging.
- [x] **2.3** Add `shared/logger.py` — structured async logging.
- [x] **2.4** Write `tests/test_interceptor.py`.

### 2B: Mutation Engine

- [x] **2.5** Implement `fast_loop/mutator.py` — baseline + rule-based mutations.
- [x] **2.6** Implement `fast_loop/mutation_operators.py` — 7 binary mutation operators.
- [x] **2.7** Implement `fast_loop/crash_monitor.py` — crash detection + auto-restart.
- [x] **2.8** Add rule watcher: poll for new rules from Slow Loop.
- [x] **2.9** Write `tests/test_mutator.py` + `tests/test_mutation_operators.py`.

---

## Phase 3: Slow Loop — Traffic Parsing & LLM Integration (Week 3-4) — ✅ DONE

**Goal:** Parse traffic logs, send to LLM, receive inferred protocol grammar.

### 3A: Traffic Parser

- [x] **3.1** Implement `slow_loop/parser.py` — read traffic log + group into sessions.
- [x] **3.2** Implement `format_for_llm()` — convert sessions to LLM-consumable payload.
- [x] **3.3** Write `tests/test_parser.py`.

### 3B: LLM Agent

- [x] **3.4** Implement `slow_loop/llm_agent.py` — litellm-based client with MOCK/REAL modes.
- [x] **3.5** Design expert system prompt for protocol reverse engineering.
- [x] **3.6** Implement `slow_loop/rule_generator.py` — grammar → SemanticRule conversion.
- [x] **3.7** Implement `slow_loop/rules_orchestrator.py` — dedup + sliding window + budget.
- [x] **3.8** Write `tests/test_llm_agent.py` + `tests/test_rules_orchestrator.py`.

---

## Phase 4: Feedback Loop & Polish (Week 5-6) — ✅ DONE

**Goal:** Close the loop — rules update Fast Loop in real-time.

- [x] **4.1** Wire Block 2 ↔ Block 3: Fast Loop reads Slow Loop rules.
- [x] **4.2** Hot-swap rules without restarting Fast Loop.
- [x] **4.3** End-to-end test: full cycle with MOCK LLM.
- [x] **4.4** Rule effectiveness tracking (`hit_count`, `crash_count`).
- [x] **4.5** EPS counter + structured stats logging.
- [x] **4.6** `config.yaml` with all parameters documented.
- [x] **4.7** Graceful shutdown (SIGINT handler).
- [x] **4.8** Write `tests/test_e2e_flow.py`.

---

## Phase 5: Live-Fire SIGSEGV Validation — ✅ DONE

**Goal:** Prove the full pipeline triggers a real crash on the vulnerable target.

- [x] **5.1** Build `sandbox/target/vulnerable_server.c` in Docker with `-fno-stack-protector`.
- [x] **5.2** Implement `fast_loop/client_process.py` — manage client as host subprocess with watchdog.
- [x] **5.3** Wire `main.py` to boot: Sandbox → Interceptor → Client → Mutator → Crash Monitor → Slow Loop.
- [x] **5.4** Run full pipeline in MOCK mode → confirmed SIGSEGV on target container.
- [x] **5.5** Crash artifacts saved to `./crashes/` directory.

**Result:** Pipeline successfully triggered live SIGSEGV using MOCK LLM mode.

---

## Phase 6: Neural-Mathematical Fusion Loop — ✅ DONE

**Goal:** Fuse the mathematical pre-processing layer (`DifferentialAnalyzer`) with the neural LLM layer (`LLMAgent`), and integrate `CrashManager` for crash deduplication and isolation.

### 6A: Missing Schemas

- [x] **6.1** Add `FieldRule` model to `shared/schemas.py` — lightweight bootstrap rule from analyzer.
- [x] **6.2** Add `CrashReport` model to `shared/schemas.py` — crash metadata for persistence.
- [x] **6.3** Update `shared/__init__.py` exports.

### 6B: Algorithm Files → Canonical Locations

- [x] **6.4** Copy `docs/differential_analyzer.py` → `slow_loop/differential_analyzer.py`.
- [x] **6.5** Copy `docs/crash_manager.py` → `shared/crash_manager.py`.

### 6C: LLM Agent — Math Hint Injection

- [x] **6.6** Add `math_hint` parameter to `LLMAgent.infer_protocol()`.
- [x] **6.7** Update `_build_prompt_from_input()` and `build_prompt()` to inject hint.
- [x] **6.8** Add `SYSTEM_PROMPT_FUSION_APPEND` — mathematical pre-analysis guidelines.
- [x] **6.9** Update `call_llm()` to use combined system prompt.

### 6D: Rules Orchestrator — Fusion + Fallback

- [x] **6.10** Integrate `DifferentialAnalyzer` into `run_cycle()`.
- [x] **6.11** Extract raw client bytes → run analysis → generate heatmap.
- [x] **6.12** Pass heatmap hint to LLM via `infer_protocol(payload, math_hint=...)`.
- [x] **6.13** Implement bootstrap fallback: if LLM fails, push `heatmap.to_field_rules()`.
- [x] **6.14** Add `_convert_field_rules()` helper: FieldRule → SemanticRule.
- [x] **6.15** Add `_strategy_to_rule_type()` mapping.
- [x] **6.16** Add `crash_manager` parameter + precision mode (k=1) for crash isolation.

### 6E: Slow Loop Entrypoint

- [x] **6.17** Wire `CrashManager` into `run_slow_loop.py`.
- [x] **6.18** Config-driven LLM mode (`mode: "REAL"` or `"MOCK"` in config.yaml).
- [x] **6.19** Log crash stats periodically.

### 6F: Tests

- [x] **6.20** Add math_hint tests to `tests/test_llm_agent.py` (8 tests).
- [x] **6.21** Add fusion + fallback + precision tests to `tests/test_rules_orchestrator.py` (6 tests).
- [x] **6.22** Create `tests/test_differential_analyzer.py` (23 tests).
- [x] **6.23** Create `tests/test_crash_manager.py` (18 tests).

**Result: 231 tests passed. Full neural-math fusion loop operational.**

---

## Phase 7: Automated Academic Benchmarking — ✅ DONE

**Goal:** Automated evaluation framework producing empirical data for RQ1, RQ2, RQ3 in the academic paper.

### 7A: Ground Truth & RQ1 Accuracy

- [x] **7.1** Create `evaluation/ground_truth.py` — LIFA protocol ground truth (4 fields: magic/opcode/length/payload).
- [x] **7.2** Create `evaluation/rq1_accuracy.py` — Precision/Recall/F1 evaluator with ±1 byte tolerance.
- [x] **7.3** Implement field matching algorithm (overlap-based with tolerance).
- [x] **7.4** Add `run_rq1_experiment()` — full RQ1 pipeline with MOCK LLM.
- [x] **7.5** CLI: `python -m evaluation.rq1_accuracy`.

### 7B: Telemetry Collection

- [x] **7.6** Create `evaluation/telemetry_collector.py` — real-time 10s JSONL snapshot.
- [x] **7.7** Metrics: EPS, crashes (total + unique), token usage, rules, precision mode.
- [x] **7.8** Add `generate_synthetic_telemetry()` for plot testing without Docker.
- [x] **7.9** Add `write_summary()` for aggregate session statistics.

### 7C: Evaluation Runner (3 Baselines)

- [x] **7.10** Create `evaluation/evaluation_runner.py` — orchestrates 3 baseline runs.
- [x] **7.11** Baseline A (Pure Random): `mode="random"`, math OFF, LLM OFF.
- [x] **7.12** Baseline B (Math-Only): `mode="smart"`, math ON, LLM OFF, bootstrap rules.
- [x] **7.13** Baseline C (Full Fusion): `mode="smart"`, math ON, LLM ON, complete pipeline.
- [x] **7.14** Per-baseline telemetry into `evaluation/results/{baseline}/telemetry.jsonl`.
- [x] **7.15** CLI: `python -m evaluation.evaluation_runner --duration 300`.

### 7D: Plot Generator (Paper-Ready PNGs)

- [x] **7.16** Create `evaluation/plot_generator.py` — matplotlib-based plot generation.
- [x] **7.17** Plot 1 (RQ2): EPS over Time — 3 baselines compared.
- [x] **7.18** Plot 2 (RQ3): Cumulative Unique Crashes over Time — time-to-first-crash annotated.
- [x] **7.19** Plot 3 (RQ1): Precision/Recall/F1 bar chart.
- [x] **7.20** CLI: `python -m evaluation.plot_generator [--synthetic]`.

### 7E: Tests

- [x] **7.21** Create `tests/test_evaluation.py` (19 tests).
- [x] **7.22** Ground truth validation (8 tests).
- [x] **7.23** RQ1 accuracy evaluation (6 tests).
- [x] **7.24** Telemetry collector (3 tests).
- [x] **7.25** Plot generator from synthetic data (1 integration test).
- [x] **7.26** RQ1 experiment integration (1 test).

**Result: 250 tests passed. Evaluation framework fully operational.**

---

## File Structure (Current)

```
LIFA-Fuzz/
├── config.yaml                        # Global configuration
├── main.py                            # Master orchestrator
├── run_slow_loop.py                   # Slow Loop daemon entrypoint
│
├── docs/
│   ├── architecture.md                # Architecture deep-dive
│   └── development_plan.md            # This file
│
├── shared/
│   ├── __init__.py
│   ├── schemas.py                     # Pydantic data contracts
│   ├── logger.py                      # Async-safe structured logging
│   ├── sandbox_abstraction.py         # BaseSandbox interface
│   └── crash_manager.py               # Two-level crash deduplication engine
│
├── fast_loop/
│   ├── interceptor.py                 # Async TCP proxy + capture
│   ├── mutator.py                     # Mutation engine (random + rule-based)
│   ├── mutation_operators.py          # 7 binary mutation operators
│   ├── crash_monitor.py               # Crash detection + auto-restart
│   └── client_process.py             # Client subprocess manager
│
├── slow_loop/
│   ├── parser.py                      # Traffic log parser
│   ├── llm_agent.py                   # LLM client (REAL/MOCK) + fusion prompts
│   ├── rule_generator.py              # Grammar → SemanticRule conversion
│   ├── rules_orchestrator.py          # Dedup + math fusion + bootstrap fallback
│   └── differential_analyzer.py       # Mathematical pre-processing layer
│
├── evaluation/
│   ├── __init__.py
│   ├── ground_truth.py                # LIFA protocol ground truth
│   ├── rq1_accuracy.py                # P/R/F1 accuracy evaluator
│   ├── telemetry_collector.py         # Real-time metrics snapshot
│   ├── evaluation_runner.py           # 3-baseline experiment runner
│   └── plot_generator.py              # Paper-ready PNG plot generation
│
├── sandbox/
│   ├── target/
│   │   ├── Dockerfile
│   │   └── vulnerable_server.c        # Deliberately vulnerable LIFA server
│   ├── client/
│   │   └── client.py                  # Honest TCP client
│   ├── docker_driver.py
│   ├── docker-compose.yml
│   └── firecracker_driver.py
│
├── tests/                             # 250 tests total
└── web_ui/                            # Streamlit dashboard
```

---

## Future Extensions

### MicroVM Migration

- [ ] **Firecracker Sandbox Driver** — `FirecrackerSandbox(BaseSandbox)`.
- [ ] **Snapshot/Restore** — VM memory snapshots for <10ms reset.
- [ ] **Performance benchmark** — compare EPS: Docker vs MicroVM.

### Other Extensions

- [ ] **Multi-protocol support** — multiple fuzz campaigns simultaneously.
- [ ] **Coverage-guided mode** — ASan/UBSan integration.
- [ ] **Protocol state machine** — LLM infers state transitions.
- [ ] **Cluster mode** — distributed Fast Loop instances.
- [ ] **AFL-style power scheduling** — allocate mutations by coverage.
