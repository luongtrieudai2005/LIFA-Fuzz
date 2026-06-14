# LIFA-Fuzz

> **Live-traffic Inference & Asynchronous Fuzzing Framework** — A black-box fuzzer for custom/proprietary network protocols that infers protocol semantics from live traffic using an LLM, without requiring RFCs or source code.

---

## Core Philosophy

LIFA-Fuzz is built on a **Fast-Slow Loop Asynchronous Architecture** that decouples high-speed fuzzing from deep protocol analysis, with a **pluggable sandbox backend** for maximum isolation:

| Loop | Speed | Role |
|------|-------|------|
| **Fast Loop** (Block 2) | 10,000+ EPS | Network interception, packet mutation, crash detection |
| **Slow Loop** (Block 3) | ~1 inference/min | Traffic parsing, LLM-powered grammar inference, rule generation |

| Sandbox Backend | `reset_state()` | Isolation | Phase |
|----------------|-----------------|-----------|-------|
| Docker (prototype) | ~200-500ms | Process-level (shared kernel) | Phase 1 |
| Firecracker MicroVM (production) | < 10ms | Kernel-level (isolated guest kernel) | Phase 4 |

The Fast Loop runs continuously at maximum speed, using the *current* rule set. Meanwhile, the Slow Loop asynchronously consumes traffic logs, infers protocol structure, and pushes updated **Semantic Rules** back to the Fast Loop — enabling intelligent, evolving fuzz campaigns.

---

## Architecture
<img width="1516" height="1038" alt="image" src="https://github.com/user-attachments/assets/022f1808-1002-44a4-99f5-db7dbda727d5" />

```mermaid
graph TB
    subgraph "Block 1: Sandbox"
        CLIENT["Client Container<br/>Sends legitimate traffic"]
        SERVER["Target Server Container<br/>Runs the proprietary protocol"]
    end

    subgraph "Block 2: Fast Loop"
        MITM["Interceptor (Proxy/MitM)<br/>Captures & mutates packets"]
        ENGINE["Mutation Engine<br/>Applies Semantic Rules"]
        MONITOR["Crash Monitor<br/>Detects panics/segfaults"]
        FAST_RULES["Active Rule Set<br/>Current mutation strategy"]
        TRAFFIC_LOG["Traffic Log Buffer<br/>Raw + mutated traffic"]
        MITM       -->|"Raw packets"|       TRAFFIC_LOG
        FAST_RULES --> ENGINE
        ENGINE     -->|"Mutated packets"|   MITM
        MONITOR    -.->|"Crash alerts"|     MITM
    end

    subgraph "Block 3: Neural-Mathematical Fusion"
        PARSER["Traffic Parser<br/>hex/pcap to JSON"]
        DIFF["DifferentialAnalyzer<br/>Shannon H, Pearson r, Kendall τ"]
        HEATMAP["HeatmapResult<br/>to_llm_hint() / to_field_rules()"]
        LLM["LLM Agent<br/>Infers protocol grammar"]
        SLOW_RULES["RulesOrchestrator<br/>Dedup + fusion + fallback"]
        RULEGEN["Rule Generator<br/>Outputs SemanticRules"]
        PARSER     -->|"Parsed traffic"|    DIFF
        DIFF       --> HEATMAP
        HEATMAP    -->|"math_hint"|         LLM
        HEATMAP    -->|"Bootstrap fallback"| SLOW_RULES
        PARSER     -->|"Raw samples"|       LLM
        LLM        -->|"Inferred grammar"|  SLOW_RULES
        SLOW_RULES --> RULEGEN
        RULEGEN    -->|"New/updated rules"| FAST_RULES
    end

    TRAFFIC_LOG -->|"Batch send"| PARSER

    subgraph "Evaluation Framework"
        TELEMETRY["TelemetryCollector<br/>Real-time 10s JSONL snapshots"]
        RQ1["RQ1 Accuracy<br/>P/R/F1 vs Ground Truth"]
        RUNNER["EvaluationRunner<br/>3 Baselines (A/B/C)"]
        PLOTS["PlotGenerator<br/>Paper-ready PNGs"]
        TELEMETRY --> RUNNER
        RQ1       --> PLOTS
        RUNNER    --> PLOTS
    end

    CLIENT    -->|"All traffic"|       MITM
    MITM      -->|"Forward / mutated"| SERVER
    SERVER    -->|"Responses"|         MITM
    MITM      -->|"Forward responses"| CLIENT

    style SERVER fill:#f9f,stroke:#333
    style LLM fill:#ff9,stroke:#333
    style FAST_RULES fill:#bbf,stroke:#333
    style DIFF fill:#bfb,stroke:#333
```

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Sandbox Setup (Docker isolation, BaseSandbox abstraction) | ✅ Done |
| Phase 2 | Fast Loop (Interceptor, Mutation Engine, Crash Monitor) | ✅ Done |
| Phase 3 | Slow Loop (Traffic Parser, LLM Agent, Rule Generator) | ✅ Done |
| Phase 4 | Feedback Loop & Polish (hot-swap rules, E2E tests) | ✅ Done |
| Phase 5 | Live-Fire SIGSEGV Validation (real crash on vulnerable target) | ✅ Done |
| Phase 6 | Neural-Mathematical Fusion (DifferentialAnalyzer + CrashManager) | ✅ Done |
| Phase 7 | Automated Academic Benchmarking (RQ1/RQ2/RQ3 evaluation) | ✅ Done |

**250 tests passing.** All 7 phases complete.

---

## Directory Structure

```
LIFA-Fuzz/
├── config.yaml                        # Global configuration
├── main.py                            # Master orchestrator (Block 1 + 2 + Slow Loop subprocess)
├── run_slow_loop.py                   # Slow Loop daemon entrypoint
│
├── sandbox/                           # Block 1: Sandbox backends
│   ├── target/
│   │   ├── Dockerfile                 #   Builds vulnerable LIFA server
│   │   └── vulnerable_server.c        #   Deliberately vulnerable C server
│   ├── client/
│   │   └── client.py                  #   Honest TCP client (LIFA protocol traffic)
│   ├── server/
│   │   └── server.py                  #   Python server variant
│   ├── docker_driver.py               #   DockerSandbox(BaseSandbox) — Phase 1 backend
│   ├── firecracker_driver.py          #   FirecrackerSandbox(BaseSandbox) — Phase 4 placeholder
│   └── docker-compose.yml             #   Orchestrates target + dashboard containers
│
├── fast_loop/                         # Block 2: High-speed fuzzing engine
│   ├── interceptor.py                 #   Async TCP proxy + packet capture
│   ├── mutator.py                     #   Mutation engine (random + rule-based)
│   ├── mutation_operators.py          #   7 binary mutation operators (overflow, bit-flip, etc.)
│   ├── crash_monitor.py               #   Crash detection + auto-restart via BaseSandbox
│   └── client_process.py              #   Client subprocess manager with watchdog
│
├── slow_loop/                         # Block 3: Neural-mathematical fusion
│   ├── parser.py                      #   Traffic log parser → interaction sessions
│   ├── llm_agent.py                   #   LLM client (REAL/MOCK modes) + fusion prompts
│   ├── rule_generator.py              #   ProtocolGrammar → SemanticRule conversion
│   ├── rules_orchestrator.py          #   Dedup + math fusion + bootstrap fallback pipeline
│   └── differential_analyzer.py       #   Shannon entropy, Pearson/Kendall per byte offset
│
├── shared/                            # Shared utilities & data models
│   ├── schemas.py                     #   Pydantic models (SemanticRule, TrafficRecord, etc.)
│   ├── sandbox_abstraction.py         #   BaseSandbox interface + driver registry
│   ├── crash_manager.py               #   Two-level crash dedup (SHA256 + structural)
│   └── logger.py                      #   Async-safe structured logging (console + JSON)
│
├── evaluation/                        # Automated academic benchmarking
│   ├── ground_truth.py                #   LIFA protocol ground truth (4 fields)
│   ├── rq1_accuracy.py                #   Precision/Recall/F1 evaluator with ±1 byte tolerance
│   ├── telemetry_collector.py         #   Real-time 10s JSONL metric snapshots
│   ├── evaluation_runner.py           #   3-baseline experiment orchestrator
│   └── plot_generator.py              #   Paper-ready PNG plots (matplotlib)
│
├── tests/                             # 250 pytest tests
│   ├── conftest.py                    #   Shared fixtures
│   ├── test_schemas.py
│   ├── test_interceptor.py
│   ├── test_mutator.py
│   ├── test_mutation_operators.py
│   ├── test_parser.py
│   ├── test_llm_agent.py
│   ├── test_rules_orchestrator.py
│   ├── test_differential_analyzer.py
│   ├── test_crash_manager.py
│   ├── test_evaluation.py
│   └── test_e2e_flow.py
│
├── web_ui/                            # Streamlit monitoring dashboard
│   ├── dashboard.py
│   └── requirements.txt
│
├── crashes/                           # Crash artifacts (PoC packets + reports)
├── docs/
│   ├── architecture.md                #   Architecture deep-dive & data contracts
│   └── development_plan.md            #   Phase-by-phase implementation roadmap
├── requirements.txt                   # Python dependencies
└── README.md                          # This file
```

---

## Setup & Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for sandbox)
- An LLM API key (OpenAI, Anthropic, or any litellm-supported provider)

### Installation

```bash
# Clone the repo
git clone https://github.com/<your-org>/LIFA-Fuzz.git
cd LIFA-Fuzz

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Quick Start (Full Pipeline)

```bash
# 1. Start the sandbox — target server container
docker compose -f sandbox/docker-compose.yml up --build

# 2. Launch the full pipeline (Sandbox → Interceptor → Client → Mutator → Crash Monitor → Slow Loop)
python main.py

#   Or run the Slow Loop separately for development:
python run_slow_loop.py
```

### Configuration

Edit `config.yaml` to set:

- **Sandbox ports** (client → proxy → server)
- **LLM provider & model** (via litellm), with MOCK mode for testing without API keys
- **Mutation strategy** (`random` for pure bit-flip, `smart` for rule-based)
- **Differential analyzer** (entropy thresholds, min packets for analysis)
- **Traffic log rotation & buffer size**
- **Crash detection thresholds** and auto-restart behavior
- **Rule generation** (confidence thresholds, max active rules)

---

## How It Works (End-to-End Flow)

1. **Block 1** — The Client sends normal LIFA protocol traffic toward the Target Server.
2. **Block 2 — Interceptor** sits between them as a transparent proxy, capturing every packet into a traffic log buffer.
3. **Block 2 — Mutation Engine** reads the active rule set and creates mutated variants of captured packets using 7 binary mutation operators (buffer overflow, integer overflow, bit-flip, boundary violation, format string, omission, random byte injection).
4. **Block 2 — Crash Monitor** watches the Target Server container. Any crash (SIGSEGV, SIGABRT, unhandled exception) is logged with the offending packet, deduplicated by `CrashManager`, and the target is auto-restarted.
5. **Block 3 — Parser** periodically reads the traffic log, converting raw bytes into structured interaction sessions.
6. **Block 3 — DifferentialAnalyzer** performs mathematical pre-processing on the parsed traffic — computing Shannon entropy, Pearson correlation, and Kendall τ per byte offset — producing a statistical heatmap in <1ms.
7. **Block 3 — LLM Agent** receives both the parsed traffic and the heatmap hint, asking the LLM to focus on semantic naming rather than raw byte discovery (70% token reduction).
8. **Block 3 — RulesOrchestrator** converts the LLM's grammar inference into `SemanticRule` objects. If the LLM call fails, bootstrap rules from the DifferentialAnalyzer's heatmap are used instead — **the fuzzer never starves**.
9. **The cycle repeats** — each iteration the Fast Loop gets smarter about where and how to mutate.

---

## Neural-Mathematical Fusion

The key innovation of LIFA-Fuzz is fusing a **mathematical pre-processing layer** with **neural LLM inference**:

```
Raw Client Packets
        │
        ▼
┌──────────────────────────┐
│ DifferentialAnalyzer     │  ← Pure math, <1ms, stateless
│(Shannon H,  Pearson r,   │
│  Kendall τ per offset)   │
│                          │
│ Output: HeatmapResult    │
│  ├─ to_llm_hint()        │──▶ Injected into LLM prompt
│  └─ to_field_rules()     │──▶ Bootstrap rules if LLM fails
└──────────────────────────┘
        │
        ▼ math_hint parameter
┌──────────────────────────┐
│ LLM Agent                │  ← Neural layer, ~60s per inference
│ infer_protocol(          │
│   traffic_input,         │
│   math_hint=heatmap      │  ← Fusion: math + neural
│ )                        │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│ RulesOrchestrator        │
│                          │
│ LLM success → Grammar    │
│ LLM failure → Bootstrap  │──▶ Fuzzer never starves
└──────────────────────────┘
```

### Crash Isolation (Precision Mode)

When `CrashManager` detects unique crashes, the orchestrator enters **precision mode (k=1)**: the Fast Loop reduces to single-field-at-a-time mutations for precise attribution of which field triggered the crash.

---

## Evaluation Framework

LIFA-Fuzz includes automated academic benchmarking for three research questions:

| RQ | Question | Metric |
|----|----------|--------|
| RQ1 | How precisely does LIFA-Fuzz infer protocol grammar? | Precision, Recall, F1-Score vs ground truth |
| RQ2 | Does the async architecture maintain high throughput? | EPS over time across 3 baselines |
| RQ3 | Does full fusion find crashes faster and discover more? | Cumulative unique crashes, time-to-first-crash |

### Three Baseline Configurations

| Baseline | Mutator | Math Layer | LLM | Expected Behavior |
|----------|---------|-----------|-----|-------------------|
| **A** (Pure Random) | `random` | OFF | OFF | Brute-force fuzzing, late crash discovery |
| **B** (Math-Only) | `smart` | ON | OFF | Bootstrap rules from analyzer, earlier crashes |
| **C** (Full Fusion) | `smart` | ON | ON | Complete pipeline, fastest crash discovery |

### Reproducing the Experiments

The `evaluation_runner` is a single command that runs the full A→B→C benchmark with custom duration, sandbox backend, and target. Below is the complete, copy-paste-able path from a fresh checkout to reproduced results.

#### 1. One-time setup

```bash
# Firecracker requires hardware virtualization (KVM). Verify on Linux/WSL2:
[ -e /dev/kvm ] && echo "KVM OK" || echo "KVM missing — enable nested virtualization"

# Build the LightFTP rootfs (compiles LightFTP with ASAN, packs an ext4 image).
# Produces sandbox/firecracker_env/rootfs_lightftp.ext4
bash scripts/build_rootfs_lightftp.sh

# Baseline C needs an LLM API key. Put it in .env (see .env.example):
#   OPENAI_API_KEY=<your key>          # Z.ai / OpenAI-compatible
cp .env.example .env && $EDITOR .env
```

#### 2. Prep the workspace (before each campaign)

```bash
# Archives prior results, kills orphaned Firecracker/Docker resources,
# purges stray core dumps, and clears shared state. Always run first so
# each campaign starts from a clean, known-good baseline.
python3 scripts/cleanup.py --force
```

#### 3. Run the benchmark

```bash
# Canonical command — run all three baselines, 600s each, on LightFTP/Firecracker
python -m evaluation.evaluation_runner \
    --duration 600 \
    --baseline all \
    --driver firecracker \
    --target lightftp
```

- Baselines run **sequentially** (A → 10s gap → B → C). Total wall time ≈ `duration × 3`.
- The Streamlit dashboard auto-starts at **http://localhost:8501** (live EPS, crashes, LLM insights, eval progress). Disable with `--no-dashboard`.
- Telemetry is snapshotted every 10s into `evaluation/results/<baseline>/telemetry.jsonl`.

#### 4. CLI reference

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `--duration` | int (seconds) | `300` | Duration **per baseline** |
| `--baseline` | `A` / `B` / `C` / `all` | `all` | Which baseline(s) to run |
| `--driver` | `docker` / `firecracker` | `docker` | Sandbox backend (use `firecracker` for production) |
| `--target` | `lifa` / `lighttpd` / `lightftp` | `lifa` | Target server (use `lightftp` for the real FTP target) |
| `--no-dashboard` | flag | off | Skip auto-starting the dashboard |
| `--dashboard-port` | int | `8501` | Dashboard port |

> Note: the CLI defaults (`docker`, `lifa`) suit the original dummy target. **For the real experiments reported in the paper, always pass `--driver firecracker --target lightftp`.**

#### 5. Common variants

```bash
# Quick smoke test — single baseline, 60s, Docker (no KVM needed)
python -m evaluation.evaluation_runner --baseline A --duration 60 --driver docker

# RQ1 grammar-inference accuracy — no sandbox/VM required
python -m evaluation.rq1_accuracy

# Generate paper-ready plots from the latest campaign results
python -m evaluation.plot_generator

# Quick core-dump sweep between runs (does not touch results/state)
python3 scripts/cleanup.py --cores-only
```

### Generated Outputs

| Output | Path | Research Question |
|--------|------|-------------------|
| EPS Over Time | `evaluation/plots/rq2_eps_over_time.png` | RQ2: Throughput |
| Cumulative Crashes | `evaluation/plots/rq3_cumulative_crashes.png` | RQ3: Vulnerability discovery |
| Accuracy Bars | `evaluation/plots/rq1_accuracy_bars.png` | RQ1: Grammar inference |
| Telemetry Snapshots | `evaluation/results/{baseline}/telemetry.jsonl` | All RQs |
| Side-by-side Summary | `evaluation/results/comparison.json` | All RQs |
| Archived Campaigns | `evaluation/archive/<target>_<driver>_<ts>/` | History |

---

## Research Context

LIFA-Fuzz is a research project exploring whether LLMs can effectively replace human protocol reverse-engineering in fuzzing campaigns. Key research questions:

- **RQ1:** Can an LLM infer enough protocol structure from traffic alone to enable *effective* structural fuzzing? (Measured by Precision/Recall/F1 against ground truth)
- **RQ2:** What is the optimal cadence for rule updates, and can the async architecture maintain high throughput? (Measured by EPS over time)
- **RQ3:** Does the full neural-mathematical fusion find crashes faster and discover more unique crashes? (Measured by cumulative crashes and time-to-first-crash)

---

## Future Extensions

- [ ] **Firecracker MicroVM driver** — `FirecrackerSandbox(BaseSandbox)` with snapshot/restore for <10ms reset
- [ ] **Multi-protocol support** — multiple fuzz campaigns simultaneously
- [ ] **Coverage-guided mode** — ASan/UBSan integration
- [ ] **Protocol state machine** — LLM infers state transitions
- [ ] **Cluster mode** — distributed Fast Loop instances
- [ ] **AFL-style power scheduling** — allocate mutations by coverage

---

## License

MIT — Research & Educational Use.
