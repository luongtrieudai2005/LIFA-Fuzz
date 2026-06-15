# LIFA-Fuzz

> **Live-traffic Inference & Asynchronous Fuzzing Framework** — A black-box fuzzer for custom/proprietary network protocols that infers protocol grammar AND state machine from live traffic using LLM + statistical analysis, without requiring RFCs, source code, or protocol specifications.

---

## What It Does

LIFA-Fuzz captures live traffic between a client and a target server, then:

1. **Infers protocol grammar** (field offsets, types, mutation strategies) using LLM + Shannon entropy / Pearson correlation / Kendall τ — **F1 = 1.0** verified on both LIFA (binary) and FTP (RFC 959, independent).
2. **Infers protocol state machine** using Veritas-inspired P-PSM (K-S test + PAM clustering + DFA construction) — pure statistical, black-box, no hardcoded keywords.
3. **Fuzzes stateful** — replays the captured session prefix (e.g. USER→PASS auth) on a single TCP connection, then mutates the target command post-auth. **98% auth rate** on LightFTP.
4. **Detects + confirms crashes** — Phase 2 confirmation replays prefix+target on a clean target to verify reproduction (reviewer can reproduce).

All without source code, RFCs, or protocol-specific knowledge in the core engine.

---

## Architecture

<img width="1516" height="1038" alt="image" src="https://github.com/user-attachments/assets/022f1808-1002-44a4-99f5-db7dbda727d5" />

```
┌──────────────────────────────────────────┐
│ Block 1: Sandbox (Firecracker MicroVM)   │
│ Target server (ASAN) + honest client     │
└──────────────────────┬───────────────────┘
                       │ traffic (JSONL)
                       ▼
┌──────────────────────────────────────────┐
│ Block 2: Fast Loop (asyncio, 50-70 EPS)  │
│                                          │
│  SeedFeeder -> FuzzTarget                │
│      |-- ProtocolModule (NullModule)     │
│      |-- MutationEngine                  │
│      |   |-- 15 generic operators        │
│      |   |-- Stateful replay (1 TCP)     │
│      |   |-- Greeting drain              │
│      |   +-- StateTracker (P-PSM)        │
│      +-- CrashMonitor + Phase 2          │
└──────────────────────┬───────────────────┘
                       │ traffic log
                       ▼
┌──────────────────────────────────────────┐
│ Block 3: Slow Loop (~1 inference/min)    │
│                                          │
│  DiffAnalyzer + StateMachineInferer      │
│      |                                   │
│      v                                   │
│  LLMAgent (grammar inference)            │
│      |                                   │
│      v                                   │
│  RulesOrchestrator -> SemanticRules      │
│  EWMA Controller -> adaptive_k.json      │
└──────────────────────────────────────────┘

IPC: file-based (JSON/JSONL), atomic rename-swap
```

### ProtocolModule: Black-Box Core + Opt-In Modules

The Fast Loop core contains **zero hardcoded protocol knowledge**. All protocol-specific logic lives in pluggable `ProtocolModule` subclasses:

- **`NullModule`** (default) — pure black-box: any reply = ACCEPTED, no framing, no state tracking. Relies on P-PSM (inferred) for state.
- **Protocol-specific modules** (opt-in, disclosed case-study) — status code parsing, framing, protocol state tracker, protocol mutation operators.

**For unknown protocols:** `NullModule` + inferred P-PSM = automatic state tracking without any protocol knowledge. This is the generality claim.

### Stateful Sequence Replay

LIFA-Fuzz captures real client traffic and groups packets by session ID into `SeedSequence` objects. The mutation engine:

1. Splits each sequence into **Prefix** (verbatim, establishes state) + **Target** (fuzzed) + **Suffix**.
2. Opens **one TCP connection**, drains the server greeting, replays the prefix, then sends the mutated target.
3. Reads and classifies the full response chain.

This solves the **stateful reachability problem**: the fuzzer authenticates and reaches post-auth code where vulnerabilities live. Without this, mutations only hit the greeting (pre-auth) and never trigger deep bugs.

---

## Evaluation Framework

### Research Questions

| RQ | Question | Metric | Status |
|----|----------|--------|--------|
| RQ1 | How precisely does LIFA-Fuzz infer protocol grammar? | P/R/F1 vs ground truth | **F1 = 1.0** (REAL LLM, LIFA + FTP) |
| RQ2 | Does the async architecture maintain throughput? | EPS over time | Pending re-run (old data invalid) |
| RQ3 | Does full fusion find crashes? | Cumulative crashes, TTC | Pending re-run (old data invalid) |

### Three Baselines

| Baseline | Mutator | Math Layer | LLM | Description |
|----------|---------|-----------|-----|-------------|
| **A** (Pure Random) | random | OFF | OFF | Brute-force baseline |
| **B** (Math-Only) | smart | ON | OFF | Bootstrap rules from DifferentialAnalyzer |
| **C** (Full Fusion) | smart | ON | ON | Complete pipeline (LLM + math + P-PSM) |

### Quick Start

```bash
# Prerequisites: Python 3.11+, KVM (for Firecracker), LLM API key
pip install -r requirements.txt
cp .env.example .env  # set OPENAI_API_KEY

# Build LightFTP rootfs (ASAN-instrumented, ~2 min)
bash scripts/build_rootfs_lightftp.sh

# Clean workspace (archives prior results, kills orphans)
python3 scripts/cleanup.py --force

# Run B,C baselines (4h each = 8h total)
LIFA_PROTOCOL_MODULE=ftp python -m evaluation.evaluation_runner \
    --baseline B,C --duration 14400 \
    --driver firecracker --target lightftp

# RQ1 grammar accuracy (no sandbox needed — LLM only)
python3 scripts/rq1_real.py --protocol ftp --self-consistent
```

### CLI Reference

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `--baseline` | `A`/`B`/`C`/`all`/`B,C` | `all` | Which baselines |
| `--duration` | int (seconds) | `300` | Per-baseline duration |
| `--driver` | `docker`/`firecracker` | `docker` | Sandbox backend |
| `--target` | `lifa`/`lightftp`/`lighttpd` | `lifa` | Target server |
| `--coverage` | flag | off | Measure gcov code coverage (slows EPS) |
| `--no-dashboard` | flag | off | Skip Streamlit dashboard |

---

## Key Components

| File | Role |
|------|------|
| `fast_loop/mutator.py` | Mutation engine: stateful replay, scheduler, greeting drain, BinaryMutator |
| `fast_loop/crash_monitor.py` | Crash detection + Phase 2 prefix+target confirmation |
| `fast_loop/binary_mutator.py` | 15 generic + 4 FTP mutation operators (BINARY_ONLY default) |
| `fast_loop/state_machine_tracker.py` | InferredStateTracker — generic P-PSM state tracking |
| `slow_loop/differential_analyzer.py` | Shannon entropy, Pearson, Kendall τ per byte offset |
| `slow_loop/state_machine_inferer.py` | Veritas P-PSM: K-S test, PAM clustering, DFA |
| `slow_loop/llm_agent.py` | LLM client (GLM-5-Turbo REAL), self-consistency |
| `slow_loop/rules_orchestrator.py` | Slow Loop pipeline: math → LLM → P-PSM → rules |
| `shared/protocol_module.py` | ProtocolModule interface + NullModule (black-box core) |
| `fast_loop/ftp_module.py` | FTPModule (disclosed case-study extension) |
| `sandbox/firecracker_driver.py` | Firecracker MicroVM sandbox (snapshot/restore) |
| `evaluation/rq1_accuracy.py` | F1 evaluator (negative offsets, custom ground truth) |

---

## Stateful Fuzzing Verification

Recent smoke test (2 min, baselines A/B/C on LightFTP/Firecracker):

```
SEQ chain examples (auth -> post-auth -> fuzzed command):
  [220, 331, 230, 215, 257, 200, 550, 550, 550, 501]  <- 10-state deep
  [220, 331, 230, 215, 257, 200, 501]                    <- 7-state
  [220, 331, 500]                                         <- auth failed

Auth rate:    98%  (98/100 chains reach logged-in state)
State depth:  83%  reach depth 5+ (deep protocol states)
Target:       65%  fuzz post-auth commands (idx 5-8)
Server:       57%  ACCEPTED mutated commands (deep processing)
```

---

## Project Status

| Component | Status |
|-----------|--------|
| Fast-Slow Loop async architecture | ✅ Operational |
| Firecracker MicroVM sandbox | ✅ Operational (snapshot/restore) |
| LLM grammar inference (RQ1) | ✅ F1=1.0 REAL (LIFA + FTP) |
| ProtocolModule abstraction | ✅ NullModule default (black-box core clean) |
| Stateful sequence replay | ✅ 98% auth rate, deep states reached |
| P-PSM state machine inference | ✅ Veritas-inspired, end-to-end verified |
| Phase 2 crash confirmation | ✅ Prefix+target replay |
| gcov code coverage infrastructure | ✅ Built (Docker variant); Firecracker extraction deferred |
| RQ2/RQ3 experimental data | ⚠️ Old data invalid (fuzzer was broken). Re-run needed. |

**772 tests passing.**

---

## Limitations (honest)

- **Jaccard position-invariant** — byte-frequency similarity can't distinguish commands with same argument bytes (USER/PASS may merge). Inherent to Veritas, documented.
- **No binary code coverage in Firecracker** — gcov↔snapshot-restore irreconcilable (snapshot discards counters). Coverage measured via Docker variant (decouple/replay deferred).
- **Old A/B/C results invalid** — measured with broken fuzzer (stuck at greeting, no auth). Must re-run with fixed pipeline.
- **0 crashes found so far** — pipeline newly fixed; overnight campaign needed.

---

## References

**State machine inference (core contribution):**
- **Veritas** — Wang, Y. et al. "Inferring Protocol State Machine from Network Traces: A Probabilistic Approach." 2011. (P-PSM inference — LIFA-Fuzz's Tầng 3)
- **ProtocolGPT** — Wei, H. et al. arXiv:2405.00393, 2024. (Contrast: white-box, needs source code)
- **Prospex** — Comparetti, P.M. et al. IEEE S&P, 2009. (Protocol spec extraction — needs binary trace)

**LLM for protocol analysis:**
- **SemFuzz** — Sun, Y. et al. WWW '26, 2026. (Semantics-aware fuzzing — needs RFC)
- **Pordanesh & Tan** — arXiv:2406.06637, 2024. (GPT-4 for binary reverse engineering)

**Protocol fuzzing & RE:**
- **NSFuzz** — Qin, S. et al. TOSEM, 2023. (State-aware fuzzing — needs source + instrumentation)
- **AFL** — Zalewski, M. 2017. / **AFL++** — 2025. / **libFuzzer** — LLVM, 2025. (Coverage-guided fuzzing baselines)
- **boofuzz** — jtpereyda, 2025. / **Peach** — 2020. / **SPIKE** — Aitel, D. 2005. (Grammar-aware fuzzing lineage)
- **Duchêne et al.** — "Protocol RE Using Shannon Entropy." IEEE TIFS, 2018. (Entropy-based field detection — justifies DifferentialAnalyzer)

**Infrastructure:**
- **Firecracker MicroVM** — AWS, 2025. https://firecracker-microvm.github.io/ (Sandbox isolation + snapshot/restore)

---

## License

MIT — Research & Educational Use.
