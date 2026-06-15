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
┌─────────────────────────────────────────────────────────────┐
│ Block 1: Sandbox (Firecracker MicroVM)                      │
│   LightFTP (ASAN-instrumented) + FTP Client                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ captured traffic (JSONL)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Block 2: Fast Loop (asyncio, ~50-70 EPS stateful)           │
│                                                               │
│  SeedFeeder ──▶ FuzzTarget ⟨Prefix, Target, Suffix⟩         │
│       │                 │                                      │
│  ProtocolModule     MutationEngine                             │
│  (NullModule =      ├─ 15 generic operators (BINARY_ONLY)    │
│   pure black-box,   ├─ 4 FTP operators (FTPModule, opt-in)   │
│   or FTPModule =    ├─ Stateful sequence replay (1 TCP conn) │
│   case-study)       ├─ Greeting drain (aligns responses)     │
│                      └─ StateTracker (InferredStateTracker    │
│                         or FTPStateTracker)                   │
│                                                               │
│  CrashMonitor ── CrashManager (SHA256 + structural dedup)    │
│       └── Phase 2: replay prefix+target on clean target      │
└──────────────────────────┬──────────────────────────────────┘
                           │ traffic log (JSONL)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Block 3: Slow Loop (separate process, ~1 inference/min)      │
│                                                               │
│  DifferentialAnalyzer    StateMachineInferer                  │
│  (Shannon H, Pearson r,  (Veritas P-PSM:                     │
│   Kendall τ per offset)   K-S filter + PAM + DFA)            │
│       │                        │                              │
│       ▼                        ▼                              │
│  LLMAgent ←──── math_hint + state_hint ──┘                   │
│  (GLM-5-Turbo REAL,                                           │
│   self-consistency N=5)                                       │
│       │                                                        │
│       ▼                                                        │
│  RulesOrchestrator ──▶ SemanticRules ──▶ Fast Loop           │
│                                                               │
│  EWMA Controller ──▶ adaptive_k.json ──▶ Fast Loop           │
└─────────────────────────────────────────────────────────────┘

IPC: file-based (JSON/JSONL), atomic rename-swap, zero blocking
```

### ProtocolModule: Black-Box Core + Opt-In Modules

The Fast Loop core contains **zero hardcoded protocol knowledge**. All protocol-specific logic (FTP status codes, CRLF framing, command extraction) lives in pluggable `ProtocolModule` subclasses:

- **`NullModule`** (default) — pure black-box: any reply = ACCEPTED, no framing, no state tracking. Relies on P-PSM (inferred) for state.
- **`FTPModule`** (opt-in, disclosed case-study) — FTP status code parsing, CRLF enforcement, FTP state tracker, 4 FTP mutation operators.

**For unknown protocols:** `NullModule` + inferred P-PSM = automatic state tracking without any protocol knowledge. This is the generality claim.

### Stateful Sequence Replay

LIFA-Fuzz captures real client traffic (e.g. FTP USER→PASS→SYST→...) and groups packets by session ID into `SeedSequence` objects. The mutation engine:

1. Splits each sequence into **Prefix** (verbatim, establishes state) + **Target** (fuzzed) + **Suffix**.
2. Opens **one TCP connection**, drains the server greeting, replays the prefix, then sends the mutated target.
3. Reads and classifies the full response chain `[220, 331, 230, 215, 257, 200, 501]`.

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
SEQ chain examples (auth → post-auth → fuzzed command):
  [220, 331, 230, 215, 257, 200, 550, 550, 550, 501]  ← 10-state deep
  [220, 331, 230, 215, 257, 200, 501]                    ← 7-state
  [220, 331, 500]                                         ← auth failed

Auth rate:    98%  (98/100 chains reach 230 = logged in)
State depth:  83%  reach depth 5+ (PWD, TYPE, LIST)
Target:       65%  fuzz post-auth commands (idx 5-8)
Server:       57%  ACCEPTED mutated commands (deep processing)
```

---

## Mathematical Foundations

Four foundations, all backed by code (`docs/mathematical_foundation.tex`):

1. **Cross-Packet Differential Analysis** — Shannon entropy (0 ≤ H ≤ 8), Pearson correlation (|r| ≤ 1), Kendall τ-b, variance. Combined priority classification → field groups.
2. **EWMA Adaptive Sampling** — `k = ⌊K_max / (1 + θ·λ_C)⌋`. Bounded (convex combination), monotonic (strictly decreasing). No Lyapunov (removed — over-dressed, proved obvious properties).
3. **P-PSM Inference** (Veritas-inspired) — K-S two-sample test (pure Python), PAM + Jaccard + Dunn index, DFA transitions (0.005 threshold). Pure black-box.
4. **IFPS Seed Scheduling** — Inverse-frequency acceptance-rejection, energy E = 1/(f+1), O(1) expected time.

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

- **Veritas** — Wang, Y. et al. "Inferring Protocol State Machine from Network Traces: A Probabilistic Approach." 2011. (P-PSM inference)
- **ProtocolGPT** — Wei, H. et al. "Unleashing the Power of LLM to Infer State Machine from the Protocol Implementation." arXiv:2405.00393, 2024. (Contrast: white-box, needs source code — LIFA-Fuzz is black-box)
- **SemFuzz** — Sun, Y. et al. "SemFuzz: A Semantics-Aware Fuzzing Framework." WWW '26, 2026. (Contrast: needs RFC)
- **NSFuzz** — Qin, S. et al. "NSFuzz: Towards Efficient and State-Aware Network Service Fuzzing." TOSEM, 2023. (Contrast: needs source + instrumentation)

---

## License

MIT — Research & Educational Use.
