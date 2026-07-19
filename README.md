# LIFA-Fuzz

> **Live-traffic Inference & Asynchronous Fuzzing Framework** — A black-box fuzzer for custom/proprietary network protocols that infers protocol grammar AND state machine from live traffic using LLM + statistical analysis, without requiring RFCs, source code, or protocol specifications.

---

## What It Does

<img align="right" width="438" height="382" alt="image" src="https://github.com/user-attachments/assets/cd0bc619-874d-4bdb-9648-a0254b435ee4" />

LIFA-Fuzz finds bugs in network servers without needing the server's source code or protocol documentation. It works by watching real traffic between a client and the server, learning the protocol structure automatically, then sending mutated packets to trigger crashes.

The system does four things:

1. **Learns the protocol format** by watching network traffic. It uses statistics to find fixed fields (magic numbers), variable fields (length, data), and command codes, then uses an LLM to name each field and pick the best mutation strategy. Verified at F1 = 1.0 on both a custom binary protocol and standard FTP.

2. **Learns the protocol state machine** automatically from traffic patterns, with no hardcoded keywords. It discovers state transitions (e.g. server sends 220, client sends USER, server responds 331) and tracks which states the fuzzer has visited.

3. **Fuzzes statefully** by replaying the real session prefix (e.g. complete USER then PASS authentication) on a single TCP connection before mutating the target command. This lets it reach post-auth code where deep bugs live. Achieves 98% auth rate on LightFTP.

4. **Confirms each crash** by replaying the exact prefix and mutated command on a clean server instance, ensuring every finding is reproducible.

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

The Fast Loop core has **zero hardcoded protocol knowledge**. All protocol-specific logic lives in pluggable `ProtocolModule` subclasses:

- **`NullModule`** (default). A pure black-box mode: every server reply is treated as accepted, no framing, no state tracking. Relies on the automatically inferred state machine for state awareness.
- **Protocol-specific modules** (opt-in, for known protocols). Add status code parsing, framing, protocol state tracker, and protocol-specific mutation operators.

**For unknown protocols:** `NullModule` plus the inferred state machine gives automatic state tracking without any protocol knowledge. This is how the system handles novel protocols without modification.

### Stateful Sequence Replay

LIFA-Fuzz captures real client traffic and groups packets by session ID into `SeedSequence` objects. The mutation engine then:

1. Splits each sequence into **Prefix** (replayed verbatim to establish server state), **Target** (the packet to fuzz), and **Suffix** (remaining traffic).
2. Opens **one TCP connection**, drains the server greeting, replays the prefix, then sends the mutated target.
3. Reads and classifies the full response chain.

This solves the core problem of stateful fuzzing: the fuzzer authenticates and reaches server logic beyond the login screen. Without this, every mutation only hits the pre-auth greeting and never triggers deeper code paths.

### Crash Discovery Reliability

Several correctness fixes make crash discovery trustworthy on length-delimited targets:

- **Length-aware payload growth** — when a variable-length payload grows, the dependent length field is recomputed so the packet stays valid. A length-clamping server computes the copy size as `min(declared, actual)`; growing actual bytes without updating the declared length leaves the old small value and masks the overflow.
- **Crash-location dedup (σ₃)** — crashes are deduplicated by crash *site* (ASAN error type + backtrace offsets from the serial console), not by payload bytes. N random-payload crashes at the same site count as one vulnerability.
- **Confirmation polling** — the replay confirmation polls target liveness for a few seconds so a slow crash chain (child abort → parent exit → guest kernel panic → VMM exit) is detected, and the hot loop is paused on a bounded time budget, not a fixed candidate count.
- Every recorded crash is **reproducible**: `lifa_repro.sh` rebuilds the target from source and replays a fuzzer-saved PoC to an ASAN crash.

### Semantic-Violation Oracle (experimental, Phase 1)

A SemFuzz-inspired oracle (paper-faithful: add/remove/update actions, length recompute, 2-category normal/error response mapping) flags divergences where a structural violation elicits a "normal" reply instead of the expected "error".

**Honest status:** the *mechanism* is correct and paper-faithful, but the *signal* is currently weak. On the disclosed FTP case-study strategies the oracle shows ~0% precision — LightFTP returns correct RFC-959 replies to commands the naive violation only mildly perturbed (server tolerance, not bugs). LIFA has no RFC ground truth, so the expected response is inferred, not specification-derived. Phase 2 (LLM-generated, grammar-targeted violations) and a richer response-content oracle are where real signal can come from; until then, the divergence counter must NOT be reported as findings.

---

## Evaluation Framework

### Research Questions

| RQ | Question | Metric | Status |
|----|----------|--------|--------|
| RQ1 | How precisely does LIFA-Fuzz infer protocol grammar? | P/R/F1 vs ground truth | **F1 = 1.0** (REAL LLM, LIFA + FTP) |
| RQ2 | Does the async architecture maintain throughput? | EPS over time | Pending re-run (old data invalid) |
| RQ3 | Does full fusion find crashes? | Cumulative crashes, TTC | Verified on the LIFA-v2 positive-control target (see honesty note) |

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
| `fast_loop/mutator.py` | Mutation engine: stateful replay, scheduler, greeting drain, BinaryMutator, length-aware growth |
| `fast_loop/crash_monitor.py` | Crash detection + confirmation (bounded time budget) + σ₃ site dedup |
| `fast_loop/binary_mutator.py` | 15 generic + 4 FTP mutation operators (BINARY_ONLY default) |
| `fast_loop/violation_mutator.py` | SemFuzz-style structural-violation engine (add/remove/update, Phase 1) |
| `fast_loop/state_machine_tracker.py` | InferredStateTracker — generic P-PSM state tracking |
| `slow_loop/differential_analyzer.py` | Shannon entropy, Pearson, Kendall τ per byte offset |
| `slow_loop/state_machine_inferer.py` | Veritas P-PSM: K-S test, PAM clustering, DFA |
| `slow_loop/llm_agent.py` | LLM client (GLM-5-Turbo REAL), self-consistency |
| `slow_loop/rules_orchestrator.py` | Slow Loop pipeline: math → LLM → P-PSM → rules |
| `shared/protocol_module.py` | ProtocolModule interface + NullModule (black-box core) |
| `shared/crash_manager.py` | Crash dedup (σ₁ payload + σ₃ crash-location) + PoC corpus |
| `fast_loop/ftp_module.py` | FTPModule (disclosed case-study extension) |
| `sandbox/firecracker_driver.py` | Firecracker MicroVM sandbox (snapshot/restore) |
| `sandbox/target/vulnerable_server.c` | LIFA-v2 positive-control target (state machine + fork, ASAN) |
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

- **State inference can confuse similar commands.** The system uses byte-frequency similarity, so commands that share the same argument bytes (like USER and PASS) may be merged into one state. This is a known limitation of the approach.
- **No binary code coverage inside the Firecracker VM.** Snapshots discard coverage counters, so gcov cannot work with snapshot-restore. Coverage is measured separately via a Docker variant.
- **Old A/B/C benchmark data is invalid.** It was collected with a broken fuzzer that was stuck at the server greeting and never authenticated. Results must be re-run with the fixed pipeline.
- **Zero crashes found so far.** The pipeline was only recently fixed; a longer overnight campaign is needed.
- **`final_coverage` is a byte-offset proxy, not semantic coverage.** It counts unique byte-offset mutation signatures, which is **not comparable across protocol types**: on text/line protocols (RTSP/HTTP) the math-only baseline (B) inflates it (per-byte signatures on a fixed packet) while the LLM baseline's (C) token mutations register few. No single number is "coverage", so `summary.json`/`comparison.json` now report several metrics transparently — `final_offset_coverage` (this byte-offset proxy), `final_state_edges` (protocol state-transition coverage), and `rule_response_stats` (per-strategy accepted/timeout, i.e. did mutations reach handlers). The decisive RQ3 metric remains **crashes**; on live555 all baselines found 0. The coverage plot is labeled accordingly.
- **Baseline B is offset-only on text protocols, by design.** B isolates the DifferentialAnalyzer (math) layer, which has no text-tokenization; on line protocols it produces byte-offset mutations rather than token-based ones. This is the ablation working as intended — a text-aware math baseline, if wanted, should be a new named baseline reusing the generic tokenizer, not a change to B.

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
