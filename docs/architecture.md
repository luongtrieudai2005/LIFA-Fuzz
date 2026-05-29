# Architecture Deep-Dive

> Detailed breakdown of each block, interfaces, data contracts, and communication patterns.

---

## Overview: Three-Block + Fusion Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                            LIFA-Fuzz System                               │
│                                                                           │
│  ┌──────────────────┐     ┌──────────────────────┐                       │
│  │   Block 1        │     │   Block 2            │                       │
│  │   Sandbox        │────▶│   Fast Loop          │                       │
│  │   (Isolation)    │     │   (Fuzzing Engine)   │                       │
│  │                  │     │                      │                       │
│  │  Client ◄──────▶ │     │  Interceptor         │                       │
│  │    Proxy ◄──────▶ │     │  Mutator             │                       │
│  │    Server        │     │  Crash Monitor       │──▶ CrashManager       │
│  └──────────────────┘     └──────────┬───────────┘    (dedup + isolate)  │
│                                      │                                    │
│                         ┌────────────┘                                    │
│                         ▼                                                 │
│            ┌─────────────────────────────────────────┐                    │
│            │   Block 3: Neural-Mathematical Fusion    │                    │
│            │                                           │                    │
│            │   Parser ──▶ DifferentialAnalyzer ──┐    │                    │
│            │        │                        │    │    │                    │
│            │        │    ┌───────────────────┘    │    │                    │
│            │        │    ▼                         │    │                    │
│            │        │  HeatmapResult               │    │                    │
│            │        │    ├─ to_llm_hint() ──▶ LLM  │    │                    │
│            │        │    └─ to_field_rules() ──┐   │    │                    │
│            │        │                         │   │    │                    │
│            │        │              Bootstrap Fallback  │                    │
│            │        │              (if LLM fails)│   │    │                    │
│            │        ▼                         ▼   │    │                    │
│            │   RulesOrchestrator ──▶ RuleGenerator   │                    │
│            │                           │             │                    │
│            │                           ▼             │                    │
│            │                    active_rules.json     │                    │
│            └─────────────────────────────────────────┘                    │
│                                                                           │
│  ┌──────────────────────────────────────────────────┐                     │
│  │   Evaluation Framework (Phase 7)                  │                     │
│  │                                                    │                     │
│  │   TelemetryCollector ──▶ telemetry.jsonl           │                     │
│  │   RQ1 Accuracy ──▶ P/R/F1 vs Ground Truth        │                     │
│  │   EvaluationRunner ──▶ 3 Baselines (A/B/C)        │                     │
│  │   PlotGenerator ──▶ Paper-ready PNGs              │                     │
│  └──────────────────────────────────────────────────┘                     │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Block 1: Sandbox (Isolation Layer)

### Purpose

Provides a reproducible, isolated environment where the Client and Target Server communicate. The sandbox ensures:

- **Kernel isolation** — a kernel-level crash in the target (Use-After-Free, OOM) cannot kill the host or the fuzzer.
- **Fast state restore** — after a crash, the target is restored to a clean state in < 10ms (MicroVM snapshot) or ~200-500ms (Docker restart).
- **Network realism** — MicroVMs emulate real hardware devices (virtio-net), essential for testing network stack implementations.
- **Reproducibility** — identical environment for every fuzz campaign.

### Backend Strategy: Docker for Prototype, MicroVM for Production

The sandbox uses a **pluggable backend** via the ``BaseSandbox`` abstract interface.
Block 2 and Block 3 code NEVER imports Docker or Firecracker directly — they depend
only on ``BaseSandbox`` methods.

| Phase | Backend | `reset_state()` Latency | Isolation | Network |
|-------|---------|------------------------|-----------|---------|
| Phase 1 (Prototype) | Docker Containers | ~200-500ms (container restart) | Process-level (shared kernel) | Network namespaces |
| Phase 4 (Production) | Firecracker MicroVM | < 10ms (snapshot restore) | Kernel-level (isolated guest) | virtio-net (hardware emulation) |

**Swap path:** Create a new class implementing ``BaseSandbox`` (e.g., ``FirecrackerSandbox``),
register it, and set ``sandbox.driver`` in ``config.yaml``. Zero changes in fast_loop/ or slow_loop/.

### `BaseSandbox` Interface

```python
class BaseSandbox(abc.ABC):
    async def start(self) -> None:              # Launch client + target
    async def stop(self) -> None:               # Destroy everything
    async def reset_state(self) -> None:        # Restore target to clean state
    async def get_target_info(self) -> ContainerInfo:  # Where to connect
    async def is_target_alive(self) -> bool:    # Crash detection
    async def get_last_crash_info(self) -> Optional[CrashInfo]:  # Crash details
    async def get_network_config(self) -> dict:  # Network topology
```

### Components

| Component | Description |
|-----------|-------------|
| **Client Instance** | Runs the legitimate client software for the target protocol. Generates "normal" traffic for the Interceptor to capture and mutate. |
| **Target Server Instance** | Runs the proprietary server under test. This is what we're trying to crash. |
| **Isolated Network** | A dedicated network connects Client → Interceptor → Server. Docker uses bridge networks; MicroVMs use TAP devices. |

### Network Topology

```
Client ──▶ [proxy_port:8001] ──▶ Interceptor ──▶ [upstream_port:9000] ──▶ Server
                │                            │
                └── same docker bridge network ──┘
```

### Interface Contracts

| Signal | From | To | Format |
|--------|------|----|--------|
| Normal traffic | Client | Interceptor (port 8001) | Raw TCP/UDP |
| Forwarded traffic | Interceptor | Server (port 9000) | Raw TCP/UDP (original or mutated) |
| Crash signal | Server container | Docker daemon | Exit code (SIGSEGV=139, SIGABRT=134) |

---

## Block 2: Fast Loop (Fuzzing Engine)

### Purpose

The high-speed path. Captures live traffic, mutates it based on active rules, forwards mutations to the target, and detects crashes. Must operate at **thousands of EPS** with minimal latency.

### Components

#### 2.1 Interceptor (`fast_loop/interceptor.py`)

A transparent TCP proxy that sits between Client and Server.

**Responsibilities:**
- Accept connections from the Client.
- Forward original packets to the Server (passthrough mode).
- Capture each packet (both directions) into the traffic log.
- Inject mutated packets from the Mutation Engine.

**Key Design Decisions:**
- Uses Python `asyncio` for concurrent connection handling.
- Traffic log is a ring buffer (memory-mapped file) for zero-copy capture.
- Dual mode: **passthrough** (capture only) and **fuzz** (capture + mutate + inject).

```python
class Interceptor:
    async def start(self) -> None:
        """Start the proxy server, listening for client connections."""

    async def handle_connection(self, client_reader, client_writer) -> None:
        """Handle a single proxied connection. Captures traffic and can inject mutations."""

    async def capture_packet(self, direction: str, data: bytes) -> None:
        """Write a captured packet to the traffic log buffer."""

    async def inject_mutation(self, mutated_data: bytes) -> None:
        """Send a mutated packet toward the server."""
```

#### 2.2 Mutation Engine (`fast_loop/mutator.py`)

Applies mutations to captured packets based on the active rule set.

**Responsibilities:**
- Maintain the current `ActiveRuleSet` (list of `SemanticRule` objects).
- Apply mutations: bit-flip, boundary fuzz, structural mutations (using inferred fields).
- Rate-limit mutations to avoid overwhelming the target.
- Track mutation coverage (which fields/offsets have been mutated).

```python
class MutationEngine:
    async def mutate(self, original_packet: bytes) -> list[bytes]:
        """Generate N mutated variants of a packet."""

    def apply_rule(self, packet: bytes, rule: SemanticRule) -> bytes:
        """Apply a single semantic rule to a packet."""

    def random_bitflip(self, data: bytes) -> bytes:
        """Pure random bit-flip mutation (baseline)."""

    def update_rules(self, new_rules: list[SemanticRule]) -> None:
        """Hot-swap the active rule set from the Slow Loop."""
```

#### 2.3 Crash Monitor (`fast_loop/crash_monitor.py`)

Watches the Target Server container for crash events.

**Responsibilities:**
- Poll container exit status via Docker API.
- On crash: log the offending packet, timestamp, and exit code.
- Notify the Interceptor to pause/resume.
- Maintain crash corpus (all packets that caused crashes).

```python
class CrashMonitor:
    async def watch(self) -> None:
        """Continuously monitor the target container for crashes."""

    async def on_crash(self, crash_info: CrashRecord) -> None:
        """Handle a crash event — save the offending packet, update corpus."""

    async def restart_target(self) -> None:
        """Restart the crashed target container for continued fuzzing."""
```

### Data Flow (Block 2 Internal)

```
Client ──▶ Interceptor ──▶ [Log Packet] ──▶ Forward to Server
                     │
                     ▼
              Mutation Engine ◀── Active Rule Set
                     │
                     ▼
              Inject Mutated Packet ──▶ Server
                     │
                     ▼ (on crash)
              Crash Monitor ──▶ Log + Save + Restart
```

---

## Block 3: Slow Loop (LLM Brain)

### Purpose

The intelligent path. Consumes accumulated traffic logs, converts raw bytes to structured representations, uses an LLM to infer protocol grammar, and generates updated mutation rules for the Fast Loop.

### Components

#### 3.1 Traffic Parser (`slow_loop/parser.py`)

Converts raw binary traffic into structured JSON for LLM consumption.

**Responsibilities:**
- Read traffic log buffer (from Block 2).
- Convert raw bytes → hex strings / field breakdowns.
- Identify repeated patterns (magic bytes, headers).
- Output structured `TrafficRecord` objects.

```python
class TrafficParser:
    async def parse_log(self) -> list[TrafficRecord]:
        """Read the traffic log buffer and return parsed samples."""

    def bytes_to_hex(self, data: bytes) -> str:
        """Convert raw bytes to hex string representation."""

    def infer_basic_structure(self, samples: list[TrafficRecord]) -> dict:
        """Lightweight local inference: find magic bytes, length fields, repeated structures."""
```

#### 3.2 LLM Agent (`slow_loop/llm_agent.py`)

Interacts with the LLM to infer protocol semantics.

**Responsibilities:**
- Build prompts from parsed traffic data.
- Call LLM API (via `litellm` for provider-agnostic access).
- Parse LLM response into structured grammar description.
- Handle rate limits, retries, and token budgeting.

```python
class LLMAgent:
    async def infer_protocol(self, traffic_samples: list[TrafficRecord]) -> ProtocolGrammar:
        """Send parsed traffic to LLM and receive inferred protocol grammar."""

    def build_prompt(self, samples: list[TrafficRecord]) -> str:
        """Construct the LLM prompt from traffic samples."""

    async def call_llm(self, prompt: str) -> str:
        """Call the LLM API with retry logic."""
```

#### 3.3 Rule Generator (`slow_loop/rule_generator.py`)

Converts LLM's protocol grammar inference into actionable `SemanticRule` objects.

**Responsibilities:**
- Validate LLM output (ensure it matches expected schema).
- Convert field descriptions into mutation rules (e.g., "fuzz bytes 4-7 as uint32 LE").
- Rank rules by estimated effectiveness.
- Push rules to the Fast Loop's active rule set.

```python
class RuleGenerator:
    def grammar_to_rules(self, grammar: ProtocolGrammar) -> list[SemanticRule]:
        """Convert an inferred grammar into a list of SemanticRules."""

    def validate_rule(self, rule: SemanticRule) -> bool:
        """Validate that a rule is safe and actionable."""

    async def push_rules(self, rules: list[SemanticRule]) -> None:
        """Push new rules to the Fast Loop via IPC/HTTP."""
```

---

## Cross-Block Data Contracts

### 1. Traffic Log → Parser (Block 2 → Block 3)

The Interceptor writes to a **shared traffic log** that the Parser reads.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `float` | Unix timestamp (epoch seconds) |
| `direction` | `str` | `"client_to_server"` or `"server_to_client"` |
| `raw_data` | `bytes` | Raw packet payload |
| `session_id` | `str` | UUID for the TCP session |
| `is_mutated` | `bool` | Whether this packet was a mutation |
| `mutation_id` | `str\|None` | ID of the mutation rule applied (if any) |

**Transport:** Memory-mapped ring buffer file (`/tmp/lifa_traffic.log`) or Redis stream.

### 2. SemanticRule (Block 3 → Block 2)

The core data contract between the Slow Loop and Fast Loop.

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `str` | Unique rule identifier |
| `rule_type` | `enum` | `"bit_flip"`, `"boundary"`, `"structural"`, `"state"` |
| `offset_start` | `int` | Start byte offset in the packet |
| `offset_end` | `int` | End byte offset (exclusive) |
| `field_name` | `str` | Human-readable field name (e.g., "header_length") |
| `field_type` | `str` | `"uint8"`, `"uint16_le"`, `"uint32_be"`, `"string"`, `"bytes"`, `"enum"` |
| `constraints` | `dict` | Mutation constraints (min, max, allowed values, valid enum set) |
| `priority` | `float` | Estimated effectiveness (0.0–1.0) |
| `protocol_state` | `str\|None` | State in which this rule applies (e.g., "handshake") |
| `created_at` | `datetime` | When this rule was generated |
| `hit_count` | `int` | How many times this rule has been applied |
| `crash_count` | `int` | How many crashes this rule caused |

**Transport:** Shared file (`/tmp/lifa_rules.json`) polled by Fast Loop, or HTTP endpoint on Fast Loop that Slow Loop POSTs to.

### 3. CrashRecord (Block 2 → Logging/Analysis)

| Field | Type | Description |
|-------|------|-------------|
| `crash_id` | `str` | Unique crash identifier |
| `timestamp` | `float` | Unix timestamp |
| `exit_code` | `int` | Container exit code |
| `signal` | `str\|None` | Signal name (e.g., "SIGSEGV") |
| `offending_packet` | `bytes` | The mutated packet that caused the crash |
| `mutation_rule_id` | `str\|None` | The rule that generated the offending packet |
| `stack_trace` | `str\|None` | Server stack trace (if available) |

---

## Communication Patterns

### Block 2 → Block 3 (Traffic Logs)

```
Interceptor ──write──▶ Traffic Log File ──read──▶ Parser
                                 │
                     (ring buffer, async file I/O)
```

- **Mechanism:** The Interceptor appends to a memory-mapped ring buffer.
- **Cadence:** Real-time (every captured packet).
- **Parser reads:** Batches every N seconds or when buffer reaches threshold.

### Block 3 → Block 2 (Semantic Rules)

```
LLM Agent ──▶ Rule Generator ──▶ Rule Update File ──▶ MutationEngine
                                                │
                                    (file watcher / HTTP POST)
```

- **Mechanism:** Rule Generator writes to a shared JSON file or POSTs to Fast Loop's HTTP endpoint.
- **Cadence:** On-demand (after each LLM inference completes, ~1 per minute).
- **Hot-swap:** Fast Loop loads new rules without restarting.

### Crash Notifications (Block 2 Internal)

```
CrashMonitor ──▶ Interceptor (pause) ──▶ Save crash record ──▶ Restart server
```

---

## Concurrency Model

```
Fast Loop (asyncio event loop)
├── Interceptor task (one per client connection)
├── Mutation Engine task (produces mutated packets)
├── Crash Monitor task (polls container status)
└── Rule Watcher task (watches for new rules from Slow Loop)

Slow Loop (separate asyncio event loop)
├── Parser task (reads traffic log periodically)
├── LLM Agent task (calls LLM API, awaits response)
└── Rule Pusher task (writes rules to shared transport)
```

Both loops run as **separate processes** communicating via file-based IPC. This ensures:
- A hung LLM call never blocks the Fast Loop.
- The Fast Loop can continue fuzzing with stale rules if the Slow Loop is down.
- Each loop can be scaled/restarted independently.

---

## Design Principles

1. **Decoupling** — Fast Loop never waits on Slow Loop. They communicate asynchronously via files/IPC.
2. **Resilience** — If the LLM call fails, the Fast Loop continues with existing rules (degraded mode), or bootstrap rules from the DifferentialAnalyzer.
3. **Evolvability** — New mutation strategies are added as new `SemanticRule` types without modifying the Interceptor.
4. **Observability** — Every packet, mutation, rule update, and crash is logged with structured logging.
5. **Reproducibility** — All fuzz inputs and crash artifacts are saved for replay.
6. **No Starvation** — The fuzzer never runs without rules: DifferentialAnalyzer produces bootstrap FieldRules in <1ms when the LLM is unavailable.

---

## Neural-Mathematical Fusion Loop (Phase 6)

### Purpose

Bridge the **mathematical pre-processing layer** (`DifferentialAnalyzer`) with the **neural inference layer** (`LLMAgent`) so the LLM receives a pre-computed statistical heatmap and focuses on semantic naming rather than raw byte discovery.

### Architecture

```
Raw Client Packets
        │
        ▼
┌─────────────────────────┐
│  DifferentialAnalyzer    │  ← Pure math, <1ms, stateless
│  (Shannon H, Pearson r,  │
│   Kendall τ per offset)  │
│                           │
│  Output: HeatmapResult   │
│    ├─ to_llm_hint()      │──▶ Injected into LLM prompt
│    └─ to_field_rules()   │──▶ Bootstrap rules if LLM fails
└─────────────────────────┘
        │
        ▼ math_hint parameter
┌─────────────────────────┐
│  LLMAgent                │  ← Neural layer, ~60s per inference
│  infer_protocol(         │
│    traffic_input,        │
│    math_hint=heatmap     │  ← Fusion: math + neural
│  )                       │
│                           │
│  Output: ProtocolGrammar │
└─────────────────────────┘
        │
        ▼
┌─────────────────────────┐
│  RulesOrchestrator       │
│                           │
│  If LLM succeeds:        │
│    grammar → SemanticRules│
│                           │
│  If LLM fails:           │
│    heatmap.to_field_rules│──▶ Bootstrap SemanticRules
│    (fuzzer never starves)│
└─────────────────────────┘
```

### Key Components

| Component | File | Speed | Purpose |
|-----------|------|-------|---------|
| DifferentialAnalyzer | `slow_loop/differential_analyzer.py` | <1ms | Classify byte offsets (STATIC/CALCULATED/HIGH_ENTROPY/LOW_ENTROPY) |
| CrashManager | `shared/crash_manager.py` | O(1) lookup | Two-level crash dedup (SHA256 primary + structural secondary) |
| RulesOrchestrator | `slow_loop/rules_orchestrator.py` | Pipeline | Orchestrates math → LLM → rules with bootstrap fallback |

### Crash Isolation (Precision Mode)

When `CrashManager` detects unique crashes, the orchestrator enters **precision mode (k=1)**:
- Fast Loop reduces to single-field-at-a-time mutations
- Enables precise attribution of which field triggered the crash
- Remains in precision mode until operator resets

### Fusion System Prompt Guidelines

The LLM receives `SYSTEM_PROMPT_FUSION_APPEND` instructing it to:
- RESPECT all STATIC labels — do NOT propose mutating those offsets
- Focus BOUNDARY_VALUES strategies on CALCULATED fields (length, sequence)
- Use BIT_FLIP on LOW_ENTROPY regions, RANDOM_BYTES on HIGH_ENTROPY
- Explain how findings ALIGN or CONTRADICT the heatmap in the `reasoning` field

---

## Evaluation Framework (Phase 7)

### Purpose

Automated academic benchmarking producing empirical data for three research questions:

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

### Evaluation Components

| File | Purpose |
|------|---------|
| `evaluation/ground_truth.py` | LIFA protocol definition (magic + opcode + length + payload) |
| `evaluation/rq1_accuracy.py` | P/R/F1 evaluator with ±1 byte tolerance |
| `evaluation/telemetry_collector.py` | Real-time 10s JSONL snapshot (EPS, crashes, tokens) |
| `evaluation/evaluation_runner.py` | 3-baseline experiment orchestrator |
| `evaluation/plot_generator.py` | Paper-ready PNG plots (matplotlib) |

### Generated Plots

| Plot | File | Research Question |
|------|------|-------------------|
| EPS Over Time | `evaluation/plots/rq2_eps_over_time.png` | RQ2: Throughput comparison |
| Cumulative Crashes | `evaluation/plots/rq3_cumulative_crashes.png` | RQ3: Vulnerability discovery |
| Accuracy Bars | `evaluation/plots/rq1_accuracy_bars.png` | RQ1: Grammar inference accuracy |

### CLI Commands

```bash
# RQ1 accuracy evaluation (no Docker needed):
python -m evaluation.rq1_accuracy

# Generate synthetic data + plots (no Docker needed):
python -m evaluation.plot_generator --synthetic

# Full benchmark (requires Docker, 5 min per baseline):
python -m evaluation.evaluation_runner --duration 300
```
