# Development Plan

> Step-by-step implementation roadmap for LIFA-Fuzz.
> Use this as your daily checklist. Each phase builds on the previous one.

---

## Phase 1: Sandbox Setup (Week 1)

**Goal:** Working sandbox with clean abstraction layer. Client sends traffic to target through a pluggable backend. Phase 1 uses Docker; Phase 4 swaps to Firecracker MicroVM without changing any other code.

### Checklist

- [ ] **1.1** Create `shared/sandbox_abstraction.py` — `BaseSandbox` abstract class with `start()`, `stop()`, `reset_state()`, `is_target_alive()`, `get_target_info()`, `get_last_crash_info()`.
- [ ] **1.2** Create `sandbox/docker_driver.py` — `DockerSandbox(BaseSandbox)` implementing all methods via Docker Engine API.
- [ ] **1.3** Create `sandbox/server/Dockerfile` — lightweight Python image.
- [ ] **1.4** Create `sandbox/server/server.py` — simple echo TCP server (dummy target).
- [ ] **1.5** Create `sandbox/client/Dockerfile` — lightweight Python image.
- [ ] **1.6** Create `sandbox/client/client.py` — client sends periodic TCP messages with protocol header.
- [ ] **1.7** Create `sandbox/docker-compose.yml` — define client + server + interceptor + network.
- [ ] **1.8** Verify traffic flows end-to-end: `docker compose up --build` and see packets in server logs.
- [ ] **1.9** Verify crash detection: kill the server container and confirm Docker reports exit code.
- [ ] **1.10** Verify `reset_state()` works: trigger crash → monitor detects → container restarts → resumes.
- [ ] **1.11** Write `tests/test_docker_driver.py` — mock Docker API, test all BaseSandbox methods.
- [ ] **1.12** Add healthcheck to server container for auto-restart testing.

**Deliverable:** Pluggable sandbox abstraction with working Docker backend. Crash → auto-detect → reset loop verified.

**Architecture Constraint:** The Crash Monitor (`fast_loop/crash_monitor.py`) MUST depend on `BaseSandbox`, not on Docker directly. The swap to Firecracker in Phase 4 changes zero lines in `crash_monitor.py`.

---

## Phase 2: Fast Loop — Interceptor & Mutation Engine (Week 2-3)

**Goal:** A transparent TCP proxy that captures traffic, mutates packets, and detects crashes.

### 2A: Interceptor

- [ ] **2.1** Implement `fast_loop/interceptor.py` — basic asyncio TCP proxy.
- [ ] **2.2** Add packet capture: log every packet (direction, timestamp, raw bytes).
- [ ] **2.3** Write traffic log to ring buffer / file.
- [ ] **2.4** Add `shared/logger.py` — structured async logging.
- [ ] **2.5** Test: run proxy between client and server, verify traffic is captured.
- [ ] **2.6** Add Docker container for the Fast Loop to `docker-compose.yml`.
- [ ] **2.7** Write `tests/test_interceptor.py` — unit tests for proxy logic.

### 2B: Mutation Engine

- [ ] **2.8** Implement `fast_loop/mutator.py` — baseline mutations (bit-flip, byte substitution).
- [ ] **2.9** Add rule-based mutation support: `apply_rule(packet, SemanticRule)`.
- [ ] **2.10** Wire mutation engine into interceptor: periodically inject mutated packets.
- [ ] **2.11** Implement `fast_loop/crash_monitor.py` — Docker API polling for container exit.
- [ ] **2.12** Wire crash monitor: on crash → save offending packet + restart server.
- [ ] **2.13** Add rule watcher: poll for new rules from Slow Loop.
- [ ] **2.14** Write `tests/test_mutator.py` — unit tests for mutation strategies.
- [ ] **2.15** Write `tests/test_crash_monitor.py` — mock Docker API tests.

**Deliverable:** Running the Fast Loop shows captured traffic, mutated packets being sent, and crashes being detected + logged.

---

## Phase 3: Slow Loop — Traffic Parsing & LLM Integration (Week 3-4)

**Goal:** Parse traffic logs, send to an LLM, and receive inferred protocol grammar.

### 3A: Traffic Parser

- [ ] **3.1** Implement `slow_loop/parser.py` — read traffic log buffer.
- [ ] **3.2** Implement `bytes_to_hex()` — convert raw bytes to readable hex strings.
- [ ] **3.3** Implement `infer_basic_structure()` — local lightweight pattern detection (magic bytes, repeated headers).
- [ ] **3.4** Output structured `TrafficSample` objects.
- [ ] **3.5** Write `tests/test_parser.py` — test with synthetic traffic data.

### 3B: LLM Agent

- [ ] **3.6** Implement `slow_loop/llm_agent.py` — litellm-based LLM client.
- [ ] **3.7** Design prompt template for protocol inference (system prompt + traffic examples).
- [ ] **3.8** Implement `build_prompt()` — construct prompt from `TrafficSample` list.
- [ ] **3.9** Implement `call_llm()` — with retry, timeout, and rate-limit handling.
- [ ] **3.10** Implement `infer_protocol()` — end-to-end: samples → prompt → LLM → parsed grammar.
- [ ] **3.11** Implement `slow_loop/rule_generator.py` — convert grammar to `SemanticRule` objects.
- [ ] **3.12** Implement `push_rules()` — write rules to shared file / POST to Fast Loop.
- [ ] **3.13** Write `tests/test_llm_agent.py` — mock LLM API tests.
- [ ] **3.14** Write `tests/test_rule_generator.py` — validate rule generation from sample grammar.

**Deliverable:** The Slow Loop can read traffic logs, call an LLM, and produce `SemanticRule` JSON files.

---

## Phase 4: Feedback Loop & Polish (Week 5-6)

**Goal:** Close the loop — Slow Loop rules update Fast Loop in real-time, creating an autonomous fuzzing cycle.

### 4A: End-to-End Integration

- [ ] **4.1** Wire Block 2 ↔ Block 3: Fast Loop reads new rules from Slow Loop output.
- [ ] **4.2** Implement hot-swap: new rules are loaded without restarting the Fast Loop.
- [ ] **4.3** Run full end-to-end test: client → proxy → mutate → crash → log → parse → LLM → rules → better mutations.
- [ ] **4.4** Add rule effectiveness tracking: `hit_count` and `crash_count` on each rule.
- [ ] **4.5** Implement rule aging: deprioritize rules that haven't caused crashes after N attempts.

### 4B: Observability & Metrics

- [ ] **4.6** Add EPS (Executions Per Second) counter to Fast Loop.
- [ ] **4.7** Add Prometheus-style metrics export (or simple stats endpoint).
- [ ] **4.8** Add crash corpus viewer: list all crashes with their offending packets.
- [ ] **4.9** Add traffic visualization: optional pcap export of captured traffic.

### 4C: Configuration & Documentation

- [ ] **4.10** Finalize `config.yaml` with all tunable parameters documented.
- [ ] **4.11** Add `.env.example` for API keys and secrets.
- [ ] **4.12** Update README.md with any changes from implementation.
- [ ] **4.13** Write integration test: `tests/test_e2e.py` — full loop with mock server.

### 4D: Robustness

- [ ] **4.14** Handle edge cases: empty traffic logs, malformed LLM output, container startup delays.
- [ ] **4.15** Add graceful shutdown (SIGINT handler) for all components.
- [ ] **4.16** Add circuit breaker: if target crashes too frequently, back off mutations.

**Deliverable:** A fully autonomous fuzzing loop that gets smarter over time, with crash corpus and metrics.

---

## Future Extensions (Post-Phase 4)

These are stretch goals, not part of the initial roadmap:

### MicroVM Migration (Phase 4b)

- [ ] **Firecracker Sandbox Driver** — implement `FirecrackerSandbox(BaseSandbox)` using Firecracker API.
- [ ] **Snapshot/Restore** — create VM memory snapshots for < 10ms `reset_state()`.
- [ ] **virtio-net networking** — real hardware device emulation for network stack fuzzing.
- [ ] **Kernel isolation verification** — confirm kernel-level crashes are fully contained.
- [ ] **Performance benchmark** — compare EPS between Docker backend and MicroVM backend.

### Other Extensions

- [ ] **Multi-protocol support** — run multiple fuzz campaigns simultaneously.
- [ ] **Coverage-guided mode** — integrate with sanitizers (ASan, UBSan) for code-coverage feedback.
- [ ] **Protocol state machine** — LLM infers state transitions, enabling state-aware fuzzing.
- [ ] **Cluster mode** — distribute Fast Loop instances across multiple machines.
- [ ] **Web UI** — real-time dashboard showing traffic, mutations, crashes, and LLM inferences.
- [ ] **AFL-style power scheduling** — allocate more mutations to rules that discover new coverage.
