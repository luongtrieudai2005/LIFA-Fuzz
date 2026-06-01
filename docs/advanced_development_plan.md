# Advanced Development Plan

> Extension of `development_plan.md` — covers Phase 8+ with extreme detail.
> Each phase includes: goal, dependencies, step-by-step checklist, expected effort, and risk assessment.

---

## Phase 8: Mutation Engine Redesign — Scheduling & Crash Isolation

**Goal:** Replace the current `fast_loop/mutator.py` with the two-mode scheduler algorithm from `docs/mutator.py`. Solve the crash isolation problem: when multiple fields are mutated simultaneously, it's impossible to pinpoint which field triggered the crash.

**Dependencies:**
- Phase 2 (Interceptor + basic mutator) — ✅ done
- Phase 6 (`shared/schemas.py` with `FieldRule`, `MutationStrategy`, `SemanticRuleSet`) — needs schema updates

**Schema Pre-work (MUST do first):**

- [ ] **8.1** Add `dictionary_values: Optional[list[str]] = None` to `FieldRule` in `shared/schemas.py`
- [ ] **8.2** Create `PacketRecord` dataclass in `shared/schemas.py`:
  ```python
  @dataclass
  class PacketRecord:
      packet_id: str        # uuid hex
      raw_bytes: bytes      # full payload
      hex_payload: str      # hex of raw_bytes
      byte_length: int      # len(raw_bytes)
      direction: Direction
  ```
  Note: existing `TrafficRecord` has `raw_data` not `raw_bytes`, and `record_id` not `packet_id`. Keep both for backward compat — convert at boundary.

- [ ] **8.3** Create `SemanticRuleSet` in `shared/schemas.py`:
  ```python
  class SemanticRuleSet(BaseModel):
      rule_set_id: str
      protocol_name: str
      base_packet: Optional[str]          # hex string
      overall_confidence: float           # 0.0–1.0
      fields: list[FieldRule]            # ALL fields (mutable + static)
      
      def get_mutable_fields(self) -> list[FieldRule]: ...
      def get_static_fields(self) -> list[FieldRule]: ...
  ```
  Note: existing `ActiveRuleSet` uses `SemanticRule` (heavy) — `SemanticRuleSet` uses `FieldRule` (lightweight from analyzer). Two different types coexist.

**Implementation Steps:**

- [ ] **8.4** Implement scheduler hierarchy in `fast_loop/schedulers.py`:
  - `_BaseScheduler` — abstract: `select(mutable_fields) -> list[FieldRule]`, `notify_crash()`, `reset()`
  - `RandomSubsetScheduler(k=2)` — random sample without replacement. Default mode.
  - `OneAtATimeScheduler(budget_per_field=20, isolation_budget=500)` — cycle fields deterministically. Auto-revert after budget.
  - `AllFieldsScheduler` — mutate everything (zero isolation, max coverage for quick smoke test)

- [ ] **8.5** Implement `fast_loop/mutator.py` (NEW — replaces existing):
  - Constructor: `MutationEngine(target_host, target_port, seed_queue, k=2, max_eps=1000, connection_timeout=1.0, recv_timeout=0.5, auto_investigate=True, investigation_budget=500)`
  - `run()` — main hot-loop: drain seeds → pick seed (round-robin) → build mutant → send → track stats → auto-investigate
  - `_build_mutant(seed)` — apply static fields first, then scheduler-selected mutable fields
  - `_send(payload, seed_id)` — fresh TCP connection per packet. Returns `PacketStatus` (ACCEPTED/REJECTED/TIMEOUT/CRASH)
  - `_dumb_mutate(buf)` — fallback bit-flip when no rules loaded
  - `set_investigation_mode(reason)` / `set_normal_mode()` — mode switching with `asyncio.Lock`
  - `update_rule_set(new_rules)` — atomic pointer swap under lock (< 1µs)
  - `pause()` / `resume()` — control flags
  - `get_stats() -> MutatorStats` — snapshot with EPS, mode, rule_set_version
  - EPS tracking: rolling window (200 timestamps), log heartbeat every 5s

- [ ] **8.6** Implement `_apply_field(buf, rule)` as module-level pure function:
  - `STATIC` — overwrite with hex value
  - `RANDOM_BYTES` — `os.urandom()`
  - `BIT_FLIP` — flip one random bit in field
  - `BOUNDARY_VALUES` — cycle: `0x00…00`, `0xFF…FF`, `0x7F…FF`, `0x80…00`, `+1`
  - `INCREMENT` — read big-endian + 1, wrap at max
  - `CALCULATED` — recalculate length (everything after this field)
  - `DICTIONARY` — pick random value from `rule.dictionary_values`
  - `SKIP` — no-op

- [ ] **8.7** Wire into `main.py`:
  - Create `asyncio.Queue` in main
  - Interceptor pushes captured packets into queue instead of writing directly to traffic log (or dual-write: both queue + file)
  - Replace old `MutationEngine` import with new one
  - Update constructor call with `target_host`, `target_port`, `seed_queue`

**Existing code to update:**

- [ ] **8.8** Update `fast_loop/interceptor.py` — push `PacketRecord` into `seed_queue` on each captured client→server packet
- [ ] **8.9** Update `main.py` — create `seed_queue`, pass to both Interceptor and new MutationEngine, add `asyncio.create_task(mutator.run())` to event loop
- [ ] **8.10** Update `tests/test_mutator.py` — rewrite for new API. Preserve `KILL_SERVER_PAYLOADS` tests
- [ ] **8.11** Update `tests/test_e2e_flow.py` — align with new `MutationEngine.__init__` signature
- [ ] **8.12** Update `evaluation/evaluation_runner.py` — same
- [ ] **8.13** Update `evaluation/telemetry_collector.py` — same
- [ ] **8.14** Update `config.yaml` — add `fast_loop.mutator` section (k, max_eps, connection_timeout, recv_timeout, auto_investigate, investigation_budget)

**Tests to write:**

- [ ] **8.15** `tests/test_schedulers.py` (12+ tests):
  - RandomSubsetScheduler: k=0, k>len(fields), distribution (run 1000×, each field picked ~k/len ratio)
  - OneAtATimeScheduler: cursor cycling, budget_per_field triggers advance, is_budget_exhausted after isolation_budget
  - AllFieldsScheduler: returns all fields
  - notify_crash on non-ONE_AT_A_TIME scheduler (no-op, not crash)

- [ ] **8.16** `tests/test_mutator_v2.py` (15+ tests):
  - Dumb mutate: empty buffer, single byte, preserves length
  - Build mutant with no rules → falls back to dumb
  - Build mutant with STATIC fields only → overwrites correctly
  - Build mutant with one mutable field → applies mutation
  - Build mutant with RANDOM_SUBSET → k=2, exactly 2 fields mutated
  - Build mutant with ONE_AT_A_TIME → exactly 1 field mutated, cycles
  - Send: successful connection, timeout, connection refused triggers crash_callback
  - EPS tracking: manual update, rolling window calculation

- [ ] **8.17** `tests/test_apply_field.py` (8 tests, one per strategy):
  - Each MutationStrategy with known input/output

**Migration strategy:**
1. Write new `fast_loop/mutator.py` alongside old one (rename old to `mutator_v1.py`)
2. Write all tests for new code
3. Wire into `main.py` with feature flag: `config.yaml → fast_loop.mutator.version: "v2"`
4. Run full e2e test with both versions, compare crash counts
5. After validation, delete `mutator_v1.py` and `mutation_operators.py`

**Risks:**
- Seed queue backpressure: if mutator sends slower than interceptor captures, queue grows unbounded. Mitigation: bound queue to 10,000, drop oldest on overflow.
- TCP connection overhead: fresh connection per packet limits EPS (~500-1000). Acceptable for Phase 8; connection pooling deferred.
- Crash during investigation mode: if server dies and auto-investigate is ON, mode flips to ONE_AT_A_TIME, but then CrashMonitor must call `mutator.pause()`. Deadlock possible if CrashMonitor also calls `set_normal_mode()`. Mitigation: `pause()` sets `_paused=True`, `run()` checks `_paused` first, skips mutation entirely until `resume()`.

**Expected effort:** 3-5 days for implementation, 1-2 days for tests and migration.

---

## Phase 9: Real LLM Integration — GLM-5-Turbo & Cost Management

**Goal:** Move from MOCK mode to REAL mode using GLM-5-Turbo via Z.ai (OpenAI-compatible endpoint). Add token budgeting, cost tracking, and graceful degradation.

**Dependencies:**
- Phase 3 (LLM Agent) — ✅ done
- Phase 6 (DifferentialAnalyzer fusion) — ✅ done
- Z.ai API key and endpoint access — ✅ configured

**Pre-flight checks:**

- [ ] **9.1** Verify API connectivity end-to-end:
  ```bash
  curl -X POST https://api.z.ai/api/coding/paas/v4/chat/completions \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model":"glm-5-turbo","messages":[{"role":"user","content":"test"}],"max_tokens":10}'
  ```

- [ ] **9.2** Verify JSON structured output works with `response_format={"type": "json_object"}` — the `llm_agent.py` uses this for forced JSON grammar output

- [ ] **9.3** Verify `extra_body={"enable_thinking": false}` disables thinking mode — without this, GLM-5-Turbo uses all tokens for reasoning and returns empty `content` (already tested and confirmed working)

**Implementation Steps:**

- [ ] **9.4** Add cost tracking to `LLMAgent`:
  - Add `cost_per_input_token: float = 0.0` and `cost_per_output_token: float = 0.0` to `__init__`
  - GLM-5-Turbo pricing: input $0.60/M, output $1.92/M (Z.ai direct)
  - On each inference, compute and log: `cost = prompt_tokens * cost_per_input_token + completion_tokens * cost_per_output_token`
  - Add `_total_cost: float` accumulator, expose via `get_stats()`

- [ ] **9.5** Add token budget enforcement:
  - `session_budget_tokens` already exists in `__init__` (default 0 = unlimited)
  - But `config.yaml` has `session_budget_tokens: 0` — change to explicit default: 100,000 tokens (~$0.25 with GLM-5-Turbo)
  - Add `daily_budget_tokens` — persist to a file, reset daily
  - Add `cost_warning_threshold: float` — log WARNING when cost exceeds this ($5 default)

- [ ] **9.6** Add rate limiting:
  - Z.ai free tier likely has RPM/TPM limits
  - Add `max_rpm: int = 10` (requests per minute) — use sliding window
  - Add `_rate_limit_semaphore: asyncio.Semaphore` — acquire before each API call
  - On 429 response: exponential backoff (already in `call_llm()`), log provider-level warning

- [ ] **9.7** Add `api_base` passthrough in `config.yaml`:
  - Already done in previous session: `api_base: "https://api.z.ai/api/coding/paas/v4"`
  - Already done in `llm_agent.py`: reads `self.api_base`, passes to `call_kwargs["api_base"]`
  - Already done in `run_slow_loop.py`: `api_base=llm_cfg.get("api_base", "")`

- [ ] **9.8** Add `enable_thinking` passthrough:
  - Already done: `llm_agent.py` has `self.enable_thinking` + `extra_body` injection
  - Already done: `run_slow_loop.py` sets `agent.enable_thinking = llm_cfg.get("enable_thinking", True)`
  - Already done: `config.yaml` has `enable_thinking: false`

- [ ] **9.9** Update `.env.example`:
  - Already done (`.env.example` exists with Z.ai instructions)
  - Add GLM-5-Turbo pricing note as comment

**Environment setup:**

- [ ] **9.10** Create `.env` from `.env.example`:
  - `LLM_MODE=REAL`
  - `OPENAI_API_KEY=<key>` (user's actual key)
  - `OPENAI_API_BASE=https://api.z.ai/api/coding/paas/v4`
  
- [ ] **9.11** Verify `load_dotenv()` works:
  - `main.py:385` — `load_dotenv(override=False)`
  - `run_slow_loop.py:323` — `load_dotenv(override=False)`
  - `evaluation/evaluation_runner.py:590` — `load_dotenv(override=False)`

**Tests:**

- [ ] **9.12** Update `tests/test_llm_agent.py`:
  - Test cost tracking with mock API responses (token counts → cost calculation)
  - Test session_budget_tokens exceeded → raises RuntimeError
  - Test rate limit semaphore blocks at max_rpm

- [ ] **9.13** Real inference integration test:
  - `LLM_MODE=REAL`, `model=glm-5-turbo`, `api_base=Z.ai`
  - Send 5 sample packets, expect valid `ProtocolGrammar` JSON response
  - Measure and log: latency, token count, cost per inference

**Configuration:**

- [ ] **9.14** Verify all `config.yaml` values are correct for GLM-5-Turbo:
  ```yaml
  slow_loop:
    llm_agent:
      mode: "REAL"
      provider: "openai"
      model: "glm-5-turbo"
      api_key_env: "OPENAI_API_KEY"
      api_base: "https://api.z.ai/api/coding/paas/v4"
      enable_thinking: false
      max_tokens: 4096
      temperature: 0.2
      timeout_seconds: 60
      max_retries: 3
      retry_backoff_ms: 5000
      session_budget_tokens: 100000
      daily_budget_tokens: 500000
      max_rpm: 10
      cost_warning_threshold: 5.0
  ```

**Migration from MOCK to REAL:**

- [ ] **9.15** First run in MOCK mode (baseline): `LLM_MODE=MOCK` — confirm everything works
- [ ] **9.16** Switch to REAL mode: `LLM_MODE=REAL` — run for 1 hour, monitor:
  - Token consumption
  - Cost accrued
  - Inference latency (should be <30s for 5-20 sample packets)
  - Grammar quality (compare with DifferentialAnalyzer output)
  - Error rate (retries, timeouts, parse failures)

**Risks:**
- Z.ai API has no SLA — could go down. Mitigation: `max_retries=3`, fallback to MOCK on persistent failure
- Thinking mode returns empty `content`. Mitigation: already handled with `enable_thinking: false`
- Cost overrun if `session_budget_tokens` is set too high or misconfigured. Mitigation: start with 100,000 tokens/day budget, log cost on every inference, send alert at $5

**Expected effort:** 1-2 days for implementation and testing.

---

## Phase 10: Web UI Refactoring — Component Separation

**Goal:** Refactor `web_ui/dashboard.py` (648 lines, monolithic) into a modular structure. Separate data readers from UI components. Each component independently testable.

**Current state:** All CSS, HTML, data reading, and rendering logic lives in a single file. Changing one metric card requires understanding the entire file. Data readers cannot be tested independently.

**Dependencies:**
- Python 3.11+ — ✅
- Streamlit — ✅
- Plotly — ✅
- Pandas — ✅

**New structure:**

```
web_ui/
├── __init__.py
├── app.py                        # Entry point: st.set_page_config + main()
├── main.py                       # Orchestrator: read data → call renderers → auto-refresh
├── components/
│   ├── __init__.py
│   ├── header.py                 # render_header(status) — title bar + pipeline status badge
│   ├── metrics.py                # render_metrics(stats, rules, crashes, eps) — 5 metric cards
│   ├── eps_chart.py              # render_eps_chart(eps_history) — Plotly line chart
│   ├── crash_table.py            # render_crash_table(crashes) — expandable crash triage
│   ├── rules_table.py            # render_rules_table(rules) — dataframe with ProgressColumn
│   ├── llm_panel.py              # render_llm_insights(insights) — prompt/response side-by-side
│   └── traffic_breakdown.py      # render_traffic_breakdown(stats) — Plotly pie chart
├── data/
│   ├── __init__.py
│   ├── reader.py                 # read_traffic_stats(), read_active_rules(),
│                                 #   read_crash_records(), read_llm_insights()
│   └── eps.py                    # compute_eps(), infer_pipeline_status()
├── styles/
│   ├── __init__.py
│   └── theme.py                  # Custom CSS as a constant str (no more st.markdown blocks)
├── Dockerfile                    # Already exists
└── requirements.txt              # Already exists
```

**Implementation Steps:**

- [ ] **10.1** Create `web_ui/styles/__init__.py` and `web_ui/styles/theme.py`:
  - Move all CSS from `dashboard.py` lines 61-123 into a `CUSTOM_CSS` constant
  - Export `CUSTOM_CSS` for injection in `main.py` or `header.py`

- [ ] **10.2** Create `web_ui/data/__init__.py` and `web_ui/data/reader.py`:
  - Move `read_traffic_stats()` (lines 131-190)
  - Move `read_active_rules()` (lines 193-203)
  - Move `read_crash_records()` (lines 205-217)
  - Move `read_llm_insights()` (lines 220-228)
  - Each returns typed dict for clarity (use TypedDict or dataclass)
  - Add type hints: `def read_traffic_stats() -> TrafficStats: ...`
  - Add unit tests: mock file contents, verify parsing

- [ ] **10.3** Create `web_ui/data/eps.py`:
  - Move `compute_eps()` (lines 248-253)
  - Move `infer_pipeline_status()` (lines 230-241)
  - Add unit tests: fixed inputs → expected outputs

- [ ] **10.4** Create `web_ui/components/__init__.py`:
  - Re-export all component functions for convenience: `from web_ui.components import render_header, render_metrics, ...`

- [ ] **10.5** Create `web_ui/components/header.py`:
  - Move `render_header(status)` (lines 261-289)
  - Accept status string, render title + badge
  - No data I/O — pure UI

- [ ] **10.6** Create `web_ui/components/metrics.py`:
  - Move `render_metrics(stats, rules, crashes, eps)` (lines 292-350)
  - 5 column layout with metric cards + crash alert
  - No data I/O

- [ ] **10.7** Create `web_ui/components/eps_chart.py`:
  - Move `render_eps_chart()` (lines 353-390)
  - Accept `eps_history: list[tuple[str, float]]` as parameter (not from session_state)
  - No data I/O

- [ ] **10.8** Create `web_ui/components/crash_table.py`:
  - Move `render_crash_table(crashes)` (lines 393-439)
  - Accept crashes list, render expandable entries
  - Hex → ASCII conversion stays in this file

- [ ] **10.9** Create `web_ui/components/rules_table.py`:
  - Move `render_rules_table(rules)` (lines 442-475)
  - Accept rules list, render pandas DataFrame with ProgressColumn

- [ ] **10.10** Create `web_ui/components/llm_panel.py`:
  - Move `render_llm_insights()` (lines 478-513) — but accept `insights` as parameter instead of calling `read_llm_insights()` internally
  - No data I/O — pure UI

- [ ] **10.11** Create `web_ui/components/traffic_breakdown.py`:
  - Move `render_traffic_breakdown(stats)` (lines 516-542)
  - Accept stats dict, render Plotly pie chart

- [ ] **10.12** Create `web_ui/main.py`:
  - Move `render_footer(stats)` (lines 545-565) — inline
  - Move `main()` (lines 573-648) — the orchestrator
  - `main()` becomes:
    1. Initialize session_state (eps_history, prev_stats, last_refresh)
    2. Read all data via `data.reader.*`
    3. Compute EPS via `data.eps.*`
    4. Call each `components.render_*` in order
    5. Auto-refresh: `time.sleep(5); st.rerun()`

- [ ] **10.13** Create `web_ui/app.py`:
  - Just 3 lines:
    ```python
    from web_ui.main import main
    main()
    ```

- [ ] **10.14** Create `__init__.py` for each new package (already listed above)

**Tests:**

- [ ] **10.15** Create `tests/test_web_ui_reader.py`:
  - Mock traffic log file with 3 JSONL lines → verify `read_traffic_stats()` returns correct counts
  - Mock rules file → verify `read_active_rules()` parses correctly
  - Test error handling: missing file, malformed JSON, empty file

- [ ] **10.16** Create `tests/test_web_ui_eps.py`:
  - `compute_eps()`: 0 elapsed → 0.0, 10 new injections in 5s → 2.0
  - `infer_pipeline_status()`: no timestamp → "stopped", 15s ago → "running", 60s ago → "idle"

**Migration:**
1. Keep old `dashboard.py` working during development
2. Build new `web_ui/` package in parallel
3. Run both and compare outputs visually
4. Switch entrypoint to `web_ui/app.py`
5. Optionally keep `dashboard.py` as deprecated alias

**Risks:**
- Streamlit component state (`st.session_state`) accessed across modules — works fine since Streamlit manages state globally, not per-module
- CSS injection order: move CSS to `theme.py`, inject once in `main.py` before any `components.render_*`, not in each component. Prevents CSS conflicts

**Expected effort:** 1-2 days for refactoring, 0.5 day for tests.

---

## Phase 11: Kubernetes Cluster Orchestration — Distributed Fuzzing

**Goal:** Scale LIFA-Fuzz across a K8s cluster — multiple pods fuzzing the same or different protocols in parallel. Single orchestrator pod manages job queue, collects results, and monitors liveness.

**Dependencies:**
- Phase 8 (standalone mutator working) — not strictly required, but recommended
- Docker images for each component — already have `Dockerfile`s
- A K8s cluster (minikube for dev, GKE/EKS/AKS for production)

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                        K8s Cluster                                  │
│                                                                     │
│  ┌──────────────────────────────┐                                   │
│  │   Orchestrator Pod            │                                   │
│  │   ┌────────────────────────┐  │    ┌────────────────────────┐    │
│  │   │ Job Queue (Redis/File) │  │    │  Shared Storage        │    │
│  │   │ ├─ fuzz HTTP:80      │  │    │  (NFS / S3 / MinIO)    │    │
│  │   │ ├─ fuzz DNS:53       │  │    │  ┌──────────────────┐   │    │
│  │   │ ├─ fuzz FTP:21       │  │    │  │ crashes/         │   │    │
│  │   │ └─ fuzz SMTP:25      │  │    │  │ rules/           │   │    │
│  │   └────────────────────────┘  │    │  │ telemetry/      │   │    │
│  │   ┌────────────────────────┐  │    │  │ models/         │   │    │
│  │   │ K8s API Watcher        │  │    │  └──────────────────┘   │    │
│  │   │ (detect pod exit/crash)│  │    └────────────────────────┘    │
│  │   └────────────────────────┘  │                                   │
│  └──────────────────────────────┘                                   │
│                                                                     │
│  ┌──────────────────────────────┐  ┌──────────────────────────────┐ │
│  │   Worker Pod #1              │  │   Worker Pod #2              │ │
│  │   ┌────────────────────────┐ │  │   ┌────────────────────────┐ │ │
│  │   │ LIFA-Fuzz Instance     │ │  │   │ LIFA-Fuzz Instance     │ │ │
│  │   │ ├ Target Server: HTTP  │ │  │   │ ├ Target Server: DNS   │ │ │
│  │   │ ├ Interceptor          │ │  │   │ ├ Interceptor          │ │ │
│  │   │ ├ Mutation Engine      │ │  │   │ ├ Mutation Engine      │ │ │
│  │   │ ├ Slow Loop (LLM)     │ │  │   │ ├ Slow Loop (LLM)      │ │ │
│  │   │ └ Uploader Sidecar    │ │  │   │ └ Uploader Sidecar     │ │ │
│  │   └────────────────────────┘ │  │   └────────────────────────┘ │ │
│  │   Resources: 1CPU, 2GB RAM  │  │   Resources: 1CPU, 2GB RAM  │ │
│  └──────────────────────────────┘  └──────────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────────┐                                   │
│  │   Worker Pod #3              │                                   │
│  │   ┌────────────────────────┐ │                                   │
│  │   │ LIFA-Fuzz Instance     │ │                                   │
│  │   │ ├ Target Server: HTTP  │ │  ← Same protocol, different seed │
│  │   │ ├ Interceptor          │ │                                  │
│  │   │ ├ Mutation Engine      │ │                                  │
│  │   │ ├ Slow Loop (LLM)     │ │                                  │
│  │   │ └ Uploader Sidecar    │ │                                  │
│  │   └────────────────────────┘ │                                  │
│  └──────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Steps:**

**11A: Containerization (pre-work)**

- [ ] **11.1** Create `Dockerfile` for LIFA-Fuzz worker at project root:
  ```dockerfile
  FROM python:3.11-slim
  
  WORKDIR /app
  COPY requirements.txt .
  RUN pip install --no-cache-dir -r requirements.txt
  
  COPY . .
  
  # Expose ports: interceptor, health check
  EXPOSE 8001 8080
  
  ENTRYPOINT ["python", "main.py"]
  ```

- [ ] **11.2** Create `Dockerfile` for orchestrator:
  ```dockerfile
  FROM python:3.11-slim
  WORKDIR /app
  COPY orchestrator/ .
  RUN pip install kubernetes redis
  ENTRYPOINT ["python", "orchestrator.py"]
  ```

- [ ] **11.3** Build and push images to registry:
  ```bash
  docker build -t lifa-fuzz-worker:latest -f Dockerfile .
  docker build -t lifa-fuzz-orchestrator:latest -f orchestrator/Dockerfile .
  docker tag ... ghcr.io/your-org/lifa-fuzz-worker:latest
  docker push ...
  ```

**11B: Orchestrator Service**

- [ ] **11.4** Create `orchestrator/` directory:
  ```
  orchestrator/
  ├── __init__.py
  ├── job_queue.py        # Queue: push_job(), pop_job(), job_status()
  ├── k8s_api.py          # Create/delete/monitor worker pods via K8s API
  ├── state_store.py      # Persistent state (Redis or file-based)
  ├── scheduler.py        # Decision logic: which job → which node
  └── main.py             # Long-running event loop
  ```

- [ ] **11.5** Implement `job_queue.py`:
  - Job spec dataclass:
    ```python
    @dataclass
    class FuzzJob:
        job_id: str
        protocol: str               # "http", "dns", "custom"
        target_image: str           # Docker image for target server
        target_port: int            # 80, 53, etc.
        duration_seconds: int       # 3600 = 1 hour
        llm_mode: str               # "MOCK" or "REAL"
        mutator_mode: str           # "random" or "smart"
        status: str                 # "pending", "running", "completed", "failed"
        created_at: str
        started_at: Optional[str]
        completed_at: Optional[str]
        result_path: Optional[str]  # S3 key for results
    ```
  - Queue backed by Redis (production) or JSON file (dev)
  - Methods: `push(job)`, `pop() → FuzzJob | None`, `update_status(job_id, status)`, `list_jobs(status)`

- [ ] **11.6** Implement `k8s_api.py`:
  - Uses `kubernetes` Python client (`pip install kubernetes`)
  - `create_worker_pod(job)` — create pod spec with:
    - Job ID as pod label
    - Environment variables (target host/port, LLM mode, etc.)
    - Resource limits (CPU/memory per pod)
    - EmptyDir for local files, sidecar for upload
  - `delete_worker_pod(job_id)` — clean up on completion
  - `watch_pods(label_selector)` — async generator for pod status events
  - `get_pod_logs(job_id)` — fetch logs before deletion (debugging)

- [ ] **11.7** Implement `state_store.py`:
  - Store cluster-level state: job queue, pod assignments, aggregate stats
  - Two modes: Redis (production, fast) or JSON file (dev, simple)
  - Interface: `get(key)`, `set(key, value)`, `lock(key)`, `unlock(key)`

- [ ] **11.8** Implement `scheduler.py`:
  - Simple FIFO scheduler initially: pop oldest pending job, assign to next available node
  - Future: priority-based, resource-aware (don't put two CPU-heavy jobs on same node)
  - `schedule_next() → (FuzzJob | None, WorkerNode | None)`

- [ ] **11.9** Implement `orchestrator/main.py`:
  - Main loop (every 5 seconds):
    1. Check for completed/failed pods (via K8s API watcher)
    2. For completed: upload results, mark job done, clean up pod
    3. For failed: increment retry count, re-queue or mark failed
    4. Check for pending jobs in queue
    5. If cluster has capacity (below max pods), schedule next job
    6. Health check: HTTP endpoint for K8s liveness probe

**11C: Worker Pod — Uploader Sidecar**

- [ ] **11.10** Create `sidecar/uploader.py`:
  - Watches `./results/` and `./crashes/` directories
  - On file creation: upload to S3/MinIO with path `{job_id}/{filename}`
  - On job completion: upload final telemetry, signal orchestrator
  - Uses `boto3` (S3-compatible: MinIO, GCS, R2)

- [ ] **11.11** Update `main.py` to support pod mode:
  - Accept all params via environment variables (not just config.yaml)
  - Add flag: `IN_CLUSTER_MODE` — when set, use sidecar for output instead of local filesystem
  - Add health check endpoint (HTTP port 8080, return `{"status": "ok", "eps": 42.0}`)
  - Handle SIGTERM gracefully: save state, upload artifacts, exit cleanly

**11D: K8s Manifests**

- [ ] **11.12** Create `k8s/` directory:
  ```
  k8s/
  ├── namespace.yaml           # lifa-fuzz namespace
  ├── orchestrator-deploy.yaml # Deployment for orchestrator
  ├── orchestrator-rbac.yaml   # ServiceAccount + Role + RoleBinding (CRUD pods)
  ├── orchestrator-svc.yaml    # Service (internal cluster IP)
  ├── storage-class.yaml       # If using NFS
  ├── pvc.yaml                 # PersistentVolumeClaim for shared storage
  ├── configmap.yaml           # Cluster-wide config (LLM endpoint, defaults)
  └── secret.yaml              # .env values (encrypted)
  ```

- [ ] **11.13** Create `k8s/configmap.yaml`:
  ```yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: lifa-fuzz-config
    namespace: lifa-fuzz
  data:
    config.yaml: |
      slow_loop:
        llm_agent:
          mode: "REAL"
          model: "glm-5-turbo"
          api_key_env: "OPENAI_API_KEY"
          api_base: "https://api.z.ai/api/coding/paas/v4"
          enable_thinking: false
          session_budget_tokens: 100000
      ...
  ```

- [ ] **11.14** Create `k8s/secret.yaml`:
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: lifa-fuzz-secret
    namespace: lifa-fuzz
  type: Opaque
  stringData:
    .env: |
      OPENAI_API_KEY=...  # from .env, not committed
      LLM_MODE=REAL
  ```

**11E: Testing on Minikube**

- [ ] **11.15** Write test script `scripts/k8s_test.sh`:
  ```bash
  #!/bin/bash
  # 1. Start minikube
  minikube start --cpus=4 --memory=8g
  
  # 2. Build images inside minikube
  eval $(minikube docker-env)
  docker build -t lifa-fuzz-worker:test -f k8s/Dockerfile.worker .
  docker build -t lifa-fuzz-orchestrator:test -f k8s/Dockerfile.orchestrator .
  
  # 3. Deploy manifests
  kubectl apply -f k8s/namespace.yaml
  kubectl apply -f k8s/configmap.yaml
  kubectl apply -f k8s/secret.yaml
  kubectl apply -f k8s/orchestrator-rbac.yaml
  kubectl apply -f k8s/orchestrator-deploy.yaml
  
  # 4. Push a test job
  kubectl exec deploy/lifa-fuzz-orchestrator -- python -c "
    from orchestrator.job_queue import push_job
    push_job(FuzzJob(
        job_id='test-001',
        protocol='lifa',
        target_image='lifa-fuzz-server:latest',
        target_port=9000,
        duration_seconds=120,
        llm_mode='MOCK',
        mutator_mode='smart',
    ))
  "
  
  # 5. Watch
  kubectl get pods -n lifa-fuzz -w
  ```

**Risks:**
- Network overhead: each pod calls LLM API independently. 10 pods at 1 inference/min = 10 API calls/min with same GLM-5-Turbo key. Z.ai rate limiting may kick in. Mitigation: configure `max_rpm` per pod (e.g., 6 RPM = 1 inference per 10s), or use separate API keys per pod
- Shared storage contention: all pods writing crash results to same S3 bucket. Mitigation: prefix per job ID, S3 handles millions of keys
- Stateful target servers: some protocols need persistent state (e.g., authenticated session). Mitigation: for first version, only fuzz stateless protocols; stateful support is future work
- Orchestrator SPOF: if orchestrator pod dies, running workers complete but no new jobs start. Mitigation: K8s Deployment with `replicas: 1` + `restartPolicy: Always`; orchestrator is stateless (jobs stored in Redis/file)

**Expected effort:** 3-5 days for scaffolding, 2-3 days for testing.

---

## Phase 12: Crash Manager Integration — Deduplication & Investigation

**Goal:** Integrate the crash deduplication engine from `docs/crash_manager.py` and implement the crash investigation workflow (auto-switch to ONE_AT_A_TIME → pinpoint exact field → generate report).

**Dependencies:**
- Phase 8 (new MutationEngine with scheduler) — provides `set_investigation_mode()`
- `docs/crash_manager.py` — already designed, needs deployment to `shared/crash_manager.py`

**Schema Pre-work:**

- [ ] **12.1** Verify `CrashReport` model exists in `shared/schemas.py` (Phase 6 should have added it)
- [ ] **12.2** Weigh two-level dedup approach from `docs/crash_manager.py`:
  - Primary: `SHA256(payload)[:16]` — exact byte match
  - Secondary: `SHA256(payload[:16] + len_bytes)[:8]` — structural similarity (same header, different payload)
  - Decision: Primary is essential; Secondary is optional for Phase 12 (add in Phase 13 if noise is high)

**Implementation Steps:**

- [ ] **12.3** Deploy `docs/crash_manager.py` to `shared/crash_manager.py`:
  - `CrashManager.__init__(crash_dir)` — creates directory, initializes index
  - `CrashManager.load()` — load existing `crash_index.json` from disk
  - `CrashManager.record(payload, crash_type, rule_set_id, notes) -> RecordResult` — dedup + save PoC + update index
  - `CrashManager.is_known(payload) -> bool` — O(1) hot-loop check
  - `CrashManager.get_statistics() -> CrashStatistics` — unique hits, total hits, dedup ratio, top 5 signatures

- [ ] **12.4** Wire CrashManager into MutationEngine:
  - Add `crash_manager` parameter to `MutationEngine.__init__`
  - In `_send()` on `ConnectionRefusedError` (crash), call `crash_manager.record(payload, "connection_refused", rule_set_id)`
  - If `RecordResult.is_new` AND `auto_investigate` → call `set_investigation_mode(reason=f"new crash {sig}")`

- [ ] **12.5** Wire CrashManager into CrashMonitor:
  - CrashMonitor polls `is_target_alive()` every 500ms (config: `fast_loop.crash_monitor.poll_interval_ms`)
  - On crash detected (target not alive):
    1. Get last injected packet from MutationEngine
    2. Call `CrashManager.record(payload, signal_type, rule_set_id)`
    3. If new crash: save PoC binary + JSON report to `./crashes/{sig}.bin` and `{sig}.report.json`
    4. Signal Interceptor to pause
    5. Signal MutationEngine to pause
    6. Wait for Sandbox to reset state (`reset_state()`)
    7. Signal Interceptor and MutationEngine to resume

- [ ] **12.6** Add crash report format:
  ```json
  {
    "crash_id": "a1b2c3d4e5f6...",
    "detected_at": "2026-05-29T15:30:00Z",
    "triggering_packet_hex": "deadbeef...",
    "triggering_packet_len": 64,
    "active_rule_set_id": "rs_abc123",
    "active_rule": "field_03_length_BOUNDARY(0)",
    "investigation_mode": true,
    "signal": "SIGSEGV",
    "exit_code": 139,
    "crash_type": "connection_refused",
    "poc_file": "crashes/a1b2c3d4e5f6.bin",
    "notes": "Triggered by boundary value 0 on length field at offset 6"
  }
  ```

**Investigation Workflow:**

- [ ] **12.7** Implement investigation close-out:
  - After `isolation_budget` (500 sends), MutationEngine auto-reverts to RANDOM_SUBSET
  - On revert: generate investigation report — which field was under test when crash was re-triggered?
  - If crash not reproduced during investigation, log: "Crash not reproducible in investigation mode (intermittent)"
  - If crash reproduced: mark the exact field as "confirmed trigger", add to crash report

**Tests:**

- [ ] **12.8** Tests for crash dedup:
  - Same payload twice → `is_new=False`, `duplicate_count=1`
  - Different payloads → `is_new=True` for both
  - Load existing index → subsequent duplicate not re-reported
  - Index persistence: crash → stop → restart → same crash reported as duplicate

- [ ] **12.9** Tests for investigation auto-switch:
  - Mutator in RANDOM_SUBSET mode
  - Inject a crash payload
  - Verify `set_investigation_mode()` was called
  - Verify scheduler switched to OneAtATime
  - After budget exhausted, verify reverted to RandomSubset

**Expected effort:** 2-3 days for integration, 1 day for tests.

---

## Phase 13: Firecracker MicroVM Migration

**Goal:** Replace Docker sandbox with Firecracker MicroVM for sub-10ms reset time + stronger isolation.

**Dependencies:**
- Phase 1 (BaseSandbox abstraction) — ✅ done
- `sandbox/firecracker_driver.py` — stub exists
- `sandbox/setup_firecracker.sh` — now fixed, downloads v1.7.0 successfully
- Kernel + rootfs images — need to be created

**Pre-work:**

- [ ] **13.1** Download kernel image:
  ```bash
  curl -fsSL -o sandbox/firecracker_env/vmlinux \
    https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
  ```

- [ ] **13.2** Create rootfs ext4 image from Docker image:
  ```bash
  # Extract filesystem from lifa-fuzz-server Docker image
  docker create --name lifa-tmp lifa-fuzz-server:latest
  docker export lifa-tmp -o sandbox/firecracker_env/rootfs.tar
  docker rm lifa-tmp
  
  # Create ext4 image
  dd if=/dev/zero of=sandbox/firecracker_env/rootfs.ext4 bs=1M count=500
  mkfs.ext4 sandbox/firecracker_env/rootfs.ext4
  
  # Mount and extract
  mkdir -p /mnt/lifa-rootfs
  sudo mount sandbox/firecracker_env/rootfs.ext4 /mnt/lifa-rootfs
  sudo tar -xf sandbox/firecracker_env/rootfs.tar -C /mnt/lifa-rootfs
  sudo umount /mnt/lifa-rootfs
  ```

- [ ] **13.3** Test firecracker manually (validate environment):
  ```bash
  # Terminal 1:
  ./sandbox/firecracker_env/firecracker --api-sock /tmp/firecracker.sock
  
  # Terminal 2:
  # Configure kernel, rootfs, start VM
  # ... (Firecracker API calls via curl)
  ```

**Implementation Steps:**

- [ ] **13.4** Implement `FirecrackerSandbox` in `sandbox/firecracker_driver.py`:
  - `start()`:
    1. Launch `firecracker` process with `--api-sock /tmp/lifa-fc.sock`
    2. Wait for API socket to appear (poll every 100ms, timeout 10s)
    3. Configure boot-source via PUT `/boot-source` (kernel image path + boot args)
    4. Configure rootfs drive via PUT `/drives/rootfs`
    5. Start VM via PUT `/actions` with `{"action_type": "InstanceStart"}`
    6. Wait for VM network to be ready
  - `stop()`:
    1. Send PUT `/actions` with `{"action_type": "SendCtrlAltDel"}` (graceful)
    2. If no response in 3s, kill firecracker process (force)
  - `reset_state()`:
    1. Stop VM
    2. Delete rootfs overlay (restore clean snapshot)
    3. Start VM
    4. Expected: < 10ms with snapshot support
  - `is_target_alive()`:
    1. TCP connect to VM's IP on target port
    2. Timeout: 1s
  - `get_target_info()`: return VM's IP, MAC, tap interface name
  - `get_last_crash_info()`: parse VM console output for exit code / panic message

- [ ] **13.5** Add snapshot/restore optimization:
  - After first successful boot: take full VM snapshot via Pause → SnapshotCreate → Resume
  - Snapshot stored in `sandbox/firecracker_env/snapshots/{version}/`
  - `reset_state()` with snapshot: Send CtrlAltDel → wait for VM to stop → Load snapshot → Resume
  - Without snapshot: full boot ~500ms (similar to Docker)
  - With snapshot: expected < 10ms

- [ ] **13.6** Update `config.yaml`:
  ```yaml
  sandbox:
    driver: "firecracker"  # switch from "docker"
    fc_kernel: "sandbox/firecracker_env/vmlinux"
    fc_rootfs: "sandbox/firecracker_env/rootfs.ext4"
    fc_snapshot_dir: "sandbox/firecracker_env/snapshots"
    fc_use_snapshot: true
    fc_vcpu_count: 1
    fc_mem_size_mib: 256
    fc_network_iface: "lifa-fc-tap0"
  ```

**Risks:**
- Firecracker requires root/`sudo` for `/dev/kvm` access. Mitigation: add user to `kvm` group, or run firecracker as root in Docker container
- No cgroup limits per VM (unlike Docker). Mitigation: Firecracker has built-in rate limiting for CPU/memory
- Network setup: need to create a TAP interface and bridge per VM. Mitigation: automate with `ip tuntap add` + `brctl`
- Snapshot compatibility: snapshot from v1.7.0 may not load on v1.8.0. Mitigation: pin version, don't auto-upgrade

**Expected effort:** 3-5 days for initial implementation, 2-3 days for snapshot/restore optimization.

---

## Phase 14: Coverage-Guided Mode (Hybrid Fuzzing)

**Goal:** Add feedback loop from target server to mutation engine — when target returns "interesting" responses (non-crash but unusual), prioritize those seeds for further mutation.

**Current limitation:** LIFA-Fuzz is fully black-box. It sends mutations without any feedback about which mutations were "interesting." The only signal is crash/no-crash.

**Approach:** Three levels of server response feedback:

- [ ] **14.1** **Level 1: Response Length Analysis** (easy, high ROI):
  - Track response lengths per seed
  - If response length changes significantly from baseline → mark seed as "interesting"
  - Interesting seeds get 2x mutation budget next round

- [ ] **14.2** **Level 2: Response Entropy Analysis** (medium):
  - Compute Shannon entropy of response bytes
  - Low entropy (same bytes repeated) + different from baseline → possible error page or protocol violation
  - High entropy + different from baseline → possible deep code path reached
  - Weight seeds by response entropy deviation

- [ ] **14.3** **Level 3: LLM-as-Classifier** (expensive, deferred):
  - Send unusual response pairs to LLM: "Did this mutated input trigger different server behavior from the baseline?"
  - LLM score: 0 = same behavior, 1 = definitely different
  - Useful only when Level 1+2 produce too many "interesting" candidates

**Implementation:**

- [ ] **14.4** Add `ResponseClassifier` to `fast_loop/response_classifier.py`:
  - `record_response(seed_id, response_bytes, baseline_bytes) -> InterestLevel`
  - Track baseline per seed type
  - `InterestLevel` enum: `BANAL = 0`, `SLIGHTLY_INTERESTING = 1`, `VERY_INTERESTING = 2`

- [ ] **14.5** Update `_send()` in mutator:
  - After receiving response, pass to `ResponseClassifier`
  - If interesting: set `PacketStatus.INTERESTING` instead of just `ACCEPTED`
  - `_update_stats()` tracks interesting counts

- [ ] **14.6** Update `_pick_seed()`:
  - Instead of pure round-robin, weight by interest level
  - `interesting_weight = 3`, `normal_weight = 1`
  - Use `random.choices(weights=[...])` for probabilitic selection

**Expected effort:** 2-3 days for Level 1+2, 2 days for Level 3 (deferred).

---

## Phase 15: CI/CD & Reproducibility

**Goal:** Ensure the research is reproducible: automated test suite, Docker-based CI, artifact archiving.

- [ ] **15.1** Create `.github/workflows/test.yml`:
  ```yaml
  name: Tests
  on: [push, pull_request]
  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with: { python-version: "3.11" }
        - run: pip install -r requirements.txt
        - run: pytest tests/ -v --tb=short
  ```

- [ ] **15.2** Create `.github/workflows/docker-build.yml`:
  - Build docker images for sandbox (target server + client)
  - Push to GHCR on tag

- [ ] **15.3** Add `Makefile`:
  ```makefile
  test:
      pytest tests/ -v --tb=short --cov=shared --cov=fast_loop --cov=slow_loop
  
  docker-sandbox:
      docker compose -f sandbox/docker-compose.yml build
  
  e2e-mock:
      python main.py --duration 60 --llm-mode MOCK
  
  lint:
      ruff check .
      mypy shared/ fast_loop/ slow_loop/
  ```

- [ ] **15.4** Add badge to `README.md`:
  ```markdown
  [![Tests](https://github.com/your-org/lifa-fuzz/actions/workflows/test.yml/badge.svg)](...)
  ```

**Expected effort:** 0.5 day for basic setup.

---

## Summary Timeline

| Phase | Description | Effort | Dependencies |
|-------|-------------|--------|--------------|
| **8** | Mutation Engine Redesign | 5-7 days | Phase 2, 6 |
| **9** | Real LLM Integration | 2-3 days | Phase 3, 6 |
| **10** | Web UI Refactoring | 2-3 days | Phase 4 |
| **11** | K8s Cluster Orchestration | 6-8 days | Phase 8 (preferred) |
| **12** | Crash Manager Integration | 3-4 days | Phase 8 |
| **13** | Firecracker Migration | 6-8 days | Phase 1 |
| **14** | Coverage-Guided Mode | 3-5 days | Phase 8 |
| **15** | CI/CD & Reproducibility | 1 day | — |

**Priority recommendation:**
1. Phase 8 (mutator redesign) — highest impact on crash isolation
2. Phase 12 (crash manager) — depends on Phase 8, closes the dedup loop
3. Phase 9 (real LLM) — already partially done, low effort
4. Phase 10 (web UI refactoring) — cosmetic but improves maintainability
5. Phase 14 (coverage-guided) — biggest research novelty
6. Phase 11 (K8s) — only if you have cluster budget
7. Phase 13 (Firecracker) — only if reset time becomes bottleneck
8. Phase 15 (CI/CD) — sprinkle throughout all phases
