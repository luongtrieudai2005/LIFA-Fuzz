# Claude Code Prompt Guide — Mutation Scheduler Improvements
# LIFA-Fuzz / fast_loop/mutator.py + mutation_operators.py

Đây là tập hợp các prompts đã được viết sẵn để paste vào Claude Code.
Thực hiện theo đúng thứ tự ưu tiên từ trên xuống.

---

## CÁCH SỬ DỤNG

```bash
# Mở Claude Code trong project root
claude

# Paste từng prompt bên dưới, chờ Claude Code hoàn thành, review diff, rồi tiếp tục
```

---

## ════════════════════════════════════════════
## PRIORITY 1 — BUG FIX (thực hiện ngay)
## ════════════════════════════════════════════

---

### PROMPT 1-A: Sửa race condition trong auto-revert (Issue F)

```
Context:
  File: fast_loop/mutator.py
  Line 681: asyncio.create_task(self.set_normal_mode())
  Line 467: set_investigation_mode() has guard "if already ONE_AT_A_TIME: return"

Problem:
  The auto-revert from ONE_AT_A_TIME → RANDOM_SUBSET uses fire-and-forget
  asyncio.create_task() while still holding _sched_lock. There is a race:
  1. Budget exhausts → create_task(set_normal_mode) scheduled
  2. Another crash fires BEFORE task runs → set_investigation_mode() hits the
     "already ONE_AT_A_TIME, return" guard and silently drops the crash trigger.
  3. set_normal_mode() finally runs → we are now in RANDOM_SUBSET, but the
     second crash was never recorded as a trigger for investigation.

Fix required:
  In _build_mutant() (lines 677-682): replace the fire-and-forget pattern with
  a dedicated asyncio.Event flag. Add a bool flag self._revert_pending = False
  to __init__. When budget is exhausted, set self._revert_pending = True (under
  the lock). In the main run() loop, after each _send() call, check and consume
  the flag: if self._revert_pending: self._revert_pending = False; await self.set_normal_mode().
  This makes the revert deterministic and serialized with the hot loop.

  Also fix: when a crash arrives and mode is already ONE_AT_A_TIME, instead of
  silently returning, call self._scheduler.reset() to restart investigation from
  field 0 with a fresh budget. Log: "Crash during investigation — restarting
  field scan from field 0".

Acceptance criteria:
  - No asyncio.create_task() inside _build_mutant() for set_normal_mode()
  - _revert_pending flag added to __init__ and MutatorStats
  - set_investigation_mode() when already in ONE_AT_A_TIME: calls scheduler.reset()
    and logs the event instead of silently returning
  - Existing tests for set_investigation_mode() and set_normal_mode() still pass
```

---

### PROMPT 1-B: Sửa DUMB mode inconsistency khi rule_set là None (Issue G)

```
Context:
  File: fast_loop/mutator.py
  Line 90-102: MutationMode enum (RANDOM_SUBSET, ONE_AT_A_TIME, ALL_FIELDS, DUMB)
  Line 641-655: _build_mutant() — when rule_set is None, goes to dumb path
                BUT self._mode stays at whatever it was (even ONE_AT_A_TIME)
  Line 311: default mode is RANDOM_SUBSET

Problem:
  When rule_set is None, _build_mutant() bypasses the scheduler entirely and
  calls _dumb_mutate(). But self._mode is still RANDOM_SUBSET (or worse,
  ONE_AT_A_TIME from a previous investigation). This means:
  1. Stats report wrong mode to dashboard
  2. investigation_field stays set even though we're doing dumb mutations
  3. If mode is ONE_AT_A_TIME, set_normal_mode() might be called while dumb
     mutating — wasted mode switch

Fix required:
  In update_rule_set() (line 499): when a new non-None rule_set arrives and
  self._mode is DUMB, automatically transition to RANDOM_SUBSET.

  In _build_mutant() (line 647): when rule_set is None, check if self._mode
  is not MutationMode.DUMB. If so, set self._mode = MutationMode.DUMB and
  self._stats.mode = "dumb" WITHOUT acquiring _sched_lock (just a write,
  no scheduler needed). Log once: "No rule set — entering DUMB mode".

  Do NOT change the scheduler instance when entering dumb mode — it's
  irrelevant until rules arrive.

Acceptance criteria:
  - self._stats.mode == "dumb" whenever rule_set is None
  - Automatic transition back to RANDOM_SUBSET when first rule_set arrives
  - investigation_field set to None when in DUMB mode
  - No new lock acquisitions in the dumb path
```

---

## ════════════════════════════════════════════
## PRIORITY 2 — ENHANCEMENT (implement this week)
## ════════════════════════════════════════════

---

### PROMPT 2-A: Dynamic k scaling in RandomSubsetScheduler (Issue A)

```
Context:
  File: fast_loop/mutator.py
  Line 141: self.k = k  (hardcoded k=2 passed at init)
  Line 144-148: RandomSubsetScheduler.select() uses min(self.k, len(fields))
  Line 288: MutationEngine.__init__ has k: int = 2

Problem:
  k=2 is always used regardless of protocol complexity. For a protocol with
  3 fields, k=2 is great (covers 67% per send). For 15 fields, k=2 means
  each send covers only 13% — very slow path through the field space.
  For 1 field, k=2 is clamped to 1 anyway.

  Research baseline (AFL, libFuzzer): adaptive k based on corpus size.
  For fuzzing, empirical sweet spot is k ≈ sqrt(num_fields).

Fix required:
  In RandomSubsetScheduler.__init__: add a parameter adaptive: bool = True.
  In RandomSubsetScheduler.select():
    if self.adaptive:
        k = max(1, min(int(len(mutable_fields) ** 0.5), len(mutable_fields) // 2 + 1))
    else:
        k = min(self.k, len(mutable_fields))
  Add k_used: int to the return (or update a counter) so the caller can log it.

  In MutationEngine.__init__: add adaptive_k: bool = True parameter.
  Pass it to RandomSubsetScheduler. Keep self.k as the MINIMUM k.
  Update MutationEngine.set_normal_mode() to pass adaptive_k=self.adaptive_k.

  Update MutatorStats to include k_this_round: int (the k actually used this send).
  Update the heartbeat log in _update_stats() to show "k={k_this_round}".

  IMPORTANT: ONE_AT_A_TIME mode always uses k=1 regardless — do NOT change it.

Acceptance criteria:
  - k=1 for 1 field, k=2 for 4-8 fields, k=3 for 9-16 fields, k=4 for 17+ fields
  - MutationEngine(k=2, adaptive_k=False) preserves old behavior (backward compat)
  - k is logged in heartbeat output
  - No change to OneAtATimeScheduler
```

---

### PROMPT 2-B: Weighted field selection by strategy priority (Issue C)

```
Context:
  File: fast_loop/mutator.py
  Line 128-152: RandomSubsetScheduler — currently uses random.sample (uniform)
  File: shared/schemas.py — FieldRule has: mutation_strategy, confidence fields
  MutationStrategy values include: BOUNDARY_VALUES, DICTIONARY, RANDOM_BYTES,
  BIT_FLIP, INCREMENT, CALCULATED, STATIC, SKIP

Problem:
  All mutable fields are sampled uniformly. But from security research, fields
  with BOUNDARY_VALUES (length fields) and DICTIONARY (opcodes) historically
  produce 80%+ of exploitable crashes. Treating them equally with RANDOM_BYTES
  (payload) wastes cycles on low-yield mutations.

  Also, FieldRule.confidence (0.0-1.0) from the LLM represents how sure the
  model is about the field classification. Low-confidence fields should be
  weighted less (we don't trust the mutation strategy for uncertain fields).

Fix required:
  Create a new class WeightedScheduler(_BaseScheduler) in mutator.py,
  placed after RandomSubsetScheduler (around line 153):

  STRATEGY_WEIGHTS dict (class-level constant):
    BOUNDARY_VALUES → 4.0   (length fields: #1 bug source)
    DICTIONARY      → 3.0   (opcodes: triggers different code paths)
    INCREMENT       → 2.5   (sequence numbers: state confusion)
    BIT_FLIP        → 1.5   (flags/enums: subtle state bugs)
    RANDOM_BYTES    → 1.0   (payload: baseline)
    CALCULATED      → 2.0   (derived fields: recalculation bugs)
    SKIP            → 0.0   (excluded from selection)

  select() implementation:
    weights = [STRATEGY_WEIGHTS.get(f.mutation_strategy, 1.0) * max(0.1, f.confidence)
               for f in mutable_fields]
    total = sum(weights)
    if total == 0: return random.sample(mutable_fields, min(k, len(mutable_fields)))
    normalized = [w / total for w in weights]
    chosen_indices = set()
    while len(chosen_indices) < min(k, len(mutable_fields)):
        idx = random.choices(range(len(mutable_fields)), weights=normalized, k=1)[0]
        chosen_indices.add(idx)
    return [mutable_fields[i] for i in chosen_indices]

  In MutationEngine.__init__: add use_weighted: bool = True parameter.
  In set_normal_mode(): use WeightedScheduler if use_weighted else RandomSubsetScheduler.
  Keep RandomSubsetScheduler for backward compat and as fallback if all weights=0.

  IMPORTANT: WeightedScheduler should still respect adaptive_k from Prompt 2-A.
  Pass k and adaptive_k to WeightedScheduler.__init__.

Acceptance criteria:
  - BOUNDARY_VALUES fields selected ~4x more often than RANDOM_BYTES in statistical tests
  - confidence=0.1 field selected ~10x less than confidence=1.0 field of same strategy
  - Falls back to uniform if all weights are 0 (e.g., all fields are SKIP)
  - MutationEngine(use_weighted=False) gives exact old behavior
  - WeightedScheduler.description property returns human-readable weight summary
```

---

### PROMPT 2-C: Log offending field before investigation reset (Issue D)

```
Context:
  File: fast_loop/mutator.py
  Line 464-483: set_investigation_mode() — creates NEW OneAtATimeScheduler,
                resets cursor to 0
  Line 485-497: set_normal_mode() — creates NEW RandomSubsetScheduler, no memory

Problem:
  When investigation mode completes (budget exhausted) and reverts to RANDOM_SUBSET,
  the system loses all knowledge of which fields were tested and whether any
  produced crashes. self._stats.investigation_field is reset to None, and the
  old OneAtATimeScheduler with its cursor state is discarded.

  For research/paper purposes, we need to know: during the investigation phase,
  which field index was being mutated when the confirming crash occurred?

Fix required:
  1. Add to MutatorStats: last_investigation_summary: dict = field(default_factory=dict)

  2. In set_normal_mode() (line 485): BEFORE replacing the scheduler, if
     isinstance(self._scheduler, OneAtATimeScheduler), capture a summary:
     self._stats.last_investigation_summary = {
         "field_index_at_revert": self._scheduler.get_current_field_index(),
         "total_sends": self._scheduler._sends_this_mode,
         "field_hits": dict(self._scheduler._field_hits),
         "reverted_at": time.monotonic(),
         "reason": "budget_exhausted",
     }
     Log this dict at WARNING level: "Investigation complete — summary: {summary}"

  3. Add public method to MutationEngine:
     def get_last_investigation_summary(self) -> dict:
         return dict(self._stats.last_investigation_summary)

  4. In crash_manager.py or the crash_callback: when crash_callback(payload, type)
     is called, also pass self._last_injected_rule_id so the crash report
     includes which field was being investigated at crash time.
     (Check if crash_callback signature supports this — if not, just log it.)

Acceptance criteria:
  - last_investigation_summary populated on every revert from ONE_AT_A_TIME
  - Summary logged at WARNING level with field index and total sends
  - get_last_investigation_summary() returns empty dict {} before first investigation
  - No change to existing investigation logic or scheduler creation
```

---

### PROMPT 2-D: Make investigation budgets configurable (Issue E)

```
Context:
  File: fast_loop/mutator.py
  Line 170-175: OneAtATimeScheduler.__init__(budget_per_field=20, isolation_budget=500)
  Line 289-293: MutationEngine.__init__ has investigation_budget: int = 500
                but no way to set budget_per_field

Problem:
  budget_per_field=20 and isolation_budget=500 are partially hardcoded.
  MutationEngine only exposes investigation_budget (maps to isolation_budget)
  but budget_per_field is always 20 regardless of EPS or protocol complexity.

  For a protocol with 10 fields: 500/(10*20) = 2.5 full cycles. Might be enough.
  For 25 fields at 500 EPS: each field gets 20 sends = 0.04 seconds of testing.
  This is clearly insufficient for statistical significance.

  Better heuristic: budget_per_field should scale with EPS.
  target_time_per_field = 5 seconds → budget_per_field = max(20, int(5 * current_eps))

Fix required:
  1. In MutationEngine.__init__, add: budget_per_field: int = 0 parameter.
     If budget_per_field == 0: use adaptive calculation.
     Store as self.budget_per_field = budget_per_field.

  2. In set_investigation_mode() (line 470): calculate adaptive budget_per_field:
     if self.budget_per_field > 0:
         bpf = self.budget_per_field  # explicit override
     else:
         # Adaptive: target ~5s per field at current EPS
         eps = self._stats.current_eps or 10.0
         bpf = max(20, min(200, int(5.0 * eps)))
     self._scheduler = OneAtATimeScheduler(
         budget_per_field=bpf,
         isolation_budget=self.investigation_budget,
     )

  3. Log the chosen budget_per_field in the "MODE → ONE_AT_A_TIME" log line.

  4. In config.yaml (or wherever it's read), document these two parameters:
     fast_loop:
       mutator:
         investigation_budget: 500      # total sends in ONE_AT_A_TIME mode
         budget_per_field: 0            # 0 = adaptive (5s * EPS per field)

Acceptance criteria:
  - MutationEngine(budget_per_field=50) uses exactly 50 hits per field
  - MutationEngine(budget_per_field=0) adapts to current EPS (logged at start of investigation)
  - budget_per_field and isolation_budget both logged when entering ONE_AT_A_TIME mode
  - Backward compat: MutationEngine(investigation_budget=500) still works
```

---

## ════════════════════════════════════════════
## PRIORITY 3 — ARCHITECTURE (sprint tiếp theo)
## ════════════════════════════════════════════

---

### PROMPT 3-A: ALL_FIELDS warm-up phase (Issue H)

```
Context:
  File: fast_loop/mutator.py
  Line 217-229: AllFieldsScheduler — exists but never used in production
  Line 390-438: run() loop — starts directly in RANDOM_SUBSET after seed drain

Problem:
  On first connection, we have no idea which fields matter. Going straight to
  RANDOM_SUBSET (k=2) means we might never touch some fields in the first minute.
  AFL and libFuzzer both do a "fast initial sweep" before settling into their
  normal exploration strategy.

  For LIFA-Fuzz: the first 30 seconds should sweep ALL mutable fields once
  (ALL_FIELDS mode) to get a baseline response profile. If any field sweep
  causes a crash, we immediately know the crash class. After 30s or one full
  cycle through all fields, revert to RANDOM_SUBSET.

Fix required:
  1. In MutationEngine.__init__: add warmup_seconds: float = 30.0 parameter.
     Store self.warmup_seconds = warmup_seconds.
     Add self._warmup_done: bool = False.

  2. In run() loop, just before the while loop:
     if self.warmup_seconds > 0 and not self._warmup_done:
         log.info(f"Starting ALL_FIELDS warm-up ({self.warmup_seconds}s)")
         async with self._sched_lock:
             self._scheduler = AllFieldsScheduler()
             self._mode = MutationMode.ALL_FIELDS
             self._stats.mode = "all_fields"
         warmup_deadline = time.monotonic() + self.warmup_seconds
     else:
         warmup_deadline = 0.0

  3. Inside the while loop, after _update_stats(), add:
     if warmup_deadline > 0 and time.monotonic() >= warmup_deadline:
         self._warmup_done = True
         await self.set_normal_mode()
         warmup_deadline = 0.0
         log.info("Warm-up complete — switching to RANDOM_SUBSET/WEIGHTED mode")

  4. Add warmup_seconds: 30 to config.yaml under fast_loop.mutator.
     Allow warmup_seconds: 0 to disable (backward compat with tests).

  5. IMPORTANT: crashes during warm-up should NOT trigger set_investigation_mode().
     In run() line 434-438, add guard: if not (self._mode == ALL_FIELDS and not self._warmup_done):

Acceptance criteria:
  - First 30s: ALL_FIELDS scheduler, all mutable fields mutated every send
  - After 30s: automatic transition to normal mode (WEIGHTED or RANDOM_SUBSET)
  - warmup_seconds=0 completely disables warm-up (old behavior)
  - Crashes during warm-up: logged but investigation NOT triggered
  - Warm-up duration logged in heartbeat stats
```

---

### PROMPT 3-B: KILL_SERVER_PAYLOADS attribution (Issue I)

```
Context:
  File: fast_loop/mutator.py
  Line 79-83: KILL_SERVER_PAYLOADS — 3 hardcoded crash payloads
  These are sent via _send() directly, bypassing _build_mutant() and the scheduler.
  (Find where KILL_SERVER_PAYLOADS are actually sent — search for "KILL_SERVER" in
  the run() loop or wherever they're dispatched)

Problem:
  When a KILL_SERVER_PAYLOAD triggers a crash:
  - self._last_injected_rule_id is NOT updated (still shows previous rule)
  - crash_callback fires with wrong attribution
  - Investigation mode starts but scheduler cursor points to a random field,
    not the field that corresponds to the kill payload structure

Fix required:
  1. Define a pseudo-FieldRule for each KILL_SERVER_PAYLOAD:
     At module level, after KILL_SERVER_PAYLOADS definition, add:
     _KILL_PAYLOAD_NAMES = [
         "null_magic_crash",
         "abort_magic_crash",
         "length_overflow_crash",
     ]

  2. Before sending each KILL_SERVER_PAYLOAD via _send(), set:
     self._last_injected_rule_id = f"kill_payload:{_KILL_PAYLOAD_NAMES[idx]}"

  3. After KILL_SERVER_PAYLOAD crash detection, do NOT enter investigation mode
     (we already know the exact payload). Instead:
     log.critical(f"Kill payload confirmed crash: {_KILL_PAYLOAD_NAMES[idx]}")
     if self.crash_callback:
         self.crash_callback(KILL_SERVER_PAYLOADS[idx], f"kill_payload:{_KILL_PAYLOAD_NAMES[idx]}")
     # Skip set_investigation_mode() for kill payloads
     continue

  4. Add to CrashManager.record() call: include "kill_payload" in crash_type arg
     so the crash report clearly distinguishes kill-payload crashes from
     fuzzing-discovered crashes.

Acceptance criteria:
  - Kill payload crashes logged with correct attribution (not previous rule_id)
  - Investigation mode NOT triggered after kill payload crash
  - crash_type in CrashReport correctly shows "kill_payload:null_magic_crash" etc.
  - KILL_SERVER_PAYLOADS list itself unchanged (backward compat)
```

---

### PROMPT 3-C: mutation_operators.py integration với scheduler (Advanced)

```
Context:
  File: fast_loop/mutation_operators.py — 7 operators (buffer_overflow,
        integer_overflow, bit_flip, boundary_violation, format_string,
        omission, random_byte_injection)
  File: fast_loop/mutator.py — _apply_field() at line 906
        Currently only uses MutationStrategy enum → simple in-place ops.
        mutation_operators.py operators are NOT called from _apply_field().

Problem:
  mutation_operators.py has much more sophisticated operators (buffer_overflow
  injects 1000-10000 bytes, format_string injects %n chains, omission truncates)
  but _apply_field() in mutator.py duplicates simpler logic and ignores these.
  The two mutation systems are disconnected.

Fix required:
  In _apply_field() (mutator.py line 906), import and use operators from
  mutation_operators.py for the corresponding strategies:

  Add at top of mutator.py:
    from fast_loop.mutation_operators import (
        op_buffer_overflow, op_integer_overflow, op_bit_flip,
        op_boundary_violation, op_format_string, op_omission,
        op_random_byte_injection,
    )

  In _apply_field(), replace inline logic with operator dispatch:
  - MutationStrategy.BOUNDARY_VALUES → with probability 0.7: op_integer_overflow(),
    with probability 0.3: op_boundary_violation() (mathematical mutation of current val)
  - MutationStrategy.RANDOM_BYTES → with probability 0.7: op_random_byte_injection(),
    with probability 0.3: op_buffer_overflow() (aggressive overflow test)
  - MutationStrategy.BIT_FLIP → op_bit_flip()
  - MutationStrategy.DICTIONARY → keep existing logic (no operator for this yet)
  - MutationStrategy.CALCULATED → keep existing logic (protocol-specific)
  - MutationStrategy.STATIC → keep existing logic (never changes)
  - Add: new strategy MutationStrategy.FORMAT_STRING → op_format_string()
    (requires schema change, add FORMAT_STRING to MutationStrategy enum in schemas.py)
  - Add: new strategy MutationStrategy.TRUNCATE → op_omission()

  All operators require MutationConstraints — create a minimal constraints object:
    from shared.schemas import MutationConstraints
    constraints = MutationConstraints()  # default: no constraints

  IMPORTANT: op_buffer_overflow() grows the packet significantly. Only call it
  for fields where rule.length == -1 (variable-length payload) OR where
  rule.mutation_strategy is explicitly BOUNDARY_VALUES on a length field.
  Add guard: if len(base) > 65536: skip buffer_overflow (prevent memory exhaustion).

Acceptance criteria:
  - _apply_field() uses mutation_operators for all numeric/byte strategies
  - op_buffer_overflow() only triggered for variable-length or explicit overflow targets
  - Format string injection available via MutationStrategy.FORMAT_STRING
  - All existing tests still pass (the logical behavior is the same, just delegated)
  - No import circular dependency (mutation_operators.py imports from schemas only)
```

---

## ════════════════════════════════════════════
## VERIFICATION PROMPTS — chạy sau khi sửa
## ════════════════════════════════════════════

### PROMPT V-1: Viết tests cho các thay đổi

```
Write pytest tests for the following changes made to fast_loop/mutator.py:

1. Test revert_pending flag (PROMPT 1-A):
   - test_revert_pending_set_when_budget_exhausted()
   - test_crash_during_investigation_resets_scheduler()
   - test_no_fire_and_forget_tasks_in_build_mutant()

2. Test DUMB mode sync (PROMPT 1-B):
   - test_stats_show_dumb_when_no_rule_set()
   - test_auto_transition_to_random_when_rules_arrive()

3. Test adaptive k (PROMPT 2-A):
   - test_adaptive_k_scaling() — verify k=1 for 1 field, k=2 for 4, k=3 for 9, k=4 for 16
   - test_static_k_when_adaptive_false()

4. Test WeightedScheduler (PROMPT 2-B):
   - test_boundary_values_selected_more_often() — run 1000 selects, verify
     BOUNDARY_VALUES fields selected >= 2x more than RANDOM_BYTES fields
   - test_low_confidence_selected_less() — confidence=0.1 vs confidence=1.0

5. Test ALL_FIELDS warmup (PROMPT 3-A):
   - test_warmup_uses_all_fields_scheduler()
   - test_warmup_does_not_trigger_investigation()
   - test_warmup_disabled_when_seconds_zero()

Place tests in: tests/test_mutator_scheduler.py
Use pytest-asyncio for async tests.
Mock the TCP connection (_send method) to return PacketStatus.ACCEPTED.
Use a minimal ActiveRuleSet fixture with 4 fields of different strategies.
```

---

### PROMPT V-2: Verify EPS không bị ảnh hưởng

```
After applying all scheduler changes to fast_loop/mutator.py, run a
benchmark to verify EPS is not degraded:

Write a benchmark script at: tests/bench_mutator_eps.py

The benchmark should:
1. Create a MutationEngine with a mock TCP server (asyncio server
   that accepts connections and immediately sends back b"OK")
2. Create an ActiveRuleSet with 5 mutable fields
3. Run the mutation loop for 10 seconds
4. Report: total_sent, EPS, mode, k_used

Run three configurations and compare:
  A) Old: k=2, use_weighted=False, adaptive_k=False, warmup_seconds=0
  B) New: k=2, use_weighted=True, adaptive_k=True, warmup_seconds=0
  C) New+warmup: k=2, use_weighted=True, adaptive_k=True, warmup_seconds=5

Expected result: EPS degradation in B and C vs A should be < 5%.
The WeightedScheduler uses random.choices() which is O(n) — acceptable.

Print a markdown table comparing EPS for all three configurations.
```

---

## ════════════════════════════════════════════
## QUICK REFERENCE — Mapping issues → prompts
## ════════════════════════════════════════════

| Issue | Description                          | Prompt  | Priority |
|-------|--------------------------------------|---------|----------|
| F     | Race condition auto-revert           | 1-A     | BUG      |
| G     | DUMB mode inconsistency              | 1-B     | BUG      |
| A     | k=2 static → dynamic sqrt(n)         | 2-A     | HIGH     |
| C     | Uniform → weighted field selection   | 2-B     | HIGH     |
| D     | Log offending field on reset         | 2-C     | HIGH     |
| E     | Hardcoded budgets → configurable     | 2-D     | MEDIUM   |
| H     | ALL_FIELDS warm-up phase             | 3-A     | MEDIUM   |
| I     | Kill payload attribution             | 3-B     | MEDIUM   |
| B     | operators.py integration             | 3-C     | LOW      |

**Estimated time per prompt (with Claude Code):**
- PROMPT 1-A: ~15 min
- PROMPT 1-B: ~10 min
- PROMPT 2-A: ~20 min
- PROMPT 2-B: ~25 min
- PROMPT 2-C: ~15 min
- PROMPT 2-D: ~20 min
- PROMPT 3-A: ~30 min
- PROMPT 3-B: ~20 min
- PROMPT 3-C: ~45 min (schema change + import restructure)

**Recommended session order:**
  Session 1 (bugs): 1-A → 1-B → V-1 (tests for bugs only)
  Session 2 (weighted): 2-A → 2-B → 2-C → V-1 (full tests)
  Session 3 (advanced): 2-D → 3-A → 3-B → V-2 (EPS benchmark)
  Session 4 (integration): 3-C (if needed for research evaluation)