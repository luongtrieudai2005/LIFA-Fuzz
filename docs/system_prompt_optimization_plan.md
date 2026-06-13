# LIFA-Fuzz — System Prompt Optimization Plan
## Implementation Spec

**Mục tiêu:** Cải thiện LLM system prompt + traffic sample handling để giảm token cost và tăng accuracy.
**Tổng effort:** ~3 giờ. **Token savings:** ước tính sơ bộ (chưa đo) — chủ yếu đến từ Step 3 (giảm sample 10→4 khi incremental) và Step 4 (JSON gọn hơn text table). Phải đo before/after thực tế bằng `estimate_tokens()` khi implement (xem Step 8), không tin con số ước tính.

> **Lưu ý:** Số dòng dưới đây đã verify khớp code tại thời điểm viết, nhưng có thể drift. Khi implement, **grep theo tên hàm/hằng số thay vì tin số dòng**. Các claim trong plan đã được đối chiếu với code hiện tại (xem phần "Audit" cuối file).

---

## Research-grounded findings (từ literature, cập nhật sau khi đọc papers)

Audit plan này dựa trên literature prompt-engineering. Các phát hiện chính, áp dụng vào LIFA-Fuzz:

| # | Phát hiện | Nguồn | Tác động lên plan |
|---|---|---|---|
| R1 | **CoT underperform direct answering trong pattern-based ICL** (CoT làm giảm hiệu quả khi suy luận pattern từ demonstrations; implicit reasoning bị CoT rationale disrupt bởi contextual distance) | [Zheng et al., "The Curse of CoT", TMLR 2025](https://arxiv.org/abs/2504.05081) | Suy luận ngữ pháp giao thức = pattern-based ICL → **Step 5 (CoT reinforcement) có thể phản tác dụng**. Phải A/B test, không mặc định có lợi. |
| R2 | **Self-consistency** (N lần inference + majority vote) → cải thiện accuracy ~17.9% GSM8K, giảm variance | [Wang et al., Self-Consistency](https://arxiv.org/abs/2203.11371); [tổng quan Adaline](https://www.adaline.ai/blog/what-is-self-consistency-prompting) | Áp dụng cho RQ1 (kết quả yếu nhất, F1=0.857). **Step 9 (mới)**. |
| R3 | **Structured-CoT** (reasoning field trong JSON) < free-form CoT về hiệu quả; còn opens injection-risk | [Goldberg, "Structured-chain-of-thought breaks language-use principles"](https://gist.github.com/yoavg/5b106275e38f4ccc796bc8ba7919060b) | LIFA-Fuzz ép `response_format=json_object` + có field `reasoning` → đang dùng structured-CoT. Không thay đổi được (JSON mode), nhưng **giữ reasoning ngắn** + không kỳ vọng nó thay CoT thật. |
| R4 | **Prompt caching** — cùng system prompt gửi lại nhiều lần → cached tokens rẻ ~10× | [Anthropic prompt caching](https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching); [OpenAI cached input](https://platform.openai.com/docs/guides/prompt-caching) | LIFA-Fuzz gửi cùng system prompt ~mỗi 30-60s. **Step 10 (mới)** — đòn bẩy chi phí lớn nhất, chưa có trong plan gốc. |
| R5 | **Few-shot số lượng**: returns diminishing nhanh; 2-3 example thường đủ, >5 ít thêm | [Prompting Guide: Few-Shot](https://www.promptingguide.ai/techniques/fewshot) | Plan có 2 example (sau Step 7) — **đủ**, không nên thêm nhiều hơn. |
| R6 | **LLM cho binary/protocol RE** dùng few-shot semantic inference; độ chính xác phụ thuộc chất lượng example + structure | [Pordanesh & Tan, GPT-4 in Binary RE](https://arxiv.org/abs/2406.06637); [Crafting Binary Protocol Reversing via Deep Learning](https://www.semanticscholar.org/paper/712414a40592a9e3a495a0cb45f2790b2370d098) | Biện luận cho việc giữ few-shot (Step 7) + đối chiếu với related work trong báo cáo. |
| R7 | **Token reduction** qua omission compression (TRIM/LLMLingua) | [TRIM, arXiv 2412.07682](https://arxiv.org/html/2412.07682v4) | Lower priority — risk mangle semantic. Không đưa vào plan trừ khi cần giảm thêm sau 3+4. |

**Kết luận ưu tiên (sửa so với plan gốc):**
- **Thêm Step 9 (self-consistency)** — giá trị cao cho RQ1, dễ triển khai.
- **Thêm Step 10 (prompt caching)** — giá trị cao cho chi phí (RQ2/EPS gián tiếp), dễ triển khai.
- **Re-eval Step 5** — chuyển từ "làm" sang "A/B test", vì Curse of CoT.
- Các step khác (1, 3, 4, 7) giữ nguyên — có nền tảng từ R5/R6.

---

## File cần sửa

| File | Dòng | Thay đổi |
|------|------|----------|
| `slow_loop/llm_agent.py` | 147-502 | Sửa các system prompt constants |
| `slow_loop/llm_agent.py` | 895-997 | Sửa `build_prompt()` — adaptive sample count |
| `slow_loop/rules_orchestrator.py` | 992-1095 | Sửa `_build_response_feedback()` — trả về JSON |
| `tests/test_llm_agent.py` | 140-165 | Cập nhật test nếu cần |

---

## Step 1 — Mở rộng FIELD TYPE REFERENCE (2 phút)

**File:** `slow_loop/llm_agent.py`, dòng 293-307

**Hiện tại:**
```python
## FIELD TYPE REFERENCE

The `field_type` MUST be one of exactly 8 values:
- `uint8`         — unsigned 8-bit integer
- `uint16_le`     — unsigned 16-bit little-endian
- `uint16_be`     — unsigned 16-bit big-endian
- `uint32_le`     — unsigned 32-bit little-endian
- `uint32_be`     — unsigned 32-bit big-endian
- `bytes`         — raw unstructured bytes (payloads, unknown regions, padding)
- `enum`          — discrete set of values (opcodes, command types, flags)
- `string`        — null-terminated or length-delimited text

NOTE: For signed fields, use the unsigned type of the same width.
NOTE: For boolean fields, use `enum` with `possible_values: ["00", "01"].
NOTE: For padding/reserved regions, use `bytes` with `is_constant: true`.
```

**Sửa thành:**
```python
## FIELD TYPE REFERENCE

The `field_type` MUST be one of exactly 15 values:
- `uint8`         — unsigned 8-bit integer
- `uint16_le`     — unsigned 16-bit little-endian
- `uint16_be`     — unsigned 16-bit big-endian
- `uint32_le`     — unsigned 32-bit little-endian
- `uint32_be`     — unsigned 32-bit big-endian
- `int8`          — signed 8-bit integer
- `int16_le`      — signed 16-bit little-endian
- `int16_be`      — signed 16-bit big-endian
- `int32_le`      — signed 32-bit little-endian
- `int32_be`      — signed 32-bit big-endian
- `bytes`         — raw unstructured bytes (payloads, unknown regions, padding)
- `enum`          — discrete set of values (opcodes, command types, flags)
- `string`        — null-terminated or length-delimited text
- `bool`          — single-byte boolean (0x00=false, else true)
- `reserved`      — padding / unused bytes

NOTE: For padding/reserved regions, use `reserved` with `is_constant: true`.
```

**Lý do:** `FieldType` enum (shared/schemas.py:61-75) có 15 values, nhưng prompt chỉ liệt kê 8 → LLM không biết các type `int8`, `bool`, `reserved`, dẫn đến schema parse error hoặc type sai.

---

## Step 2 — Safety trigger rephrase (1 phút)

**File:** `slow_loop/llm_agent.py`

### 2a: Dòng 151
```python
# TRƯỚC
- CVE analysis and exploit development
# SAU
- Protocol security analysis and vulnerability research
```

### 2b: Dòng 270
```python
# TRƯỚC
Inject: format strings (%s%s%s%n), path traversal (../../../etc/passwd), \
# SAU
Inject: format specifier sequences, path traversal sequences, \
```

---

## Step 3 — Adaptive sample count (1 giờ)

**File:** `slow_loop/llm_agent.py`, method `build_prompt()` (dòng 895-997)

### 3a: Thêm parameter `max_samples`

```python
# TRƯỚC (dòng 895-901):
def build_prompt(
    self,
    samples: list[TrafficRecord],
    math_hint: Optional[str] = None,
    previous_grammar_summary: Optional[dict[str, Any]] = None,
    response_feedback: Optional[str] = None,
) -> str:

# SAU:
def build_prompt(
    self,
    samples: list[TrafficRecord],
    math_hint: Optional[str] = None,
    previous_grammar_summary: Optional[dict[str, Any]] = None,
    response_feedback: Optional[str] = None,
    max_samples: Optional[int] = None,
) -> str:
```

### 3b: Thêm logic adaptive count sau `clean_samples`

Chèn sau dòng 933 (`clean_samples = [s for s in samples if not s.is_mutated]`):

```python
# Adaptive sample count:
#   - First inference (no previous grammar): send max ~10 samples
#   - Incremental (has previous grammar): send max ~4 samples
#   - Explicit override via max_samples parameter
if max_samples is None:
    max_samples = 4 if previous_grammar_summary else 10
if len(clean_samples) > max_samples:
    # Take evenly spaced samples across the timeline
    step = max(1, len(clean_samples) // max_samples)
    clean_samples = clean_samples[::step][:max_samples]
```

**Lưu ý:** Lấy evenly spaced samples thay vì first N để tránh bias về đầu traffic log.

### 3c: Cập nhật prompt header để phản ánh đúng số sample

Dòng 951-965:
```python
# TRƯỚC:
if previous_grammar_summary:
    header = (
        f"Review {len(clean_samples)} NEW network traffic packets that "
        ...
    )
else:
    header = (
        f"Analyze {len(clean_samples)} clean network traffic packets below.\n"
        ...
    )

# SAU: header tự động dùng len(clean_samples) sau khi trim → không cần sửa
```

Header đã dùng `len(clean_samples)` nên tự động đúng. Không cần sửa.

### 3d: Caller KHÔNG cần sửa (nhưng lý do khác với giả định ban đầu)

**File:** `slow_loop/rules_orchestrator.py` — dòng 694

> ⚠️ **Sửa lỗi trong phiên bản plan trước:** plan cũ viết `grammar = await llm_agent.build_prompt(...)` ở orchestrator — **SAI**. Orchestrator thật gọi `infer_protocol()`, không gọi `build_prompt()`.

Chuỗi gọi thực tế:
```
orchestrator.run_cycle() (rules_orchestrator.py:694)
  → agent.infer_protocol(payload, math_hint=..., response_feedback=...)   (llm_agent.py:607)
      → self._build_prompt_from_input(...)                                 (llm_agent.py:647 → 999)
          → self.build_prompt(...)                                         (llm_agent.py:1054)
```

`max_samples` có default `None` → `build_prompt` tự detect (4 nếu có previous grammar, 10 nếu không). Vì vậy **không cần truyền `max_samples` qua chuỗi `infer_protocol → _build_prompt_from_input → build_prompt`** — default đã đủ. Chỉ sửa nếu sau này muốn override từ ngoài (lúc đó mới phải thêm param vào `infer_protocol` và `_build_prompt_from_input`).

---

## Step 4 — Structured response feedback (1 giờ)

> 🔴 **CRITICAL — fix marker detection (lỗi trong phiên bản plan trước):**
> `response_feedback` được embed **thẳng vào prompt, không có header bọc** (`llm_agent.py:986`: `prompt += response_feedback`).
> `call_llm` (llm_agent.py:~1144) check `if "RESPONSE FEEDBACK" in prompt` (viết HOA + space) để quyết định có thêm `SYSTEM_PROMPT_FEEDBACK_APPEND` (instruction diễn giải) hay không.
>
> Version text-table hiện tại bắt đầu bằng `"## RESPONSE FEEDBACK FROM PREVIOUS RULES"` → **marker khớp**. Nhưng JSON thuần có `"type": "response_feedback"` (thường + gạch dưới) → **marker KHÔNG khớp** → guidance bị tắt lặng, LLM nhận JSON thô không có instruction.
>
> **→ Bắt buộc** prepend `## RESPONSE FEEDBACK` header vào output JSON (xem dòng `return` bên dưới). Đừng chỉ trả JSON thuần.

### 4a: Sửa `_build_response_feedback()` trong rules_orchestrator.py

**File:** `slow_loop/rules_orchestrator.py`, dòng 992-1095

Thay toàn bộ method từ format text table → format JSON:

```python
# AFTER:
def _build_response_feedback(self) -> Optional[str]:
    """Build response feedback as structured JSON for the LLM.

    Returns:
        JSON string with per-strategy stats, or None if no data.
    """
    try:
        from pathlib import Path as _Path
        stats_path = _Path("shared/rule_response_stats.json")
        if not stats_path.exists():
            return None
        import json as _json
        data = _json.loads(stats_path.read_text(encoding="utf-8"))
        if not data:
            return None
    except Exception:
        return None

    has_previous = self._previous_grammar_summary is not None
    total_rules = len(self._previous_grammar_summary.get("fields", [])) if has_previous else 0

    field_stats = []
    grand_total = 0
    grand_accepted = 0
    for strategy, counts in data.items():
        accepted = counts.get("accepted", 0)
        rejected = counts.get("rejected", 0)
        timeout = counts.get("timeout", 0)
        crash = counts.get("crash", 0)
        total = accepted + rejected + timeout + crash
        if total == 0:
            continue
        grand_total += total
        grand_accepted += accepted
        field_stats.append({
            "strategy": strategy,
            "accepted": accepted,
            "rejected": rejected,
            "timeout": timeout,
            "crash": crash,
            "total": total,
            "accept_rate": round(accepted / total, 3) if total > 0 else 0.0,
        })

    if grand_total == 0:
        return None

    feedback = {
        "type": "response_feedback",
        "version": 2,
        "total_rules": total_rules if has_previous else None,
        "field_stats": field_stats,
        "overall": {
            "total_sends": grand_total,
            "accepted": grand_accepted,
            "acceptance_rate": round(grand_accepted / grand_total, 3),
        },
        "guidance_rules": [
            "High rejection (>70%) on a field → offset or type likely WRONG",
            "High acceptance on BOUNDARY_VALUES → grammar is accurate",
            "High timeout (>30%) → server may be crashing",
        ],
    }
    # CRITICAL: prepend the "## RESPONSE FEEDBACK" marker so call_llm's
    # `if "RESPONSE FEEDBACK" in prompt` check matches and appends
    # SYSTEM_PROMPT_FEEDBACK_APPEND. JSON thuần ("response_feedback") sẽ
    # KHÔNG khớp marker (hoa + space) → guidance bị tắt.
    return "## RESPONSE FEEDBACK\n\n" + _json.dumps(feedback, indent=2)
```

### 4b: Cập nhật SYSTEM_PROMPT_FEEDBACK_APPEND trong llm_agent.py

**File:** `slow_loop/llm_agent.py`, dòng 474-502

Thay text blob bằng instruction ngắn cho JSON format:

```python
# SAU (dòng 474-502):
SYSTEM_PROMPT_FEEDBACK_APPEND = """\

## RESPONSE FEEDBACK (STRUCTURED JSON)

A "RESPONSE FEEDBACK" block below contains real server response statistics
as structured JSON. Use the `guidance_rules` field for interpretation.

High rejection (>70%) on a strategy → the field offsets/types for that
strategy are likely WRONG. Try different boundaries.

Low rejection + high acceptance → grammar is accurate for those fields."""
```

---

## Step 5 — CoT reinforcement: A/B TEST, KHÔNG mặc định làm

> ⚠️ **Cập nhật sau khi đọc literature (R1):** Plan gốc đề nghị ép CoT dài
> ("step-by-step: 1) magic 2) length 3) enum 4) checksum"). Nhưng
> [Zheng et al. "The Curse of CoT" (TMLR 2025)](https://arxiv.org/abs/2504.05081)
> cho thấy CoT **underperform direct answering** trong **pattern-based ICL**
> — và suy luận ngữ pháp giao thức (tìm magic/length/opcode từ few-shot
> packets) CHÍNH LÀ pattern-based ICL. CoT rationale tăng contextual
> distance, disrupt implicit reasoning. Thêm vào đó, LIFA-Fuzz đã ép
> `response_format=json_object` + field `reasoning` → đang dùng
> structured-CoT, mà [Goldberg](https://gist.github.com/yoavg/5b106275e38f4ccc796bc8ba7919060b)
> ghi nhận **kém hơn** free-form CoT.

**Hành động:** KHÔNG mặc định áp dụng CoT dài. Thay vào đó **A/B test**:
1. **Variant A (baseline):** reasoning field ngắn hiện tại —
   `"explain your analysis methodology, key findings, and strategy rationale"`.
2. **Variant B (CoT dài):** reasoning field ép step-by-step (code block dưới).
3. Chạy RQ1 trên cùng batch traffic, so F1. **Chỉ giữ Variant B nếu F1 cao hơn có ý nghĩa** (>2 điểm).
4. Nếu B không hơn (khả năng cao theo Curse of CoT), **giữ A** — đỡ token, đỡ risk.

```python
# Variant B (CHỈ nếu A/B test thắng) — slow_loop/llm_agent.py:~345:
    "reasoning": "string — step-by-step analysis: 1) identify constant/magic bytes "
                 "2) detect length fields via correlation with remaining bytes "
                 "3) infer enum/opcode fields from limited value sets "
                 "4) check for checksums / state machine patterns. "
                 "Explain WHY each field was classified as it was."
```

**Lý do giữ reasoning field (dù structured-CoT yếu hơn):** cần checksum/state
detection cho sâu hơn, và JSON mode ép toàn bộ output vào structure. Nhưng
giữ nó **ngắn, optional** — không kỳ vọng nó thay CoT thật.

---

## Step 6 — Fusion consolidation (10 phút)

**File:** `slow_loop/llm_agent.py`

### 6a: BỎ — giữ nguyên Step 2 (KHÔNG rút gọn)

> ⚠️ **Sửa lỗi trong phiên bản plan trước:** plan cũ đề nghị xóa câu
> `"CRITICAL: NEVER fuzz these — they are required for the packet to
> reach the parser's main logic. Without them, the server rejects the
> packet before reaching any vulnerable code path."`
> để tiết kiệm ~50 token. **Đừng làm** — đây chính là instruction
> quan trọng nhất về magic bytes, và Step 6b còn thêm lại một phiên bản
> cho fusion. Xóa đi là tự phản tác dụng. Giá trị tiết kiệm token không
> đáng so với rủi ro LLM fuzz nhầm magic → server reject → lãng phí send.

Giữ nguyên SYSTEM_PROMPT Step 2 như hiện tại. Bước này chỉ giữ lại để
ghi nhận quyết định (không sửa code).

### 6b: Thêm chi tiết vào FUSION_APPEND (dòng 398-439)

Thêm 1 dòng vào instruction của FUSION_APPEND:

```python
# TRƯỚC (dòng 317-321 trong to_llm_hint):
### Instruction
The heatmap is MATHEMATICALLY COMPUTED, not guessed.
Your task: name fields, identify semantics, flag CHECKSUM/SEQUENCE patterns.
Do NOT re-derive what is already marked STATIC or HIGH_ENTROPY.

# SAU (thêm dòng cuối):
### Instruction
The heatmap is MATHEMATICALLY COMPUTED, not guessed.
Your task: name fields, identify semantics, flag CHECKSUM/SEQUENCE patterns.
Do NOT re-derive what is already marked STATIC or HIGH_ENTROPY.
CRITICAL: Mutating STATIC/magic fields wastes sends — server rejects before
reaching vulnerable code paths. Only fuzz non-constant fields.
```

---

## Step 7 — Thêm 1 opcode-based few-shot example (15 phút)

**File:** `slow_loop/llm_agent.py`

Thêm vào cuối SYSTEM_PROMPT (sau example hiện tại, trước dòng 395):

```python

## EXAMPLE 2: Opcode-based protocol

Packet: ca fe ba be  01  00 05  48 65 6c 6c 6f
        [magic 4B ] [opc] [len ] [payload 5B   ]

Packet: ca fe ba be  02  00 03  42 79 65
        [magic 4B ] [opc] [len ] [pl 3B]

Correct output:
{
    "protocol_name": "cmd_protocol",
    "description": "Opcode-based protocol with command-type dispatch",
    "magic_bytes": "cafebabe",
    "fields": [
        {"name": "magic",   "offset_start": 0, "offset_end": 4,
         "field_type": "bytes", "is_constant": true,
         "mutation_strategy": "static",
         "description": "Magic header 0xCAFEBABE"},
        {"name": "opcode",  "offset_start": 4, "offset_end": 5,
         "field_type": "enum", "is_constant": false,
         "mutation_strategy": "dictionary",
         "possible_values": ["01", "02"],
         "description": "Command opcode: 0x01=cmd_a, 0x02=cmd_b"},
        {"name": "length",  "offset_start": 5, "offset_end": 7,
         "field_type": "uint16_be", "is_constant": false,
         "mutation_strategy": "boundary_values",
         "description": "Payload length, uint16_be = 5 or 3"},
        {"name": "payload", "offset_start": 7, "offset_end": -1,
         "field_type": "bytes", "is_constant": false,
         "mutation_strategy": "random_bytes",
         "description": "Variable-length payload"}
    ],
    "total_header_size": 7, "min_packet_size": 7, "max_packet_size": 65535,
    "confidence": 0.95,
    "reasoning": "Bytes 0-3 constant → magic. Byte 4 has limited values {01,02} → opcode field. \
Bytes 5-6 encode remaining bytes → length. Rest is variable payload."
}
```

---

## Step 8 — Đo token before/after thực tế (KHÔNG tin ước tính)

**File:** `slow_loop/llm_agent.py`, function `estimate_tokens()`

Không cần sửa code. Trước khi apply plan, đo token prompt cho 1 batch traffic cố định (cả first-inference lẫn incremental) bằng `estimate_tokens()`. Sau khi apply, đo lại cùng batch. So sánh delta. Báo cáo số thực thay vì con số ước tính "~21.5%" — vì Step 1 (thêm field types) và Step 7 (thêm example) **tăng** token, chỉ Step 3 + Step 4 mới **giảm**. Net savings có thể nhỏ hơn hoặc lớn hơn 21.5% tùy traffic.

---

## Step 9 — Self-consistency cho RQ1 (mới, giá trị cao)

> **Cơ sở literature (R2):** [Wang et al., Self-Consistency (ICLR 2023)](https://arxiv.org/abs/2203.11371)
> — sinh N reasoning paths ở temperature cao, majority vote. Cải thiện
> accuracy +17.9% GSM8K, giảm variance. Đặc biệt hiệu quả cho
> **high-stakes structured extraction** ([zeroentropy.dev](https://zeroentropy.dev/concepts/self-consistency/))
> — đúng profile suy luận ngữ pháp giao thức (field offset sai 1 byte = lệch rule).

**Mục tiêu:** RQ1 là kết quả yếu nhất hiện tại (F1=0.857, MOCK). Self-consistency
là kỹ thuật test-time-compute rẻ nhất để cải thiện.

**File:** `slow_loop/llm_agent.py` (thêm method), `evaluation/rq1_accuracy.py` (gọi).

### 9a: Thêm `infer_protocol_self_consistent()` vào LLMAgent

```python
async def infer_protocol_self_consistent(
    self,
    payload: dict,
    math_hint: Optional[str] = None,
    previous_grammar_summary: Optional[dict] = None,
    response_feedback: Optional[str] = None,
    n_samples: int = 5,
    vote_temp: float = 0.7,  # cao hơn temp mặc định (0.2) để sinh path đa dạng
) -> ProtocolGrammar:
    """Self-consistency: N inference paths + majority vote on field structure.

    Args:
        n_samples: Số lần inference (trade-off: accuracy vs cost/latency ×N).
                  Khuyến nghị 3-5 cho RQ1.
        vote_temp: Temperature cao để các path đa dạng (self-consistency cần
                  diversity; temp 0.2 → output gần giống nhau → vote vô nghĩa).
    """
    grammars: list[ProtocolGrammar] = []
    original_temp = self.temperature
    self.temperature = vote_temp
    try:
        for _ in range(n_samples):
            try:
                g = await self.infer_protocol(
                    payload, math_hint=math_hint,
                    previous_grammar_summary=previous_grammar_summary,
                    response_feedback=response_feedback,
                )
                grammars.append(g)
            except (RuntimeError, ValueError):
                continue  # bỏ path fail
    finally:
        self.temperature = original_temp

    if not grammars:
        raise RuntimeError("All self-consistency samples failed")
    return self._vote_grammars(grammars)
```

### 9b: Vote trên grammar

Vote theo **field signature** (offset_start, offset_end, field_type) thay vì
toàn bộ grammar object — vì offset là thứ quyết định P/R/F1 (RQ1 metric):

```python
@staticmethod
def _vote_grammars(grammars: list[ProtocolGrammar]) -> ProtocolGrammar:
    """Chọn grammar có field set phổ biến nhất (majority vote per field)."""
    from collections import Counter
    # Đếm field signatures qua các samples
    sig_counter: Counter[tuple] = Counter()
    sample_with_sig: dict[tuple, "InferredField"] = {}
    for g in grammars:
        for f in g.fields:
            sig = (f.offset_start, f.offset_end, f.field_type.value)
            sig_counter[sig] += 1
            sample_with_sig.setdefault(sig, f)
    # Giữ field xuất hiện ở >50% samples (majority)
    threshold = len(grammars) / 2
    winning_fields = [
        sample_with_sig[sig] for sig, cnt in sig_counter.items() if cnt > threshold
    ]
    # Chọn grammar base có nhiều field thắng nhất (lấy metadata: protocol_name, magic, ...)
    base = max(grammars, key=lambda g: sum(
        1 for f in g.fields
        if (f.offset_start, f.offset_end, f.field_type.value) in {s for s, c in sig_counter.items() if c > threshold}
    ))
    return base.model_copy(update={"fields": winning_fields})
```

### 9c: Gọi trong RQ1 evaluation

```python
# evaluation/rq1_accuracy.py — REAL mode path
grammar = await agent.infer_protocol_self_consistent(
    payload, math_hint=math_hint, n_samples=5
)
```

**Trade-off (phải nêu trong báo cáo):** self-consistency ×N cost/latency.
- 5 samples × ~$0.03/inference = ~$0.15/RQ1-run. Chấp nhận được cho đánh giá.
- **KHÔNG** dùng self-consistency trên hot path fuzzing — chỉ cho RQ1 offline.
- Đo: so sánh RQ1 F1 single-inference vs self-consistency (N=3,5) trên cùng batch.

### 9d: Khi nào KHÔNG dùng
- Baseline C (Full Fusion) trên hot path: self-consistency ×5 sẽ giết EPS
  (đã yếu 141). Chỉ áp dụng cho RQ1 offline accuracy, KHÔNG cho RQ2/RQ3 runtime.

---

## Step 10 — Prompt caching (mới, đòn bẩy chi phí lớn nhất)

> **Cơ sở literature (R4):** [Anthropic prompt caching](https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching),
> [OpenAI automatic caching](https://platform.openai.com/docs/guides/prompt-caching).
> Cùng prefix prompt gửi lại trong TTL (Anthropic 5ph, OpenAI tự động) →
> cached input tokens giá ~10× rẻ hơn. LIFA-Fuzz gửi cùng SYSTEM_PROMPT
> (lớn, ~3-4k token) + cùng few-shot example mỗi ~30-60s → cache hit gần như 100%.

**Mục tiêu:** giảm cost LLM ~50-70% (system prompt + few-shot = phần lớn input
token, và nó cố định). Không đổi accuracy, không đổi logic — chỉ cấu hình.

**Lưu ý provider:** Caching behavior khác nhau:
- **OpenAI-compatible (Z.ai GLM):** caching thường **tự động** (≥1024 token prefix),
  không cần flag. Verify bằng `response.usage.prompt_tokens_details.cached_tokens`.
- **Anthropic:** cần `cache_control` marker tường minh.

### 10a: Verify cache hit hiện tại (Z.ai GLM qua litellm)

**File:** `slow_loop/llm_agent.py`, trong `call_llm()` (sau line 1200):

```python
# Track cache hit (OpenAI-compatible cached_tokens)
if hasattr(response, "usage") and response.usage:
    # ... existing token tracking ...
    prompt_details = getattr(response.usage, "prompt_tokens_details", None)
    if prompt_details:
        cached = getattr(prompt_details, "cached_tokens", 0) or 0
        if cached:
            self._cached_tokens_used += cached
            logger.debug(f"Cache hit: {cached} cached input tokens")
```

Thêm field `_cached_tokens_used: int = 0` vào `__init__`, expose qua property
cho telemetry. **Chạy 2 inference liên tiếp**, check log — nếu `cached_tokens > 0`
ở inference #2 → Z.ai đã cache tự động, **không cần làm gì thêm**.

### 10b: Đảm bảo prefix ổn định (cache cần prefix IDENTICAL)

Cache match trên **exact prefix**. Để tối ưu hit rate:
- **System prompt:** đã cố định (constant) ✓.
- **Few-shot examples (Step 7):** cố định trong system prompt ✓ (không dynamic).
- **math_hint / response_feedback:** nằm CUỐI prompt, sau phần cố định → không
  phá prefix. **Verify** thứ tự trong `_build_prompt_from_input`: system cố định
  phải đứng trước, phần dynamic (traffic, hint, feedback) đứng sau. Nếu dynamic
  chen vào giữa → cache miss. Đây là kiểm tra quan trọng nhất của Step 10.

```python
# Verify thứ tự: CỐ ĐỊNH (system+example) | DYNAMIC (hint+feedback+traffic)
# trong build_prompt / _build_prompt_from_input.
# Nếu sai thứ tự → sửa để prefix cố định luôn đứng đầu.
```

### 10c: Báo cáo (cho paper)
Đo + báo cáo `cached_tokens / prompt_tokens` ratio trên một chiến dịch C.
Nếu Z.ai cache tự động → con số này cho thấy cost thực < cost danh nghĩa. Đây
là kết quả tích cực cho RQ2 (chi phí fusion thấp hơn apparent).

### 10d: Khi nào KHÔNG kỳ vọng cache
- Nếu `api_base` (Z.ai endpoint) **không** support caching → `cached_tokens`
  luôn 0. Khi đó Step 10 = no-op (chỉ thêm telemetry, không lợi). Đừng giả định
  có cache — **đo** trước.

---

## Test impact

| Test file | Test | Impact |
|-----------|------|--------|
| `tests/test_llm_agent.py:143` | `test_build_prompt_with_records` | ❌ **SẼ PASS** — không chạm format hex. Dùng `sample_traffic_records` (2 records) dưới threshold adaptive count |
| `tests/test_llm_agent.py:487` | `test_system_prompt_has_fusion_guidelines` | ✅ **PASS** — vẫn check keywords STATIC/CALCULATED/HIGH_ENTROPY/LOW_ENTROPY/reasoning |
| `tests/test_llm_agent.py:411-435` | Các test build_prompt với hint | ✅ **PASS** — không chạm logic hint injection |
| `tests/test_llm_agent.py:507-520` | `TestHexToAscii` | ✅ **PASS** — không chạm `_hex_to_ascii()` |
| Các test mock LLM | — | ✅ **PASS** — MOCK mode trả về JSON hardcoded, không phụ thuộc prompt content |

## Implementation order

```
1. Step 1 (FIELD TYPE REFERENCE)     — 2 phút   [giá trị cao, bug thật]
2. Step 3 (adaptive sample count)    — 30 phút  [giá trị cao, token win lớn nhất]
3. Step 4 (structured feedback)      — 45 phút  [BẮT BUỘC fix marker ở 4a]
4. Step 10 (prompt caching)          — 30 phút  [đòn bẩy chi phí lớn nhất, verify prefix]
5. Step 9 (self-consistency cho RQ1) — 1 giờ    [giá trị cao cho RQ1 accuracy, offline only]
6. Step 7 (opcode example)           — 15 phút  [tùy chọn, tăng accuracy + token]
7. Step 5 (CoT)                      — 30 phút  [A/B TEST — Curse of CoT, không mặc định làm]
8. Step 2 (safety rephrase)          — 1 phút   [marginal]
9. Step 6b (fusion consolidation)    — 5 phút   [6a đã BỎ]
                                   ─────────
                                    ~4h15m
```

Run tests sau mỗi step: `python -m pytest tests/test_llm_agent.py -x -v`

**Đo lường bắt buộc (Step 8 + 10):** token before/after, cache hit ratio, RQ1 F1
single vs self-consistency. Báo cáo số thực, không tin ước tính.

---

## Audit (đối chiếu plan với code hiện tại)

Đã verify các claim trong plan với code thực tế (phiên bản này sửa các sai sót):

| Claim trong plan | Trạng thái | Ghi chú |
|---|---|---|
| `FieldType` enum có 15 giá trị, prompt liệt kê 8 | ✅ Đúng | schemas.py:54-75 (15), llm_agent.py:295 ("exactly 8 values") |
| Safety strings "CVE analysis..." / "format strings..." | ✅ Đúng | llm_agent.py:155, 270 |
| `build_prompt` signature + `clean_samples` line 933 | ✅ Đúng | llm_agent.py:895, 933 |
| `_build_response_feedback` trả text table | ✅ Đúng | rules_orchestrator.py:~992 |
| ~~Orchestrator gọi `build_prompt`~~ (plan cũ 3d) | ❌ **SAI** | Orchestrator gọi `infer_protocol` (line 694) → chuỗi `infer_protocol → _build_prompt_from_input → build_prompt`. Đã sửa 3d. |
| ~~JSON feedback thuần đủ dùng~~ (plan cũ 4a) | ❌ **SAI** | `response_feedback` embed thẳng vào prompt không header (llm_agent.py:986); `call_llm` check marker `"RESPONSE FEEDBACK"` (hoa+space) để thêm guidance. JSON thuần gãy marker. Đã thêm `## RESPONSE FEEDBACK` header vào 4a. |
| ~~Bỏ câu "CRITICAL: NEVER fuzz..."~~ (plan cũ 6a) | ❌ **SAI** | Phản tác dụng — là instruction quan trọng, 6b còn thêm lại. Đã đổi 6a thành BỎ. |
| "Tiết kiệm ~21.5% token" | ⚠️ Chưa đo | Step 1 + 7 TĂNG token, Step 3 + 4 GIẢM. Phải đo before/after (Step 8). |

### Cập nhật sau literature

| Thay đổi | Lý do (literature) |
|---|---|
| Step 5: "làm" → **A/B test** | [Curse of CoT (TMLR 2025)](https://arxiv.org/abs/2504.05081): CoT underperform direct answering trong pattern-based ICL = đúng profile suy luận ngữ pháp |
| **Step 9 mới** (self-consistency) | [Wang et al. ICLR 2023](https://arxiv.org/abs/2203.11371): N samples + vote → +17.9% accuracy. Áp cho RQ1 (kết quả yếu nhất). Offline only. |
| **Step 10 mới** (prompt caching) | [Anthropic](https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching)/[OpenAI](https://platform.openai.com/docs/guides/prompt-caching): prefix cố định → cached tokens ~10× rẻ. System prompt + few-shot cố định → hit rate cao. Verify prefix order trước. |
| Note structured-CoT | [Goldberg](https://gist.github.com/yoavg/5b106275e38f4ccc796bc8ba7919060b): reasoning-in-JSON < free-form CoT; JSON mode ép buộc, giữ reasoning ngắn. |
| Few-shot giữ 2 (sau Step 7) | [Prompting Guide](https://www.promptingguide.ai/techniques/fewshot): diminishing return nhanh, 2-3 đủ. |
