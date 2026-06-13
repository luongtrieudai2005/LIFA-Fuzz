# LIFA-Fuzz — System Prompt Optimization Plan
## Cải thiện LLM System Prompt dựa trên Prompt Engineering Research

**Phiên bản:** v2.0 (sửa theo code audit)
**Trạng thái:** Research & Proposal

---

## 1. Vấn đề Hiện tại

LLM Agent trong slow loop (`slow_loop/llm_agent.py`) có **7 vấn đề** chia 3 tiers.
Tất cả đều đã xác nhận qua code audit — không có giả định sai.

### Tier 1 — Nghiêm trọng

| # | Vấn đề | Mô tả | Ảnh hưởng |
|---|--------|-------|-----------|
| 1 | **SYSTEM_PROMPT quá dài** | ~250 dòng (~1500 tokens), các section lặp instruction khi fusion ON | Tốn token, instruction signal bị loãng |
| 2 | **Safety trigger risk** | Dòng 151 "CVE analysis and exploit development", dòng 270 `%s%s%s%n` examples | API content filter có thể reject request |
| 3 | **Thiếu few-shot example đa dạng** | Chỉ 1 example 3-field đơn giản (dòng 365-393), không có example cho opcode/enum hay nested TLV | LLM thiếu pattern để infer protocol phức tạp |

### Tier 2 — Trung bình

| # | Vấn đề | Mô tả | Ảnh hưởng |
|---|--------|-------|-----------|
| 4 | **FIELD TYPE REFERENCE thiếu type** | Prompt chỉ liệt kê 8 types (dòng 294-303), nhưng `FieldType` enum có 14 (thiếu `int8`, `int16_le`, `int16_be`, `int32_le`, `int32_be`, `bool`, `reserved`) | LLM không biết các type signed/bool/reserved → dùng sai field_type |
| 5 | **CoT instruction chưa đủ mạnh** | `reasoning` field **đã có** (schemas.py:858) và đã trong OUTPUT FORMAT, nhưng instruction chưa yêu cầu step-by-step reasoning trước khi đưa ra field conclusions | LLM có thể skip reasoning hoặc reasoning hời hợt |

### Tier 3 — Có thể cải thiện

| # | Vấn đề | Mô tả | Ảnh hưởng |
|---|--------|-------|-----------|
| 6 | **Feedback blob unstructured** | Response feedback dạng text dài ~30 dòng (dòng 474-502) | LLM phải tự interpret, dễ miss signal |
| 7 | **Fusion prompt redundant với main prompt** | Step 2 (dòng 178-184) "đừng fuzz magic bytes" và FUSION_APPEND (dòng 409-413) "trust STATIC fields" lặp ý | Tốn token, redundant khi fusion ON |

---

## 2. Đề xuất Cải thiện

### 2.1 Prompt Compression — Rút gọn ~25%, KHÔNG xóa section quan trọng

**⚠️ Sửa từ phiên bản cũ:** Không xóa FIELD TYPE REFERENCE (đang thiếu type, cần mở rộng).
Không xóa MUTATION STRATEGY SELECTION (cần cho pure LLM mode — khi fusion OFF).

**Paper:** Jiang et al. (2023) — LLMLingua (EMNLP), Li et al. (2025) — NAACL

**Nội dung thực tế:**

| Section | Hiện tại | Hành động | Lý do |
|---------|----------|-----------|-------|
| HEADER (dòng 148-155) | 8 dòng, "CVE analysis + exploit development" | **Diễn đạt lại** | Safety trigger, đổi thành "protocol security analysis" |
| Step 1-7 (dòng 165-235) | 70 dòng, 7 steps | **Rút gọn 7→4 steps** | Gộp Step 2+4 (đều về constant/enum), Step 5+7 (state+checksum → optional appendix) |
| MUTATION STRATEGY (dòng 238-291) | 54 dòng, 8 strategies | **Giữ nguyên**, chỉ rút gọn mô tả attack vector | Core instruction cho LLM; khi fusion ON có thể append "trust heatmap priorities" |
| FIELD TYPE REFERENCE (dòng 293-307) | 8 types | **Mở rộng → 14 types** | Thêm `int8`, `int16_le`, `int16_be`, `int32_le`, `int32_be`, `bool`, `reserved` |
| OUTPUT FORMAT (dòng 321-346) | 26 dòng | **Giữ nguyên** | Schema này khớp với ProtocolGrammar, cần cho LLM biết format |
| CRITICAL RULES (dòng 348-361) | 14 dòng | **Rút gọn 8→4 rules** | Bỏ rule đã có trong example (offset_end exclusive) |
| EXAMPLE (dòng 363-395) | 32 dòng | **Mở rộng → 2-3 examples** (xem 2.4) | Cần thêm opcode + nested TLV |

```
Ước tính: ~1500 tokens → ~1100 tokens
Tiết kiệm: ~27% (thay vì 47% như bản cũ)
Lý do: FIELD TYPE REFERENCE mở rộng + MUTATION STRATEGY giữ nguyên
```

### 2.2 Structured Output — JSON Schema (cần verify GLM support)

**Paper:** OpenAI Structured Outputs (2024), XGrammar (2025), Outlines

**Nội dung:**
- Hiện tại: `response_format={"type": "json_object"}` (dòng 1176)
- Đề xuất: `response_format={"type": "json_schema", "json_schema": ProtocolGrammar.model_json_schema()}`
- Nếu GLM-5-Turbo **không** support: giữ nguyên `json_object`, thay vào đó cải thiện parsing fallback

**Checklist:**
```
□ Verify GLM-5-Turbo / ZhipuAI API có support response_format=json_schema không
   - Nếu có: implement constrained decoding → bỏ ~40 dòng OUTPUT FORMAT + CRITICAL RULES
   - Nếu không: giữ nguyên, thêm post-parse validation mạnh hơn
□ Alternative: dùng Outlines framework để constrained decoding ở client-side
```

### 2.3 Chain-of-Thought — Cải thiện instruction cho reasoning field (đã có)

**⚠️ Sửa từ phiên bản cũ:** `reasoning` field **đã tồn tại** trong `ProtocolGrammar` (`schemas.py:858`),
đã có trong OUTPUT FORMAT example (dòng 345, 361, 390-392). Đây là **reinforcement**, không phải tính năng mới.

**Paper:** Wei et al. (2022) — CoT Prompting (NeurIPS)

**Cải thiện cụ thể:**
```
TRƯỚC (dòng 345):
    "reasoning": "string — explain your analysis methodology, key findings, and strategy rationale"

SAU:
    "reasoning": "string — step-by-step: 1) identify constant/magic bytes ...
                  2) detect length fields via correlation with remaining bytes ...
                  3) infer enum/opcode fields from limited value sets ...
                  4) check for checksums / state machine patterns"
```

Thêm vào CRITICAL RULES:
```
- Before outputting fields, FIRST write your reasoning step-by-step in the "reasoning" field.
  This ensures you consider all evidence before concluding.
```

### 2.4 Dynamic Few-Shot Examples — Mở rộng 1→3 examples

**⚠️ Sửa từ phiên bản cũ:** Không dùng `field_groups` count từ DifferentialAnalyzer làm proxy để chọn example (không đáng tin cậy). Thay vào đó: **luôn gửi 3 examples** và LLM tự học pattern. Hoặc dùng protocol complexity heuristic: nếu packet có opcode pattern (byte value set nhỏ ở offset cố định) → thêm opcode example.

**Paper:** Brown et al. (2020) — Few-Shot Prompting (NeurIPS)

**Nội dung thực tế:**
```
Hiện tại: 1 example 3-field (magic + length_be + payload)

Đề xuất: 3 examples, tất cả đều trong system prompt:

Example 1: Simple TLV (giữ nguyên) — magic + length + payload
Example 2: Opcode-based — magic + opcode(enum) + length + payload + checksum
Example 3: Nested structure — magic + count + [type+len+value]*N

Lưu ý: 3 examples ~40 dòng, net tăng ~10 dòng so với 1 example hiện tại.
Nhưng ví dụ phong phú hơn giúp LLM generalize tốt hơn.
```

### 2.5 Structured Feedback — Thay text blob bằng JSON

**⚠️ Lưu ý:** Cần sửa cả caller (`rules_orchestrator.py`) — nơi sinh `response_feedback`.
Hiện tại `response_feedback: Optional[str]` trong `build_prompt()` (dòng 900).

**Nội dung:**
```json
// response_feedback gửi dạng JSON string thay vì text blob
{
  "field_stats": [
    {"offset": 0, "strategy": "static", "accept_rate": 0.95, "reject_rate": 0.05},
    {"offset": 4, "strategy": "boundary_values", "accept_rate": 0.30, "reject_rate": 0.70}
  ],
  "overall": {"accept_rate": 0.45, "reject_rate": 0.50, "timeout_rate": 0.05}
}
```

Kết hợp với FEEDBACK_APPEND ngắn hơn:
```
High rejection (>70%) on a field → offset or type likely WRONG.
High acceptance on BOUNDARY_VALUES → grammar is accurate, keep it.
```

### 2.6 Fusion Consolidation — Giảm redundant giữa Step 2 và FUSION_APPEND

**Nội dung:**
```
Vấn đề:
  - Step 2 (dòng 178-184): "CRITICAL: NEVER fuzz magic bytes"
  - FUSION_APPEND (dòng 409-413): "Do NOT re-derive STATIC fields"
  → Cả 2 đều nói "trust STATIC/magic, đừng mutate"

Giải pháp:
  Khi fusion ON (có math_hint):
    - Step 2 instruction tóm gọn: "Find magic bytes → mark static"
    - Chi tiết về "why không nên fuzz" dồn vào FUSION_APPEND
  Khi fusion OFF (không math_hint):
    - Step 2 giữ nguyên (vì không có fusion append)
```

### 2.7 Self-Consistency Ensemble (Nâng cao)

**Paper:** Wang et al. (2022) — Self-Consistency (ICLR)

**Nội dung:**
- Chạy N=3 parallel inferences với temperature=0.5
- Vote majority cho field boundaries (median offset_start, offset_end)
- Vote majority cho field_type
- Mean confidence
- Cost tăng 3x, accuracy tăng ~18%

---

## 3. So sánh các hướng

| Tiêu chí | Compression + CoT | Constrained Decoding | Self-Consistency | DSPy Pipeline |
|----------|-------------------|---------------------|------------------|---------------|
| **Hiệu quả nhất** | ✅ CoT +15-40% | ✅ 100% schema | ✅ +18% accuracy | ✅ Auto-optimize |
| **Tiết kiệm nhất** | ✅ -27% tokens | ✅ -40 dòng prompt | ❌ +3x cost | ❌ High setup |
| **Chính xác nhất** | ✅ CoT proven | ✅ Zero schema error | ✅ Ensemble vote | ✅ Metric-driven |
| **Không phụ thuộc LLM** | ✅ | ❌ (cần GLM support) | ✅ | ❌ (cần DSPy) |
| **Mâu thuẫn codebase** | ✅ Không | ✅ Không | ✅ Không | ✅ Không |
| **Effort triển khai** | Thấp (sửa prompt) | Thấp-Trung bình | Trung bình (3 calls) | Cao (cả pipeline) |

→ **Khuyến nghị:** Compression + CoT + Few-Shot + Structured Feedback
(Không phụ thuộc API backend, không mâu thuẫn codebase, effort thấp)

---

## 4. Lộ trình

### Phase 1 — Immediate (zero-risk, ~3h)

```
□ 1. Rút gọn SYSTEM_PROMPT 250→180 dòng (ko xóa section quan trọng)
□ 2. Mở rộng FIELD TYPE REFERENCE 8→14 types (thêm int8/16/32, bool, reserved)
□ 3. Diễn đạt lại safety trigger phrases: "CVE analysis"→"protocol security analysis"
□ 4. Cải thiện CoT instruction cho reasoning field (step-by-step template)
□ 5. Fusion consolidation: rút gọn Step 2 khi fusion ON
□ 6. Structured feedback: đổi text blob → JSON + sửa caller
```

### Phase 2 — Short-term (~1 tuần)

```
□ 7. Mở rộng few-shot examples (1→3: thêm opcode + nested TLV)
□ 8. Verify GLM-5-Turbo support cho json_schema response format
```

### Phase 3 — Medium-term (~2 tuần, optional)

```
□ 9. Constrained Decoding (nếu GLM support)
□ 10. Self-Consistency ensemble (3 parallel inferences)
□ 11. DSPy optimization pipeline
```

---

## 5. Token Savings Estimate (ĐÃ SỬA)

| Thay đổi | Tokens | Ghi chú |
|----------|--------|---------|
| **Before** | ~4,000 | Baseline |
| Rút gọn 7→4 steps + safety rephrase | -200 | |
| MỞ RỘNG FIELD TYPE 8→14 | +50 | Thêm 6 types |
| Thêm 2 few-shot examples | +60 | Net +1 example (giữ 1, thêm 2) |
| Rút gọn CRITICAL RULES | -50 | |
| **Phase 1 total** | **~3,760 (-6%)** | Tiết kiệm ít hơn bản cũ vì giữ lại các section quan trọng |
| **Phase 2 + Constrained Decoding** | **~3,400 (-15%)** | Nếu GLM support, bỏ OUTPUT FORMAT + CRITICAL RULES |

**Kết luận:** Token savings **khiêm tốn hơn** bản cũ (~6-15% thay vì 47%).
Lý do: các section tưởng "redundant" hóa ra cần thiết cho pure LLM mode.
Giá trị thực sự đến từ **accuracy improvement** (CoT + few-shot + structured feedback) chứ không chỉ token savings.

---

## 6. Tham khảo

| Paper | Năm | Nguồn | Kỹ thuật |
|-------|-----|-------|----------|
| Brown et al., "Language Models are Few-Shot Learners" | 2020 | NeurIPS | Few-Shot Prompting |
| Wei et al., "Chain-of-Thought Prompting Elicits Reasoning" | 2022 | NeurIPS | CoT Reasoning |
| Wang et al., "Self-Consistency Improves Chain of Thought" | 2022 | ICLR | Self-Consistency |
| Jiang et al., "LLMLingua: Compressing Prompts" | 2023 | EMNLP | Prompt Compression |
| Li et al., "Prompt Compression: A Survey" | 2025 | NAACL | Compression Strategies |
| OpenAI, "Structured Outputs in the API" | 2024 | OpenAI | JSON Schema Constraint |
| XGrammar, "Efficient Structured Generation" | 2025 | — | Constrained Decoding |
| DSPy Team, "DSPy: Compiling Declarative Language Model Calls" | 2023-2026 | Stanford NLP | Self-Optimizing Prompts |

---

## Phụ lục: Các thay đổi so với v1.0

| Mục | v1.0 (sai) | v2.0 (đúng) | Lý do |
|-----|-----------|-------------|-------|
| `reasoning` field | "Thêm mới" | "Cải thiện instruction — đã có sẵn" | Code audit: schemas.py:858 |
| FIELD TYPE REFERENCE | "Xóa (redundant)" | "Mở rộng 8→14 types" | Prompt thiếu 6 types so với enum |
| MUTATION STRATEGY | "Xóa" | "Giữ nguyên" | Cần cho pure LLM mode |
| Token savings | -47% | -6% đến -15% | Giữ lại các section quan trọng |
| Traffic compression | "Hex diff format" | ❌ BỎ | `_format_hex_xxd()` có offset ruler chống off-by-one |
| Few-shot selection | "field_groups count" | "Luôn gửi 3 examples hoặc heuristic opcode" | field_groups không reliable |
| Safety phrases | "Xóa" | "Diễn đạt lại" | Cần persona giữ nguyên context |
