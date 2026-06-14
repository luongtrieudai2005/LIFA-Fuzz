# LIFA-Fuzz — Adaptive Scheduling as an Adversarial Bandit (VAMAB)

**Phiên bản:** v2.0 (tái cấu trúc từ v1.0) · **Trạng thái:** Thiết kế xong, sẵn sàng triển khai theo pha
**Cơ sở lý thuyết:** EcoFuzz / VAMAB (USENIX Security 2020) · Woo et al. (CCS 2013) · AFLFast (Böhme et al., TSE 2017) · Patil & Kanade (arXiv 2018)

> Văn kiện này **thay thế v1.0**. v1.0 đặt vấn đề đúng (MAB scheduling, epsilon-decay,
> self-correction) nhưng đặt **sai khung phương pháp**: giả định reward mỗi-send
> (mâu thuẫn với fire-and-forget) và dùng crash làm reward (anti-pattern mà
> Woo et al. + EcoFuzz cảnh báo thẳng). v2.0 tái cấu trúc bằng khung **Adversarial
> Bandit (VAMAB)**, nơi các mâu thuẫn tự tan và **không phá kiến trúc cốt lõi**.

---

## 0. TL;DR

- **Vấn đề cốt lõi:** LIFA-Fuzz cần adaptive scheduling (chọn seed/strategy, cấp
  năng lượng, cân bằng exploration/exploitation) nhưng là **black-box fire-and-forget**
  (recv chỉ mỗi k-send) → không có reward mỗi execution.
- **Giải pháp:** Mô hình hóa scheduling là **Variant of the Adversarial Multi-Armed
  Bandit (VAMAB)**. Arm = seed/strategy. Reward = **sự kiện novelty đã dedup**
  (KHÔNG phải crash). Reward-probability ước lượng bằng **SPEM** từ *tần suất
  novelty quan sát trên recv lấy mẫu* — cập nhật **mỗi epoch** (Slow Loop), per-send
  cost = 0.
- **3 trục điều phối trực giao** (EcoFuzz chứng minh scheduling là nhiều quyết định
  bandit, không phải 1): (A) chọn arm — SPEM, (B) cấp năng lượng — AAPS, (C) lấy mẫu
  feedback — EWMA (đã có). Không chồng, không đánh nhau.
- **Epsilon-decay KHÔNG tồn tại riêng** — nó là **trạng thái bandit**
  (initial/exploration/exploitation). "Epsilon spike khi stuck" = transition
  exploitation→exploration khi tìm thấy novelty mới.
- **Không phá kiến trúc:** per-epoch (không per-send), Fast-Slow Loop async giữ
  nguyên, fire-and-forget giữ nguyên (bandit chạy trên quan sát lấy mẫu), bootstrap
  fallback giữ nguyên.

---

## 1. Bối cảnh & nguyên lý kế thừa (KHÔNG thay đổi)

### 1.1 Nguyên lý LIFA-Fuzz được giữ nguyên toàn bộ

| Nguyên lý | Vì sao VAMAB tương thích |
|---|---|
| **Fast-Slow Loop bất đồng bộ** (Fast 400+ EPS, Slow LLM ~1/min) | Bandit cập nhật ở **Slow Loop** (per-epoch); Fast Loop chỉ đọc state bandit qua file IPC |
| **Fire-and-forget + EWMA recv sampling** | Bandit ước lượng reward từ **recv lấy mẫu** — chính triết lý proxy-on-sample của EWMA |
| **Bootstrap fallback** (math layer) | Bandit prune rule xấu → math layer bù → không đói |
| **Neural-Mathematical Fusion** | Không liên quan, giữ nguyên |

### 1.2 Vấn đề v1.0 đặt đúng nhưng giải sai

v1.0 (Task 2/3/4) đặt đúng nhu cầu: penalize rule ảo, cân bằng exploration/
exploitation, LLM học từ lỗi. Nhưng **3 sai khung phương pháp**:

| Sai của v1.0 | Vì sao sai (literature) |
|---|---|
| Reward/penalty **mỗi recv()** (+5/−0.5) | Fire-and-forget: recv chỉ mỗi k-send → 99.5% send không có reward. Bandit không cần reward mỗi execution — nó ước lượng từ **tần suất tích lũy** |
| **Reward +5 cho crash** | EcoFuzz §7.1 + Woo et al.: *"focusing on crashes triggers the same crashes repeatedly"*. Crash là **anti-pattern**; reward phải là **coverage novelty** |
| **MAB + epsilon + EWMA** là 3 controller riêng | EcoFuzz: scheduling là **nhiều quyết định bandit trực giao**, không phải 3 thứ đánh nhau. Epsilon **là trạng thái** bandit, không phải controller |

---

## 2. Cơ sở lý thuyết — VAMAB (EcoFuzz) thích nghi cho black-box

### 2.1 Mô hình VAMAB

EcoFuzz mô hình hóa coverage-based fuzzing là **Variant of the Adversarial MAB**:

- **Arm** = seed `t_i`. (LIFA-Fuzz: arm = **seed/strategy-cluster**.)
- **Trial** = mutate arm → execute.
- **Reward** = trial sinh input → **khám phá path MỚI** (novelty).
- **Reward probability** `P_R(t_i)` = xác suất arm i tìm path mới = `1 − Σ_j p_ij`.
- **Probability attenuation**: khi nhiều path đã tìm, `P_R` **giảm** → reward
  distribution **không dừng** → **adversarial** bandit (Exp3 family), không phải
  stochastic MAB (UCB).

**Tham chiếu:** EcoFuzz định nghĩa 3.1–3.4; Eq. 6–7 (reward probability); §3.2
(probability attenuation).

### 2.2 SPEM — ước lượng reward probability khi không có source

EcoFuzz §3.3: reward probability **không tính được chính xác** (cần source để suy
path constraints). Giải pháp **SPEM** (Self-transition Probability Estimation):

$$P_R(t_i) \approx \frac{1 - f_{ii}}{\sqrt{i}}$$

- `f_ii` = **self-transition frequency** = tỷ lệ mutation của seed i vẫn rơi vào cùng
  path cũ (tần suất **quan sát được**, tích lũy qua nhiều trial).
- `√i` = hệ số attenuation (seed khám phá sớm → reward probability attenuate nhiều).
- **Chỉ cần magnitude relationship** (so sánh arm), không cần giá trị chính xác.

→ **Đây chính chìa khóa cho black-box**: `f_ii` ước lượng từ **quan sát lấy mẫu**
(recv mỗi k-send), cập nhật tích lũy. **Không cần reward mỗi execution.**

### 2.3 AAPS — cấp năng lượng theo average-cost

EcoFuzz §4.3: năng lượng (số mutation/arm) = hàm của **average-cost**
(executions/path mới), với **regret adaptation** (cấp quá nhiều → giảm lần sau).

### 2.4 Ba trạng thái (thay epsilon tĩnh)

EcoFuzz §3.2: seeds set ở 1 trong 3 trạng thái, mỗi trạng thái 1 chiến lược:

| Trạng thái | Hành vi | Tương đương epsilon |
|---|---|---|
| **Initial** | chưa fuzz seed nào | exploration thuần |
| **Exploration** | fuzz seed chưa thử + ước lượng `P_R` | cân bằng |
| **Exploitation** | ưu tiên arm có `P_R` cao (SPEM) | tập trung |
| **Transition** | tìm novelty mới → **exploitation → exploration** | = "epsilon spike" |

→ **Epsilon-decay (v1.0 Task 3) tan vào trạng thái bandit.** Không còn controller thứ 4.

---

## 3. Áp vào LIFA-Fuzz — 3 trục điều phối trực giao

### 3.1 Ánh xạ VAMAB → black-box LIFA-Fuzz

| Khái niệm EcoFuzz (grey-box) | Ánh xạ LIFA-Fuzz (black-box) |
|---|---|
| Arm = seed | Arm = **seed** (SeedSequence) hoặc **strategy-cluster** (nhóm SemanticRule theo MutationStrategy) |
| Reward = new **code path** | Reward = **novelty signal đa chiều**: new response-fingerprint / new state-edge / new ASAN-crash-signature (đã dedup) |
| `f_ii` = self-transition (cùng path) | `f_ii` = tỷ lệ mutation cho **cùng response-class** (không mới) — ước lượng từ recv lấy mẫu |
| Reward probability | `P_R ≈ (1 − f_ii)/√i` trên sampled observations |
| 3 trạng thái | áp nguyên (initial/exploration/exploitation) |

**Novelty signal (black-box proxy cho "new path"):** vì LIFA-Fuzz không thấy code
coverage, dùng các **observable**:
- **New response-fingerprint** (hash 8-byte đầu response + length) — chưa từng thấy.
- **New state-edge** (STG: `(prev_code, command, new_code)` chưa thấy) — cho FTP.
- **New ASAN-crash-signature** (Task 1.1: hash 3 dòng stack ASAN) — crash NOVEL.
- **Accepted-rate delta** (EWMA proxy B hiện có).

→ **Đa tín hiệu, protocol-agnostic** (giải mâu thuẫn "STG binary-specific" của v1.0).

### 3.2 Ba trục trực giao

| Trục | Quyết định | Thuật toán | Cadence | Hiện có |
|---|---|---|---|---|
| **A. Chọn arm** | play seed/strategy nào | **SPEM** (sort by `P_R`) | per-epoch (Slow Loop) | WeightedScheduler (static) → nâng cấp |
| **B. Cấp năng lượng** | mấy mutation/arm | **AAPS** (average-cost + regret) | per-epoch | investigation_budget (cố định) → AAPS |
| **C. Lấy mẫu feedback** | mỗi k-send recv 1 lần | **EWMA controller** | per-packet (Fast Loop) | ✅ ĐÃ CÓ, giữ nguyên |

**Không chồng**: A quyết định *chọn ai*, B quyết định *bao nhiêu*, C quyết định
*khi nào quan sát*. EcoFuzz chứng minh A+B là 2 bandit riêng; C là LIFA-specific
(EWMA). **Không có 2 controller đánh nhau** (mối lo v1.0 Task 3).

### 3.3 Cập nhật per-epoch (không per-send) — không phá EPS

```
Fast Loop (hot, 400 EPS):
  mỗi send → ghi (arm_id, response_observed?) vào shared bandit_buffer.jsonl  [O(1), không lock]
  đọc bandit_state.json mỗi N packet (giống adaptive_k.json)                 [lock-free]

Slow Loop (~1/min):
  đọc bandit_buffer → cập nhật f_ii, novelty-count cho mỗi arm
  tính P_R = (1 − f_ii)/√i  cho mỗi arm
  xác định trạng thái (initial/exploration/exploitation)
  viết bandit_state.json (arm ordering + energy + state)
```

→ **Per-send cost = 1 ghi-append O(1) (không lock)**, như `_crash_window` hiện có.
Tính toán bandit (SPEM/AAPS/state) ở Slow Loop → **EPS đường nóng không đổi**.

---

## 4. Bốn tác vụ — tái cấu trúc từ v1.0

> Thứ tự phụ thuộc: Task 1 (crash pipeline) độc lập; Task 2 (novelty signal) là
> nền cho Task 3 (bandit); Task 4 (LLM self-correction) dùng output Task 3.

### Task 1 — Crash Analysis & Isolation Pipeline (giữ, chuẩn hóa)

*(Kế thừa v1.0 Task 1, kết hợp Phase 1 confirmation đã implement.)*

#### 1.1 ASAN-based dedup (AUGMENT, không REPLACE)
- **Modify:** `shared/crash_manager.py` — `compute_sigma1`.
- **Logic:** signature primary = **hash 3 dòng đầu stack ASAN** (nếu có, từ
  `get_last_crash_info().stack_trace`); **fallback** = SHA256(payload) hiện có
  khi không có ASAN (SIGSEGV thuần, OOM, normal exit). **Không bỏ** payload dedup.
- **Lý do AUGMENT:** ASAN không luôn có → payload fallback đảm bảo mọi crash đều
  dedup được. v1.0 nói "REPLACE" → gãy cho non-ASAN.

#### 1.2 ONE_AT_A_TIME isolation (ĐÃ CÓ — chỉ wire)
- **Modify:** `fast_loop/mutator.py`.
- **Logic:** `set_investigation_mode()` + `OneAtATimeScheduler` **đã tồn tại**.
  Wire: khi `crash_monitor` ghi crash mới (sau Phase 1 confirmation), **freeze crashing
  seed** + vào investigation mode cô lập 1 field/lần.
- **Kết nối Phase 1:** Phase 1 xác nhận *packet* reproduce; Task 1.2 cô lập *field*
  trong packet đó. Hai pha nối tiếp, không trùng.

#### 1.3 Structured report (bổ sung `isolated_trigger`)
- **Modify:** `shared/schemas.py` `CrashRecord` (đã có `reproduced`/`confirmation_method`).
- **Add:** `isolated_trigger: {offending_field, applied_strategy}` — điền từ
  `OneAtATimeScheduler.get_current_field_index()` khi investigation xác nhận field.
- **Report schema** khớp v1.0 nhưng thêm `reproduced` (Phase 1) + `confirmation_method`.

### Task 2 — Novelty Signal Pipeline (MỚI — nền cho bandit)

*(Thay thế v1.0 Task 2.2 "reward/penalty".)*

#### 2.1 Novelty observer trong Fast Loop
- **Modify:** `fast_loop/mutator.py` — trong `_send`, khi `_should_recv()` → recv.
- **Logic:** classify response thành **response-class** (fingerprint: hash 8-byte
  đầu + length + optional FTP status code). Nếu class **chưa từng thấy** → novelty
  event. Ghi `(arm_id, novelty?, response_class)` vào `bandit_buffer.jsonl` (O(1) append,
  như `_crash_window`).
- **KHÔNG có reward/penalty magnitude** (v1.0 ±5/±1 — bỏ). Chỉ ghi **fact** novelty.

#### 2.2 Novelty aggregator trong Slow Loop
- **Modify:** `slow_loop/rules_orchestrator.py` (hoặc bandit module mới).
- **Logic:** mỗi epoch, đọc `bandit_buffer.jsonl` → cho mỗi arm tính:
  - `s_i` = tổng trial của arm i.
  - `f_ii` = tỷ lệ trial cho **cùng response-class phổ biến nhất** (= self-transition).
  - `novelty_count_i` = số response-class mới arm i khám phá.

### Task 3 — VAMAB Scheduling (thay v1.0 Task 2.1/2.3 + Task 3)

#### 3.1 Bandit state (tách riêng, không schema SemanticRule)
- **New:** `shared/bandit_state.py` — `BanditArm {arm_id, s_i, f_ii, novelty_count,
  last_energy, P_R}`, `BanditState {arms, phase, average_cost}`.
- **Lý do tách:** tránh migration `SemanticRule` (v1.0 thêm field mỗi send);
  bandit state là per-seed/strategy, cập nhật per-epoch.

#### 3.2 SPEM — chọn arm (trục A)
- **Modify:** scheduler selection.
- **Logic:** sort arm by `P_R ≈ (1 − f_ii)/√i`; exploration state → round-robin
  arm chưa thử; exploitation state → ưu tiên `P_R` cao (SPEM).

#### 3.3 AAPS — cấp năng lượng (trục B)
- **Logic:** energy = `average_cost × coefficient × rate`, `coefficient` theo tỷ lệ
  `s_i/average_cost` (EcoFuzz Algorithm 2), `rate` adapt theo regret. Cap `M = 16×average_cost`.

#### 3.4 State machine (thay epsilon)
- **Logic:** initial → exploration (fuzz hết arm chưa thử) → exploitation (SPEM);
  **tìm novelty mới → exploitation → exploration** (= epsilon spike, tự động).
- **KHÔNG có epsilon vô hướng** (v1.0 Task 3 — bỏ). Exploration level = hàm của state.

### Task 4 — LLM Self-Correction (giữ, dùng output Task 3)

*(Kế thừa v1.0 Task 4, dùng bandit output thay reputation ad-hoc.)*

#### 4.1 Closed-loop feedback (đã có `_build_response_feedback`, mở rộng)
- **Modify:** `slow_loop/rules_orchestrator.py` `_build_response_feedback` (đã là JSON).
- **Logic:** inject vào prompt: (a) response stats hiện có + (b) **arm có `P_R` thấp
  nhất** (strategy/offset bị bandit đánh giá kém) + (c) novelty mới khám phá.
- **Prompt injection (chuẩn hóa v1.0):** *"Feedback: strategy X at offset Y has low
  novelty yield (P_R=0.02, tried N times, 0 new response-class). Re-analyze the heatmap
  and propose alternatives. Recently discovered response-classes: [list]."*

---

## 5. Bất biến thiết kế (phải giữ qua mọi implementation)

1. **Per-send cost = O(1), không lock.** Bandit compute ở Slow Loop (per-epoch).
   Fast Loop chỉ append buffer + đọc state (lock-free, như EWMA hiện có).
2. **Reward = novelty (dedup), KHÔNG phải crash.** Crash NOVEL là 1 loại novelty
   signal, không phải reward trực tiếp (Woo/EcoFuzz).
3. **3 trục trực giao.** SPEM (chọn) / AAPS (năng lượng) / EWMA (lấy mẫu) — mỗi cái
   1 trục, không can thiệp nhau.
4. **Epsilon = state, không phải controller.** Không có epsilon vô hướng riêng.
5. **ASAN dedup AUGMENT.** Payload fallback khi không có ASAN.
6. **Bootstrap floor.** Bandit prune không được làm số rule < N tối thiểu (math layer bù).
7. **Failure isolation.** Bandit lỗi → fallback WeightedScheduler static hiện có.

---

## 6. Lộ trình triển khai (chia pha, kiểm chứng từng bước)

### Phase 1 — ĐÃ CÓ: Post-crash confirmation (freeze + replay PoC)
- Commit `c2f0691`. Xác nhận PoC reproduce. Nền cho Task 1.

### Phase 2 — Task 1: ASAN dedup + field isolation + structured report (2–3 ngày)
- 1.1 ASAN dedup (augment). 1.2 wire investigation mode. 1.3 `isolated_trigger`.
- **Verify:** crash LIFA thật → `crashes/*.json` có `crash_id` = ASAN hash +
  `isolated_trigger.offending_field` + `reproduced=True`.

### Phase 3 — Task 2: Novelty signal pipeline (2 ngày)
- 2.1 novelty observer (Fast Loop append). 2.2 aggregator (Slow Loop).
- **Verify:** chạy MOCK 5 phút → `bandit_buffer.jsonl` có novelty events; `f_ii`
  per-arm tính được.

### Phase 4 — Task 3: VAMAB scheduling (3–4 ngày)
- 3.1 bandit_state. 3.2 SPEM. 3.3 AAPS. 3.4 state machine.
- **Verify:** 3 trạng thái chuyển đúng; arm có `P_R` cao được ưu tiên; novelty
  mới → về exploration; EPS không đổi (so A/B).

### Phase 5 — Task 4: LLM self-correction (1 ngày)
- 4.1 mở rộng `_build_response_feedback` inject arm `P_R` thấp + novelty mới.
- **Verify:** prompt có feedback bandit; LLM output tránh strategy kém.

---

## 7. Đánh giá & metric nghiệm thu

| Metric | Định nghĩa | Mục tiêu |
|---|---|---|
| **Novelty discovery rate** | response-class mới / epoch | tăng so với random (Baseline A) |
| **Path/coverage proxy** | cumulative unique response-class + state-edge | VAMAB > random, so sánh A/B/C |
| **Energy efficiency** | novelty mới / mutation (average-cost ngược) | giảm average-cost (EcoFuzz style) |
| **EPS impact** | EPS trước/sau bandit | **= 0** trên đường nóng (per-epoch compute) |
| **State transition correctness** | exploration↔exploitation đúng timing | xác nhận bằng log |
| **Crash reproducibility** | `reproduced_crashes / unique_crashes` | >80% (Phase 1 + Task 1) |

> **EPS impact = 0 là bất biến thiết kế** (§5.1), không phải mục tiêu.

---

## 8. Tương thích báo cáo khoa học (`bao_cao_cuoi_ky.md`)

### 8.1 Không bác bỏ kết quả RQ1/RQ2
- RQ1 (F1=0.857 MOCK), RQ2 (EPS A=414/B=400/C=141) **không đổi**.
- VAMAB ảnh hưởng **RQ3** (crash discovery) + thêm phân tích scheduling efficiency.

### 8.2 Đóng góp mới (đề xuất thêm vào báo cáo)
- **Adaptive scheduling bằng VAMAB** cho black-box protocol fuzzing — thích nghi
  EcoFuzz (grey-box) sang black-box bằng **novelty signal đa chiều** thay code path.
- **3 trục điều phối trực giao** (SPEM/AAPS/EWMA) — generalize EcoFuzz's 2 trục
  (+ feedback sampling cho fire-and-forget).
- **Crash confirmation pipeline** (Phase 1 + Task 1) — PoC deterministic cho
  black-box fire-and-forget (giải attribution limitation đã document).

### 8.3 Hạn chế thừa nhận
- Novelty signal (response-class) là **proxy** của code coverage → nhiễu hơn
  grey-box. Bandit hội tụ chậm hơn (variance cao từ sampled observation).
- ASAN dedup phụ thuộc serial capture độ tin cậy (truncation/buffer).

---

## 9. Rủi ro & giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Novelty signal nhiễu (proxy ≠ code path) → bandit chọn sai arm | đa tín hiệu + EWMA smoothing + bootstrap floor |
| `f_ii` ước lượng từ sampled observation variance cao | cần đủ sample/arm; cold-start dùng exploration state |
| ASAN serial truncation → dedup sai | fallback payload SHA256 (augment) |
| Bandit prune quá hung → đói rule tạm | bootstrap floor (§5.6) |
| Per-epoch latency → rule update chậm | chấp nhận (rule update mỗi 1-2 phút là đủ, kiến trúc hiện có) |
| Tương tác investigation mode × bandit | investigation (Task 1.2) override tạm; xong → resume bandit state |

---

## 10. Nguồn (literature grounding)

- **EcoFuzz / VAMAB** — Yue et al., "EcoFuzz: Adaptive Energy-Saving Greybox
  Fuzzing as a Variant of the Adversarial Multi-Armed Bandit", USENIX Security 2020.
  Khung chính: VAMAB (§3), SPEM (§4.2, Eq. 10), AAPS (§4.3), 3 trạng thái (§3.2),
  crash-over-focus caveat (§7.1).
  <https://www.usenix.org/system/files/sec20fall_yue_prepub_0.pdf>
- **Woo et al.** — "Scheduling Black-box Mutational Fuzzing", CCS 2013. Black-box
  MAB precedent; crash-over-focus warning.
  <https://users.ece.cmu.edu/~dbrumley/pdf/Woo%2520et%2520al._2013_Scheduling%2520Black-box%2520Mutational%2520Fuzzing(2).pdf>
- **AFLFast** — Böhme et al., "Coverage-based Greybox Fuzzing as Markov Chain",
  IEEE TSE 2017. Transition probability foundation.
- **Patil & Kanade** — "Greybox Fuzzing as a Contextual Bandits Problem",
  arXiv:1806.03806, 2018. Energy multiplier as bandit.
  <https://arxiv.org/abs/1806.03806>
- **MOPT** — Lyu et al., "Optimized Mutation Scheduling for Fuzzers", USENIX
  Security 2019. Bandit trên mutation operators (per-epoch update precedent).

> **Lập luận cốt lõi:** grey-box giải scheduling bằng coverage feedback mỗi execution.
> Black-box fire-and-forget không có feedback mỗi execution → phải giải bằng
> **adversarial bandit với reward-probability ước lượng từ novelty quan sát lấy mẫu**
> (SPEM). Đây là khác biệt căn bản và là lý do VAMAB (không phải per-send RL)
> là hướng đúng cho LIFA-Fuzz.

---

## 11. Non-goals (KHÔNG làm)

- ❌ Không đổi fire-and-forget thành sync recv (giết RQ2).
- ❌ Không thêm instrumentation/coverage (thoát black-box).
- ❌ Không dùng crash làm reward trực tiếp (anti-pattern Woo/EcoFuzz).
- ❌ Không thêm epsilon vô hướng riêng (là state, không controller).
- ❌ Không per-send reputation bookkeeping (per-epoch, không phá EPS).
- ❌ Không REPLACE payload dedup bằng ASAN (AUGMENT, có fallback).

---

*v2.0 tự nhất quán: nguyên lý kế thừa (§1) → cơ sở lý thuyết (§2) → ánh xạ 3 trục
trực giao (§3) → 4 tác vụ (§4) → bất biến (§5) → lộ trình (§6) → nghiệm thu (§7).
Không mâu thuẫn nội bộ, không bác bỏ ý tưởng gốc, sửa lỗi phương pháp v1.0 bằng
cơ sở literature.*
