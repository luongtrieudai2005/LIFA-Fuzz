# LIFA-Fuzz — Adaptive Scheduling: Paper-Scope Design

**Phiên bản:** v3.0 (tinh giản từ v2.0 — loại over-engineering cho paper)
**Cơ sở:** EcoFuzz/VAMAB (USENIX Sec'20) · Woo et al. (CCS'13)
**Nguyên tắc phiên bản này:** paper mạnh ở đóng góp rõ + ablation nghiêm ngặt, KHÔNG ở
phức tạp thuật toán không bóc tách được. v2.0 port gần như nguyên vẹn EcoFuzz (SPEM +
AAPS + 3-state machine) → over-engineering: cơ chế khó ablate, rủi ro bị review là
"EcoFuzz-variant". v3.0 giữ **1 cơ chế mới** (ablate được thành Baseline D), phần phức
tạp đẩy sang Future Work.

> **Quyết định biên giới:** đóng góp chính của paper là **LLM grammar inference +
> math fusion** (RQ1/RQ2). Adaptive scheduling là đóng góp **phụ**, **không** làm
> lu mờ luận điểm chính. v3.0 giữ scheduling ở mức tối thiểu đủ minh chứng.

---

## 1. Vấn đề & vì sao v1.0 sai (giữ — giá trị Related Work)

LIFA-Fuzz fire-and-forget (recv mỗi k-send) → không có reward mỗi execution.
v1.0 (bản upgrade gốc) giải sai 2 chỗ:

1. **Reward mỗi recv** (+5/−0.5) — fire-and-forget chỉ recv mỗi k-send (k biến thiên
   theo EWMA, tới ~200) → đại đa số send không có reward.
2. **Reward +5 cho crash** — Woo et al. (CCS'13) + EcoFuzz §7.1 cảnh báo thẳng:
   *"focusing on crashes re-triggers the same crash"*. Crash là **anti-pattern**;
   reward phải là **novelty**.

→ Literature: scheduling black-box fuzzing nên mô hình là **bandit** (Woo), reward =
**coverage novelty** (EcoFuzz), reward-probability **ước lượng từ tần suất quan sát**
(không cần reward mỗi execution). Đây là cơ sở đúng — nhưng **không** bắt buộc port
toàn bộ cơ chế EcoFuzz.

---

## 2. Cơ sở lý thuyết (gọn — đủ cite, không exegesis)

- **Bandit framing** (Woo et al., CCS'13; EcoFuzz, USENIX'20): arm = mutation
  strategy, reward = sự kiện novelty. Reward ước lượng từ **tần suất quan sát lấy mẫu**
  — không cần reward mỗi execution → tương thích fire-and-forget.
- **Reward = novelty, không crash** (EcoFuzz §7.1): crash-over-focus anti-pattern.
- **Reward của LIFA-Fuzz = novelty rate trực tiếp** (KHÔNG phải proxy self-transition
  của EcoFuzz SPEM). Ta định nghĩa:

  $$\text{reward}(\text{strategy } s) = \text{novelty rate}(s) = \frac{\#\text{ new response-class do } s \text{ khám phá (gần đây)}}{\#\text{ trial của } s \text{ (gần đây)}}$$

  (EWMA-smoothed trên một cửa sổ trial). Đây **sạch hơn** proxy `1−f_ii` của EcoFuzz
  (vốn = P(path *khác*, gồm cả known-different)): novelty rate đo *chính xác* tỷ lệ
  khám phá class mới. Cite EcoFuzz cho *ý* "ước lượng reward từ tần suất quan sát",
  nhưng định nghĩa reward là của ta. EcoFuzz's `√i` (discovery-order index AFL) không
  áp dụng — LIFA không có queue tăng trưởng kiểu AFL.

**Tham chiếu paper (Related Work):** cite EcoFuzz (VAMAB/SPEM), Woo (black-box MAB),
AFLFast (Markov-chain transition probability). Đây là đủ — **không** port AAPS hay
3-state machine của EcoFuzz (xem §6 Future Work).

---

## 3. Đóng góp paper-scope: novelty-weighted selection + plateau ε-decay

**ĐÚNG 1 cơ chế mới**, ablate được thành **Baseline D**.

### 3.1 Novelty-weighted strategy selection
- Arm = **MutationStrategy** (BOUNDARY_VALUES / DICTIONARY / RANDOM_BYTES / ...).
  LIFA-Fuzz có **vài strategy** (≤ ~8), nên đây thực chất là **adaptive strategy
  weighting** — trung thực gọi vậy, không "bandit" phóng đại.
- Mỗi epoch (Slow Loop): cho mỗi strategy tính `novelty rate(s)` (xem §2). Strategy có
  novelty rate cao được ưu tiên.
- Selection = weighted by `novelty rate` (thay **static heuristic weights** của
  `WeightedScheduler` hiện có — vốn gán BOUNDARY=4.0/DICTIONARY=3.0/RANDOM=1.0 cứng).
- **Granularity limit (phải thừa nhận):** weight ở mức strategy-toàn-cục, không
  phân biệt "BOUNDARY trên field A" vs "BOUNDARY trên field B". Future: per-(strategy,field).

### 3.2 Plateau ε-decay (thay epsilon tĩnh + thay 3-state machine)
- `ε` decay khi **không có novelty mới trong W epoch** (plateau). Reset về cao khi
  **rule set đổi** (LLM/bootstrap đẩy rule mới → cần khám phá lại).
- 1 scalar, cơ chế đơn giản, **ablate được** (so ε tĩnh).

### 3.3 Novelty signal (2 tín hiệu, không 4)
- **New response-class** (hash 8-byte đầu + length) — chưa từng thấy. (Mở rộng
  `_record_response_sample` / `response_buffer` đã có.) Đây là reward **chính**.
- **New crash-signature** (payload SHA256, đã có trong CrashManager) — đóng góp
  novelty **CHỈ khi signature mới** (đã dedup). Lưu ý: đây KHÔNG mâu thuẫn với
  anti-pattern "crash-as-reward" (§1) — anti-pattern là reward *mỗi* crash (trùng lặp
  bị tính lại); đây đếm *signature mới* (dedup) như 1 loại response-class đặc biệt,
  proportionate.
- ~~State-edge (FTP-specific)~~ và ~~accepted-rate-delta (trùng EWMA proxy)~~ — bỏ,
  tránh over-engineering.

### 3.4 Cadence (không phá EPS)
- Novelty observer chỉ chạy trên **sampled recv** (mỗi k-send), piggyback
  `response_buffer` đã có. **Không file I/O mỗi send.**
- Bandit compute ở Slow Loop (per-epoch). Per-send cost ≈ 0.

---

## 4. Đánh giá (1 ablation sạch)

| Baseline | Scheduling | Ý nghĩa |
|---|---|---|
| **B** (Math-Only, có sẵn) | **static heuristic weights** (WeightedScheduler: BOUNDARY=4.0/DICTIONARY=3.0/RANDOM=1.0 cứng) | baseline scheduling hiện có |
| **D** = B + novelty-weighted selection + plateau ε | **adaptive** (weights học từ novelty rate) | đóng góp §3 |

**So sánh D vs B = adaptive vs static-heuristic** (KHÔNG phải "vs random" — B đã
weighted). **Metric chính:** novelty discovery rate (new response-class / epoch) +
cumulative unique response-class. **Hypothesis:** D > B (adaptive weights khám phá
đa dạng hơn heuristic cứng, với cùng số mutation). **Ablation** tách đóng góp scheduling
khỏi đóng góp LLM (C). EPS của D phải ≈ B (per-epoch compute, kiểm chứng bất biến §3.4).

> Nếu D không thắng B có ý nghĩa → đóng góp scheduling **không đứng vững**, bỏ ra
> khỏi paper. Đây là điểm trung thực quan trọng — **chỉ giữ scheduling nếu ablation
> thắng**.

---

## 5. Crash confirmation (Phase 1 — đã implement, giữ)

Commit `c2f0691`: freeze attribution window + replay-confirm PoC trên snapshot sạch.
Giải crash attribution limitation (empty PoC) → unique-crash count **tin cậy hơn**
(nhưng không loại bỏ hoàn toàn nhiễu — xem Limitations). Đây là phần **đã xong**,
không phải over-engineering — trực tiếp sửa bug đo lường.

---

## 6. Future Work (đẩy phần phức tạp ra khỏi paper)

Những thứ v2.0 từng đưa vào paper-scope nhưng **over-engineering** (cơ chế khó
ablate / port EcoFuzz / rủi ro "EcoFuzz-variant") → **defer**:

- **AAPS** (energy scheduling theo average-cost + regret, EcoFuzz §4.3) — port đầy
  đủ; protocol fuzzing seed không grow kiểu AFL → cần justification riêng + ablation
  riêng. Future.
- **3-state machine** (initial/exploration/exploitation, EcoFuzz §3.2) — thay bằng
  plateau ε-decay đơn giản (§3.2). Future: nếu cần scheduling tinh tế hơn.
- **ASAN-stack dedup pipeline** đầy đủ (hash 3 dòng stack ASAN) — giữ payload SHA256
  (đã có); ASAN-augment chỉ khi serial capture tin cậy. Future.
- **Field isolation** (one-at-a-time trên crashing seed để cô lập field gây crash) —
  experiment riêng; Phase 1 confirmation đã đủ cho PoC sound. Future.
- **LLM self-correction** (inject strategy có `P_R` thấp vào prompt) — phụ thuộc §3
  chạy được; nếu scheduling không vào paper thì cái này cũng defer.
- **Self-consistency / prompt caching** (từ plan prompt-optimization) — chưa wire
  vào eval; chỉ nếu RQ1 accuracy là headline.

→ v3.0 **không implement** những thứ này trước paper. Cite literature + ghi future work.

---

## 6b. Limitations (paper phải thừa nhận)

- **Sampling bias:** novelty rate ước lượng trên recv lấy mẫu (mỗi k-send, k biến
  thiên tới ~200) → variance cao, có thể sai lệch (bias) nếu k lớn. Mitigate: EWMA
  smoothing + đủ trial/arm.
- **Coarse granularity:** weight ở mức strategy-toàn-cục, không phân biệt strategy
  trên field nào (xem §3.1). Mắt reviewer: đây là giới hạn rõ, không che giấu.
- **Per-epoch latency:** rule/weight update chậm (Slow Loop cadence ~1/min). Thay đổi
  scheduling phản ứng chậm với chuyển dịch dynamic.
- **Novelty proxy ≠ code coverage:** response-class mới không đồng nghĩa path mới
  (mutation đổi state nội bộ nhưng response giống → miss). Proxy noisier grey-box.
- **Single-target eval:** D vs B chứng minh trên LightFTP/LIFA; generalization sang
  protocol khác cần thêm ( reviewer sẽ hỏi).

---

## 7. Non-goals

## 7. Non-goals

- ❌ Không port AAPS / 3-state machine EcoFuzz (over-engineering, khó ablate).
- ❌ Không đổi fire-and-forget → sync recv (giết RQ2).
- ❌ Không dùng crash làm reward trực tiếp (anti-pattern Woo/EcoFuzz).
- ❌ Không thêm per-send bookkeeping (per-epoch).
- ❌ Không để scheduling lu mờ đóng góp chính (LLM grammar inference).

---

## 8. Nguồn

- EcoFuzz / VAMAB — Yue et al., USENIX Security 2020.
  <https://www.usenix.org/system/files/sec20fall_yue_prepub_0.pdf>
- Woo et al. — Scheduling Black-box Mutational Fuzzing, CCS 2013.
  <https://users.ece.cmu.edu/~dbrumley/pdf/Woo%2520et%2520al._2013_Scheduling%2520Black-box%2520Mutational%2520Fuzzing(2).pdf>
- AFLFast — Böhme et al., CGF as Markov Chain, IEEE TSE 2017.

---

*v3.0: lõi = 1 cơ chế (novelty-weighted selection + plateau ε), 1 ablation (D vs B),
trung thực (chỉ giữ nếu D thắng). Phần phức tạp → Future Work, cite literature. Không
over-engineering, không lu moh đóng góp chính.*
