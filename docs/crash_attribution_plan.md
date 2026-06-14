# LIFA-Fuzz — Crash Attribution: Post-Crash Confirmation Phase

**Bản vẤn:** v1.0 · **Trạng thái:** Thiết kế xong, sẵn sàng triển khai · **Tác giả:** audit nội bộ

> Văn kiện này kế thừa kiến trúc hiện tại, **không bác bỏ** bất kỳ nguyên lý
> nào của LIFA-Fuzz (Fast-Slow Loop bất đồng bộ, fire-and-forget cho
> throughput, Neural-Mathematical Fusion). Nó bổ sung **một pha xác nhận
> hậu-sự (post-crash confirmation)** nhằm phục hồi độ tin cậy của PoC mà
> **không làm tổn thương throughput ở đường nóng**. Đây là phần còn thiếu
> mà ba baseline A/B/C đều cần — và là nguyên nhân RQ3 chưa kết luận được.

---

## 0. TL;DR

- **Vấn đề:** Ở ~400 EPS (A/B), sau khi `crash_monitor` phát hiện crash
  (lag ≤ 500ms), packet gây crash đã **bị đẩy ra khỏi `_crash_window`**
  (maxlen=100 → ~0.25s). Hơn nữa, các send bị *connection-refused* vẫn
  **được append** vào window (verified `mutator.py:1640-1642`). Do đó
  `crash_window[-1]` — nguồn attribution hiện tại — gần như chắc chắn
  **không phải packet gây crash**.
- **Hậu quả:** PoC `.bin` ghi ra có thể **không reproduce**; giá trị
  triage của mỗi "unique crash" giảm; RQ3 (cumulative unique crashes,
  time-to-first-crash) thiếu độ tin cậy.
- **Căn nguyên biện chứng:** đây không phải bug code đơn lẻ mà là
  **tension vật lý** giữa *fire-and-forget* (điều kiện cần của 400 EPS,
  vì black-box không có sync signal như NSFuzz) và *attribution chính
  xác* (cần biết packet nào đang in-flight lúc crash).
- **Giải pháp đề xuất:** Pha **Post-Crash Confirmation** — khi phát
  hiện crash: **đóng băng window**, reset target về snapshot sạch, rồi
  **replay-kiểm tra** (binary-search / delta-debugging) các ứng viên
  trong window để tìm packet thật sự reproduce. Chi phí trả **chỉ khi
  có crash** (sự kiện hiếm), nên EPS đường nóng **không bị ảnh hưởng**.
- **Tương thích ý tưởng gốc:** hoàn toàn. Đây chính là **bước tự nhiên
  kế tiếp** của cơ chế `ONE_AT_A_TIME` (precision mode) đã có — nhưng áp
  vào *lịch sử* thay vì *tương lai*.

---

## 1. Bối cảnh & nguyên lý được kế thừa

### 1.1 Nguyên lý LIFA-Fuzz (KHÔNG thay đổi)

| Nguyên lý | Ý nghĩa | Vì sao giữ nguyên |
|---|---|---|
| **Fast-Slow Loop bất đồng bộ** | Fast Loop fire-and-forget 400+ EPS; Slow Loop LLM ~1/min, không bao giờ block đường nóng | Cốt lõi đề tài; EPS là RQ2 |
| **Fire-and-forget recv sampling** | `recv()` mỗi `k` packet (EWMA) — không sync từng send | Sync từng send → 40–80 EPS, mất lợi thế; vì vậy black-box không thể dùng signal-sync như NSFuzz |
| **ONE_AT_A_TIME precision mode** | Khi phát hiện crash mới, mutator chuyển sang đột biến 1-field/lần để cô lập | Đã có; pha confirmation **mở rộng** ý tưởng này |
| **Bootstrap fallback** | Math layer đảm bảo fuzzer không bao giờ "đói" rules | Không liên quan, giữ nguyên |

### 1.2 Cơ chế attribution hiện tại (di sản)

```
mutator._send()                                       [mỗi send]
  ├─ gửi payload (fire-and-forget / sampled recv)
  └─ self._crash_window.append((ts, payload, rule_id))   ← mutator.py:1642

crash_monitor.watch()                                  [poll 500ms]
  ├─ is_target_alive() == False → _verify_crash()
  └─ on_crash():
       offending = crash_window[-1]   ← GIẢ THIẾT: send cuối = culprit
       crash_manager.record(offending)   → PoC .bin, signature, unique count
```

Giả thiết "**send cuối = culprit**" đúng khi và chỉ khi detection lag ≪
window depth. Phần 2 chứng minh giả thiết này **vi phạm** ở A/B.

---

## 2. Vấn đề — định lượng và kiểm chứng

### 2.1 Toán học của sự thất bại attribution

| Đại lượng | Ký hiệu | Giá trị (A/B) | Nguồn |
|---|---|---|---|
| Throughput | λ | ≈ 400 EPS | báo cáo Table 2 |
| Độ trễ phát hiện | Δt | ≤ 500 ms | `poll_interval_ms=500` (`eval:448`) + verify fast-path |
| Chiều sâu window | W | 100 send | `_crash_window = deque(maxlen=100)` (`mutator:594`) |
| Số send trong độ trễ | λ·Δt | ≈ **200 send** | 400 × 0.5 |
| Tỷ lệ chồng lấp | (λ·Δt)/W | **2.0×** | 200/100 |

**Bất biến:** attribution tin cậy yêu cầu `W ≥ λ·Δt`. Hiện `W = 0.5·λ·Δt`
→ window **chứa tối đa nửa** khoảng nghi vấn → culprit **nằm ngoài window
với xác suất cao**, trừ khi nó xảy ra trong 250ms cuối.

### 2.2 Ô nhiễm window (verified)

`mutator.py:1640-1642` nằm **ngoài try/except**, chạy cho **mọi status**:

```python
# Backward compat — crash_monitor reads these
self._last_injected_packet = payload
self._crash_window.append((time.monotonic(), payload, self._last_injected_rule_id))
```

→ Sau khi target chết, các send tiếp theo nhận *ConnectionRefused* vẫn
được append. Khi `crash_monitor` poll lần nữa và vào `on_crash()`,
`window[-1]` gần như chắc chắn là một send **refused** (không phải
culprit). PoC ghi ra không reproduce.

### 2.3 Hệ quả đối với 3 câu hỏi nghiên cứu

| RQ | Hệ quả |
|---|---|
| **RQ3** (cumulative unique crashes, TTC) | `unique_crashes` count vẫn đúng (dedup theo signature), nhưng **giá trị** mỗi crash giảm (artifact không replay được). TTC có thể báo cáo nhưng cần footnote về độ tin cậy. |
| **RQ1** | Không ảnh hưởng (đo grammar inference, không liên quan attribution). |
| **RQ2** | Không ảnh hưởng (đo EPS). |

> **Nuance biện chứng thú vị:** Baseline C (~141 EPS) có `λ·Δt ≈ 70 <
> W=100` → attribution C **ít hỏng hơn** A/B. Nghĩa là phần mềm
> baseline "chậm hơn" (C) lại cho PoC **tin cậy hơn** — một nghịch lý
> do tension throughput/attribution. Phải nêu rõ để không kết luận
> sai rằng C "kém hơn" trên tiêu chí artifact.

---

## 3. Căn nguyên biện chứng — vì sao không sửa "bằng cách thêm recv"

### 3.1 Không mâu thuẫn với fire-and-forget

Có ba hướng "naive" đều **tự mâu thuẫn** với nguyên lý gốc và phải bị loại:

| Hướng naive | Vì sao mâu thuẫn | Kết luận |
|---|---|---|
| (a) Sync `recv()` mỗi send | EPS rơi từ 400 → 40–80; mất điều kiện RQ2 | ❌ bác bỏ |
| (b) SIGSTOP/signal sync như NSFuzz | Cần instrumentation (grey-box); LIFA-Fuzz thuần black-box | ❌ bác bỏ |
| (c) Tăng `maxlen` lên ≥ λ·Δt | Giảm ô nhiễm nhưng `window[-1]` **vẫn không phải culprit** (chỉ mở rộng tập nghi vấn, không định vị) | ❌ không đủ |

→ Phải có cơ chế **khác biệt về bản chất**: không đoán từ lịch sử, mà
**xác nhận bằng thực nghiệm** (replay). Đây là chỗ pha confirmation
điền vào.

### 3.2 Đồng nhất với precision mode đã có

LIFA-Fuzz **đã có** tư duy "xác nhận bằng cô lập": `ONE_AT_A_TIME` tự
chuyển sang đột biến 1-field/lần khi thấy crash mới (`mutator:839
set_investigation_mode`). Pha confirmation là **cùng một nguyên lý**,
áp dụng theo trục khác:

| Trục | Precision mode (hiện có) | Confirmation phase (đề xuất) |
|---|---|---|
| Áp vào | Mutation **tương lai** | Attribution **quá khứ** |
| Mục đích | Cô lập *field* gây crash | Xác định *packet* thật sự reproduce |
| Khi nào | Sau crash đầu tiên (k=1) | Ngay khi detect crash |
| Chi phí | Trả trên đường nóng (tạm thời) | Trả **ngoài** đường nóng (post-crash) |

→ Không có mâu thuẫn; hai cơ chế **bổ sung** nhau: confirmation định
vị packet, precision mode sau đó định vị field trong packet đó.

---

## 4. Thiết kế — Post-Crash Confirmation Phase

### 4.1 Nguyên lý

> **Đóng băng → reset → replay-kiểm tra → chỉ ghi PoC đã xác nhận.**

Không đoán `window[-1]`. Trả chi phí **xác nhận** chỉ khi có crash (sự
kiện hiếm so với tổng send), do đó đường nóng `mutator._send()` **không
thêm một await nào**. EPS của A/B **bảo toàn**.

### 4.2 Máy trạng thái pha confirmation

```
                    crash detected (is_target_alive == False, verified)
                                  │
                                  ▼
        ┌─────────────────────────────────────────────┐
        │ S1. FREEZE: crash_monitor báo mutator         │
        │     _freeze_crash_window() — ngừng append      │
        │     snapshot candidate set C = list(window)    │
        └─────────────────────────────────────────────┘
                                  │
                                  ▼
        ┌─────────────────────────────────────────────┐
        │ S2. RESET: sandbox.reset_state() (snapshot     │
        │     restore <10ms Firecracker / restart Docker)│
        │     chờ target alive                           │
        └─────────────────────────────────────────────┘
                                  │
                                  ▼
        ┌─────────────────────────────────────────────┐
        │ S3. CONFIRM: replay-kiểm tra C lên target sạch │
        │     chiến lược: binary-search trên trục thời   │
        │     gian (gần-nhất trước), hoặc tuần tự từ cuối │
        │     window lùi về đầu cho tới khi reproduce     │
        │     → culprit = packet reproduce đầu tiên       │
        └─────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
        reproduce thành công            không reproduce
                    │                           │
                    ▼                           ▼
        S4a. ghi PoC (culprit)         S4b. ghi PoC=kém-tin-cậy
             crash_manager.record()         flag `reproduced=False`
             flag reproduced=True           (vẫn đếm, footnote)
                    │                           │
                    └───────────┬───────────────┘
                                ▼
        ┌─────────────────────────────────────────────┐
        │ S5. UNFREEZE: mutator resume crash_window,     │
        │     resume fuzzing (precision mode nếu muốn)   │
        └─────────────────────────────────────────────┘
```

### 4.3 Thành phần cần thêm / sửa

| File | Hàm | Loại | Nội dung |
|---|---|---|---|
| `fast_loop/mutator.py` | `_freeze_crash_window()` / `_unfreeze_...` | **thêm** | cờ `_window_frozen: bool`; `_send` skip-append khi frozen; getter candidate set |
| `fast_loop/mutator.py` | `_send` | **sửa** | bao bọc `append` bởi `if not self._window_frozen` (chỉ 1 nhánh if — chi phí đường nóng ≈ 0) |
| `fast_loop/crash_monitor.py` | `on_crash` | **sửa** | trước khi ghi PoC: gọi freeze → reset → replay-confirm → ghi PoC đã xác nhận |
| `fast_loop/crash_monitor.py` | `_confirm_crash(candidates)` | **thêm** | replay tuần tự / binary-search lên target sạch; trả `(culprit_payload, reproduced: bool)` |
| `shared/schemas.py` | `CrashEntry` / `CrashReport` | **sửa** | thêm `reproduced: bool`, `confirmation_method: str` |
| `shared/crash_manager.py` | `record()` | **sửa** | nhận `reproduced` flag; signature cho PoC kém-tin-cậy thêm hậu tố để không trộn |
| `evaluation/telemetry_collector.py` | snapshot | **sửa** | thêm metric `reproduced_crashes` / `unreproduced_crashes` tách biệt |

### 4.4 Chiến lược replay — binary search theo thời gian

Tập ứng viên `C` (≤ W=100 packet) được sắp theo **thời gian tăng dần**
(cũ → mới). Crash thường do packet gần thời điểm chết, nên duyệt **từ
cuối lùi về đầu** (most-recent-first) để bắt culprit sớm:

```
def _confirm_crash(candidates, target_sandbox):
    # candidates: list[(ts, payload, rule_id)] tăng dần theo ts
    for ts, payload, rule_id in reversed(candidates):
        await target_sandbox.reset_state()
        status = await _replay_one(payload)   # gửi đơn lẻ, recv kết quả
        if status == CRASH:
            return payload, rule_id, reproduced=True
    # không packet nào reproduce → crash có thể do tương tác chuỗi
    return candidates[-1][1], candidates[-1][2], reproduced=False
```

**Điểm dừng sớm:** dừng ngay khi reproduce (thường trong vài send cuối).
Trường hợp xấu (cần duyệt hết W): ≤ 100 reset × ~100ms (Firecracker
snapshot) ≈ **10s mỗi crash** — chấp nhận được vì crash hiếm.

> **Lưu ý lý thuyết:** crash stateful có thể cần **chuỗi prefix** (USER
> → PASS → mutated RETR). Khi `reproduced=False` sau khi duyệt từng
> packet đơn lẻ, nên thử replay **kèm prefix session** (LIFA-Fuzz đã có
> `SeedSequence`/`setup_packets`). Đây là biến tấu của delta-debugging
> trên trục *sequence* — để ở Phase 2 (xem §6).

### 4.5 Bất biến thiết kế (phải giữ qua mọi implementation)

1. **Đường nóng không thêm await.** Pha confirmation chạy **sau** khi
   `on_crash` đã pause interceptor+mutator. EPS đường nóng bảo toàn.
2. **Không sinh PoC mà không có `reproduced` flag.** Mọi CrashReport phải
   ghi rõ xác nhận hay chưa → RQ3 minh bạch.
3. **Failure isolation:** nếu pha confirmation lỗi (reset fail, replay
   throw), **không được crash pipeline** — fallback ghi PoC=kém-tin-cậy
   + `reproduced=False`, resume fuzzing.
4. **Backward-compat:** `_crash_window` API cũ (`get_crash_window()`)
   giữ nguyên; freeze chỉ thêm cờ.

---

## 5. Tương thích ba baseline (A/B/C)

| Baseline | λ (EPS) | λ·Δt | Attribution hiện tại | Sau confirmation |
|---|---|---|---|---|
| A (Pure Random) | ~414 | ~207 | hỏng (2× W) | **cải thiện rõ** — PoC reproduce được |
| B (Math-Only) | ~400 | ~200 | hỏng (2× W) | **cải thiện rõ** |
| C (Full Fusion) | ~141 | ~70 | ít hỏng (< W) | cài đặt nhẹ; xác nhận cái đã ổn |

→ Pha confirmation **cải thiện A/B nhiều nhất**, làm cho so sánh A/B/C
trên RQ3 **công bằng hơn** (trước đây A/B bị phạt bởi attribution hỏng
mà C không). Đây là một điểm **biện chứng quan trọng**: fix này không
thiên vị baseline nào; nó san bằng điều kiện thí nghiệm.

---

## 6. Lộ trình triển khai (chia pha, kiểm chứng từng bước)

### Phase 1 — Freeze + replay-đơn-lẻ (core, 1–2 ngày)
- S1–S3 + S4a/S4b với replay **packet đơn lẻ**.
- Metric mới: `reproduced_crashes`.
- **Verification:** tạo target có crash đã biết → gửi 200 packet (1
  culprit + 199 lành) → xác nhận `_confirm_crash` trả đúng culprit và
  `reproduced=True`.
- **Test đơn vị:** `tests/test_crash_confirmation.py`.

### Phase 2 — Sequence-aware confirmation (stateful, 2–3 ngày)
- Khi `reproduced=False` (đơn lẻ), replay kèm **prefix session**
  (`setup_packets`).
- Áp delta-debugging (Zeller) trên trục sequence để tối thiểu hóa
  prefix cần thiết.
- **Verification:** target FTP crash chỉ khi đã AUTH → mutated RETR.

### Phase 3 — Đánh giá & báo cáo (1 ngày)
- Chạy lại RQ3 trên 3 baseline **với** confirmation.
- Báo cáo `reproduced_crashes` / `total_unique` ratio cho mỗi baseline.
- Cập nhật `bao_cao_cuoi_ky.md` Hạn chế + Hướng phát triển (xem §8).

---

## 7. Đánh giá & metric nghiệm thu

| Metric | Định nghĩa | Mục tiêu |
|---|---|---|
| **Reproduction rate** | `reproduced_crashes / unique_crashes` | A/B: tăng từ ≈? lên **>80%** |
| **Confirmation latency** | thời gian S1→S4 mỗi crash | < 10s (Firecracker) |
| **EPS impact** | EPS trước/sau confirmation | **= 0** trên đường nóng (confirmation chạy post-crash) |
| **False-negative replay** | packet lành bị ghi là culprit | = 0 (replay là oracle deterministic) |

> EPS impact = 0 là **bất biến thiết kế**, không phải mục tiêu "thử
> đạt". Pha confirmation chỉ chạy khi pipeline đã pause — đo lại EPS
> đường nóng phải không đổi.

---

## 8. Tương thích báo cáo khoa học (`bao_cao_cuoi_ky.md`)

### 8.1 Không bác bỏ, chỉ bổ sung

Văn kiện này **không yêu cầu sửa** kết quả RQ1/RQ2 đã báo cáo (F1=0.857
MOCK; EPS A=414/B=400/C=141). Nó giải thích **vì sao RQ3 chưa kết luận**
(Section 5.3 báo cáo: "số unique crash ghi nhận không ổn định") và đưa ra
**phương án nghiệm thu RQ3** trước khi nộp/bảo vệ.

### 8.2 Đoạn đề xuất thêm vào "Hạn chế" (Section 6.4)

> *"Cơ chế attribution crash hiện tại giả định packet cuối trong
> `_crash_window` (maxlen=100) là packet gây crash. Ở ~400 EPS với độ
> trễ phát hiện 500ms, khoảng nghi vấn chứa ~200 send — gấp đôi chiều
> sâu window — nên packet gây crash có khả năng bị đẩy ra ngoài.
> Hơn nữa các send bị connection-refused sau crash vẫn được ghi vào
> window, khiến attribution (`window[-1]`) thường không phải culprit.
> Hệ quả: PoC artifact có thể không reproduce; `unique_crashes` vẫn
> đếm đúng (dedup theo signature) nhưng giá trị triage mỗi crash giảm.
> Đây là tension cơ bản giữa fire-and-forget (điều kiện cần của 400 EPS
> thuần black-box) và attribution chính xác (cần sync signal như
> NSFuzz — không khả thi black-box). Lưu ý: baseline C (~141 EPS) có
> attribution tin cậy hơn A/B do EPS thấp. Hướng khắc phục: pha
> post-crash confirmation (đóng băng window + replay-kiểm tra lên
> snapshot sạch) — xem `docs/crash_attribution_plan.md`."*

### 8.3 Đoạn đề xuất thêm vào "Hướng phát triển" (Section 7.2)

> *"Post-Crash Confirmation Phase: khi phát hiện crash, đóng băng
> attribution window, reset target về snapshot sạch (Firecracker <10ms),
> và replay-kiểm tra các ứng viên (binary-search / delta-debugging trên
> trục packet và trục sequence) để xác định packet thật sự reproduce.
> Chi phí chỉ trả khi có crash (sự kiện hiếm), nên EPS đường nóng không
> thay đổi. Cơ chế này là phần mở rộng tự nhiên của ONE_AT_A_TIME
> precision mode hiện có, áp vào attribution quá khứ; và là bước tiền
> đề để RQ3 đạt độ tin cậy cần thiết."*

---

## 9. Rủi ro & giảm thiểu

| Rủi ro | Xác suất | Tác động | Giảm thiểu |
|---|---|---|---|
| Crash chỉ reproduce với **chuỗi prefix** (stateful) → đơn lẻ fail | Cao (FTP) | reproduced=False | Phase 2 (sequence replay + delta-debug) |
| Pha confirmation kéo dài (nhiều reset) → trì hoãn fuzzing | TB | giảm throughput hiệu dụng tạm | điểm dừng sớm + cap số reset (vd 50) |
| Snapshot restore không deterministic → replay nhiễu | Thấp | false negative | benchmark determinism snapshot; nếu lỗi → flag reproduced=uncertain |
| Pha confirmation crash chính nó | Thấp | pipeline chết | failure isolation (§4.5.3) — fallback PoC kèm flag |
| Tương tác với precision mode (cả 2 chạy khi crash) | TB | logic chồng | xác nhận xong RỒI mới vào precision mode (tuần tự) |

---

## 10. Nguồn (literature grounding)

- **NSFuzz** — signal-based I/O sync (SIGSTOP), loại guessing delay; grey-box.
  <https://www.ndss-symposium.org/wp-content/uploads/fuzzing2022_23006_paper.pdf>
- **AFLnet** — lưu message sequence + coverage; crash = sequence đến trạng thái crash-prone; `aflnet-replay`.
  <https://www.usenix.org/system/files/sec22-ba.pdf>
- **PULSAR** — stateful black-box, dựng state machine từ traffic.
  <https://intellisec.de/pubs/2015-securecomm.pdf>
- **Delta debugging (Zeller 1999/2002)** — binary-search tối thiểu hóa test case giữ crash.
  <https://www.fuzzingbook.com/>
- **LLM-Boofuzz** — black-box network fuzzing thế hệ mới.
  <https://www.mdpi.com/2079-9292/14/23/4550>

> **Lập luận cốt lõi:** grey-box giải attribution bằng *synchronization*
> (sync send ↔ feedback). Black-box thuần không thể sync (mất EPS).
> Do đó black-box phải giải bằng *xác nhận hậu-sự* (replay) — trả chi phí
> chỉ khi có crash. Đây là khác biệt căn bản và là lý do pha confirmation
> là hướng đúng cho LIFA-Fuzz, không phải sự bắt chước NSFuzz.

---

## 11. Non-goals (KHÔNG làm, để tránh scope creep)

- ❌ Không thay fire-and-forget bằng sync recv (giết RQ2).
- ❌ Không thêm instrumentation / coverage (thoát black-box).
- ❌ Không đoán culprit bằng heuristic ML (không deterministic).
- ❌ Không sửa RQ1/RQ2 — chúng đã ổn định và không bị ảnh hưởng.
- ❌ Phase 1 không xử lý sequence-stateful (để Phase 2).

---

*Văn kiện này tự nhất quán: nguyên lý (§1) → vấn đề định lượng (§2) →
căn nguyên biện chứng (§3) → thiết kế (§4) → tương thích baseline (§5)
→ lộ trình (§6) → nghiệm thu (§7) → báo cáo (§8). Không mâu thuẫn nội
bộ và không bác bỏ ý tưởng gốc của đề tài.*
