# LIFA-Fuzz — Hướng đánh giá sau thực nghiệm (v4.0)

**Phiên bản:** v4.0 (thay thế v3.0 — *Adversarial Bandit / VAMAB*)
**Trạng thái:** định hướng đánh giá, rút từ dữ liệu thực nghiệm thật
**Cơ sở:** kết quả A/B/C đo được trên LightFTP/Firecracker (`logs/state_coverage_stats_{A,B,C}.csv`)

> **Khác biệt so với v3.0.** v3.0 đề xuất bổ sung một cơ chế *adaptive scheduling* kiểu
> bandit (novelty-weighted selection + plateau ε-decay, ablate thành Baseline D) dựa trên
> literature Woo/EcoFuzz. Sau khi phân tích dữ liệu thực (xem §1), hướng đó bị **loại bỏ**
> vì lý do thực dụng: không cần thiết cho paper, chi phí/nhiễu cao, và reward đề xuất trùng
> vùng proxy mà baseline B đã dẫn đầu. v4.0 giữ nguyên đóng góp đã code xong, frame lại thành
> *engineering design*, và dồn effort vào hai việc thật sự còn thiếu: đo code coverage nhị
> phân và gọi LLM thật cho RQ1.

---

## 0. TL;DR

- **Bỏ Baseline D (novelty-bandit).** Lý do thực dụng (xem §1.3): không cần thiết cho paper,
  chi phí/nhiễu cao cho một đóng góp phụ, và reward đề xuất trùng vùng proxy mà B đã dẫn đầu
  nên kỳ vọng cải thiện biên nhỏ. Dữ liệu C<B (C: 1,63 vs B: 3,91 edges/1000 exec) cho thấy
  hướng cần làm là *hiểu* trade-off và *đo đúng*, không phải thêm cơ chế.
- **Scheduling = engineering design, không phải contribution thuật toán.** WeightedScheduler,
  EWMA sampling, two-mode crash isolation, State Transition Graph đã code xong và giải vấn đề
  thực tế (xem §2). Trình bày dưới góc kỹ thuật có cite protocol-RE, không cần ablate, không
  cần bandit.
- **Crash confirmation (đã implement) = đóng góp về độ tin cậy thực nghiệm**, không phải
  đóng góp thuật toán (xem §3).
- **Hai ưu tiên nghiên cứu thật** còn lại (xem §4): (1) đo code coverage nhị phân, (2) gọi
  LLM thật cho RQ1 trên protocol có ground-truth độc lập.

---

## 1. Vì sao bỏ Baseline D (novelty-bandit) — lý do từ dữ liệu

### 1.1 Kết quả thực nghiệm thật

Từ `logs/state_coverage_stats_{A,B,C}.csv` (chiến dịch mở rộng trên LightFTP/Firecracker),
metric đáng tin nhất hiện có là số transition trạng thái giao thức (STG edges = bộ ba
`prev_code, command, new_code`):

| Baseline | Executions | STG edges | **edges / 1000 exec** |
|---|---|---|---|
| A — Pure Random | 1.438.799 | 3.752 | 2,61 |
| B — Math-Only | 1.422.891 | **5.563** | **3,91** |
| C — Full Fusion | 1.356.229 | 2.217 | **1,63** |

Chuẩn hóa theo số execution: **B (3,91) > A (2,61) > C (1,63)**. Baseline dùng LLM (C)
khám phá state transition **kém nhất**, kém B khoảng 2,4 lần.

### 1.2 Cơ chế — vì sao C lại kém

LLM gán `STATIC` cho magic/constant → fuzzer skip; các trường còn lại tập trung vào
`BOUNDARY_VALUES` (length) và `DICTIONARY` (opcode). Hệ quả fuzzer sinh **ít loại command
FTP khác nhau** → ít transition `(prev_code, cmd, new_code)`. B (math-only) ít thu hẹp
command hơn → vô tình chạm nhiều transition hơn.

> *Lưu ý: §1.1 là số đo trực tiếp từ CSV; §1.2 là **giả thuyết cơ chế** nhất quán với dữ liệu
> nhưng chưa được kiểm chứng trực tiếp (chưa đếm command-diversity từng baseline). Việc xác
> minh cơ chế — đếm số command FTP khác nhau mà mỗi baseline thực sự gửi — là một kiểm tra
> nhỏ, đáng làm trước khi viết finding này vào paper.*

### 1.3 Vì sao không làm bandit

Lý do bỏ không phải "bandit sẽ bác bỏ đề tài" (đó là lập luận quá mạnh — bandit đo state
coverage, đề tài RQ1 đo grammar inference, hai trục khác nhau). Lý do thật đơn giản hơn và
thực dụng hơn:

1. **Không cần thiết cho paper.** Câu chuyện scheduling của đề tài đứng vững ở mức
   *engineering design* (§2) — giải vấn đề thực. Không có yêu cầu phải có thêm một thuật
   toán scheduling để paper "đủ đóng góp".
2. **Dữ liệu C<B chỉ ra hướng cần hiểu, không phải hướng cần thêm cơ chế.** LLM đang *đánh
   đổi* state coverage lấy độ chính xác ngữ pháp. Việc đáng làm là hiểu trade-off này (đã
   là finding §1.4) và đo đúng (§4.1), chứ không phải xếp thêm một tầng bandit lên trên.
3. **Chi phí/nhiễu cao cho đóng góp phụ.** Novelty rate đòi hỏi gắn strategy vào từng
   response (schema `response_buffer` phải thêm `rule_id` — hiện chưa có), chia sẻ
   `response_buffer.jsonl` với EWMA controller vốn đọc-truncate, và định nghĩa lại vai trò
   của ε. Toàn bộ chỉ để thử một đóng góp phụ, với xác suất thắng thấp (B đã dẫn đầu state
   coverage → bandit ít khả năng vượt).
4. **Tín hiệu reward trùng vùng với proxy đã đo.** Novelty rate ≈ "đã thấy response/state
   mới", cùng họ với state coverage. Tối ưu cho nó gần như tối ưu cho thứ B đã giỏi — kỳ
   vọng cải thiện biên nhỏ, không xứng công.

### 1.4 Nhưng phát hiện C<B tự nó có giá trị

Việc LLM "hiểu đúng giao thức nhưng thận trọng quá" — tăng độ chính xác ngữ pháp nhưng
giảm độ phủ trạng thái — là một **trade-off chưa được báo cáo** trong LLM-for-fuzzing. Đây
là *finding* có giá trị khi viết lên, không cần thêm cơ chế nào để khai thác. Lưu ý quan
trọng để không diễn giải sai: Bảng 2b đo *state coverage*, **không** phải code coverage
nhị phân (hệ thống chưa có — xem §4.1). C kém hơn B ở state coverage là đã xác nhận; C
kém hơn B ở code path thật thì chưa đo được.

---

## 2. Scheduling giữ nguyên — frame lại thành engineering design

Không đổi code. Chỉ đổi cách trình bày: từ "thuật toán" sang "giải pháp kỹ thuật có nền
tảng".

| Cơ chế (đã code) | Vấn đề thực tế giải | Nền tảng |
|---|---|---|
| **WeightedScheduler** (`mutator.py:344-355`) — trọng số `BOUNDARY_VALUES=4.0`, `DICTIONARY=3.0`, `RANDOM_BYTES=1.0` | Trường length là nguồn buffer overflow phổ biến nhất → ưu tiên mutation vào đó | Protocol-RE: offset có tương quan tuyến tính với packet length thường là trường length (Duchêne et al. [1]) |
| **EWMA adaptive sampling** (`ewma_controller.py`) — `k = ⌊K_max/(1+θ·λ_C)⌋` | Tension vật lý giữa throughput (fire-and-forget) và khả năng quan sát trạng thái (recv). Công thức liên tục tránh chattering của AIMD step | Điều khiển thích nghi chuẩn (EWMA smoothing) |
| **Two-mode scheduling** (`mutator.py`) — RANDOM_SUBSET/WEIGHTED ↔ ONE_AT_A_TIME | Crash isolation: khi nhiều trường cùng đột biến, không biết trường nào gây crash | Engineering response cho triage, không phải thuật toán |
| **State Transition Graph** (`state_transition_graph.py`) | Giao thức có trạng thái (FTP) cần đo độ phủ *transition*, không chỉ offset | Tương tự edge coverage của AFL nhưng ở tầng protocol |

**Không ablate.** Đây là các quyết định kỹ thuật giải bài toán thực (length-field overflow,
throughput-observability trade-off, crash triage). Chúng không cần "chứng minh đóng góp
độc lập qua ablation" — giá trị nằm ở việc giải được vấn đề cụ thể. Trình bày thẳng như
engineering, cite protocol-RE literature cho cơ sở, không dress-up thành bandit.

---

## 3. Crash Confirmation — đã implement, là đóng góp về độ tin cậy

Commit `c2f0691`: pha post-crash confirmation (freeze attribution window → reset snapshot
sạch → replay-confirm → ghi PoC với cờ `reproduced`). Schema đã có `reproduced: bool` +
`confirmation_method` (`schemas.py:238-241`, `crash_manager.py:94-100`).

**Frame:** đây là đóng góp về **độ tin cậy của kết quả thực nghiệm**, không phải đóng góp
thuật toán. Nó giải một vấn đề đo lường thật (PoC ghi từ `window[-1]` thường không
reproduce ở 400 EPS vì detection lag > window depth — xem `crash_attribution_plan.md §2`)
bằng cách trả chi phí replay *chỉ khi có crash* (sự kiện hiếm), giữ nguyên EPS đường nóng.

Khi viết báo cáo: mô tả cơ chế + metric `reproduced_crashes / unique_crashes`, nêu rõ nó
làm RQ3 *tin cậy hơn* (không phải hoàn toàn sạch — vẫn phụ thuộc điều kiện phiên). Không
coi đây là "thuật toán mới".

---

## 4. Hai ưu tiên nghiên cứu thật (đây là việc đáng làm)

### 4.1 Đo code coverage nhị phân thật

**Vấn đề.** Hệ thống hiện *không có* feedback coverage nhị phân. Chỉ số
`unique_code_branches` thực ra đếm cặp (offset, giá trị) bị đột biến — là độ rộng mutation,
không phải branch nhị phân. Vì vậy mọi kết luận A/B/C đến nay chỉ dựa trên proxy ở tầng
giao thức (STG edges). Không thể trả lời "C chạm ít code path hơn B thật không, hay chỉ ít
state transition hơn".

**Việc.** Hiện LightFTP chỉ biên dịch với `-fsanitize=address` (phát hiện memory error,
**không** sinh code coverage). Để có coverage nhị phân, cần build lại LightFTP với
`-fprofile-arcs -ftest-coverage` (gcc → `.gcov`/lcov) — đây là một cờ *khác* ASAN, không
dùng chung. Telemetry đã có hàm parse lcov (`telemetry_collector.py:137-209`, chưa wire) và
đọc kết quả qua shared filesystem giữa host và MicroVM. Khi có code coverage thật, Bảng 2b
bổ sung được cột "code branches" và C<B được kiểm tra lại đúng nghĩa.

**Tầm quan trọng.** Đây là điều kiện cần cho *mọi* kết luận định lượng về độ phủ. Không có
nó, C<B chỉ là khẳng định về state coverage, không phải code coverage.

### 4.2 Gọi LLM thật cho RQ1 trên protocol có ground-truth độc lập

**Vấn đề.** RQ1 hiện chỉ đo ở chế độ MOCK (F1 = 0,857) trên giao thức LIFA do chính tác giả
thiết kế → *evaluation leak*. Chưa bao giờ gọi LLM thật để đo khả năng suy diễn ngữ pháp —
đây chính là claim headline của đề tài mà chưa verify.

**Việc.** Chạy RQ1 ở REAL mode (GLM-5-Turbo) trên một protocol chuẩn với ground truth độc
lập: parser lệnh FTP `USER`/`PASS`/`LIST` theo RFC 959, target LightFTP đã có. Dùng
self-consistency (đã code, commit `aa65ed1`) để giảm variance LLM. Báo cáo F1 thật — kể cả
nếu thấp.

**Tầm quan trọng + rủi ro.** Nếu F1 thật thấp, phải báo cáo thấp — nhưng đó là việc phải
làm, vì claim "LLM suy diễn grammar" chưa được kiểm tra thì đề tài chưa khép kín. Scope
hẹp (một vài command FTP) để chi phí/token kiểm soát được.

---

## 5. Non-goals (KHÔNG làm — tránh scope creep)

- ❌ **Không implement Baseline D (novelty-bandit).** Đã bác bỏ bằng dữ liệu (§1.3).
- ❌ **Không port cơ chế EcoFuzz** (AAPS energy scheduling, 3-state machine). Over-engineering,
  khó ablate, không khớp bài toán (protocol fuzzing không có seed queue kiểu AFL).
- ❌ **Không dress-up scheduling thành đóng góp thuật toán.** Giữ ở engineering (§2).
- ❌ **Không đổi fire-and-forget → sync recv.** Giết RQ2 (throughput).
- ❌ **Không coi crash confirmation là thuật toán mới.** Nó là cải thiện độ tin cậy (§3).

---

## 6. Nguồn

- [1] Duchêne, F., et al. "Protocol Reverse Engineering Using Shannon Entropy." IEEE TIFS, 2018.
      — cơ sở cho DifferentialAnalyzer (entropy per offset → phân loại field).
- [2] Firecracker MicroVM — AWS. https://firecracker-microvm.github.io/
      — sandbox isolation + snapshot/restore.

---

*v4.0: bỏ cơ chế không đứng vững trên dữ liệu thật, giữ engineering design đã code, dồn
effort vào code coverage thật và RQ1 LLM thật. Khoa học hơn vì trung thực với dữ liệu, gọn
hơn vì không nhồi lý thuyết.*
