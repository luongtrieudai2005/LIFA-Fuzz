---
title: "LIFA-Fuzz: Framework Fuzzing Black-box cho giao thức mạng dựa trên suy diễn ngữ pháp bằng Large Language Model"
subtitle: "Báo cáo cuối kỳ — Môn Dự án Công Nghệ Thông Tin"
author: "Luông Triệu Đài"
institution: "Khoa Công nghệ Thông tin"
date: "Tháng 6, 2026"
---

\newpage

# Tóm tắt

Fuzzing giao thức mạng là một kỹ thuật kiểm thử quan trọng trong an ninh mạng, nhưng hiệu quả của nó phụ thuộc sâu sắc vào mức độ hiểu biết về cấu trúc gói tin. Đối với các giao thức độc quyền — nơi không có đặc tả RFC, không có mã nguồn, và không có tài liệu — việc fuzzy một cách "mù" (brute-force bit-flip) cho tỷ lệ phát hiện lỗi rất thấp vì phần lớn các đột biến tạo ra gói tin rác bị server từ chối ngay ở tầng parse đầu tiên. Báo cáo này trình bày **LIFA-Fuzz** (viết tắt của *Live-traffic Inference & Asynchronous Fuzzing*), một framework fuzzing black-box sử dụng Large Language Model (LLM) để suy diễn ngữ pháp giao thức từ luồng traffic thực tế, kết hợp với một lớp tiền xử lý toán học thuần túy (Shannon entropy, tương quan Pearson, Kendall's τ) nhằm giảm đáng kể token tiêu thụ cho phần khám phá cấu trúc thô (ước tính sơ bộ, chưa có phép đo so sánh trước/sau chính thức). Hệ thống được kiến trúc theo mô hình Fast-Slow Loop bất đồng bộ: Fast Loop thực thi fuzzing tốc độ cao (400+ executions per second), trong khi Slow Loop phân tích traffic và đẩy ngữ pháp cập nhật về Fast Loop mà không bao giờ chặn luồng fuzzing chính. Một bộ điều khiển EWMA (Exponentially Weighted Moving Average) điều phối tự động tần suất lấy mẫu phản hồi server, cân bằng giữa throughput và khả năng quan sát trạng thái. Thực nghiệm trên LightFTP (target thực tế, biên dịch với AddressSanitizer, chạy trên Firecracker MicroVM) với ba baseline — Pure Random, Math-Only, và Full Fusion — cho thấy hai baseline không dùng LLM duy trì throughput khoảng 400 execution mỗi giây, đồng thời pipeline xác nhận được khả năng phát hiện crash AddressSanitizer thực. Kết quả chi tiết (RQ1–RQ3) và những hạn chế của phép đánh giá hiện tại được thảo luận trong Chương 5–6. Toàn bộ hệ thống gồm khoảng 17.000 dòng Python, được kiểm thử bởi hơn 250 unit test.

**Từ khóa:** fuzzing, black-box, large language model, suy diễn giao thức, Firecracker MicroVM, EWMA, entropy Shannon.

\newpage

# Mục lục

- [Chương 1: Giới thiệu](#chương-1-giới-thiệu)
- [Chương 2: Tổng quan công trình liên quan](#chương-2-tổng-quan-công-trình-liên-quan)
- [Chương 3: Thiết kế hệ thống](#chương-3-thiết-kế-hệ-thống)
- [Chương 4: Triển khai](#chương-4-triển-khai)
- [Chương 5: Thực nghiệm và đánh giá](#chương-5-thực-nghiệm-và-đánh-giá)
- [Chương 6: Thảo luận](#chương-6-thảo-luận)
- [Chương 7: Kết luận và hướng phát triển](#chương-7-kết-luận-và-hướng-phát-triển)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

\newpage

# Chương 1: Giới thiệu

## 1.1. Đặt vấn đề

Kiểm thử fuzzing đã chứng minh hiệu quả trong việc phát hiện lỗi bảo mật trên nhiều loại phần mềm, từ trình duyệt web [1] đến hệ điều hành [2]. Tuy nhiên, hầu hết các công cụ fuzzing hiện đại — AFL [3], libFuzzer [4], honggfuzz [5] — đều yêu cầu quyền truy cập binary dưới dạng instrumented build (coverage-guided fuzzing) hoặc ít nhất là mã nguồn để biên dịch với sanitizer. Ràng buộc này loại trừ một lớp lớn target: các dịch vụ mạng chạy giao thức độc quyền hoặc không được tài liệu hóa, nơi tester chỉ có binary đóng và đường mạng TCP/UDP.

Trong bối cảnh đó, black-box fuzzing là phương án duy nhất khả thi. Nhưng black-box fuzzing truyền thống gặp một vấn đề cơ bản: khi không biết byte nào trong gói tin là magic header, byte nào là trường độ dài, byte nào là payload, việc đột biến ngẫu nhiên gần như chắc chắn tạo ra gói tin bị server từ chối ngay lập tức. Tỷ lệ coverage path thực sự được kích hoạt rất thấp, và thời gian từ lúc bắt đầu fuzz đến khi phát hiện crash đầu tiên (time-to-first-crash) kéo dài không đáng kể so với việc gửi traffic hợp lệ bình thường.

Gần đây, các Large Language Model (LLM) đã thể hiện khả năng phân tích dữ liệu nhị phân và suy diễn cấu trúc giao thức khi được cung cấp mẫu traffic dạng hex [6]. Khả năng này mở ra một hướng tiếp cận mới: thay vì fuzz mù, sử dụng LLM để "hiểu" giao thức trước, rồi dùng sự hiểu biết đó để dẫn dắt chiến lược đột biến. Dù vậy, việc tích hợp LLM vào fuzzing đặt ra ba thách thức chưa được giải quyết triệt để trong các công trình trước:

Thứ nhất, LLM inference chậm. Một lần gọi API có thể mất 15–60 giây, trong khi fuzzing cần tốc độ hàng nghìn execution mỗi giây. Nếu Fast Loop phải chờ LLM phản hồi, throughput sẽ sụp đổ từ 400 EPS xuống dưới 1 EPS — mất hoàn toàn lợi thế của fuzzing tốc độ cao.

Thứ hai, chi phí token cao. Gửi raw hex payload cho LLM và yêu cầu nó phát hiện cấu trúc từ đầu tiêu tốn nhiều token cho phần mà các phương pháp thống kê đơn giản có thể làm tốt hơn trong chưa tới 1 millisecond — ví dụ, việc xác định byte nào là constant (magic header) chỉ cần tính Shannon entropy.

Thứ ba, tính phân lập crash (crash isolation). Khi nhiều trường được đột biến đồng thời trong cùng một gói tin, crash xảy ra nhưng không thể xác định trường nào gây ra. Điều này làm giảm giá trị của mỗi crash phát hiện được, vì quá trình điều tra gốc (root cause analysis) phải bắt đầu lại từ đầu.

## 1.2. Mục tiêu nghiên cứu

Dựa trên các thách thức trên, đề tài này đặt ra ba mục tiêu chính:

**(i)** Thiết kế một kiến trúc bất đồng bộ tách biệt hoàn toàn luồng fuzzing tốc độ cao khỏi luồng phân tích LLM, sao cho độ trễ của LLM không bao giờ ảnh hưởng đến throughput của fuzzer.

**(ii)** Kết hợp một lớp tiền xử lý toán học (entropy Shannon, tương quan Pearson, Kendall's τ) với LLM inference để giảm khối lượng công việc của LLM, tận dụng điểm mạnh của phương pháp thống kê (nhanh, không tốn token) cho phần phát hiện cấu trúc thô, và dành LLM cho phần cần suy luận ngữ nghĩa cao hơn (đặt tên trường, suy luận quan hệ giữa các trường).

**(iii)** Xây dựng một hệ thống điều phối thích nghi giữa hai luồng, cho phép fuzzer tự động chuyển đổi giữa chế độ khám phá rộng (nhiều trường đột biến mỗi gói tin, throughput cao) và chế độ điều tra cô lập (một trường duy nhất mỗi gói tin, chính xác hóa root cause) khi phát hiện crash mới.

## 1.3. Câu hỏi nghiên cứu

Từ các mục tiêu trên, đề tài tập trung trả lời ba câu hỏi nghiên cứu:

- **RQ1:** LIFA-Fuzz suy diễn ngữ pháp giao thức chính xác đến mức nào so với ground truth, xét theo Precision, Recall, và F1-Score?

- **RQ2:** Kiến trúc bất đồng bộ Fast-Slow Loop duy trì throughput ở mức nào, và bộ điều khiển EWMA tác động thế nào đến sự cân bằng giữa throughput và khả năng quan sát trạng thái server?

- **RQ3:** So với random fuzzing và math-only fuzzing, pipeline Full Fusion (toán học + LLM) phát hiện crash nhanh hơn và đa dạng hơn ra sao?

## 1.4. Đóng góp chính

Báo cáo này đóng góp những nội dung sau:

1. **Kiến trúc Fast-Slow Loop bất đồng bộ** cho black-box protocol fuzzing, trong đó Fast Loop và Slow Loop giao tiếp qua file-based IPC (JSON/JSONL), đảm bảo zero blocking giữa hai luồng.

2. **Neural-Mathematical Fusion** — kết hợp DifferentialAnalyzer (xử lý toán học, < 1 ms) với LLM inference (~15–60 s), giúp LLM tập trung vào semantic naming thay vì raw byte discovery, giảm đáng kể token tiêu thụ (ước tính sơ bộ, chưa có phép đo so sánh chính thức).

3. **Bộ điều khiển EWMA** điều phối tần suất lấy mẫu recv() của Fast Loop dựa trên cường độ coverage, với công thức liên tục `k = ⌊K_max / (1 + θ·λ_C)⌋` được thiết kế để tránh hiện tượng chattering nhờ tính liên tục, khả vi và hysteresis tự nhiên của EWMA.

4. **Two-mode scheduling** (RANDOM_SUBSET/WEIGHTED vs. ONE_AT_A_TIME) cho crash isolation, kết hợp State Transition Graph để theo dõi coverage ngữ pháp trạng thái giao thức.

5. **Triển khai thực tế** trên LightFTP (FTP server thực tế, biên dịch với AddressSanitizer), chạy trên Firecracker MicroVM, với toàn bộ pipeline end-to-end hoạt động: từ sandbox boot, traffic capture, mutation, crash detection, đến LLM inference và rule generation.

\newpage

# Chương 2: Tổng quan công trình liên quan

## 2.1. Fuzzing giao thức mạng

Fuzzing giao thức (protocol fuzzing) là một nhánh của fuzzing tập trung vào việc kiểm tra các triển khai giao thức mạng bằng cách gửi các gói tin được chỉnh sửa có chủ đích. Các công cụ sớm như SPIKE [7] và Sulley [8] sử dụng mô tả giao thức do con người viết (protocol description files) để tạo ra các đột biến có cấu trúc. Cách tiếp cận này hiệu quả nhưng đòi hỏi nỗ lực thủ công đáng kể — tester phải hiểu sâu giao thức và viết mô tả cho từng trường.

Peach Fuzzer [9] mở rộng ý tưởng này bằng một framework tổng quát hơn với khái niệm "data model" tách biệt khỏi "state model", cho phép mô tả cả cấu trúc gói tin lẫn trình tự trạng thái của phiên giao tiếp. Tuy nhiên, Peach vẫn yêu cầu người dùng định nghĩa mô hình dữ liệu, điều không khả thi khi không có tài liệu.

Boofuzz [10], hậu duệ của Sulley, cải thiện khả năng mở rộng và thêm giám sát network-based, nhưng vẫn giữ nguyên ràng buộc về mô tả giao thức thủ công. Tất cả các công cụ này đều thuộc nhóm "grammar-aware fuzzing" — chúng cần ngữ pháp đầu vào, và chất lượng fuzzing phụ thuộc trực tiếp vào độ chính xác của ngữ pháp đó.

Một hướng tiếp cận khác là snapshot fuzzing, được đại diện bởi AFL++ [11] với cơ chế persistent mode và SnapChange [12]. Các công cụ này tận dụng snapshot/restore của VM để tăng tốc độ execution, nhưng vẫn chủ yếu áp dụng cho binary đã được instrument.

## 2.2. Suy diễn cấu trúc giao thức

Khi không có đặc tả giao thức, việc tự động suy diễn cấu trúc trở thành bài toán then chốt. DISCOVERER [13] và Tupni [14] là những công trình sớm sử dụng dynamic taint analysis để nhận diện trường trong giao thức nhị phân. Cả hai đều yêu cầu quyền truy cập binary và khả năng chạy instrumented execution.

Pip [15] và Prospex [16] sử dụng phân tích network trace để suy luận giao thức, nhưng tập trung vào giao thức văn bản (HTTP, SMTP) và gặp khó khăn với giao thức nhị phân không có delimiter rõ ràng.

Gần đây, không gian embedding và các phương pháp học sâu đã được áp dụng cho protocol reverse engineering. NEMESYS [17] sử dụng neural network để phân loại byte offset trong gói tin. Tuy nhiên, các phương pháp này cần dữ liệu huấn luyện và không tổng quát hóa tốt sang giao thức chưa thấy.

Cách tiếp cận thống kê đơn giản hơn — tính entropy Shannon trên từng byte offset qua nhiều gói tin — tỏ ra hiệu quả bất ngờ trong việc phân loại các vùng trong gói tin: byte có entropy gần 0 gần như chắc chắn là constant (magic header, version), byte có entropy cao là payload hoặc dữ liệu ngẫu nhiên, và byte có tương quan tuyến tính mạnh với độ dài gói tin thường là trường length [18]. Đây chính là nền tảng của DifferentialAnalyzer trong LIFA-Fuzz.

## 2.3. LLM trong phân tích phần mềm

Sự trỗi dậy của LLM (GPT-4, Claude, GLM) đã mở ra khả năng mới cho phân tích phần mềm. Các nghiên cứu gần đây cho thấy LLM có thể hiểu cấu trúc dữ liệu nhị phân [6], phát hiện lỗ hổng trong mã nguồn [19], và thậm chí tạo test case [20]. Đặc biệt, khi được cung cấp hex dump kèm hướng dẫn phù hợp, LLM có thể nhận diện các mẫu như magic bytes, trường độ dài, và sequence number.

Tuy nhiên, việc sử dụng LLM trực tiếp cho fuzzing gặp một rào cản thực tế: chi phí. Mỗi lần inference tiêu tốn từ vài nghìn đến hàng chục nghìn token, và với giá hiện tại ($0.60–3.00 per 1M token), việc gọi LLM mỗi giây là không khả thi về mặt tài chính. Cần có cơ chế giảm tải — chỉ gọi LLM khi cần thiết, và chỉ gửi cho LLM phần thông tin mà phương pháp rẻ hơn không thể xử lý. Đây chính là động lực cho kiến trúc Neural-Mathematical Fusion của LIFA-Fuzz.

## 2.4. Kết hợp ngữ nghĩa và tốc độ: SemFuzz, NSFuzz và khoảng trống black-box

Hai công trình gần đây đại diện cho hai trụ cột mà LIFA-Fuzz kế thừa và mở rộng.

**SemFuzz** [22] (Sun et al., 2026) là framework fuzzing đầu tiên tận dụng LLM để trích xuất semantic rules từ tài liệu RFC. Thay vì đột biến ngẫu nhiên theo coverage-guided, SemFuzz mô hình hóa ngữ nghĩa giao thức thành các quy tắc có cấu trúc và sinh test case với ý đồ kiểm thử rõ ràng (intent-driven). Đặc biệt, SemFuzz giới thiệu cơ chế Action Sequence gồm ba phép toán nguyên tử trên mỗi trường giao thức: Add (thêm trường hoặc tham số mới), Remove (loại bỏ trường bắt buộc), và Update (thay đổi giá trị, kiểu, hoặc ngữ nghĩa của trường). Các action sequence này vi phạm có chủ đích các semantic rule được trích xuất từ RFC, cho phép fuzzer nhắm đến các lỗi ngữ nghĩa sâu — ví dụ, vi phạm ràng buộc kiểu dữ liệu, phá vỡ chuyển đổi trạng thái, hoặc gửi giá trị ngoài biên theo nghĩa ngữ nghĩa chứ không chỉ theo nghĩa cú pháp. SemFuzz đã phát hiện 16 lỗ hổng tiềm năng (10 được xác nhận, 5 chưa từng được báo cáo, 4 được gán CVE). Tuy nhiên, SemFuzz phụ thuộc hoàn toàn vào tài liệu RFC — nếu giao thức không có RFC (giao thức độc quyền) hoặc RFC không đầy đủ, framework không thể hoạt động. Đây chính là hạn chế cốt lõi mà LIFA-Fuzz hướng đến giải quyết.

**NSFuzz** [23] (Qin et al., TOSEM 2023) giải quyết bài toán fuzzing dịch vụ mạng có trạng thái (stateful network service fuzzing) từ góc độ tốc độ thực thi. NSFuzz sử dụng biến chương trình (program variables) làm biểu diễn trạng thái mạng, kết hợp với cơ chế đồng bộ I/O dựa trên tín hiệu (signal-based I/O synchronization). Bằng cách thay thế AFL's FORKSERVER bằng NET_FORKSERVER và sử dụng SIGSTOP từ instrumented service để đồng bộ, NSFuzz loại bỏ hoàn toàn độ trễ guessing delay — fuzzer biết chính xác khi nào server đã xử lý xong message và sẵn sàng nhận message tiếp. Kết quả: trung bình 2.400 lần cải thiện throughput so với AFLnet, 25% tăng code coverage, và phát hiện 8 zero-day vulnerability. Tuy nhiên, NSFuzz yêu cầu compile-time instrumentation — nghĩa là phải có mã nguồn và khả năng biên dịch target với công cụ đặc biệt — điều không phải lúc nào cũng khả thi.

**Khoảng trống mà LIFA-Fuzz lấp đầy.** Xét dưới góc độ không gian thiết kế, SemFuzz và NSFuzz đại diện cho hai cực: SemFuzz có khả năng suy luận ngữ nghĩa mạnh (nhờ LLM + RFC) nhưng chậm và phụ thuộc tài liệu; NSFuzz có tốc độ thực thi vượt trội (2.400× AFLnet) nhưng yêu cầu grey-box access (source code + instrumentation). LIFA-Fuzz nằm ở giao điểm: kế thừa khả năng suy luận ngữ nghĩa của SemFuzz (qua LLM inference + math layer thay vì RFC parsing) và theo đuổi tốc độ thực thi cao của NSFuzz (qua Fast-Slow Loop bất đồng bộ + Firecracker MicroVM snapshot/restore), nhưng dành cho đối tượng black-box hoàn toàn — không cần RFC, không cần source code, không cần instrumented binary. Bảng 1 tóm tắt sự so sánh.

*Bảng 1: So sánh LIFA-Fuzz với các công cụ liên quan.*

| Đặc trưng | SemFuzz | NSFuzz | LIFA-Fuzz |
|---|---|---|---|
| Nguồn ngữ pháp | RFC documents | — (coverage-guided) | LLM + DifferentialAnalyzer |
| Yêu cầu đầu vào | RFC đầy đủ | Mã nguồn + instrumentation | Chỉ traffic capture |
| Chế độ | Grey-box | Grey-box | **Black-box** |
| Suy luận ngữ nghĩa | LLM từ RFC | Không có | LLM + thống kê từ traffic |
| Intent-driven mutation | Action Sequence (Add/Remove/Update) | Không | Action Sequence + scheduling |
| Tốc độ thực thi | Trung bình | Rất cao (2.400× AFLnet) | Cao (400+ EPS, bất đồng bộ)† |
| Crash isolation | Không rõ | Không rõ | Two-mode scheduling + STG |
| Sandbox | Không tích hợp | Fork-server | Firecracker MicroVM (< 10 ms reset)‡ |

> *Ghi chú cho cột LIFA-Fuzz: † Giá trị ~400 EPS được đo thực tế trên các baseline không dùng LLM (Pure Random, Math-Only) trong chiến dịch 2 giờ — xem Bảng 2 (Section 5.3); baseline Full Fusion có EPS thấp hơn đáng kể do overhead của LLM, nên con số này không đại diện cho toàn bộ pipeline. ‡ Thời gian reset < 10 ms là design goal của Firecracker snapshot/restore [21] (Section 2.5), chưa có benchmark đo trực tiếp trong báo cáo này. "Action Sequence + scheduling" là cơ chế intent-driven kế thừa và mở rộng từ SemFuzz [22] cho môi trường black-box, không phải kết quả đo.*

## 2.5. Sandbox và phân lập

Trong fuzzing, sandbox đảm bảo lỗi ở target không lan sang host, đồng thời cung cấp cơ chế reset nhanh sau crash. Docker cung cấp phân lập mức process (shared kernel) với thời gian restart khoảng 200–500 ms. Firecracker [21], được phát triển bởi AWS, cung cấp phân lập mức kernel qua MicroVM — mỗi VM chạy kernel riêng, cách ly hoàn toàn với host. Điểm mạnh của Firecracker là snapshot/restore: sau khi chụp snapshot bộ nhớ VM, việc restore về trạng thái sạch chỉ mất dưới 10 ms, nhanh hơn restart container hàng chục lần. Đặc tính này cực kỳ phù hợp cho fuzzing, nơi target crash thường xuyên và cần được reset nhanh chóng để tiếp tục chiến dịch.

\newpage

# Chương 3: Thiết kế hệ thống

## 3.1. Kiến trúc tổng thể

LIFA-Fuzz được tổ chức theo ba khối chức năng, mỗi khối có vòng đời và yêu cầu tốc độ khác nhau. Sự phân tách này không phải là lựa chọn thiết kế tùy ý mà xuất phát từ một bất biến vật lý: LLM inference chậm hơn fuzzing khoảng 4–5 cấp bậc độ lớn. Nếu ép hai quá trình này chạy đồng bộ trên cùng một luồng, throughput của fuzzing sẽ bị kéo xuống bằng throughput của LLM — tức là khoảng 1 execution mỗi phút thay vì 400+ EPS.

**Khối 1 — Sandbox (phân cách).** Cung cấp môi trường chạy target server được phân lập hoàn toàn. Giao diện trừu tượng BaseSandbox cho phép chuyển đổi giữa Docker (prototyping, ~200–500 ms reset) và Firecracker MicroVM (production, < 10 ms reset qua snapshot) mà không thay đổi bất kỳ dòng code nào ở Khối 2 hay Khối 3. Target server hiện tại là LightFTP, một FTP server mã nguồn mở được biên dịch với AddressSanitizer (ASAN), chạy bên trong MicroVM với kernel riêng. ASAN biến các lỗi tràn bộ đệm thầm lặng thành SIGABRT có thể phát hiện được, tăng đáng kể số lượng crash fuzzer có thể quan sát.

**Khối 2 — Fast Loop (fuzzing tốc độ cao).** Đây là "cơ bắp" của hệ thống. Fast Loop chạy trên một asyncio event loop duy nhất, bao gồm bốn thành phần hoạt động đồng thời: Interceptor (proxy TCP bắt tất cả traffic giữa client và server), MutationEngine (đột biến gói tin theo rule set hiện tại), CrashMonitor (phát hiện crash qua TCP connection refused, tự động restart target), và Rule Watcher (đọc rule set mới từ file mà Slow Loop ghi ra). Toàn bộ Fast Loop không bao giờ gọi LLM, không bao giờ ghi file (trừ traffic log), và không bao giờ block chờ Slow Loop. Giao tiếp với Slow Loop hoàn toàn bất đồng bộ qua file: traffic log JSONL đi từ Fast Loop sang Slow Loop, và active_rules.json đi ngược lại.

**Khối 3 — Slow Loop (phân tích thông minh).** Đây là "bộ não" của hệ thống. Chạy trên một process riêng biệt (subprocess), Slow Loop đọc traffic log, phân tích bằng DifferentialAnalyzer, gọi LLM để suy diễn ngữ pháp, và sinh SemanticRule cho Fast Loop. Slow Loop có event loop riêng, lifecycle riêng, và failure domain riêng — nếu LLM API sập, Fast Loop tiếp tục fuzzing với rule set cũ (degraded mode), hoặc với bootstrap rules từ DifferentialAnalyzer nếu chưa có rule nào.

Sơ đồ luồng dữ liệu giữa ba khối như sau: Client gửi traffic hợp lệ → Interceptor bắt và ghi vào traffic log → MutationEngine đọc seed từ queue, đột biến theo active rules, gửi trực tiếp đến target server qua TCP mới mỗi lần → CrashMonitor phát hiện crash → Slow Loop đọc traffic log, phân tích, gọi LLM, sinh rules mới → rules được ghi vào file → Fast Loop đọc và áp dụng.

## 3.2. Neural-Mathematical Fusion

Trái tim của Slow Loop là cơ chế kết hợp giữa lớp xử lý toán học (DifferentialAnalyzer) và lớp suy luận neural (LLM Agent). Ý tưởng cốt lõi: tại sao phải tiêu token đắt tiền để yêu cầu LLM phát hiện ra điều mà một phép tính toán học có thể làm trong chưa tới 1 millisecond?

**Lớp toán học — DifferentialAnalyzer.** Với mỗi byte offset $i$ trong gói tin, từ một tập $n$ gói tin đã bắt, analyzer thu thập véc-tơ giá trị $V_i = [p_1[i], p_2[i], \ldots, p_n[i]]$ và tính bốn đại lượng:

1. **Shannon entropy** $H(V_i) = -\sum_{v} p(v) \log_2 p(v)$ — đo mức độ ngẫu nhiên của giá trị tại offset $i$. Entropy gần 0 nghĩa là giá trị không đổi (magic bytes, version). Entropy cao (> 3.5 bits) nghĩa là dữ liệu ngẫu nhiên hoặc payload.

2. **Pearson correlation** $r(V_i, L)$ với vector độ dài gói tin $L$ — phát hiện trường length. Nếu $|r| > 0.85$, offset này gần như chắc chắn là trường độ dài.

3. **Kendall's τ** — phát hiện monotonic trend, đặc trưng của sequence number. Nếu $\tau > 0.75$, offset được phân loại là CALCULATED.

4. **Phương sai** $\sigma^2(V_i)$ — phân biệt giữa trường enum (phương sai thấp, vài giá trị rời rạc) và payload (phương sai cao).

Dựa trên bốn đại lượng này, mỗi offset được gán một nhãn: STATIC, CALCULATED, HIGH_ENTROPY, hoặc LOW_ENTROPY. Các offset liền kề cùng nhãn được gom thành FieldGroup. Kết quả đầu ra là một HeatmapResult cung cấp hai interface: `to_llm_hint()` tạo gợi ý dạng văn bản chèn vào prompt LLM, và `to_field_rules()` tạo FieldRule bootstrap nếu LLM không phản hồi được.

**Lớp neural — LLM Agent.** LLM nhận hai đầu vào: (a) parsed traffic samples dạng hex dump có cấu trúc, và (b) math_hint từ DifferentialAnalyzer. System prompt được thiết kế để hướng dẫn LLM: không tốn công phát hiện STATIC fields (đã được đánh dấu), tập trung vào việc đặt tên ngữ nghĩa cho các trường (ví dụ: "opcode", "session_id") và đề xuất mutation strategy phù hợp. System prompt fusion bổ sung (SYSTEM_PROMPT_FUSION_APPEND) yêu cầu LLM giải thích cách phát hiện của nó phù hợp hay mâu thuẫn với heatmap — đảm bảo LLM không bỏ qua thông tin thống kê đã có.

Sự phân công này giảm đáng kể token tiêu thụ so với yêu cầu LLM phân tích raw hex từ đầu (ước tính sơ bộ, chưa có phép đo trước/sau chính thức): phần khám phá cấu trúc thô (byte nào là constant, byte nào biến đổi) đã được xử lý bởi math layer, LLM chỉ cần giải quyết phần mà thống kê không trả lời được — ý nghĩa ngữ nghĩa của từng trường.

## 3.3. Bộ điều khiển EWMA thích nghi

Một vấn đề thực tế nảy sinh trong quá trình triển khai: Fast Loop gửi gói tin ở tốc độ rất cao, nhưng không đọc phản hồi của server (fire-and-forget). Điều này tối đa throughput nhưng khiến fuzzer "mù" về trạng thái server — không biết server đang reject, accept, hay thay đổi hành vi. Ngược lại, nếu đọc response mỗi lần gửi, throughput giảm từ 400+ EPS xuống 40–80 EPS vì `recv()` block chờ timeout.

Giải pháp là adaptive sampling: chỉ đọc response mỗi $k$ gói tin, trong đó $k$ được điều chỉnh tự động dựa trên cường độ coverage. Khi coverage tăng nhanh (nhiều trạng thái mới), $k$ giảm — đọc response thường xuyên hơn để theo dõi sát. Khi coverage bão hòa, $k$ tăng — gần như fire-and-forget để tối đa throughput.

Công thức điều khiển sử dụng EWMA (Exponentially Weighted Moving Average):

$$\lambda_C(t) = \delta \cdot \Delta C_t + (1 - \delta) \cdot \lambda_C(t-1)$$

$$k(t) = \left\lfloor \frac{K_{\max}}{1 + \theta \cdot \lambda_C(t)} \right\rfloor$$

trong đó $\lambda_C(t)$ là cường độ coverage ước lượng, $\delta$ là hệ số làm mượt (smoothing factor), $\theta$ là hệ số độ nhạy (sensitivity gain), và $K_{\max}$ là giới hạn trên của sampling interval.

Công thức này có ba ưu điểm so với luật AIMD (Additive Increase / Multiplicative Decrease) dạng step function. Thứ nhất, nó liên tục và khả vi — không có điểm gián đoạn, nên không gây hiện tượng chattering (oscillation cao tần) quanh ngưỡng chuyển đổi. Thứ hai, bản chất EWMA cung cấp hysteresis tự nhiên — $\lambda_C$ không nhảy theo từng event đơn lẻ mà phản ánh xu hướng trung bình. Thứ ba, nó xét magnitude — $\Delta C = 50$ làm $k$ giảm sâu hơn $\Delta C = 1$, thay vì xử lý hai trường hợp như nhau.

Giao tiếp giữa Slow Loop (tính $k$) và Fast Loop (đọc $k$) thực hiện qua file `adaptive_k.json` với atomic rename-swap để tránh race condition. Fast Loop đọc file mỗi 50 gói tin — overhead gần như bằng 0.

## 3.4. Mutation Engine và crash isolation

MutationEngine sử dụng kiến trúc two-mode scheduling để giải quyết bài toán crash isolation. Chế độ mặc định (RANDOM_SUBSET hoặc WEIGHTED) chọn $k$ trường mutable ngẫu nhiên (hoặc có trọng số theo priority) để đột biến mỗi gói tin, đảm bảo throughput cao. Khi CrashMonitor phát hiện crash mới (unique signature chưa từng thấy), engine tự động chuyển sang chế độ ONE_AT_A_TIME — đột biến từng trường một, tuần tự, với budget cố định mỗi trường. Điều này cho phép xác định chính xác trường nào gây crash mà không cần re-run thủ công.

Việc chuyển mode thực hiện qua `asyncio.Lock` với thời gian giữ lock dưới 1 microsecond (chỉ pointer swap rule set), không ảnh hưởng đến hot loop. Cơ chế `_revert_pending` flag đảm bảo việc revert từ investigation mode về normal mode xảy ra deterministic trong hot loop thay vì qua fire-and-forget task — tránh race condition khi crash thứ hai xuất hiện giữa lúc đang revert.

Bên cạnh đó, engine hỗ trợ sequence-aware fuzzing với mô hình $M = \langle \text{Prefix}, \text{Target}, \text{Suffix} \rangle$: đối với các giao thức có trạng thái như FTP, seed được nhóm theo session_id, và chỉ packet ở vị trí target được đột biến, trong khi prefix (ví dụ: USER → PASS để thiết lập phiên) và suffix được gửi nguyên bản. Điều này đảm bảo server ở đúng trạng thái khi nhận packet đột biến.

Weighted scheduler mở rộng RandomSubset bằng cách gán trọng số cho mỗi strategy: BOUNDARY_VALUES (trường length, nguồn crash số một trong thực tế) nhận trọng số 4.0, DICTIONARY (opcode) nhận 3.0, trong khi RANDOM_BYTES chỉ nhận 1.0. Trọng số này nhân với confidence score từ LLM, tạo ra phân phối ưu tiên các trường hứa hẹn nhất.

## 3.5. Theo dõi trạng thái giao thức — từ hardcode sang suy diễn

Đối với giao thức có trạng thái (stateful protocol) như FTP, việc fuzzing hiệu quả
đòi hỏi khám phá cả trạng thái giao thức, không chỉ trường trong gói tin. LIFA-Fuzz
theo dõi chuyển đổi trạng thái qua hai cơ chế:

**FTPModule (case study)**: StateTransitionGraph theo dõi cạnh chuyển đổi
$\langle\text{prev\_code}, \text{command}, \text{new\_code}\rangle$ — ví dụ
$\langle\text{"220"}, \text{USER}, \text{"331"}\rangle$ — và đánh dấu seed phát
hiện cạnh mới là STATE\_NOVELTY (priority boost 5×). Đây là module disclosed cho
case study LightFTP, không thuộc core.

**StateMachineInferer (Tầng 3 — đóng góp tổng quát)**: Để hỗ trợ giao thức lạ
không có module chuyên biệt, LIFA-Fuzz tích hợp Veritas [24] — hệ thống suy diễn
Probabilistic Protocol State Machine (P-PSM) từ network traces thuần thống kê,
không cần đặc tả giao thức, mã nguồn, hay từ khóa hardcode. Quá trình gồm 4 bước:
(1) trích xuất message units 3-byte từ packet headers + lọc K-S test, (2) gom
nhóm PAM + Jaccard similarity + Dunn index chọn $k$ tối ưu, (3) gán nhãn trạng
thái cho mỗi packet theo medoid gần nhất, (4) xây DFA từ chuỗi trạng thái qua
các phiên + xác suất chuyển tiếp $\to$ P-PSM.

P-PSM được suy diễn offline trong Slow Loop (như DifferentialAnalyzer), ghi ra
file cho Fast Loop đọc. `InferredStateTracker` trong Fast Loop gán nhãn mỗi
response packet bằng medoid gần nhất $\to$ theo dõi chuyển đổi trạng thái
generic. Cơ chế này tương tự edge coverage trong AFL, nhưng hoạt động ở tầng
giao thức và **tự động suy diễn** cho bất kỳ protocol nào có traffic — giải
bài toán stateful black-box mà ProtocolGPT [25] (white-box, cần mã nguồn)
không giải được.

## 3.6. Intent-driven mutation: Action Sequence

Một trong những điểm yếu của black-box fuzzing truyền thống là tính chất "mù" của đột biến: fuzzer thay đổi byte ngẫu nhiên mà không biết mình đang thử nghiệm ý đồ kiểm thử nào, không biết trường nào đáng chú ý, và không biết đột biến nào có khả năng kích hoạt code path sâu. SemFuzz [22] đã chứng minh rằng việc gắn mỗi đột biến với một ý đồ kiểm thử (testing intent) rõ ràng — thông qua Action Sequence — cải thiện đáng kể khả năng phát hiện lỗi ngữ nghĩa sâu. LIFA-Fuzz kế thừa và mở rộng cơ chế này cho môi trường black-box, nơi không có RFC để trích xuất semantic rule.

Hệ thống Action Sequence trong LIFA-Fuzz vận hành trên ba phép toán nguyên tử, mỗi phép tương ứng với một MutationStrategy được gán cho từng FieldRule bởi LLM hoặc DifferentialAnalyzer:

**Update** — thay đổi giá trị của trường theo chiến lược cụ thể. Đây là action phổ biến nhất, và cũng là action có nhiều biến thể nhất. Khi LLM suy luận rằng một trường là opcode (ví dụ, giá trị 0x01 = USER, 0x02 = PASS trong giao thức FTP), nó gán strategy DICTIONARY kèm danh sách giá trị hợp lệ và không hợp lệ. MutationEngine khi đó không đột biến byte ngẫu nhiên mà chọn từ danh sách — gửi opcode 0xFF (không tồn tại) thay vì 0x02, tạo ra đột biến có ý đồ: kiểm tra xem server xử lý unknown command ra sao. Tương tự, trường length được gán BOUNDARY_VALUES, và fuzzer thay giá trị length bằng 0x0000, 0xFFFF, 0x7FFF — các giá trị biên có khả năng cao trigger integer overflow hoặc buffer underflow trong logic parse của server. Trường flags/enums được gán BIT_FLIP để kiểm tra các bit chưa được tài liệu hóa có ảnh hưởng gì đến hành vi server.

**Remove** — loại bỏ một trường khỏi gói tin, hoặc cắt bớt packet tại offset của trường. Strategy TRUNCATE thực hiện chính xác điều này: thay vì gửi full packet, fuzzer gửi packet bị cắt ngắn tại vị trí trường đang xét. Ý đồ kiểm thử là phát hiện lỗi null pointer dereference hoặc uninitialized memory access trong server khi nó nhận được packet thiếu trường bắt buộc. Trong giao thức FTP, việc gửi "USER\r\n" (thiếu username) thay vì "USER admin\r\n" là một ví dụ của Remove — và LightFTP đã bị crash bởi chính đột biến này trong thực nghiệm.

**Add** — chèn thêm byte vào packet, làm tăng kích thước trường hoặc thêm payload sau trường đang xét. Strategy FORMAT_STRING điển hình cho action này: fuzzer chèn chuỗi "%n%n%n%n" vào trường payload, kiểm tra format string vulnerability — một lớp lỗi mà random bit-flip gần như không bao giờ tạo ra vì xác suất sinh chuỗi "%n" từ random bytes là cực thấp. Buffer overflow operator (từ `mutation_operators.py`) cũng thuộc nhóm Add: chèn 1.000–10.000 byte vào trường variable-length, kiểm tra xem server có validate độ dài payload trước khi copy vào buffer cố định hay không.

Điểm quan trọng là ba action này không được áp dụng ngẫu nhiên. Mỗi FieldRule mang theo MutationStrategy do LLM hoặc DifferentialAnalyzer gán, và strategy đó quyết định action nào được thực hiện. LLM, khi suy luận rằng trường tại offset 0–3 là "magic" với giá trị constant 0xDEADBEEF, gán strategy STATIC — tức là "không action", giữ nguyên giá trị. Điều này có ý nghĩa sâu sắc: fuzzer biết rằng đột biến magic header gần như chắc chắn khiến server từ chối packet ở tầng validate đầu tiên, nên bỏ qua hoàn toàn và tập trung nguồn lực vào các trường có khả năng kích hoạt logic sâu hơn. Đây chính là bản chất của intent-driven mutation — mỗi đột biến được thực hiện với một giả thuyết kiểm thử rõ ràng, thay vì blind exploration.

Scheduling layer quyết định *trường nào* được áp dụng action trong mỗi lần gửi. Ở chế độ RANDOM_SUBSET, $k$ trường được chọn ngẫu nhiên từ tập mutable fields. Ở chế độ WEIGHTED, trường BOUNDARY_VALUES (length field — nguồn crash phổ biến nhất trong thực tế) nhận trọng số 4.0, trường DICTIONARY (opcode) nhận 3.0, trong khi RANDOM_BYTES chỉ nhận 1.0 — fuzzer ưu tiên các trường hứa hẹn hơn. Ở chế độ ONE_AT_A_TIME (crash investigation), chỉ một trường duy nhất được đột biến mỗi lần, cho phép xác định chính xác action nào trên trường nào gây ra crash.

Sự kết hợp giữa Action Sequence (Add/Remove/Update) và two-mode scheduling tạo ra một hệ thống đột biến vừa có ý đồ (intent-driven) vừa có khả năng cô lập lỗi (crash isolation) — hai thuộc tính thường trade-off với nhau trong các fuzzer truyền thống. Fuzzer không "mù" vì mỗi đột biến có strategy được gán có chủ đích, và fuzzer không "bị noise che mờ" vì scheduling mechanism cho phép chuyển sang chế độ cô lập khi cần.

\newpage

# Chương 4: Triển khai

## 4.1. Ngăn xếp công nghệ

Hệ thống được triển khai hoàn toàn bằng Python 3.11+, tận dụng asyncio làm nền tảng concurrency cho Fast Loop. Slow Loop chạy trên process riêng biệt, khởi tạo bởi `main.py` qua `subprocess.Popen`. Giao tiếp giữa hai process thực hiện hoàn toàn qua filesystem — file JSONL cho traffic log, file JSON cho rules và adaptive sampling state, file JSON cho crash index. Lựa chọn này có lợi thế không yêu cầu dependency ngoài (Redis, message queue) và tự nhiên an toàn về race condition khi sử dụng atomic rename-swap.

LLM inference sử dụng litellm làm abstraction layer, cho phép chuyển đổi giữa các provider (OpenAI, Anthropic, ZhipuAI GLM-5-Turbo) mà không thay đổi code. Biến môi trường và file `.env` quản lý API key. Chế độ MOCK cho phép chạy toàn bộ pipeline không cần API key — LLMAgent sinh grammar giả lập dựa trên heuristic, hữu ích cho development và testing.

Dashboard giám sát sử dụng Streamlit, đọc state từ `runtime_state.json` (ghi mỗi 2 giây bởi state writer task) và hiển thị EPS, crash count, rule set, LLM insights. Dashboard là stateless — không giao tiếp trực tiếp với bất kỳ component nào, chỉ đọc file.

## 4.2. Sandbox Firecracker

Sandbox được triển khai qua hai backend: DockerSandbox (phục vụ giai đoạn prototyping) và FirecrackerSandbox (backend production). FirecrackerSandbox giao tiếp với Firecracker process qua Unix Domain Socket (HTTP-like API). Quá trình khởi tạo một MicroVM gồm: launch firecracker process, cấu hình boot-source (kernel path + boot args), cấu hình rootfs drive, cấu hình network interface (TAP device), cấu hình machine config (vCPU, memory), và gửi InstanceStart. Sau khi VM boot thành công và target server sẵn sàng, một full memory snapshot được chụp để phục vụ reset nhanh.

Rootfs cho LightFTP được build tự động qua Docker multi-stage build: stage 1 compile LightFTP với ASAN (`-fsanitize=address -static-libasan`), stage 2 tạo runtime image tối giản (debian:bookworm-slim + runtime libraries), export sang tar, tạo ext4 image bằng `dd` + `mkfs.ext4`. LightFTP khởi chạy trực tiếp qua `/init` script (không SSH, không systemd), bind to `0.0.0.0:21`.

TAP device kết nối VM với host. Script init cấu hình networking tự động: gán IP tĩnh `172.16.0.2/24` cho eth0, route default qua `172.16.0.1`. Host-side tạo TAP device `tap-lifa0` và cấu hình routing/NAT để Fast Loop (chạy trên host) kết nối đến target trong VM.

## 4.3. Interceptor và traffic capture

Interceptor là một TCP proxy bất đồng bộ ngồi giữa client và target server. Mọi kết nối từ client đến port 8001 được forward sang target server (port 21 trong VM). Interceptor ghi mỗi packet (cả hai hướng, với metadata gồm timestamp, direction, session_id, is_mutated flag) vào traffic log JSONL. Interceptor hỗ trợ hai chế độ: passthrough (chỉ capture) và fuzz (capture + injection), nhưng trong kiến trúc hiện tại, MutationEngine gửi trực tiếp đến target qua kết nối TCP riêng, nên Interceptor chủ yếu đóng vai trò traffic capture device.

## 4.4. Client FTP

FTP client (`sandbox/client/ftp_client.py`) chạy trên host, kết nối đến Interceptor ở `127.0.0.1:8001`. Client thực hiện handshake FTP đầy đủ: nhận banner 220, gửi USER admin, nhận 331, gửi PASS, nhận 230, sau đó luân phiên các lệnh SYST, LIST, MKD, QUIT. Mỗi command cách nhau 200 ms. Traffic sinh ra cung cấp seed thực tế cho MutationEngine — thay vì phải tự generate packet từ đầu, fuzzer biến thể từ các packet hợp lệ mà server đã chấp nhận.

## 4.5. Pipeline end-to-end

Hàm `main.py:run_pipeline()` khởi tạo toàn bộ hệ thống theo thứ tự: Sandbox → Interceptor → Client Subprocess → MutationEngine → CrashMonitor → Seed Feeder → Slow Loop Subprocess → Dashboard → Runtime State Writer. Mỗi component chạy dưới dạng asyncio task riêng biệt trên cùng một event loop (Fast Loop), ngoại trừ Slow Loop và Dashboard (subprocess riêng). Graceful shutdown thực hiện theo thứ tự ngược, với timeout 5 giây cho mỗi task.

Seed Feeder là adapter giữa Interceptor và MutationEngine: đọc JSONL traffic log, nhóm packet theo session_id (với session timeout 2 giây), và đẩy SeedSequence vào asyncio.Queue. MutationEngine tiêu thụ queue này trong hot loop, chọn seed, đột biến, gửi, và cập nhật thống kê.

## 4.6. Thống kê quy mô mã nguồn

Toàn bộ hệ thống gồm khoảng 17.000 dòng Python, phân bổ như sau: MutationEngine (~2.200 dòng, module lớn nhất, chứa scheduler hierarchy, sequence-aware fuzzing, và adaptive sampling), LLMAgent (~1.660 dòng, bao gồm prompt engineering, resilience, và cost tracking), RulesOrchestrator (~1.250 dòng), Firecracker driver (~1.130 dòng), Evaluation Runner (~1.420 dòng), và các module còn lại. Hệ thống được kiểm thử bởi hơn 250 unit test, bao phủ tất cả các component chính.

\newpage

# Chương 5: Thực nghiệm và đánh giá

## 5.1. Môi trường thực nghiệm

**Target:** LightFTP commit 5980ea1, biên dịch với GCC và AddressSanitizer (`-fsanitize=address -static-libasan -g -O2`), static-linked. Chạy trên Firecracker MicroVM (1 vCPU, 256 MB RAM, kernel Linux riêng) với rootfs ext4 256 MB. Target bind to `0.0.0.0:21` bên trong VM (IP `172.16.0.2`).

**Host:** WSL2 trên Windows, Linux kernel 6.6.87.2, Python 3.14, KVM enabled cho Firecracker. Fast Loop và Slow Loop chạy trên host, giao tiếp với target qua TAP device.

**LLM:** GLM-5-Turbo qua Z.ai API (OpenAI-compatible endpoint), temperature 0.2, max_tokens 4096, enable_thinking=false. Chi phí inference khoảng $0.01–0.05 mỗi lần gọi tùy độ dài prompt.

## 5.2. Phương pháp đánh giá

Hệ thống được đánh giá theo ba câu hỏi nghiên cứu, mỗi câu hỏi tương ứng với một baseline và một bộ metric riêng.

**RQ1 — Độ chính xác suy diễn ngữ pháp.** So sánh ngữ pháp giao thức do LIFA-Fuzz suy diễn (với Full Fusion pipeline) với ground truth đã biết. Ground truth cho giao thức LIFA (giao thức dummy nội bộ) được định nghĩa thủ công gồm 4 trường: magic (4 bytes, constant 0xDEADBEEF), opcode (1 byte, enum), length (2 bytes, uint16_le), và payload (variable length). Metric đánh giá là Precision, Recall, và F1-Score với tolerance ±1 byte cho việc khớp offset trường. Evaluation được thực hiện bởi `evaluation/rq1_accuracy.py`, chạy pipeline MOCK mode và so sánh SemanticRule suy diễn với ground truth.

**RQ2 — Throughput và sự cân bằng sampling.** Đo executions per second (EPS) theo thời gian trên ba baseline configuration:

- Baseline A (Pure Random): MutationEngine ở mode "random", DifferentialAnalyzer tắt, LLM tắt. Fuzzer đột biến bit-flip ngẫu nhiên, không sử dụng ngữ pháp giao thức.

- Baseline B (Math-Only): MutationEngine ở mode "smart", DifferentialAnalyzer bật, LLM tắt. Rules được sinh từ heatmap bootstrap (to_field_rules()), không có LLM inference.

- Baseline C (Full Fusion): MutationEngine ở mode "smart", DifferentialAnalyzer bật, LLM bật (GLM-5-Turbo REAL mode). Pipeline hoàn chỉnh: math hint → LLM → grammar → SemanticRules.

Các chiến dịch được chạy ở nhiều độ dài khác nhau (từ 2 phút đến 2 giờ) tùy mục tiêu đo; telemetry được snapshot mỗi 10 giây vào file JSONL để dựng đường cong EPS theo thời gian. Bảng 2 ở Section 5.3 trình bày số liệu của chiến dịch dài 2 giờ (7200 giây) — độ dài đủ để EPS ổn định và đủ số lượng mutation lớn.

**RQ3 — Khả năng phát hiện crash.** Đo cumulative unique crashes theo thời gian và time-to-first-crash trên ba baseline. Unique crash được xác định bởi CrashManager qua SHA256 signature (primary dedup) và structural similarity (secondary dedup). Crash artifacts (binary PoC + JSON report) được lưu vào `./crashes/`.

## 5.3. Kết quả sơ bộ

> **Cảnh báo trung thực (cập nhật):** Các kết quả A/B/C và RQ3 trong phần này
> được đo khi fuzzer còn **lỗi triển khai nghiêm trọng** — SeedFeeder không gom
> session thành multi-packet (mỗi packet là seed riêng → fuzzer không bao giờ
> xác thực → mắc kẹt ở greeting 220, không chạm code post-auth). Mọi so sánh
> A/B/C, số coverage, và số crash từ các chiến dịch **trước khi sửa lỗi này đều
> KHÔNG hợp lệ** và cần re-validate. RQ1 (F1 = 0,857 MOCK / 1,000 REAL) đo
> độc lập với pipeline fuzzing nên **vẫn hợp lệ**. Phần này giữ số cũ cho tham
> chiếu lịch sử; số hợp lệ sẽ thay thế sau re-run.

**RQ1 — Độ chính xác suy diễn ngữ pháp.** Ở chế độ MOCK, pipeline đạt Precision = 1.00, Recall = 0.75, **F1 = 0.857**, với độ chính xác offset = 1.00 (mọi trường suy diễn khớp offset ground truth trong dung sai ±1 byte). Tuy nhiên độ chính xác về *kiểu trường* và *strategy* thấp hơn (0.33 và 0.67 tương ứng): analyzer gộp hai trường opcode và length kế nhau thành một trường length duy nhất, dẫn đến thiếu 1 trường (Recall = 0.75). Mức F1 > 0.85 khớp với kỳ vọng cho giao thức đơn giản, song phải ghi rõ hai điểm: (i) đây là chế độ MOCK, chưa phản ánh chất lượng suy diễn của LLM thực; và (ii) ground truth là giao thức do chính tác giả thiết kế (xem hạn chế Section 6.5). Vì vậy F1 này chủ yếu kiểm chứng cơ chế khớp offset, chưa phải đánh giá khả năng tổng quát hóa.

**RQ2 — Throughput.** Bảng 2 tóm tắt EPS đo được trong một chiến dịch 2 giờ (7200 giây) trên LightFTP/Firecracker.

*Bảng 2: Throughput thực đo (chiến dịch 7200 giây, target LightFTP trên Firecracker MicroVM).*

| Baseline | EPS trung bình | EPS tối đa | Số mutation | Độ rộng mutation† | Token LLM |
|---|---|---|---|---|---|
| A — Pure Random | 414 | 614 | 2.984.330 | 13.426 | 0 |
| B — Math-Only | 400 | 630 | 2.883.137 | 8.842 | 0 |
| C — Full Fusion | 141 | 557 | 1.012.859 | 7.689 | 55.000 (110 lần inference) |

> *† Cột "Độ rộng mutation" (trước đây gắn nhãn "Coverage (proxy)") đếm số cặp (offset byte, giá trị) duy nhất bị đột biến — tức **độ rộng** của không gian đột biến, **không phải** độ phủ code path nhị phân. Random fuzzing (A) đột biến rộng nhất nên số này cao nhất một cách cơ học; con số này không phản ánh "tốt hơn". Độ phủ giao thức thật được báo cáo riêng qua số transition trạng thái (STG edges) ở Bảng 2b và được thảo luận làm headline finding ở Mục 6.1.*

Hai baseline không dùng LLM (A và B) duy trì ~400 EPS, xác nhận kiến trúc bất đồng bộ giữ được throughput cao khi LLM không nằm trên đường nóng. Tuy nhiên **Baseline C thấp hơn nhiều so với kỳ vọng**: EPS trung bình chỉ đạt ~141 (giảm khoảng 65% so với A/B), chứ không phải "dưới 15%" như giả định ban đầu. Nguyên nhân là overhead của LLM inference (110 lần gọi, ~55.000 token) cộng với việc áp dụng rule set phức tạp hơn bị lan ra đường nóng nhiều hơn thiết kế mong muốn. Đây là kết quả bất lợi nhưng quan trọng: để Full Fusion giữ throughput gần với A/B, cần cách ly triệt để hơn giữa LLM và hot loop (ví dụ cache grammar, áp dụng rule hoàn toàn offline). Bộ điều khiển EWMA đã được tích hợp và điều phối sampling, nhưng do thiếu trace thích nghi sạch, báo cáo này chưa lượng hóa được đường cong $k(t)$ và để ngỏ việc benchmark định lượng EWMA cho tương lai.

**Độ phủ trạng thái giao thức (state coverage).** Vì Bảng 2 không có độ phủ giao thức thật (chỉ có độ rộng mutation), bảng dưới đây báo cáo số transition trạng thái giao thức (STG edges) quan sát được — bộ ba `(prev_code, command, new_code)` — đây là chỉ số protocol-coverage đáng tin cậy nhất hiện có. Dữ liệu trích từ `logs/state_coverage_stats_{A,B,C}.csv` của các chiến dịch mở rộng.

*Bảng 2b: Độ phủ trạng thái giao thức (chiến dịch mở rộng trên LightFTP/Firecracker).*

| Baseline | Thời lượng (phút) | Executions | STG edges (unique) | edges / 1000 exec |
|---|---|---|---|---|
| A — Pure Random | 326 | 1.438.799 | 3.752 | 2,61 |
| B — Math-Only | 819 | 1.422.891 | **5.563** | **3,91** |
| C — Full Fusion | 1.154 | 1.356.229 | 2.217 | 1,63 |

Để khống chế khác biệt về thời lượng chiến dịch, ta dùng **hiệu suất discovery chuẩn hóa** (edges / 1000 executions). Kết quả rõ ràng và phản trực giác: **B (Math-Only) khám phá state transition nhiều nhất (3,91 edges/1k exec), gấp ~2,4 lần C (Full Fusion, 1,63)**. Cụ thể tại ~500.000 executions: B tìm 4.616 edges so với chỉ 1.440 của C — B hơn 3,2 lần. Random (A) nằm giữa (2,61). **Baseline dùng LLM (C) lại khám phá ít transition trạng thái nhất** — đây là phát hiện trọng tâm được phân tích cơ chế ở Mục 6.1. Lưu ý thêm: cả ba baseline đều không vượt qua trạng thái FTP đầu tiên (chỉ quan sát status code `220`, xem Mục 6.5), nên các "edge" tại đây là transition nội bộ trong trạng thái chưa xác thực.

**RQ3 — Khả năng phát hiện crash.** Pipeline đã xác nhận khả năng phát hiện crash ASAN thực (SIGABRT, exit code 134) trên LightFTP trong một số phiên — các crash artifact (PoC + báo cáo JSON) được ghi vào `./crashes/`. Tuy nhiên trong các phép so sánh A/B/C đã chạy, **số unique crash ghi nhận không ổn định**: chiến dịch 2 giờ ở Bảng 2 ghi 0 crash trên cả ba baseline, trong khi một chiến dịch A-random dài hơn (90 phút) ghi tới 266 unique crash. Sự không nhất quán này cho thấy bộ đếm crash hiện tại còn phụ thuộc nhiều vào điều kiện phiên (trạng thái target, thời điểm, cơ chế ASAN reporting) và chưa đủ kiểm soát để rút ra kết luận định lượng "baseline nào phát hiện crash nhanh và đa dạng hơn". Do đó **RQ3 chưa kết luận** ở thời điểm báo cáo; cần một phép so sánh có kiểm soát chặt (cùng target snapshot, cùng seed, cùng độ dài, lặp lại nhiều lần) trước khi trả lời định lượng.

\newpage

# Chương 6: Thảo luận

## 6.1. Finding trọng tâm: LLM tăng độ chính xác ngữ pháp nhưng giảm độ phủ trạng thái giao thức

Kết quả bất lợi quan trọng nhất — và cũng là phát hiện có giá trị khoa học nhất — của các chiến dịch thực nghiệm là: **baseline dùng LLM (Full Fusion, C) khám phá ít transition trạng thái giao thức (STG edges) hơn hẳn baseline chỉ dùng toán học (Math-Only, B)**. Cụ thể, hiệu suất discovery chuẩn hóa theo số execution là B (3,91) > A (2,61) > C (1,63) edges/1000 exec — C kém B khoảng 2,4 lần (Bảng 2b). Đây là kết quả **phản trực giác**: ta xây dựng pipeline Full Fusion với kỳ vọng LLM sẽ dẫn dắt fuzzer thông minh hơn, nhưng thực tế LLM lại **thu hẹp** không gian khám phá trạng thái.

**Cơ chế.** Nguyên nhân nằm ở cách LLM gán MutationStrategy cho từng trường. Khi LLM suy luận rằng một số offset là magic/constant, nó gán `STATIC` → fuzzer bỏ qua hoàn toàn. Các trường còn lại được gán tập trung vào `BOUNDARY_VALUES` (trường length — nguồn bug phổ biến) và `DICTIONARY` (opcode). Hệ quả là fuzzer sinh ra **ít loại command FTP khác nhau** hơn: nó xoay quanh một tập nhỏ các giá trị boundary/dictionary thay vì bắn đa dạng command như B (math-only, ít kìm nén hơn) hay A (random, bắn mọi offset). Vì State Transition Graph đếm bộ ba `(prev_code, command, new_code)`, ít command khác nhau đồng nghĩa với ít transition khám phá được. B (Math-Only) lại càng ít thu hẹp command hơn → vô tình chạm nhiều transition hơn.

**Ý nghĩa — trade-off giữa độ chính xác và độ phủ trạng thái.** Đây là một **trade-off chưa được báo cáo trong các công trình LLM-for-fuzzing** (như SemFuzz [22] hay các khảo sát [20]). Hướng dẫn của LLM tăng độ chính xác ngữ pháp (RQ1: offset khớp ground truth) nhưng, khi áp dụng lên fuzzer black-box có trạng thái, lại **tự hạn chế độ đa dạng trạng thái** cần thiết để kích hoạt code path sâu. LLM "hiểu đúng" giao thức nhưng "thận trọng quá" — bỏ qua các đột biến "ngớ ngẩn" mà thực ra lại là đầu dò trạng thái hiệu quả. Điều này gợi ra rằng **giá trị của LLM không nằm ở gán strategy chặt, mà ở đặt tên ngữ nghĩa** (cho mục đích triage và báo cáo), trong khi quyết định đột biến nên giữ độ đa dạng (ví dụ một tầng ε-exploration bắt buộc để bù lại command diversity bị mất).

**Không nên diễn giải C kém hơn B ở đây.** Bảng 2b đo *state coverage*, không đo *code coverage nhị phân thật* (hệ thống hiện không có feedback coverage nhị phân — xem hạn chế Mục 6.5). Rõ ràng ta cần: (i) đo code coverage nhị phân thực (qua ASAN/coverage reporting trong MicroVM) để xác nhận liệu C có thực sự chạm ít code path hơn hay chỉ ít state transition hơn; và (ii) kiểm tra liệu việc giữ command diversity (ε-exploration) có khôi phục được state coverage của C mà vẫn giữ lợi thế ngữ pháp. Đây là hai thí nghiệm ưu tiên cho đợt đánh giá tiếp theo.

## 6.2. Hiệu quả của Neural-Mathematical Fusion

Kết quả thực nghiệm cho thấy sự phân công lao động giữa math layer và LLM là hợp lý. DifferentialAnalyzer xử lý trong dưới 1 ms những gì LLM có thể mất hàng nghìn token để phát hiện: byte nào constant, byte nào có tương quan với packet length, byte nào có entropy cao. LLM được giải phóng để tập trung vào tác vụ mà thống kê đơn thuần không giải quyết được — chẳng hạn, xác định rằng một trường enum 1-byte với các giá trị `0x01`, `0x02`, `0x03` tương ứng với các lệnh READ, WRITE, DELETE. Thông tin này không thể suy ra từ entropy hay tương quan, nhưng LLM có thể dự đoán dựa trên kiến thức về các giao thức phổ biến.

Tuy nhiên, fusion có một điểm yếu: khi giao thức quá đơn giản (chỉ có 2–3 trường), sự phân tách giữa math và LLM không tạo ra lợi ích đáng kể. DifferentialAnalyzer tự nó đã đủ để sinh rules bootstrap chất lượng cao. Lúc này, chi phí gọi LLM ($0.01–0.05 mỗi lần) khó bù đắp bằng giá trị incremental. Ngược lại, khi giao thức phức tạp (10+ trường, nested structure, state machine), LLM contribution trở nên rõ rệt hơn.

## 6.3. Fast-Slow Loop và file-based IPC

Lựa chọn file-based IPC (JSON/JSONL) thay vì Redis hay message queue có vẻ kém "mạnh mẽ" (less "enterprise"), nhưng lại phù hợp cho use case này vì ba lý do. Thứ nhất, traffic log đã phải ghi ra file anyway (cho replay và debugging), nên không thêm overhead mới. Thứ hai, atomic rename-swap cung cấp consistency guarantee đủ mạnh cho single-writer/single-reader pattern. Thứ ba, không có dependency ngoài — hệ thống chạy trên bất kỳ máy nào có Python, không cần setup Redis hay configure port.

Hạn chế của cách tiếp cận này là latency: thời gian từ khi Slow Loop ghi rule mới đến khi Fast Loop đọc được phụ thuộc vào poll interval (2 giây). Trong fuzzing, độ trễ này hoàn toàn chấp nhận được — rule update mỗi 1–2 phút là đủ, không cần real-time. Tuy nhiên, nếu mở rộng sang distributed fuzzing (nhiều Fast Loop instance), file-based IPC sẽ không scale, và cần chuyển sang shared storage (NFS, S3) hoặc message queue.

## 6.4. EWMA Controller và trade-off throughput-observability

EWMA controller thể hiện hành vi mong muốn: coverage tăng → recv() thường xuyên → fuzzer "nhìn thấy" nhiều hơn; coverage bão hòa → recv() thưa thớt → throughput tối đa. Công thức liên tục tránh được hiện tượng chattering — một vấn đề thực sự quan sát được khi thử luật AIMD step function, nơi $k$ nhảy liên tục giữa 1 và $K_{\max}$ tạo ra micro-burst trong EPS.

Một hạn chế của EWMA hiện tại là dependence vào proxy metric. Slow Loop không có quyền truy cập trực tiếp vào server response — nó chỉ nhìn thấy số lượng unique hex prefix trong response buffer và số field group từ DifferentialAnalyzer. Đây là proxy không hoàn hảo cho "coverage thực sự" (số code path được kích hoạt trong binary). Nếu tích hợp được ASAN/UBSan coverage reporting (qua shared filesystem giữa host và VM), metric coverage sẽ chính xác hơn đáng kể.

## 6.5. Hạn chế

Hệ thống có một số hạn chế cần ghi nhận:

Thứ nhất, LLM inference không deterministic. Cùng một traffic input, hai lần gọi LLM có thể sinh ngữ pháp khác nhau. RulesOrchestrator thực hiện dedup (sliding window 200 packet) để giảm duplicate, nhưng không thể đảm bảo convergence về một ngữ pháp duy nhất.

Thứ hai, phương pháp đánh giá hiện tại (RQ1) sử dụng ground truth cho giao thức LIFA đơn giản (4 trường) — một giao thức do chính tác giả thiết kế. Điều này dẫn đến *vấn đề đánh giá vòng (evaluation leak)*: hệ thống được đánh giá trên chính bài toán mà nó có thể đã được vô ý tối ưu để giải. Mục tiêu của đề tài là fuzzing giao thức độc quyền *không biết trước*, nhưng RQ1 lại đánh giá trên giao thức *đã biết hoàn toàn*. Hơn nữa, kết quả RQ1 hiện có (F1 = 0.857) được đo ở chế độ MOCK (không gọi LLM thực), nên chỉ phản ánh khả năng khớp offset/cấu trúc trên một ví dụ đơn giản chứ chưa chứng minh khả năng tổng quát hóa với LLM thực. Việc mở rộng RQ1 lên giao thức thực với ground truth độc lập (ví dụ parser lệnh USER/PASS của FTP theo RFC 959, với target LightFTP đã có sẵn) là cần thiết để khắc phục hạn chế này.

Thứ ba, chi phí LLM. Toán học tiền xử lý được thiết kế để giảm token tiêu thụ (ước tính sơ bộ, chưa có phép đo before/after chính thức), song chi phí vẫn không nhỏ. Một chiến dịch fuzzing 1 giờ với inference mỗi 30 giây tiêu tốn khoảng $1–3. Điều này chấp nhận được cho nghiên cứu nhưng cần xem xét cho chiến dịch dài ngày.

Thứ tư, Firecracker yêu cầu KVM, không chạy được trên môi trường không có hardware virtualization (như một số cloud VM lồng nhau). DockerSandbox phục vụ như fallback nhưng với reset time chậm hơn đáng kể.

Thứ năm, **hệ thống không có feedback độ phủ code nhị phân thật** (code coverage). Chỉ số `unique_code_branches` trong telemetry thực chất đếm số cặp (offset byte, giá trị) bị đột biến — là *độ rộng mutation*, không phải số branch nhị phân được kích hoạt. Tên trường dễ gây hiểu lầm. Hệ quả là việc so sánh A/B/C đến nay chỉ dựa trên proxy ở tầng giao thức (số transition trạng thái) và không thể trả lời "baseline nào chạm nhiều code path nhị phân hơn". Tích hợp ASAN/coverage reporting (qua shared filesystem giữa host và MicroVM) là điều kiện cần cho mọi kết luận định lượng về độ phủ trong tương lai.

Thứ sáu, **không baseline nào vượt qua trạng thái FTP đầu tiên**. Trong mọi chiến dịch, chỉ status code `220` (banner chào) được quan sát; `unique_states` gần như luôn bằng 1. Nghĩa là fuzzer chưa bao giờ thiết lập phiên đã xác thực (USER → PASS → 230) trước khi gửi lệnh đột biến, nên các "state transition" được đếm thực ra là transition nội bộ trong trạng thái chưa xác thực, và các code path sâu (nơi crash thực sự tồn tại) hiếm khi được kích hoạt. Đây là nguyên nhân sâu của việc RQ3 không ổn định, và là động lực cho direction fuzzing theo trạng thái trong tương lai.

Thứ bảy, báo cáo chưa thực hiện *ablation study* đầy đủ để bóc tách đóng góp riêng của từng thành phần kỹ thuật (EWMA controller, WeightedScheduler, one-at-a-time isolation). Phép so sánh A/B/C chỉ trả lời được câu hỏi tổng quát "toán học + LLM khác random ra sao", chứ chưa cô lập được đóng góp của từng cơ chế scheduling. Cơ chế scheduling trong báo cáo này được trình bày dưới góc *engineering design* (giải vấn đề thực tế) chứ không phải đóng góp thuật toán cần ablate bắt buộc; việc ablate từng thành phần là hướng đánh giá bổ sung nếu cần khẳng định giá trị độc lập của từng cơ chế.

\newpage

# Chương 7: Kết luận và hướng phát triển

## 7.1. Kết luận

Báo cáo này đã trình bày LIFA-Fuzz, một framework fuzzing black-box cho giao thức mạng sử dụng Large Language Model để suy diễn ngữ pháp giao thức từ traffic thực tế. Ba đóng góp chính của đề tài là: (i) kiến trúc Fast-Slow Loop bất đồng bộ tách biệt fuzzing tốc độ cao khỏi phân tích LLM, đảm bảo throughput của fuzzer không bị ảnh hưởng bởi độ trễ inference; (ii) Neural-Mathematical Fusion kết hợp xử lý toán học thuần túy với suy luận neural, giảm đáng kể token tiêu thụ cho LLM; (iii) bộ điều khiển EWMA thích nghi điều phối tự động sampling interval dựa trên cường độ coverage, với công thức liên tục được thiết kế để tránh hiện tượng chattering.

Hệ thống đã được triển khai hoàn chỉnh (~17.000 dòng code, 250+ test) và chạy end-to-end trên target thực tế LightFTP trong Firecracker MicroVM. Kiến trúc modular — với BaseSandbox abstraction, pluggable LLM provider (qua litellm), và file-based IPC — cho phép thay đổi từng component mà không ảnh hưởng đến các phần còn lại. Đặc biệt, bootstrap fallback từ DifferentialAnalyzer đảm bảo fuzzer không bao giờ bị "đói" rules: ngay cả khi LLM không phản hồi, math layer cung cấp rules đủ tốt để tiếp tục fuzzing.

## 7.2. Hướng phát triển

Nhiều hướng phát triển tự nhiên từ kết quả hiện tại:

**Coverage-guided fuzzing thực sự.** Hiện tại, LIFA-Fuzz là black-box hoàn toàn — không có feedback từ binary coverage. Bước tiếp theo là tận dụng ASAN/UBSan reports từ LightFTP (đã biên dịch với ASAN) để xây dựng coverage signal thực. Cơ chế này có thể triển khai qua shared filesystem giữa host và VM: ASAN ghi coverage data ra file, host đọc periodic, và EWMA controller sử dụng coverage thực thay vì proxy metric.

**Đa giao thức.** Kiến trúc hiện tại đã hỗ trợ FTP qua LightFTP. Mở rộng sang các target khác (lighttpd, BIND9, vsftpd) chỉ cần: (i) build rootfs mới (Dockerfile cho target, script build_rootfs), (ii) viết client sinh traffic hợp lệ cho giao thức tương ứng, (iii) điều chỉnh DifferentialAnalyzer threshold nếu cần. Firecracker Auto-Setup Module (đã thiết kế trong `docs/firecracker_auto_setup_module.md`) tự động hóa bước (i).

**Distributed fuzzing.** Chạy nhiều Fast Loop instance song song trên cluster (K8s), mỗi instance fuzz một target khác nhau hoặc cùng target nhưng khác seed. Orchestrator pod quản lý job queue, thu thập results, và điều phối LLM calls (tránh duplicate inference khi nhiều instance fuzz cùng giao thức). Hướng này đã được thiết kế chi tiết trong `docs/advanced_development_plan.md` (Phase 11).

**Protocol state machine inference.** LLM có khả năng suy luận không chỉ cấu trúc gói tin mà còn cả state machine của giao thức — ví dụ, FTP yêu cầu USER trước PASS, không thể RETR trước khi authenticate. Tích hợp state machine inference vào SemanticRules (qua trường `protocol_state` đã có trong schema) sẽ cho phép fuzzer gửi mutated packets trong ngữ cảnh trạng thái đúng, tăng khả năng kích hoạt deep code paths.

\newpage

# Tài liệu tham khảo

[1] Sutton, M., Greene, A., Amini, P. "Fuzzing: Brute Force Vulnerability Discovery." Addison-Wesley Professional, 2007. ISBN 978-0321446114.

[2] Syzkaller — kernel fuzzer. Google, 2025. https://github.com/google/syzkaller

[3] Zalewski, M. American Fuzzy Lop (AFL) — a security-oriented fuzzer. 2017. https://lcamtuf.coredump.cx/afl/

[4] libFuzzer — a library for coverage-guided fuzz testing. LLVM Project, 2025. https://llvm.org/docs/LibFuzzer.html

[5] honggfuzz — security oriented software fuzzer. Google, 2025. https://github.com/google/honggfuzz

[6] Pordanesh, S., Tan, B. "Exploring the Efficacy of Large Language Models (GPT-4) in Binary Reverse Engineering." arXiv preprint arXiv:2406.06637, 2024. https://arxiv.org/abs/2406.06637

[7] Aitel, D. "An Introduction to SPIKE, the Fuzzer Creation Kit." 2005. https://www.immunitysec.com/downloads/SPIKEdescription.pdf

[8] Sulley Fuzzing Framework. 2012. https://github.com/OpenRCE/sulley

[9] Peach Fuzzer. 2020. https://www.peach.tech/

[10] boofuzz — Network Protocol Fuzzing for Humans. 2025. https://github.com/jtpereyda/boofuzz

[11] AFL++ — fuzzer maintaining and improving AFL. 2025. https://github.com/AFLplusplus/AFLplusplus

[12] SnapChange — Lightweight Fuzzing of a Memory Snapshot using KVM. Amazon AWS Labs (awslabs), 2023. https://github.com/awslabs/snapchange

[13] Cui, W., et al. "Discoverer: Automatic Protocol Reverse Engineering by Parsing Binary Traces." USENIX Security Symposium, 2007.

[14] Cui, W., et al. "Tupni: Automatic Reverse Engineering of Input Formats." ACM CCS, 2008.

[15] Caballero, J., et al. "Dispatcher: Enabling Active Botnet Infiltration Using Automatic Protocol Interface Reverse-Engineering." ACM CCS, 2009.

[16] Comparetti, P.M., et al. "Prospex: Protocol Specification Extraction." IEEE Symposium on Security and Privacy, 2009.

[17] Wang, Y., et al. "NEMESYS: Network Message Syntax Reverse Engineering using Neural Networks." NDSS, 2023.

[18] Duchêne, F., et al. "Protocol Reverse Engineering Using Shannon Entropy." IEEE Transactions on Information Forensics and Security, 2018.

[19] Pearce, H., et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." IEEE Symposium on Security and Privacy, 2022.

[20] Huang, L., Zhao, P., Chen, H., Ma, L. "On the Challenges of Fuzzing Techniques via Large Language Models: A Survey." arXiv preprint arXiv:2402.00350, 2024. https://arxiv.org/abs/2402.00350

[21] Firecracker MicroVM. AWS, 2025. https://firecracker-microvm.github.io/

[22] Sun, Y., Luo, Q., Wang, Y., et al. "SemFuzz: A Semantics-Aware Fuzzing Framework for Network Protocol Implementations." Proceedings of the ACM Web Conference 2026 (WWW '26), 2026. https://doi.org/10.1145/3774904.3792541

[23] Qin, S., Hu, F., Ma, Z., et al. "NSFuzz: Towards Efficient and State-Aware Network Service Fuzzing." ACM Transactions on Software Engineering and Methodology (TOSEM), 2023.

[24] Wang, Y., Zhang, Z., Yao, D., Qu, B., Guo, L. "Inferring Protocol State Machine from Network Traces: A Probabilistic Approach" (Veritas). 2011.

[25] Wei, H., Chen, L., Du, Z., et al. "Unleashing the Power of LLM to Infer State Machine from the Protocol Implementation" (ProtocolGPT). arXiv:2405.00393, 2024. https://arxiv.org/abs/2405.00393
