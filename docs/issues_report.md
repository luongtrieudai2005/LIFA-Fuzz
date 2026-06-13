Tôi đã đọc toàn bộ 414 dòng. Đây là góp ý thật sự, không phải khen xã giao:

---

## 🔴 VẤN ĐỀ NGHIÊM TRỌNG — Phải sửa trước khi nộp

### 1. Chương 5 không có kết quả thực — chỉ có "kết quả dự kiến"

Đây là vấn đề nghiêm trọng nhất. Section 5.3 được đặt tên **"Kết quả dự kiến"** (*expected results*) thay vì kết quả thực đo được. Trong một báo cáo cuối kỳ, điều này tương đương với việc nộp đề cương thay vì báo cáo.

Cụ thể những con số đang thiếu:

| Claim | Hiện trạng | Cần có |
|-------|-----------|--------|
| "400+ EPS" | Chỉ assertion | Benchmark table: A/B/C EPS trung bình ± std |
| "F1-Score > 0.85" | "Dự kiến" | Con số thực từ `rq1_accuracy.py` |
| "70% token reduction" | Không có bằng chứng | Token count trước/sau với math hint |
| "crash nhanh hơn" | Mô tả định tính | Time-to-first-crash (giây) cho A, B, C |

**Fix:** Chạy thực nghiệm và thay Section 5.3 bằng bảng số liệu thực. Dù kết quả không như kỳ vọng, kết quả thực vẫn có giá trị hơn "dự kiến".

---

### 2. RQ1 ground truth là giao thức tự thiết kế — vòng tròn

Ground truth cho RQ1 là **giao thức LIFA** — do chính tác giả thiết kế với 4 trường cố định. Đây là vấn đề về tính độc lập: ta đang đánh giá khả năng của hệ thống trên bài toán mà hệ thống có thể đã được "vô tình" tối ưu hóa để giải.

Quan trọng hơn: mục tiêu của đề tài là fuzzing **giao thức độc quyền không biết trước** — nhưng RQ1 đánh giá trên giao thức **đã biết hoàn toàn**. Đây là *evaluation leak*.

**Fix tối thiểu:** Thêm một câu thừa nhận hạn chế này trong Section 6.4. Ví dụ:
> *"RQ1 evaluation hiện chỉ thực hiện trên giao thức LIFA, một giao thức đơn giản do tác giả thiết kế. Điều này giới hạn khả năng tổng quát hóa của kết quả..."*

**Fix lý tưởng:** Chạy RQ1 trên một phần nhỏ của giao thức FTP thực (ít nhất là parser lệnh USER/PASS) với ground truth từ RFC 959 — target LightFTP đã có sẵn.

---

### 3. Lỗi đánh máy trong tiêu đề chương

**Trang 33, dòng 32:** `# Chương 1: Giới thích` → phải là `# Chương 1: Giới thiệu`

Đây là typo trong *tiêu đề chương* — người đọc gặp ngay từ trang đầu.

---

## 🟠 VẤN ĐỀ HỌC THUẬT — Ảnh hưởng đến điểm

### 4. Tài liệu tham khảo sai và không nhất quán

**[1]** — Trích dẫn AFL cho "browser fuzzing" và gán cho Google 2025. AFL do Michał Zalewski viết (lcamtuf), không phải Google, và không phải công cụ browser fuzzer chính. [3] sau đó trích đúng tác giả AFL — hai tài liệu mâu thuẫn nhau cho cùng một công cụ.

**[12]** — `"SnapChange — snapshot fuzzing using KVM. AFLplusplus/AFLplusplus"`. SnapChange là công cụ riêng biệt của Microsoft Research, không phải một phần của AFLplusplus repository.

**[6]** — `"Tork, M., et al. 'Can Large Language Models Reason About Binary Protocol Specifications?' arXiv 2024"`. Tên tác giả và tiêu đề này không xác minh được — cần kiểm tra lại hoặc thay bằng paper thực.

**Fix:** Verify tất cả 23 tài liệu tham khảo trước khi nộp. Ít nhất kiểm tra [1], [6], [12].

---

### 5. Bảng 1 thiếu nguồn tham chiếu cho claims về LIFA-Fuzz

Bảng 1 so sánh LIFA-Fuzz với SemFuzz và NSFuzz, nhưng cột LIFA-Fuzz liệt kê các tính năng như "Action Sequence + scheduling", "400+ EPS", và "< 10 ms reset" mà không có citation hay measurement. Người đọc không thể phân biệt đây là *design goal* hay *measured result*.

**Fix:** Thêm footnote cho mỗi claim trong cột LIFA-Fuzz, ví dụ: "†Đo trong môi trường thực nghiệm Section 5.1" hoặc "‡Design goal, chưa có benchmark so sánh trực tiếp".

---

### 6. Thiếu ablation study — không rõ contribution của từng component

Báo cáo có Baseline A (Pure Random), B (Math-Only), C (Full Fusion) nhưng thiếu câu hỏi: trong Full Fusion, đóng góp tương đối của EWMA controller, WeightedScheduler, và One-at-a-time isolation là bao nhiêu?

Đây là **ablation study tiêu chuẩn** trong bài báo ML/security — thiếu nó làm yếu luận điểm rằng mỗi component là cần thiết.

**Fix tối thiểu:** Thêm Baseline D = Full Fusion không có EWMA (k cố định = 200). So sánh D với C là đủ để chứng minh giá trị của EWMA controller.

---

### 7. Luận điểm Lyapunov stability không được chứng minh

Section 3 và Abstract đề cập "công thức ổn định theo nghĩa Lyapunov" nhưng Chương 3 không có proof. Đây là một claim toán học mạnh — nếu không chứng minh, nên đổi thành "được thiết kế để tránh chattering" hoặc trích dẫn Document 4 như một technical reference.

---

## 🟡 GÓP Ý VỀ TRÌNH BÀY

### 8. Cấu trúc chương 5 nên đổi thứ tự

Thứ tự hiện tại: Môi trường → Phương pháp → **Kết quả dự kiến**

Thứ tự chuẩn cho báo cáo kỹ thuật: Môi trường → Phương pháp → **Kết quả thực** → Phân tích

Đồng thời, Section 6.1 đến 6.3 đang làm nhiệm vụ phân tích kết quả mà lẽ ra phải có trong Chương 5. Hai chương đang overlap.

---

### 9. "LIFA" không được giải thích trong Abstract hay Introduction

Abstract nhắc "LIFA-Fuzz" nhưng không mở rộng từ viết tắt. Tên đầy đủ trong title là *"Live-traffic Inference & Asynchronous Fuzzing"* — thông tin này nên xuất hiện ở đoạn đầu Section 1.2 hoặc cuối Abstract.

---

## ✅ ĐIỂM MẠNH — Thực sự tốt

Để công bằng, những phần này được viết tốt và thể hiện hiểu biết sâu:

- **Section 2.4** — Phân tích khoảng trống giữa SemFuzz (whitebox + RFC) và NSFuzz (greybox + instrumentation) và định vị LIFA-Fuzz vào đúng điểm giao: rõ ràng, thuyết phục, đúng học thuật.
- **Section 3** — Giải thích tại sao Fast-Slow Loop là *tất yếu vật lý* (4-5 bậc tốc độ khác nhau) thay vì lựa chọn tùy ý — đây là cách lập luận đúng.
- **Section 6.2** — Lý giải tại sao file-based IPC tốt hơn Redis cho use case này: logic tốt, không overengineer.
- **17,000 dòng code + 250 tests** — Quy mô triển khai thực sự đáng kể cho một project cuối kỳ.

---

## TÓM TẮT ƯU TIÊN

```
Trước khi nộp (bắt buộc):
  1. Sửa typo "Giới thích" → "Giới thiệu"
  2. Verify [1], [6], [12] trong tài liệu tham khảo
  3. Thêm câu thừa nhận hạn chế RQ1 ground truth vào Section 6.4

Nếu còn thời gian (tăng điểm đáng kể):
  4. Chạy thực nghiệm thực → thay Section 5.3 "dự kiến" bằng số liệu thực
  5. Thêm Baseline D (Full Fusion, k cố định) làm ablation cho EWMA
  6. Thêm footnote cho claims trong Bảng 1
```

Nhìn chung kiến trúc và lý luận của báo cáo **tốt hơn nhiều** so với phần lớn project cuối kỳ — vấn đề chính là **thiếu kết quả thực nghiệm**. Nếu có số liệu thực, đây là một báo cáo đáng điểm cao.