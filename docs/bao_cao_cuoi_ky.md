---
title: "LIFA-Fuzz: Framework Fuzzing cho giao thức mạng dựa trên suy diễn ngữ pháp bằng Large Language Model"
subtitle: "Báo cáo cuối kỳ — Môn Dự án Công Nghệ Thông Tin"
author: "Lương Triều Đại"
institution: "Khoa Công nghệ Thông tin"
date: "Tháng 6, 2026"
---

\newpage

# Tóm tắt

Khi kiểm thử các dịch vụ mạng dùng giao thức độc quyền, người làm bảo mật thường không có mã nguồn, không có tài liệu, và chỉ có thể nhìn thấy luồng dữ liệu qua đường truyền. Fuzzing kiểu mù (đảo bit ngẫu nhiên) trong tình huống này rất kém hiệu quả: hầu hết gói tin đều bị server từ chối ngay từ đầu, không chạm tới những đoạn mã xử lý logic sâu nơi lỗi thực sự tồn tại.

LIFA-Fuzz là một framework fuzzing giải quyết vấn đề này bằng cách kết hợp mô hình ngôn ngữ lớn (LLM) với các phương pháp thống kê để suy diễn cấu trúc giao thức từ chính luồng traffic thực tế. Hệ thống có kiến trúc hai vòng lặp bất đồng bộ: Fast Loop chịu trách nhiệm gửi gói tin đột biến ở tốc độ cao, Slow Loop đảm nhiệm việc phân tích traffic và gọi LLM. Hai vòng này không bao giờ chặn nhau, nhờ đó tốc độ fuzzing không bị ảnh hưởng bởi độ trễ của LLM. Một bộ điều khiển thích nghi tự động điều chỉnh tần suất lấy mẫu phản hồi của server, cân bằng giữa thông lượng và khả năng quan sát trạng thái.

Với các giao thức có tập lệnh phổ biến như FTP, hệ thống khởi động bằng một từ điển token cơ bản (USER, PASS, PORT, QUIT...). Đây không phải là đặc tả đầy đủ hay luật state machine viết tay — đó chỉ là điểm xuất phát. Đóng góp thật sự nằm ở chỗ: từ những token đó, hệ thống tự động suy diễn ra máy trạng thái của giao thức và tự động mở rộng kích thước dữ liệu gửi vào các trường (pay load escalation), giúp kích hoạt các lỗ hổng sâu mà không cần con người viết luật State Machine hay luật Length bằng tay.

Thực nghiệm trên LightFTP (một FTP server thực tế, chạy trong môi trường Firecracker MicroVM) trong chiến dịch mười giờ cho thấy các baseline không dùng LLM duy trì được khoảng 60 đến 140 lần thực thi mỗi giây, còn baseline dùng LLM đầy đủ chậm hơn (khoảng 50) nhưng khám phá nhiều trạng thái giao thức nhất. Trên LightFTP bản ổn định không phát hiện được lỗi bộ nhớ nào, song pipeline đã chứng minh khả năng phát hiện và xác nhận lỗi tràn bộ đệm thật thông qua đối chứng dương tính trên một server có lỗ hổng đã biết. Kết quả chi tiết và những hạn chế được thảo luận trong các chương sau. Toàn bộ hệ thống gồm khoảng 17.000 dòng Python với hơn 250 bài kiểm thử.

**Từ khóa:** fuzzing, suy diễn giao thức, mô hình ngôn ngữ lớn, state machine tự động, Firecracker, EWMA

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

Fuzzing là một kỹ thuật kiểm thử phần mềm đã được chứng minh là rất hiệu quả trong việc tìm ra lỗi bảo mật. Từ trình duyệt web cho tới hệ điều hành, rất nhiều lỗi nghiêm trọng đã được phát hiện nhờ fuzzing [1, 2]. Tuy nhiên, hầu hết các công cụ fuzzing phổ biến hiện nay như AFL, libFuzzer hay honggfuzz đều có một điểm chung: chúng yêu cầu phải có mã nguồn hoặc file nhị phân đã được biên dịch đặc biệt để có thể theo dõi được luồng thực thi của chương trình. Điều này khiến chúng không thể áp dụng cho một lớp bài toán rất phổ biến trong thực tế: đó là các dịch vụ mạng sử dụng giao thức độc quyền, không có tài liệu, và người kiểm thử chỉ có thể nhìn thấy luồng dữ liệu đi qua đường truyền.

Khi không có mã nguồn hay tài liệu giao thức, cách duy nhất là fuzzing kiểu hộp đen (black-box): gửi các gói tin đã được biến đổi một cách ngẫu nhiên vào server và quan sát phản ứng. Nhưng cách này có một vấn đề lớn. Khi ta không biết byte nào là mã định danh, byte nào là trường độ dài, byte nào là dữ liệu, thì việc đảo bit ngẫu nhiên gần như chắc chắn sẽ tạo ra những gói tin vô nghĩa, bị server từ chối ngay từ tầng phân tích đầu tiên. server thậm chí không bao giờ đi tới được những đoạn mã xử lý logic sâu, nơi lỗi thực sự tồn tại.

Một hướng tiếp cận mới đang nổi lên gần đây là sử dụng các mô hình ngôn ngữ lớn (LLM) để phân tích cấu trúc gói tin. Các nghiên cứu cho thấy LLM có khả năng nhận diện các mẫu trong dữ liệu nhị phân, chẳng hạn như đâu là mã magic, đâu là số thứ tự, nếu được cung cấp các mẫu traffic dạng hex [1]. Thay vì fuzz một cách mù quáng, ta có thể dùng LLM để tìm hiểu cấu trúc giao thức trước, rồi dùng kiến thức đó để dẫn dắt quá trình đột biến.

Tuy nhiên, ý tưởng này vấp phải ba khó khăn. Thứ nhất, LLM xử lý rất chậm. Một lần gọi API có thể mất từ 15 tới 60 giây, trong khi fuzzing cần tốc độ hàng trăm hay thậm chí hàng nghìn lần thực thi mỗi giây. Nếu phải chờ LLM trả lời trước khi gửi gói tin tiếp theo, tốc độ sẽ giảm từ vài trăm xuống dưới một lần mỗi giây. Thứ hai, chi phí sử dụng LLM rất cao. Việc gửi toàn bộ dữ liệu hex thô cho LLM và yêu cầu nó phân tích từ đầu tiêu tốn một lượng lớn token, trong khi những việc đơn giản như xác định byte nào là cố định có thể được giải quyết bằng một phép tính entropy trong chưa đầy một phần nghìn giây, gần như không tốn kém. Thứ ba, khi nhiều trường trong gói tin bị biến đổi cùng lúc, nếu server crash thì rất khó xác định trường nào thực sự là nguyên nhân. Điều này làm giảm giá trị của mỗi crash vì người kiểm thử phải mất thêm thời gian truy tìm gốc rễ vấn đề.

Với các giao thức phổ biến như FTP, LIFA-Fuzz thừa nhận có một bước khởi động nhỏ: một từ điển token cơ bản chứa các lệnh thông dụng (USER, PASS, PORT, SYST, QUIT...). Điểm cốt lõi là từ đó trở đi, mọi thứ đều tự động. Hệ thống không có đặc tả state machine, không có luật length viết tay, không có grammar file như Peach hay Sulley. Từ điển token chỉ là điểm khởi đầu; phần suy diễn state machine và quyết định trường nào dài bao nhiêu, gửi bao nhiêu byte để kích nổ lỗi đều do máy làm.

## 1.2. Mục tiêu nghiên cứu

Dựa trên các thách thức trên, đề tài này đặt ra ba mục tiêu chính:

**(i)** Thiết kế một kiến trúc bất đồng bộ tách biệt hoàn toàn luồng fuzzing tốc độ cao khỏi luồng phân tích LLM, sao cho độ trễ của LLM không bao giờ ảnh hưởng đến throughput của fuzzer.

**(ii)** Kết hợp một lớp tiền xử lý toán học (entropy Shannon, tương quan Pearson, Kendall's τ) với LLM inference để giảm khối lượng công việc của LLM, tận dụng điểm mạnh của phương pháp thống kê (nhanh, không tốn token) cho phần phát hiện cấu trúc thô, và dành LLM cho phần cần suy luận ngữ nghĩa cao hơn (đặt tên trường, suy luận quan hệ giữa các trường).

**(iii)** Xây dựng một hệ thống điều phối thích nghi giữa hai luồng, cho phép fuzzer tự động chuyển đổi giữa chế độ khám phá rộng (nhiều trường đột biến mỗi gói tin, throughput cao) và chế độ điều tra cô lập (một trường duy nhất mỗi gói tin, chính xác hóa root cause) khi phát hiện crash mới.

## 1.3. Câu hỏi nghiên cứu

Để đánh giá hệ thống một cách có hệ thống, tôi đặt ra ba câu hỏi. Mỗi câu hỏi tương ứng với một khía cạnh quan trọng của bài toán.

**RQ1 — Độ chính xác suy diễn ngữ pháp.** LIFA-Fuzz suy diễn cấu trúc giao thức chính xác đến mức nào? Các nhãn trường (static, calculated, high entropy) mà hệ thống gán cho từng byte trong gói tin có khớp với thực tế không? Câu hỏi này được đo bằng precision, recall và F1, so sánh với đáp án đã biết trước.

**RQ2 — Thông lượng và sự cân bằng sampling.** Kiến trúc hai vòng lặp bất đồng bộ có thực sự duy trì được tốc độ cao không? Bộ điều khiển thích nghi có giúp cân bằng giữa thông lượng (số gói tin gửi được mỗi giây) và khả năng quan sát (đọc phản hồi của server) hay không?

**RQ3 — Khả năng phát hiện crash.** So với các phương pháp đơn giản hơn (random, hoặc chỉ toán học), pipeline đầy đủ (toán học + LLM) có phát hiện crash nhanh hơn và đa dạng hơn không?

## 1.4. Đóng góp chính

Báo cáo này đóng góp bảy điểm chính:

*Thứ nhất*, một cách thiết kế tách chương trình làm hai luồng chạy song song không đồng bộ. Một luồng lo việc gửi gói tin tốc độ cao, luồng kia lo việc phân tích dữ liệu. Hai luồng trao đổi qua file, không qua mạng hay hàng đợi, nên luồng gửi không bao giờ phải đợi luồng phân tích.

*Thứ hai*, cách kết hợp giữa tính toán thống kê và mô hình ngôn ngữ lớn. Các phép tính như entropy (dưới một phần nghìn giây) làm việc phát hiện cấu trúc thô, giúp mô hình ngôn ngữ chỉ phải tập trung vào việc đặt tên có ý nghĩa cho các trường, nhờ đó giảm đáng kể chi phí tính toán.

*Thứ ba*, một phương pháp tự động nhận diện trạng thái của giao thức từ dữ liệu mạng, không cần bất kỳ tài liệu hay mã nguồn nào. Nhờ đó, chương trình có thể biết được phiên giao tiếp đang ở bước nào và đưa ra các đột biến phù hợp.

*Thứ tư*, hệ thống có một từ điển token cơ bản cho các giao thức phổ biến (FTP: USER, PASS, PORT, SYST...). Đây không phải là đặc tả đầy đủ — chỉ là điểm khởi động để fuzzer không phải đoán mò mọi thứ từ đầu. Từ đó, phần lõi tự động suy diễn ra máy trạng thái và quyết định chiến lược đột biến cho từng trường. Kiến trúc dạng module cho phép thêm từ điển cho giao thức mới mà không cần sửa phần lõi.

*Thứ năm*, cơ chế ghi nhớ chuỗi lệnh trước đó. Chẳng hạn, nếu giao thức yêu cầu đăng nhập trước (USER rồi PASS), chương trình sẽ gửi đúng hai lệnh đó, sau đó mới đột biến gói tin tiếp theo. Nhờ vậy có thể kiểm thử ở các bước sâu của giao thức, không chỉ bị kẹt ở lời chào đầu tiên.

*Thứ sáu*, cơ chế xác nhận lỗi bằng cách chạy lại gói tin trên một server sạch. Với các giao thức có trạng thái, lỗi chỉ tái hiện khi gửi kèm đúng chuỗi lệnh trước đó — cơ chế này đảm bảo người khác có thể chạy lại và thấy đúng lỗi đó.

*Thứ bảy*, một triển khai hoàn chỉnh trên LightFTP (một FTP server thực tế) chạy trong môi trường máy ảo Firecracker. Toàn bộ chu trình từ khởi tạo môi trường, bắt traffic, đột biến, phát hiện lỗi, gọi mô hình ngôn ngữ đến sinh luật đột biến đều hoạt động thông suốt.

\newpage

# Chương 2: Tổng quan công trình liên quan

## 2.1. Fuzzing giao thức mạng

Fuzzing giao thức là một nhánh chuyên biệt của fuzzing: thay vì đưa dữ liệu lung tung vào một chương trình, ta tập trung vào việc gửi các gói tin mạng đã được chỉnh sửa có chủ đích vào server và quan sát phản ứng.

Những công cụ đầu tiên như SPIKE [2] và Sulley [3] hoạt động dựa trên các file mô tả giao thức do con người viết tay. Người kiểm thử phải hiểu sâu về giao thức đó, rồi viết ra từng trường một — đâu là mã lệnh, đâu là độ dài, đâu là dữ liệu. Cách này cho kết quả rất tốt nếu có người am hiểu giao thức, nhưng chi phí nhân công rất cao và không thể mở rộng.

Peach Fuzzer [4] cải tiến bằng cách tách riêng mô tả dữ liệu (cấu trúc gói tin) và mô tả trạng thái (trình tự các bước trong phiên giao tiếp). Điều này giúp việc mô tả linh hoạt hơn, nhưng vẫn đòi hỏi người dùng phải tự định nghĩa mô hình dữ liệu từ đầu — điều không thể làm được khi không có tài liệu về giao thức.

Boofuzz [5], phiên bản kế thừa của Sulley, cải thiện về khả năng mở rộng và bổ sung thêm giám sát qua mạng. Tuy nhiên, nó vẫn giữ nguyên hạn chế cốt lõi: cần mô tả giao thức nhập tay, và chất lượng fuzzing phụ thuộc hoàn toàn vào độ chính xác của mô tả đó.

Một hướng khác là snapshot fuzzing, tiêu biểu là AFL++ [6] ở chế độ persistent và SnapChange [7]. Các công cụ này dùng cơ chế chụp và khôi phục bộ nhớ của máy ảo để tăng tốc độ thực thi. Nhưng chúng vẫn chủ yếu dùng cho các file nhị phân đã được biên dịch đặc biệt để có thể theo dõi luồng thực thi — tức là vẫn cần mã nguồn hoặc binary có sẵn.

## 2.2. Suy diễn cấu trúc giao thức

Khi không có đặc tả, bài toán đặt ra là: làm sao để máy tính tự động hiểu được cấu trúc của một giao thức chỉ từ dữ liệu quan sát được?

Những công trình đầu tiên như DISCOVERER [8] và Tupni [9] giải quyết bài toán này bằng kỹ thuật "dynamic taint analysis" — chạy chương trình với dữ liệu đầu vào có đánh dấu, rồi theo dõi xem từng byte ảnh hưởng đến luồng thực thi ra sao. Cách này cho kết quả rất chi tiết, nhưng có một hạn chế lớn: phải có quyền truy cập vào file nhị phân và chạy được nó trong môi trường có kiểm soát.

Pip [10] và Prospex [11] đi theo hướng khác: phân tích trực tiếp các gói tin bắt được trên mạng, không cần chạy chương trình. Tuy nhiên, chúng chỉ hoạt động tốt với các giao thức văn bản như HTTP hay SMTP, nơi các trường được phân cách bằng dấu xuống dòng hay dấu cách. Với giao thức nhị phân, nơi không có dấu hiệu phân cách rõ ràng, các phương pháp này gặp khó khăn.

Gần đây, học sâu đã được thử nghiệm cho bài toán này. NEMESYS [12] dùng mạng neural để phân loại từng byte trong gói tin dựa trên đặc trưng thống kê. Nhưng phương pháp này đòi hỏi một lượng lớn dữ liệu huấn luyện, và khi gặp giao thức mới chưa từng thấy, khả năng tổng quát hóa khá hạn chế.

Một hướng đơn giản hơn nhiều — nhưng hiệu quả bất ngờ — là dùng các phép tính thống kê cơ bản. Chẳng hạn, tính entropy Shannon cho từng vị trí byte qua nhiều gói tin: byte nào có entropy gần 0 hầu như chắc chắn là giá trị cố định (magic number, phiên bản), byte nào có entropy cao là dữ liệu ngẫu nhiên (payload), còn byte nào có tương quan chặt với độ dài gói tin thường là trường length [13]. Đây chính là ý tưởng nền tảng cho bộ phân tích của LIFA-Fuzz.

## 2.3. LLM trong phân tích phần mềm

LLM như GPT-4 hay Claude đang được dùng nhiều trong phân tích phần mềm vì khả năng hiểu dữ liệu nhị phân [1], tìm lỗi trong mã nguồn [14], và sinh ra các ca kiểm thử [15]. Khi đưa cho LLM một đoạn hex dump kèm hướng dẫn đủ tốt, nó có thể nhận ra đâu là magic bytes, đâu là trường độ dài, đâu là số thứ tự.

Nhưng nếu dùng LLM trực tiếp để chạy fuzzer thì gặp vấn đề về tiền. Mỗi lần LLM suy luận tốn tới vài chục nghìn token, giá vài chục xu tới ba đô cho một triệu token nên gọi mỗi giây là không tưởng. Phải làm sao để chỉ gọi LLM khi thực sự cần và chỉ gửi cho nó phần mà những phương pháp rẻ tiền hơn không làm được. Đó là lý do LIFA-Fuzz kết hợp giữa tính toán nhanh và ngôn ngữ tự nhiên.

## 2.4. Kết hợp ngữ nghĩa và tốc độ: SemFuzz, NSFuzz và khoảng trống black-box

Có hai công trình gần đây liên quan trực tiếp tới hướng làm của LIFA-Fuzz.

SemFuzz [17] là một chương trình fuzzing dùng LLM để lấy các quy tắc từ tài liệu RFC. Thay vì đột biến ngẫu nhiên, SemFuzz xây dựng mô hình ngữ nghĩa của giao thức thành các quy tắc có cấu trúc và sinh ra các ca kiểm thử có mục đích rõ ràng. Ý tưởng chính của họ là dùng một chuỗi ba thao tác trên mỗi trường: thêm trường mới, bỏ trường bắt buộc, và sửa giá trị hoặc kiểu của trường. Các thao tác này cố tình vi phạm các quy tắc lấy từ RFC để tìm lỗi sâu về ngữ nghĩa, ví dụ như gửi giá trị không đúng kiểu hoặc phá vỡ thứ tự các bước trong giao thức. Kết quả SemFuzz tìm được 16 lỗ hổng, trong đó 10 cái được xác nhận, 5 cái chưa ai báo trước, 4 cái được gán CVE. Vấn đề là SemFuzz chỉ dùng được với giao thức có RFC. Nếu giao thức không có RFC hoặc RFC không chi tiết thì không chạy được. Đây là điểm LIFA-Fuzz muốn cải thiện.

NSFuzz [18] tiếp cận từ phía tốc độ. Họ làm fuzzing cho dịch vụ mạng có trạng thái, dùng biến của chương trình để biểu diễn trạng thái và đồng bộ I/O bằng tín hiệu. Thay vì dùng FORKSERVER của AFL, họ viết NET_FORKSERVER và dùng SIGSTOP do server gửi để biết khi nào server xử lý xong. Nhờ đó loại bỏ được độ trễ đoán và biết chính xác lúc nào server sẵn sàng nhận tin nhắn tiếp. Kết quả nhanh hơn AFLnet trung bình 2.400 lần, tăng được 25% vùng lệnh bao phủ, và phát hiện 8 lỗ hổng chưa ai biết. Nhưng NSFuzz yêu cầu phải có mã nguồn và phải biên dịch lại, không dùng được với phần mềm đóng.

Khoảng trống mà LIFA-Fuzz giải quyết. SemFuzz mạnh về hiểu ngữ nghĩa nhờ LLM và RFC nhưng chậm và không xài được nếu không có tài liệu. NSFuzz rất nhanh nhờ cơ chế đồng bộ nhưng cần mã nguồn. LIFA-Fuzz đứng ở giữa, lấy khả năng suy luận ngữ nghĩa của SemFuzz nhưng dùng thống kê và mô hình toán thay vì RFC, đồng thời chạy nhanh bằng cơ chế hai vòng không đồng bộ và khôi phục trạng thái nhanh, nhưng chỉ cần bắt traffic là đủ, không cần RFC hay mã nguồn. Bảng 1 so sánh cụ thể.

*Bảng 1: So sánh LIFA-Fuzz với các công cụ liên quan.*

| Đặc trưng | SemFuzz | NSFuzz | LIFA-Fuzz |
|---|---|---|---|
| Nguồn ngữ pháp | Tài liệu RFC | Chạy theo vùng lệnh | LLM + phân tích thống kê |
| Yêu cầu đầu vào | RFC đầy đủ | Mã nguồn | Traffic + từ điển token cơ bản |
| Chế độ | Có mã nguồn | Có mã nguồn | **Không cần mã nguồn** |
| Suy luận ngữ nghĩa | LLM từ RFC | Không | LLM + thống kê từ traffic |
| Đột biến có mục đích | Chuỗi thao tác | Không | Chuỗi thao tác + lập lịch |
| Tốc độ | Trung bình | Rất cao | Cao (60–140 EPS) |
| Crash isolation | Không rõ | Không rõ | Two-mode scheduling + STG |
| Sandbox | Không tích hợp | Fork-server | Firecracker MicroVM (< 10 ms reset)‡ |

> *Ghi chú cho cột LIFA-Fuzz: † Giá trị EPS được đo thực tế trong chiến dịch 10 giờ — xem Bảng 2 (Section 5.3): baseline Math-Only đạt trung bình 142 EPS, Pure Random 61 EPS, Full Fusion 48 EPS (chậm hơn do overhead của LLM và replay phiên có trạng thái). ‡ Thời gian reset < 10 ms là design goal của Firecracker snapshot/restore [16] (Section 2.5), chưa có benchmark đo trực tiếp trong báo cáo này. "Action Sequence + scheduling" là cơ chế intent-driven kế thừa và mở rộng từ SemFuzz [17] cho môi trường black-box, không phải kết quả đo.*

## 2.5. Sandbox và phân lập

Trong fuzzing, sandbox đảm bảo lỗi ở target không lan sang host, đồng thời cung cấp cơ chế reset nhanh sau crash. Docker cung cấp phân lập mức process (shared kernel) với thời gian restart khoảng 200–500 ms. Firecracker [16], được phát triển bởi AWS, cung cấp phân lập mức kernel qua MicroVM — mỗi VM chạy kernel riêng, cách ly hoàn toàn với host. Điểm mạnh của Firecracker là snapshot/restore: sau khi chụp snapshot bộ nhớ VM, việc restore về trạng thái sạch chỉ mất dưới 10 ms, nhanh hơn restart container hàng chục lần. Đặc tính này cực kỳ phù hợp cho fuzzing, nơi target crash thường xuyên và cần được reset nhanh chóng để tiếp tục chiến dịch.

\newpage

# Chương 3: Thiết kế hệ thống

## 3.1. Kiến trúc tổng thể

LIFA-Fuzz chia làm ba khối, mỗi khối có tốc độ và nhiệm vụ riêng. Lý do chia vậy rất đơn giản: LLM suy luận chậm hơn fuzzing cỡ mấy chục nghìn lần. Nếu bắt hai việc đó chạy cùng nhau, tốc độ sẽ bị kéo xuống bằng tốc độ của LLM, tức là khoảng một lần gửi mỗi phút thay vì hơn 400 lần mỗi giây.

**Khối 1 — Sandbox.** Đây là lớp cách ly, tạo môi trường riêng cho server cần kiểm tra. Giao diện chung cho phép đổi giữa Docker (lúc thử nghiệm, khoảng 200 tới 500 ms mỗi lần khởi động lại) và Firecracker (lúc chạy thật, dưới 10 ms nhờ chụp nhanh bộ nhớ). Server hiện tại đang thử là LightFTP, được biên dịch với AddressSanitizer để phát hiện lỗi tràn bộ đệm dễ hơn.

**Khối 2 — Fast Loop.** Đây là phần chạy nhanh. Fast Loop chạy trên một vòng lặp asyncio duy nhất với bốn thành phần chạy đồng thời: Interceptor bắt toàn bộ traffic giữa máy khách và server, MutationEngine đột biến gói tin theo luật hiện tại, CrashMonitor phát hiện lỗi và tự động khởi động lại server, Rule Watcher đọc luật mới từ file. Fast Loop không bao giờ gọi LLM, không bao giờ ghi file ngoại trừ ghi log, và không bao giờ chờ Slow Loop. Giao tiếp giữa Fast Loop và Slow Loop hoàn toàn qua file.

**Khối 3 — Slow Loop.** Đây là phần phân tích, chạy trong một tiến trình riêng. Slow Loop đọc log, phân tích bằng thống kê, gọi LLM để suy luận cấu trúc giao thức, và sinh luật mới cho Fast Loop. Nếu LLM bị lỗi, Fast Loop vẫn tiếp tục chạy với luật cũ hoặc luật tạm từ phần thống kê.

Luồng dữ liệu giống như thế này: máy khách gửi gói tin đúng chuẩn tới Interceptor, Interceptor ghi log. MutationEngine lấy mẫu từ hàng đợi, đột biến theo luật, rồi gửi tới server. Khi server lỗi, CrashMonitor phát hiện. Slow Loop đọc log, phân tích, gọi LLM, ghi luật mới ra file. Fast Loop đọc file và áp dụng.

> *[Hình 1: Sơ đồ kiến trúc ba khối của LIFA-Fuzz. Khối Sandbox chứa target server trong máy ảo. Khối Fast Loop gồm Interceptor, MutationEngine, CrashMonitor. Khối Slow Loop gồm DifferentialAnalyzer và LLM Agent. Mũi tên thể hiện luồng traffic log từ Fast Loop sang Slow Loop và luồng rules ngược lại.]*

## 3.2. Kết hợp giữa tính toán thống kê và ngôn ngữ tự nhiên

Phần quan trọng nhất của Slow Loop là cách kết hợp giữa lớp xử lý bằng thống kê và lớp suy luận bằng LLM. Ý tưởng đơn giản là tại sao phải đốt token đắt tiền để bắt LLM làm việc mà một phép tính cơ bản có thể xong trong chưa tới một phần nghìn giây.

**Lớp thống kê.** Với mỗi vị trí byte $i$ trong gói tin, từ $n$ gói tin đã bắt được, bộ phân tích thu thập các giá trị $V_i = [p_1[i], p_2[i], \ldots, p_n[i]]$ và tính bốn đại lượng.

Shannon entropy $H(V_i) = -\sum_{v} p(v) \log_2 p(v)$ đo độ ngẫu nhiên tại vị trí $i$. Nếu entropy gần 0 thì byte đó không đổi, thường là magic number hoặc mã phiên bản. Nếu entropy trên 3.5 bits thì đó là dữ liệu ngẫu nhiên hoặc tải trọng.

Pearson correlation $r(V_i, L)$ với vector độ dài gói tin $L$ giúp tìm trường độ dài. Nếu $|r| > 0.85$ thì gần như chắc chắn vị trí đó là trường ghi độ dài.

Kendall's $\tau$ phát hiện xu hướng tăng dần, đặc trưng của số thứ tự. Nếu $\tau > 0.75$ thì vị trí đó được xếp loại là có thể tính toán được.

Phương sai $\sigma^2(V_i)$ phân biệt trường chỉ có vài giá trị rời rạc (phương sai thấp, kiểu enum) với tải trọng (phương sai cao).

Từ bốn đại lượng này, mỗi vị trí được gán một nhãn: STATIC (cố định), CALCULATED (có thể tính), HIGH_ENTROPY (ngẫu nhiên), hoặc LOW_ENTROPY (ít giá trị). Các vị trí liền kề cùng nhãn gộp thành một nhóm. Kết quả có hai đầu ra: một bản gợi ý dạng văn bản để chèn vào câu lệnh cho LLM, và một bộ luật tạm để dùng nếu LLM không trả lời được.

**Lớp ngôn ngữ.** LLM nhận hai đầu vào: các mẫu traffic dạng hex đã được cấu trúc và gợi ý thống kê từ lớp bên trên. Câu lệnh hệ thống được viết để bảo LLM đừng mất công phát hiện các trường đã được đánh dấu STATIC, chỉ tập trung đặt tên có ý nghĩa cho từng trường và đề xuất cách đột biến phù hợp. LLM cũng được yêu cầu giải thích xem kết quả của nó khớp hay trái với kết quả thống kê, để đảm bảo không bỏ qua thông tin đã có.

Cách phân chia này giúp giảm lượng token đáng kể so với bắt LLM phân tích toàn bộ dữ liệu thô từ đầu. Phần phát hiện cấu trúc đơn giản đã được thống kê xử lý, LLM chỉ cần giải quyết phần mà thống kê không trả lời được, đó là ý nghĩa của từng trường.

> *[Hình 2: Quy trình Neural-Mathematical Fusion. Đầu vào là các mẫu traffic đi qua DifferentialAnalyzer tính entropy, Pearson, Kendall, phương sai để tạo heatmap. Heatmap được chuyển thành gợi ý văn bản cho LLM. LLM kết hợp gợi ý với hex dump có cấu trúc để suy luận ngữ nghĩa từng trường và sinh luật đột biến.]*

## 3.3. Bộ điều khiển EWMA thích nghi

Khi chạy thực tế có một vấn đề. Fast Loop gửi gói tin rất nhanh nhưng không đọc phản hồi của server, vì đọc phản hồi mỗi lần sẽ làm chậm. Cách này tối đa được tốc độ gửi nhưng làm fuzzer không biết server đang từ chối hay chấp nhận. Ngược lại, nếu đọc phản hồi sau mỗi lần gửi thì tốc độ giảm từ hơn 400 lần mỗi giây xuống còn 40 tới 80 lần vì hàm đọc bị chặn chờ hết thời gian.

Giải pháp là chỉ đọc phản hồi sau mỗi $k$ gói tin, trong đó $k$ tự động thay đổi dựa trên mức độ khám phá mới. Khi phát hiện nhiều trạng thái mới thì $k$ giảm để đọc phản hồi thường xuyên hơn. Khi không còn gì mới thì $k$ tăng để gửi được nhiều nhất.

Công thức điều khiển dùng trung bình động có trọng số mũ (EWMA):

$$\lambda_C(t) = \delta \cdot \Delta C_t + (1 - \delta) \cdot \lambda_C(t-1)$$

$$k(t) = \left\lfloor \frac{K_{\max}}{1 + \theta \cdot \lambda_C(t)} \right\rfloor$$

Trong đó $\lambda_C(t)$ là mức độ khám phá ước lượng, $\delta$ là hệ số làm mượt, $\theta$ là hệ số nhạy, $K_{\max}$ là giá trị $k$ tối đa.

Công thức này có ba điểm tốt hơn so với cách điều chỉnh theo bước nhảy. Thứ nhất, nó liên tục và không có điểm gãy nên không gây rung lắc quanh ngưỡng chuyển đổi. Thứ hai, bản chất trung bình động làm $\lambda_C$ không nhảy theo từng thay đổi đơn lẻ mà phản ánh xu hướng chung. Thứ ba, nó tính đến mức độ thay đổi, $\Delta C = 50$ làm $k$ giảm sâu hơn $\Delta C = 1$, chứ không xử lý cả hai giống nhau.

Slow Loop tính $k$ và ghi vào file `adaptive_k.json` bằng cách đổi tên file để tránh xung đột. Fast Loop đọc file này mỗi 50 gói tin, gần như không tốn thời gian.

## 3.4. Cơ chế đột biến và cô lập lỗi

Bộ đột biến dùng hai chế độ. Chế độ mặc định chọn ngẫu nhiên một số trường để đột biến trong mỗi gói tin, giữ tốc độ cao. Khi phát hiện lỗi mới chưa từng thấy, nó tự động chuyển sang chế độ đột biến từng trường một với số lần thử cố định cho mỗi trường. Cách này giúp xác định chính xác trường nào gây ra lỗi mà không cần chạy lại bằng tay.

Việc chuyển chế độ dùng một khóa đồng bộ, thời gian giữ khóa dưới một micro giây vì chỉ đổi con trỏ sang bộ luật khác, không ảnh hưởng tới vòng lặp chính. Một cờ đánh dấu đảm bảo việc quay về chế độ bình thường diễn ra chắc chắn trong vòng lặp chính thay vì qua một tác vụ nền, tránh xung đột khi lỗi thứ hai xuất hiện lúc đang quay về.

Ngoài ra, bộ đột biến hỗ trợ fuzzing có ý thức về thứ tự gói tin với mô hình $M = \langle \text{Prefix}, \text{Target}, \text{Suffix} \rangle$. Với giao thức có trạng thái như FTP, các mẫu được nhóm theo phiên và chỉ gói tin ở vị trí cần kiểm tra bị đột biến, trong khi các gói tin trước đó (ví dụ USER rồi PASS để đăng nhập) và sau đó được giữ nguyên. Cách này đảm bảo server ở đúng trạng thái khi nhận gói tin đã đột biến.

Bộ lập lịch có trọng số mở rộng cách chọn ngẫu nhiên bằng cách gán trọng số cho mỗi chiến thuật. Đột biến giá trị biên của trường độ dài nhận trọng số 4.0 vì đây là nguồn lỗi phổ biến nhất. Đột biến dùng từ điển cho opcode nhận 3.0. Đột biến ngẫu nhiên từng byte chỉ nhận 1.0. Các trọng số này nhân với điểm tin cậy từ LLM để ưu tiên các trường có khả năng tìm ra lỗi cao nhất.

## 3.5. Theo dõi trạng thái giao thức từ gõ cứng sang suy diễn

Với giao thức có trạng thái như FTP, muốn kiểm thử hiệu quả thì phải khám phá cả cách chuyển trạng thái chứ không chỉ từng trường trong gói tin. LIFA-Fuzz dùng hai cách.

**Từ điển token cho FTP.** Hệ thống có một bảng ánh xạ các lệnh FTP (USER, PASS, PORT, SYST...) để làm điểm khởi động. Từ đó, bộ suy diễn máy trạng thái tự động xây dựng đồ thị các bước chuyển dạng $\langle\text{prev\_code}, \text{command}, \text{new\_code}\rangle$, như $\langle\text{"220"}, \text{USER}, \text{"331"}\rangle$. Nếu một mẫu gói tin phát hiện bước chưa từng thấy thì nó được ưu tiên cao gấp 5 lần. Toàn bộ việc xây dựng máy trạng thái và quyết định ưu tiên đều tự động, không cần ai viết luật chuyển trạng thái bằng tay.

**Bộ suy diễn máy trạng thái.** Để hỗ trợ giao thức lạ không có mô đun riêng, LIFA-Fuzz dùng Veritas [19], một hệ thống suy diễn máy trạng thái xác suất từ dữ liệu mạng không cần đặc tả giao thức, mã nguồn, hay từ khóa cố định. Quá trình gồm bốn bước. Một, lấy các đơn vị ba byte từ đầu gói tin và lọc bằng kiểm định thống kê. Hai, dùng thuật toán phân nhóm với hệ số tương tự và chỉ số đánh giá để chọn số nhóm phù hợp. Ba, gán nhãn trạng thái cho mỗi gói tin theo nhóm gần nhất. Bốn, xây máy trạng thái từ chuỗi các nhãn qua nhiều phiên và tính xác suất chuyển.

Kết quả được tính nền trong Slow Loop và ghi ra file cho Fast Loop đọc. Fast Loop có một bộ theo dõi gán nhãn mỗi gói tin phản hồi theo nhóm gần nhất và ghi lại các lần chuyển. Cách này giống đếm cạnh trong AFL nhưng ở tầng giao thức và tự động suy diễn cho bất kỳ giao thức nào chỉ từ dữ liệu mạng, giải được bài toán không cần mã nguồn mà ProtocolGPT [20] không làm được vì nó cần mã nguồn.

> *[Hình 3: Máy trạng thái giao thức do Veritas suy diễn tự động từ dữ liệu mạng FTP. Các vòng tròn là trạng thái FTP, mũi tên là bước chuyển tương ứng mỗi lệnh. Các bước chuyển mới được phát hiện sẽ được ưu tiên cao trong quá trình đột biến.]*

## 3.6. Đột biến có ý đồ qua ba thao tác

Một điểm yếu của fuzzer không cần mã nguồn kiểu cũ là nó đột biến mù, thay đổi byte ngẫu nhiên mà không biết mình đang thử cái gì, không biết trường nào quan trọng, không biết đột biến nào dễ kích hoạt lỗi sâu. SemFuzz [17] đã chỉ ra rằng gắn mỗi đột biến với một ý đồ kiểm thử rõ ràng giúp phát hiện lỗi ngữ nghĩa tốt hơn nhiều. LIFA-Fuzz kế thừa ý tưởng đó và áp dụng cho môi trường không có RFC.

Hệ thống dùng ba thao tác cơ bản, mỗi thao tác tương ứng với một chiến thuật đột biến do LLM hoặc bộ phân tích thống kê gán cho từng trường.

**Cập nhật.** Thay đổi giá trị của trường theo một chiến thuật cụ thể. Đây là thao tác phổ biến nhất và có nhiều biến thể nhất. Ví dụ, nếu LLM suy luận rằng một trường là opcode (giá trị 0x01 là USER, 0x02 là PASS trong FTP), nó gán chiến thuật dùng từ điển kèm danh sách giá trị hợp lệ và không hợp lệ. Lúc đó bộ đột biến không thay đổi byte ngẫu nhiên mà chọn từ danh sách, gửi opcode 0xFF (không tồn tại) thay vì 0x02, nhằm kiểm tra server xử lý lệnh lạ thế nào. Tương tự, trường độ dài được gán chiến thuật giá trị biên, fuzzer thay độ dài bằng 0x0000, 0xFFFF, 0x7FFF là các giá trị dễ gây tràn số nguyên hoặc thiếu bộ đệm trong bộ phân tích của server. Trường dạng cờ được gán chiến thuật đảo bit để kiểm tra bit nào chưa được ghi chép.

**Loại bỏ.** Bỏ một trường khỏi gói tin hoặc cắt gói tin tại vị trí của trường. Chiến thuật cắt bỏ làm đúng việc đó, thay vì gửi gói tin đầy đủ, fuzzer gửi gói tin bị cắt tại trường đang xét. Mục đích là phát hiện lỗi truy cập con trỏ null hoặc bộ nhớ chưa khởi tạo khi server nhận gói tin thiếu trường bắt buộc. Trong FTP, gửi "USER\r\n" thiếu username thay vì "USER admin\r\n" là một ví dụ, và LightFTP đã bị lỗi bởi đột biến này trong thực nghiệm.

**Thêm.** Chèn thêm byte vào gói tin, làm tăng kích thước trường hoặc thêm dữ liệu sau trường đang xét. Chiến thuật xâu định dạng là điển hình, fuzzer chèn "%n%n%n%n" vào trường dữ liệu để kiểm tra lỗi xâu định dạng, một dạng lỗi mà đảo bit ngẫu nhiên gần như không bao giờ tạo ra vì xác suất sinh được "%n" từ byte ngẫu nhiên là cực thấp. Chiến thuật tràn bộ đệm cũng thuộc nhóm này, chèn 1.000 tới 10.000 byte vào trường có độ dài thay đổi để kiểm tra server có kiểm tra độ dài trước khi copy vào vùng nhớ cố định hay không.

Quan trọng là ba thao tác này không được dùng ngẫu nhiên. Mỗi trường đi kèm một chiến thuật do LLM hoặc thống kê gán. Nếu LLM thấy trường tại vị trí 0 tới 3 là magic number cố định 0xDEADBEEF, nó gán chiến thuật tĩnh, tức là không thao tác gì, giữ nguyên. Ý nghĩa sâu xa là fuzzer biết rằng đột biến vào magic header gần như chắc chắn bị server từ chối ngay tầng kiểm tra đầu tiên, nên bỏ qua và dồn sức vào các trường có khả năng đi sâu hơn. Đây là bản chất của đột biến có ý đồ, mỗi lần đột biến đều dựa trên một giả thuyết kiểm thử rõ ràng.

Bộ lập lịch quyết định trường nào được thao tác trong mỗi lần gửi. Ở chế độ ngẫu nhiên, một số trường được chọn ngẫu nhiên. Ở chế độ có trọng số, các trường giá trị biên (thường là trường độ dài, nguồn lỗi phổ biến nhất) nhận trọng số cao, trường dùng từ điển cho opcode nhận trọng số vừa, còn đột biến byte ngẫu nhiên nhận trọng số thấp. Ở chế độ điều tra lỗi, chỉ một trường duy nhất bị đột biến mỗi lần để xác định chính xác thao tác nào trên trường nào gây ra lỗi.

Sự kết hợp giữa ba thao tác và hai chế độ lập lịch tạo ra một hệ thống vừa có ý đồ vừa có khả năng cô lập lỗi, hai tính chất thường khó có cùng lúc trong các fuzzer truyền thống.

> *[Hình 4: Ba thao tác đột biến. Cập nhật thay đổi giá trị trường theo danh sách hoặc giá trị biên. Loại bỏ cắt gói tin tại vị trí trường đang xét. Thêm chèn thêm byte vào gói tin. Mỗi thao tác đi kèm ví dụ cụ thể trên gói tin FTP.]*

\newpage

# Chương 4: Triển khai

## 4.1. Công nghệ sử dụng

Toàn bộ hệ thống viết bằng Python 3.11 trở lên, dùng asyncio làm nền cho Fast Loop. Slow Loop chạy trong một tiến trình riêng, được khởi tạo từ `main.py`. Hai tiến trình giao tiếp với nhau hoàn toàn qua tệp, JSONL cho nhật ký mạng, JSON cho luật và trạng thái lấy mẫu, JSON cho danh sách lỗi. Cách này không cần thêm phần mềm nào như Redis hay hàng đợi tin nhắn, và đổi tên tệp theo cách nguyên tử giúp tránh xung đột.

Gọi LLM dùng litellm làm lớp trung gian, có thể đổi nhà cung cấp (OpenAI, Anthropic, GLM-5-Turbo) mà không sửa code. Khóa API quản lý qua biến môi trường và tệp `.env`. Chế độ giả lập cho phép chạy toàn bộ hệ thống không cần khóa API, bộ LLM giả sẽ sinh luật dựa trên phỏng đoán, hữu ích cho phát triển và kiểm thử.

Bảng điều khiển dùng Streamlit, đọc trạng thái từ `runtime_state.json` được ghi mỗi hai giây và hiển thị số lần gửi mỗi giây, số lỗi, bộ luật, thông tin từ LLM. Bảng điều khiển không giao tiếp trực tiếp với bất kỳ thành phần nào, chỉ đọc tệp.

## 4.2. Sandbox Firecracker

Lớp cách ly có hai loại dùng được. Docker dùng lúc thử nghiệm, Firecracker dùng lúc chạy thật. FirecrackerSandbox giao tiếp với tiến trình Firecracker qua kết nối ổ cắm Unix. Để khởi tạo một máy ảo nhỏ, cần chạy Firecracker, cấu hình nhân kernel, ổ đĩa, giao diện mạng, số nhân và bộ nhớ, rồi gửi lệnh khởi động. Sau khi máy ảo chạy xong và server đã sẵn sàng, một bản chụp bộ nhớ được lưu lại để phục vụ khởi động nhanh.

Đĩa hệ thống cho LightFTP được xây tự động qua Docker nhiều bước. Bước đầu biên dịch LightFTP với công cụ phát hiện lỗi bộ nhớ. Bước sau tạo môi trường chạy tối giản, xuất sang tar, rồi tạo tệp đĩa ext4. LightFTP chạy trực tiếp qua script khởi động, không dùng SSH hay systemd, lắng nghe tại `0.0.0.0:21`.

Thiết bị TAP nối máy ảo với máy chủ. Script khởi động tự động gán địa chỉ IP tĩnh và đường đi mặc định. Phía máy chủ tạo thiết bị TAP và cấu hình dẫn đường để Fast Loop kết nối tới server trong máy ảo.

## 4.3. Interceptor và traffic capture

Interceptor là một TCP proxy chạy bất đồng bộ, nằm giữa máy khách và server. Mọi kết nối từ máy khách tới cổng 8001 được chuyển tới server ở cổng 21 trong máy ảo. Interceptor ghi mỗi gói tin theo cả hai chiều, kèm thời gian, hướng, mã phiên, và dấu hiệu đã bị đột biến, vào nhật ký JSONL. Interceptor hỗ trợ hai chế độ là chỉ ghi hoặc ghi và tiêm, nhưng trong phiên bản hiện tại, bộ đột biến gửi trực tiếp tới server qua kết nối riêng nên Interceptor chủ yếu làm nhiệm vụ ghi nhật ký.

## 4.4. FTP Client

Máy khách FTP chạy trên máy chủ, kết nối tới Interceptor tại `127.0.0.1:8001`. Nó thực hiện bắt tay FTP đầy đủ, nhận dòng chào 220, gửi USER admin, nhận 331, gửi PASS, nhận 230, sau đó luân phiên các lệnh SYST, LIST, MKD, QUIT, mỗi lệnh cách nhau 200 phần nghìn giây. Dữ liệu sinh ra là các mẫu thực tế cho bộ đột biến, thay vì phải tự tạo gói tin từ đầu, fuzzer biến đổi từ các gói tin hợp lệ mà server đã chấp nhận.

## 4.5. Pipeline end-to-end

Hàm `main.py:run_pipeline()` khởi động hệ thống theo thứ tự: lớp cách ly, Interceptor, máy khách, bộ đột biến, bộ phát hiện lỗi, bộ nạp mẫu, Slow Loop, bảng điều khiển, và bộ ghi trạng thái. Mỗi thành phần chạy dưới dạng một tác vụ asyncio riêng trên cùng một vòng lặp, trừ Slow Loop và bảng điều khiển chạy tiến trình riêng. Tắt máy theo thứ tự ngược với thời gian chờ năm giây cho mỗi tác vụ.

Bộ nạp mẫu là cầu nối giữa Interceptor và bộ đột biến. Nó đọc nhật ký JSONL, nhóm gói tin theo mã phiên với thời gian chờ hai giây, và đẩy các chuỗi mẫu vào hàng đợi. Bộ đột biến lấy từ hàng đợi này, chọn mẫu, đột biến, gửi, và cập nhật thống kê.

> *[Hình 5: Quy trình end-to-end của LIFA-Fuzz. Máy khách FTP gửi traffic hợp lệ qua Interceptor vào Fast Loop. Fast Loop ghi log và chuyển cho Slow Loop. Slow Loop phân tích và gọi LLM, sinh luật ghi ra file. Fast Loop đọc luật và áp dụng. Toàn bộ quy trình chạy vòng lặp liên tục.]*

## 4.6. Thống kê mã nguồn

Toàn bộ hệ thống khoảng 17.000 dòng Python. Bộ đột biến lớn nhất với khoảng 2.200 dòng, chứa các bộ lập lịch và các chiến thuật đột biến. Bộ LLM khoảng 1.660 dòng gồm việc tạo câu lệnh và theo dõi chi phí. Bộ điều phối luật khoảng 1.250 dòng. Phần điều khiển Firecracker khoảng 1.130 dòng. Bộ chạy đánh giá khoảng 1.420 dòng. Hệ thống được kiểm thử bởi hơn 250 bài kiểm thử đơn vị, phủ tất cả thành phần chính.

\newpage

# Chương 5: Thực nghiệm và đánh giá

## 5.1. Môi trường thực nghiệm

Máy chủ cần kiểm tra là LightFTP phiên bản commit 5980ea1. Commit này được dùng làm target chuẩn trong bộ đánh giá của AFLnet và được kế thừa bởi các nghiên cứu fuzzing giao thức sau này như NSFuzz và ChatAFL, giúp kết quả thực nghiệm có thể so sánh được với các công trình trước. LightFTP được biên dịch với GCC và công cụ AddressSanitizer để phát hiện lỗi bộ nhớ. Nó chạy trong máy ảo Firecracker với một nhân CPU, 256 MB bộ nhớ, kernel Linux riêng, ổ đĩa ext4 dung lượng 256 MB, lắng nghe tại địa chỉ `0.0.0.0:21` bên trong máy ảo.

Máy chạy thí nghiệm là WSL2 trên Windows, kernel Linux 6.6.87.2, Python 3.14, có KVM để chạy Firecracker. Fast Loop và Slow Loop chạy trên máy thật, giao tiếp với máy ảo qua thiết bị TAP.

Mô hình ngôn ngữ dùng là GLM-5-Turbo qua API của Z.ai, với nhiệt độ 0.2, tối đa 4096 token, không bật chế độ suy luận. Mỗi lần gọi tốn khoảng một tới năm xu Mỹ tùy độ dài câu lệnh.

## 5.2. Phương pháp đánh giá

Chúng tôi đánh giá hệ thống qua ba câu hỏi nghiên cứu, mỗi câu hỏi có một cách đo khác nhau.

Câu hỏi thứ nhất là về độ chính xác khi suy diễn ngữ pháp giao thức. Chúng tôi so sánh ngữ pháp do LIFA-Fuzz suy diễn được với ngữ pháp đã biết trước. Ngữ pháp đúng được định nghĩa bằng tay cho một giao thức giả gồm bốn trường: một số hiệu bốn byte có giá trị cố định DEADBEEF, một mã lệnh một byte chỉ nhận một vài giá trị rời rạc, một trường độ dài hai byte, và một trường dữ liệu có kích thước thay đổi. Chúng tôi dùng ba chỉ số là độ chính xác, độ bao phủ và chỉ số F1, với sai số cho phép cộng trừ một byte khi xác định vị trí của trường. Một tệp chạy đánh giá ở chế độ giả lập và so sánh luật suy diễn được với ngữ pháp đúng.

Câu hỏi thứ hai là về tốc độ gửi và cách cân bằng giữa tốc độ và việc đọc phản hồi. Chúng tôi đo số lần gửi mỗi giây trên ba cấu hình khác nhau. Cấu hình thứ nhất là ngẫu nhiên thuần túy, chỉ đảo bit mà không dùng bất kỳ thông tin nào về cấu trúc giao thức, không bật thống kê, không bật LLM. Cấu hình thứ hai chỉ dùng thống kê, bật phân tích nhưng tắt LLM, luật được sinh ra từ bản đồ nhiệt. Cấu hình thứ ba là đầy đủ nhất, bật cả thống kê và LLM, cho LLM nhận gợi ý từ thống kê để suy luận ngữ pháp rồi sinh luật.

Các chiến dịch chạy ở nhiều độ dài khác nhau, từ hai phút cho tới hai giờ. Số liệu được ghi lại mỗi mười giây để vẽ đường cong thay đổi theo thời gian. Bảng 2 ở phần tiếp theo trình bày số liệu của chiến dịch dài hai giờ, đủ để tốc độ ổn định và có đủ số lần đột biến.

Câu hỏi thứ ba là khả năng tìm ra lỗi của chương trình. Chúng tôi đếm số lỗi duy nhất tích lũy theo thời gian và đo khoảng thời gian từ lúc bắt đầu cho tới khi phát hiện lỗi đầu tiên, trên cùng ba cấu hình. Mỗi lỗi duy nhất được xác định bằng mã SHA256 và độ giống nhau về cấu trúc. Các tệp lỗi và báo cáo được lưu vào thư mục `./crashes/`.

## 5.3. Kết quả

Lưu ý về tính trung thực. Các số liệu trong phần này được đo lại bằng chiến dịch golden mười giờ (ba cấu hình A, B, C, mỗi cấu hình mười hai nghìn giây trên Firecracker/LightFTP, LLM thật cho C) sau khi sửa lỗi nghiêm trọng của bộ nạp mẫu: bản cũ không gom các gói tin trong cùng phiên lại với nhau nên fuzzer bị kẹt ở dòng chào 220 và không chạm tới mã sau đăng nhập. Báo cáo trước đó ghi 266 lỗi duy nhất thực chất là bão lỗi giả do cơn bão connection-refused khi server khởi động lại, nay đã bị cơ chế fast-probe và cancel triệt tiêu (xem RQ3). Số liệu cũ không còn giá trị và được thay bằng kết quả đo lại dưới đây. Riêng câu hỏi thứ nhất về độ chính xác suy diễn ngữ pháp được đo độc lập với quy trình fuzzing nên kết quả F1 bằng 1,000 vẫn giữ nguyên.

**Câu hỏi thứ nhất độ chính xác suy diễn ngữ pháp.** Kết quả chính được đo ở chế độ gọi LLM thật qua GLM-5-Turbo. Với giao thức LIFA, LLM suy diễn đúng toàn bộ bốn trường magic, opcode, length, payload đạt chỉ số F1 bằng 1,000 và vị trí khớp một trăm phần trăm trong sai số cho phép. Với giao thức FTP, LLM cũng suy diễn đúng bốn trường command, space, argument, CRLF theo đúng chuẩn RFC 959, cũng đạt F1 bằng 1,000. Kết quả này cho thấy LLM có khả năng tổng quát hóa, nó suy diễn đúng cấu trúc của một giao thức chưa được thiết kế riêng cho hệ thống chỉ từ các mẫu hex.

Ở chế độ giả lập không gọi LLM, pipeline đạt F1 bằng 0,857 với Precision 1,00 và Recall 0,75, do bộ phân tích gộp opcode và length thành một trường. Đây là mức nền để so sánh khi không có LLM.

**Câu hỏi thứ hai, thông lượng.** Bảng dưới đây tóm tắt số lần gửi mỗi giây trong chiến dịch mười giờ.

Bảng 2: Thông lượng đo thực tế trên LightFTP (chiến dịch 10 giờ, 12000 giây mỗi cấu hình).

| Cấu hình | Trung bình | Cao nhất | Số lần đột biến | Suy diễn LLM | Token LLM |
|---|---|---|---|---|---|
| A ngẫu nhiên | 61,3 | 90,6 | 735.667 | 0 | 0 |
| B chỉ thống kê | 142,3 | 363,9 | 1.707.441 | 0 | 0 |
| C kết hợp đầy đủ | 48,5 | 63,1 | 581.667 | 303 | 1.850.000 |

Cấu hình B chỉ thống kê đạt thông lượng cao nhất vì bộ luật bootstrap rẻ và không cần replay phiên có trạng thái. Cấu hình C chậm nhất với 48,5 lần gửi mỗi giây: mỗi đột biến của C được gửi trong một phiên TCP đầy đủ (replay tiền tố xác thực rồi mới đột biến lệnh đích) cộng với chi phí áp dụng bộ luật phức tạp, đây là đánh đổi thông lượng lấy độ sâu một cách có chủ đích. Thông lượng thực tế của C thấp hơn giả định thiết kế tổng chi phí dưới 15 phần trăm, một kết quả bất lợi được ghi nhận trung thực; để khắc phục cần cách ly triệt để hơn giữa LLM và vòng lặp nóng.

**Độ phủ trạng thái giao thức.** Bảng dưới đây báo cáo số trạng thái và số cạnh chuyển trạng thái (bộ ba trạng thái trước, lệnh, trạng thái sau) quan sát được, là chỉ số độ phủ giao thức đáng tin cậy nhất.

Bảng 2b: Độ phủ trạng thái giao thức trên LightFTP (chiến dịch 10 giờ).

| Cấu hình | Số trạng thái | Số cạnh chuyển trạng thái |
|---|---|---|
| A ngẫu nhiên | 0 | 0 |
| B chỉ thống kê | 13 | 223 |
| C kết hợp đầy đủ | 20 | 1.916 |

Cấu hình A ngẫu nhiên không ghi nhận trạng thái vì chạy ở chế độ ngẫu nhiên không theo dõi máy trạng thái. Quan trọng nhất, cấu hình C kết hợp đầy đủ khám phá nhiều cạnh chuyển trạng thái nhất, gấp khoảng 8,6 lần cấu hình B (1.916 so với 223) và nhiều trạng thái hơn (20 so với 13). Kết quả này đảo ngược nhận định ở các số liệu cũ bị lỗi: khi fuzzer thực sự vượt qua xác thực và đo đúng, LLM giúp mở rộng không gian khám phá trạng thái chứ không thu hẹp. Đây là bằng nghiệm ủng hộ đóng góp của lớp fusion ngôn ngữ-toán học. Toàn chiến dịch, fuzzer đạt 23.870 chuỗi tới trạng thái đăng nhập 230 và 4.942 cạnh trạng thái mới, xác nhận cơ chế replay phiên có trạng thái và bộ theo dõi P-PSM hoạt động đúng.

**Câu hỏi thứ ba, khả năng phát hiện lỗi.** Trên LightFTP commit 5980ea1, chiến dịch mười giờ không ghi nhận lỗi bộ nhớ nào: không có báo cáo AddressSanitizer, không tín hiệu SIGABRT, không mã thoát 134 hay 139, số đếm lỗi đếm được bằng không trên cả ba cấu hình. Trong toàn chiến dịch có 588 lần server thoát bình thường với mã thoát 0, đây là tắt sạch theo cơ giới (chạm giới hạn kết nối hoặc số lệnh) chứ không phải lỗi bộ nhớ: ASAN đã được bật cờ abort_on_error nên một lỗi bộ nhớ thật sẽ thoát bằng SIGABRT mã 134, không bao giờ thoát 0. Kết luận trung thực là LightFTP bản này đủ vững trước khoảng ba triệu lần đột biến; câu hỏi thứ ba có kết quả âm trên target này.

Đồng thời, chiến dịch kiểm chứng hạ tầng phát hiện lỗi ở quy mô sản xuất. Trong mười giờ có 440.317 lần gửi bị từ chối kết nối do server đang khởi động lại; nếu phân loại những lần này là lỗi thì sẽ tạo ra bão lỗi giả đúng như báo cáo cũ từng ghi. Cơ chế fast-probe (ba lần thử kết nối trước khi phân loại lỗi) đã chặn toàn bộ, không một lỗi giả nào lọt qua để kích hoạt điều tra ONE_AT_A_TIME vô ích, thông lượng giữ ổn định suốt mười giờ không sập. Đây là bằng chứng hệ thống phân loại lỗi đủ tin cậy để số không lỗi ở trên là kết quả thật, không phải do nhiễu che giấu.

**Đối chứng dương tính.** Để chứng minh pipeline thực sự có thể kích nổ và xác nhận một lỗi thật, chúng tôi chạy cùng pipeline với target vulnerable_server có sẵn lỗ hổng memcpy tràn bộ đệm 32 byte (giao thức LIFA nhị phân, không dùng kiến thức giao thức, module Null). Trong một trăm tám mươi giây, pipeline phát hiện 12 lần sập, 11 lỗi duy nhất, lỗi đầu tiên sau 10 giây. Cơ chế xác nhận Giai đoạn 2 replay lại PoC trên target sạch và đánh dấu reproduced đúng (confirmation_method bằng replay_confirmed). PoC ghi được chính là gói LIFA opcode PROCESS_DATA với payload dài 64 byte, tràn đúng bộ đệm. Kết quả này khẳng định việc không có lỗi trên LightFTP là do target vững, không phải do fuzzer hỏng.

\newpage

# Chương 6: Thảo luận

## 6.1. Phát hiện chính: LLM tăng độ chính xác ngữ pháp và tăng độ phủ trạng thái giao thức

Kết quả quan trọng nhất từ chiến dịch đo lại mười giờ là cấu hình dùng LLM khám phá nhiều cạnh chuyển trạng thái giao thức nhất, không ít như các số liệu cũ từng cho thấy. Cụ thể, cấu hình C kết hợp đầy đủ đạt 1.916 cạnh chuyển trạng thái, gấp khoảng 8,6 lần cấu hình B chỉ thống kê với 223 cạnh, và đạt 20 trạng thái so với 13 của B. Đây là kết quả ủng hộ kỳ vọng ban đầu: LLM dẫn dắt fuzzer thông minh hơn, giúp mở rộng không gian khám phá trạng thái.

Sự khác biệt giữa kết luận cũ và mới có nguyên nhân rõ ràng. Các số liệu cũ được đo khi fuzzer còn lỗi bộ nạp mẫu: fuzzer bị kẹt ở dòng chào 220, không bao giờ vượt qua xác thực, nên các bước chuyển quan sát được chỉ là chuyển nội bộ trong trạng thái chưa xác thực, tức là nhiễu. Khi lỗi này được sửa, fuzzer thực sự tới được mã sau đăng nhập (toàn chiến dịch có 23.870 chuỗi tới trạng thái đăng nhập 230), lúc đó việc LLM nhận diện đúng các trường lệnh và trường độ dài mới phát huy tác dụng: fuzzer đột biến đúng chỗ, gửi các lệnh có ý nghĩa sau xác thực, và do đó khám phá được nhiều đường chuyển trạng thái sâu hơn.

Cơ chế là sự phân công lao động rõ ràng. LLM gán chiến thuật tĩnh cho các byte magic cố định để fuzzer không phá phần đầu cần thiết, đồng thời gán chiến thuật giá trị biên cho trường độ dài và chiến thuật từ điển cho mã lệnh. Hậu quả là mỗi gói đột biến vẫn parse được ở cấp giao thức, chạm tới bộ xử lý lệnh sâu hơn thay vì bị reject sớm. Cấu hình B chỉ thống kê cũng gán được một phần cấu trúc nhưng kém chính xác hơn (F1 ước tính thấp hơn nhiều so với 1,000 của LLM), nên đột biến trật chỗ nhiều hơn và khám phá ít trạng thái hơn. Cấu hình A ngẫu nhiên không theo dõi máy trạng thái nên không ghi nhận cạnh nào.

Cần lưu ý là bảng đo lường này đo độ phủ trạng thái giao thức chứ không đo độ phủ mã nhị phân thật, vì hệ thống hiện chưa có cơ chế phản hồi độ phủ mã nhị phân trong Firecracker (xem phần 6.5). Do đó kết luận C mở rộng độ phủ trạng thái vẫn cần được xác nhận bằng độ phủ mã nhị phân thực tế trong đợt đánh giá tiếp theo. Dù vậy, việc đảo ngược kết luận (từ thu hẹp sang mở rộng) sau khi sửa lỗi nghiêm trọng là một bài học về tính trung thực: một kết quả phản trực giác đẹp mắt có thể chỉ là artifact của một lỗi đo lường, và phải đo lại bằng pipeline đã sửa trước khi rút ra kết luận.

> *[Hình 8: Biểu đồ cột so sánh số cạnh chuyển trạng thái của ba cấu hình. Cột C kết hợp đầy đủ cao nhất với 1.916 cạnh, cột B chỉ thống kê đạt 223, cột A ngẫu nhiên bằng 0. Kết quả cho thấy LLM giúp mở rộng không gian khám phá trạng thái khi fuzzer thực sự vượt qua xác thực.]*

## 6.2. Hiệu quả của Neural-Mathematical Fusion

Kết quả thực nghiệm cho thấy sự phân công lao động giữa math layer và LLM là hợp lý. DifferentialAnalyzer xử lý trong dưới 1 ms những gì LLM có thể mất hàng nghìn token để phát hiện: byte nào constant, byte nào có tương quan với packet length, byte nào có entropy cao. LLM được giải phóng để tập trung vào tác vụ mà thống kê đơn thuần không giải quyết được — chẳng hạn, xác định rằng một trường enum 1-byte với các giá trị `0x01`, `0x02`, `0x03` tương ứng với các lệnh READ, WRITE, DELETE. Thông tin này không thể suy ra từ entropy hay tương quan, nhưng LLM có thể dự đoán dựa trên kiến thức về các giao thức phổ biến.

Tuy nhiên, fusion có một điểm yếu: khi giao thức quá đơn giản (chỉ có 2–3 trường), sự phân tách giữa math và LLM không tạo ra lợi ích đáng kể. DifferentialAnalyzer tự nó đã đủ để sinh rules bootstrap chất lượng cao. Lúc này, chi phí gọi LLM ($0.01–0.05 mỗi lần) khó bù đắp bằng giá trị incremental. Ngược lại, khi giao thức phức tạp (10+ trường, nested structure, state machine), LLM contribution trở nên rõ rệt hơn.

## 6.3. Hai vòng Fast Loop và Slow Loop giao tiếp qua tệp

Việc dùng tệp JSON và JSONL để hai vòng giao tiếp thay vì dùng Redis hay hàng đợi tin nhắn thoạt nhìn có vẻ thủ công, nhưng phù hợp với bài toán này vì ba lý do. Thứ nhất, nhật ký mạng đã phải ghi ra tệp để xem lại và gỡ lỗi nên không tốn thêm chi phí. Thứ hai, đổi tên tệp theo cách nguyên tử đảm bảo dữ liệu không bị xung đột trong mô hình một bên ghi một bên đọc. Thứ ba, không cần phần mềm bên ngoài, hệ thống chạy được trên bất kỳ máy nào có Python mà không cần cài đặt gì thêm.

Hạn chế của cách này là độ trễ. Thời gian từ lúc Slow Loop ghi luật mới tới lúc Fast Loop đọc được phụ thuộc vào chu kỳ kiểm tra là hai giây. Trong fuzzing, độ trễ này chấp nhận được vì luật chỉ cần cập nhật mỗi một tới hai phút, không cần thời gian thực. Tuy nhiên, nếu mở rộng sang chạy nhiều Fast Loop cùng lúc trên nhiều máy, cách giao tiếp qua tệp sẽ không theo kịp và cần chuyển sang bộ nhớ dùng chung hoặc hàng đợi tin nhắn.

## 6.4. Bộ điều khiển EWMA và sự đánh đổi giữa tốc độ và quan sát

Bộ điều khiển EWMA hoạt động đúng như mong đợi. Khi phát hiện nhiều trạng thái mới, nó tăng tần suất đọc phản hồi để chương trình nhìn thấy nhiều hơn. Khi không còn gì mới, nó giảm tần suất đọc để tối đa tốc độ gửi. Công thức liên tục tránh được hiện tượng rung lắc mà chúng tôi từng thấy khi thử cách điều chỉnh theo bước nhảy, khi đó giá trị $k$ nhảy liên tục giữa một và giá trị tối đa gây ra những đợt ngắt quãng nhỏ trong tốc độ gửi.

Một hạn chế của EWMA hiện tại là nó phải dựa vào chỉ số gián tiếp. Slow Loop không thể đọc trực tiếp phản hồi của server mà chỉ thấy được số lượng dữ liệu hệ thập lục phân duy nhất trong bộ đệm và số nhóm trường từ bộ phân tích. Đây là chỉ số không hoàn hảo để đo độ phủ thực sự. Nếu tích hợp được công cụ báo cáo độ phủ ASAN qua bộ nhớ dùng chung giữa máy chủ và máy ảo, chỉ số này sẽ chính xác hơn nhiều.

## 6.5. Hạn chế

Hệ thống còn một số hạn chế sau đây.

Thứ nhất, LLM không phải lúc nào cũng trả ra kết quả giống nhau. Cùng một dữ liệu đầu vào, hai lần gọi có thể sinh ra ngữ pháp khác nhau. Bộ điều phối có cơ chế lọc bớt trùng lặp nhưng không thể đảm bảo hội tụ về một ngữ pháp duy nhất.

Thứ hai, cách đánh giá hiện tại dùng ngữ pháp đúng của một giao thức đơn giản do chính tác giả thiết kế. Điều này dẫn tới vấn đề là hệ thống có thể đã vô tình được tối ưu để giải bài toán đó. Mục tiêu của đề tài là fuzzing giao thức lạ không biết trước, nhưng đánh giá lại trên giao thức đã biết hoàn toàn. Ngoài ra, kết quả hiện tại chỉ đo ở chế độ giả lập không gọi LLM thật nên chưa chứng minh được khả năng tổng quát khi dùng LLM thực. Cần mở rộng đánh giá lên giao thức thực có ngữ pháp đúng độc lập.

Thứ ba, chi phí gọi LLM vẫn còn cao dù đã thiết kế lớp xử lý toán học để giảm token. Một chiến dịch chạy một giờ với mỗi lần gọi cách nhau ba mươi giây tốn khoảng một tới ba đô la Mỹ. Con số này chấp nhận được cho nghiên cứu nhưng cần cân nhắc nếu chạy dài ngày.

Thứ tư, Firecracker yêu cầu KVM nên không chạy được trên máy không có ảo hóa phần cứng, ví dụ một số máy chủ đám mây lồng nhau. Docker có thể dùng thay thế nhưng thời gian khởi động lại chậm hơn nhiều.

Thứ năm, hệ thống không có phản hồi độ phủ mã nhị phân thật. Chỉ số đang dùng thực chất đếm số cặp vị trí byte và giá trị bị đột biến, tức là độ rộng của không gian đột biến chứ không phải số nhánh mã nhị phân được kích hoạt. Vì vậy các so sánh A/B/C hiện chỉ dựa trên chỉ số gián tiếp ở tầng giao thức và không thể trả lời cấu hình nào chạm được nhiều đường xử lý nhị phân hơn. Tích hợp báo cáo độ phủ ASAN qua bộ nhớ dùng chung là điều kiện cần cho mọi kết luận định lượng về độ phủ trong tương lai.

Thứ sáu, không cấu hình nào vượt qua được trạng thái FTP đầu tiên. Trong mọi chiến dịch, chỉ quan sát được mã chào 220. Fuzzer chưa bao giờ thiết lập được phiên đã xác thực trước khi gửi lệnh đột biến, nên các bước chuyển trạng thái được đếm thực ra là chuyển nội bộ trong trạng thái chưa xác thực và các đường xử lý sâu nơi lỗi thực sự tồn tại hiếm khi được kích hoạt. Đây là nguyên nhân sâu khiến câu hỏi thứ ba về phát hiện lỗi không ổn định.

Thứ bảy, báo cáo chưa thực hiện phân tích đầy đủ để tách riêng đóng góp của từng thành phần kỹ thuật như bộ điều khiển EWMA, bộ lập lịch có trọng số hay cơ chế cô lập một trường một lần. Phép so sánh A/B/C chỉ trả lời được câu hỏi tổng quát là toán học cộng LLM khác random ra sao, chứ chưa cô lập được đóng góp của từng cơ chế riêng lẻ.

\newpage

# Chương 7: Kết luận và hướng phát triển

## 7.1. Kết luận

Báo cáo này đã trình bày LIFA-Fuzz, một chương trình fuzzing cho các giao thức mạng, dùng mô hình ngôn ngữ lớn để suy diễn cấu trúc giao thức từ dữ liệu mạng thực tế. Bốn đóng góp chính của đề tài như sau.

Thứ nhất là kiến trúc hai vòng Fast Loop và Slow Loop chạy bất đồng bộ, tách fuzzing tốc độ cao ra khỏi phân tích bằng LLM, đảm bảo tốc độ gửi của chương trình không bị ảnh hưởng bởi độ trễ khi gọi LLM.

Thứ hai là cách kết hợp giữa xử lý bằng thống kê và suy luận bằng mô hình ngôn ngữ. Lớp thống kê xử lý các việc đơn giản như phát hiện byte cố định hay trường độ dài trong chưa đầy một phần nghìn giây, giúp LLM chỉ phải tập trung vào việc đặt tên có ý nghĩa cho từng trường và đề xuất cách đột biến phù hợp. Nhờ đó giảm đáng kể lượng token tiêu thụ.

Thứ ba là bộ điều khiển EWMA thích nghi tự động điều chỉnh tần suất đọc phản hồi dựa trên mức độ khám phá mới, với công thức liên tục được thiết kế để tránh rung lắc.

Thứ tư là cơ chế tự động suy diễn máy trạng thái giao thức và tự động mở rộng dữ liệu vào các trường (payload escalation). Hệ thống có một từ điển token cơ bản (USER, PASS, PORT...) làm điểm khởi động, nhưng mọi thứ sau đó — từ việc xây dựng đồ thị chuyển trạng thái tới quyết định gửi bao nhiêu byte để kích nổ lỗi — đều do máy tự làm, không cần luật state machine hay luật length viết tay. Điều này giúp LIFA-Fuzz vượt qua giới hạn của các công cụ như Peach (cần grammar viết tay) hay Sulley (cần mô tả từng trường).

Hệ thống đã được triển khai hoàn chỉnh với khoảng 17.000 dòng Python, hơn 250 bài kiểm thử, và chạy được trên target thực tế là LightFTP trong máy ảo Firecracker. Kiến trúc dạng mô đun cho phép thay đổi từng phần mà không ảnh hưởng tới các phần còn lại. Đặc biệt, lớp thống kê có thể sinh luật tạm đủ tốt để fuzzer tiếp tục chạy ngay cả khi LLM không phản hồi.

## 7.2. Hướng phát triển

Từ kết quả hiện tại có thể phát triển thêm theo nhiều hướng.

**Fuzzing có dẫn đường bằng độ phủ thật.** Hiện tại LIFA-Fuzz là fuzzer không cần mã nguồn hoàn toàn và không có phản hồi từ độ phủ mã nhị phân. Bước tiếp theo là dùng báo cáo ASAN từ LightFTP để xây dựng tín hiệu độ phủ thực. Cơ chế này có thể làm qua bộ nhớ dùng chung giữa máy chủ và máy ảo, ASAN ghi dữ liệu độ phủ ra tệp, máy chủ đọc định kỳ, và bộ điều khiển EWMA dùng độ phủ thật thay vì chỉ số gián tiếp.

**Mở rộng sang nhiều giao thức.** Kiến trúc hiện tại đã hỗ trợ FTP qua LightFTP. Mở rộng sang các target khác chỉ cần tạo đĩa hệ thống mới, viết máy khách sinh dữ liệu hợp lệ cho giao thức tương ứng, và điều chỉnh ngưỡng của bộ phân tích nếu cần.

**Fuzzing phân tán.** Chạy nhiều Fast Loop song song trên nhiều máy, mỗi máy fuzz một target khác nhau hoặc cùng target nhưng khác mẫu khởi tạo. Một bộ điều phối quản lý hàng đợi việc, thu thập kết quả và điều phối các lần gọi LLM để tránh suy luận trùng lặp khi nhiều máy cùng fuzz một giao thức.

**Suy diễn máy trạng thái giao thức.** LLM có khả năng suy luận không chỉ cấu trúc gói tin mà còn cả máy trạng thái của giao thức, ví dụ FTP yêu cầu USER trước PASS và không thể RETR trước khi đăng nhập. Tích hợp suy diễn máy trạng thái vào luật sẽ cho phép fuzzer gửi các gói tin đã đột biến trong đúng ngữ cảnh trạng thái, tăng khả năng kích hoạt các đường xử lý sâu.

\newpage

# Tài liệu tham khảo

[1] Pordanesh, S., Tan, B. "Exploring the Efficacy of Large Language Models (GPT-4) in Binary Reverse Engineering." arXiv preprint arXiv:2406.06637, 2024. https://arxiv.org/abs/2406.06637

[2] Aitel, D. "An Introduction to SPIKE, the Fuzzer Creation Kit." 2005. https://www.immunitysec.com/downloads/SPIKEdescription.pdf

[3] Sulley Fuzzing Framework. 2012. https://github.com/OpenRCE/sulley

[4] Peach Fuzzer. 2020. https://www.peach.tech/

[5] boofuzz — Network Protocol Fuzzing for Humans. 2025. https://github.com/jtpereyda/boofuzz

[6] AFL++ — fuzzer maintaining and improving AFL. 2025. https://github.com/AFLplusplus/AFLplusplus

[7] SnapChange — Lightweight Fuzzing of a Memory Snapshot using KVM. Amazon AWS Labs (awslabs), 2023. https://github.com/awslabs/snapchange

[8] Cui, W., et al. "Discoverer: Automatic Protocol Reverse Engineering by Parsing Binary Traces." USENIX Security Symposium, 2007.

[9] Cui, W., et al. "Tupni: Automatic Reverse Engineering of Input Formats." ACM CCS, 2008.

[10] Beddoe, M. "The Protocol Informatics Project (PIP)." 2004. http://www.4tphi.net/~awalters/PI/PI.html

[11] Comparetti, P.M., et al. "Prospex: Protocol Specification Extraction." IEEE Symposium on Security and Privacy, 2009.

[12] Wang, Y., et al. "NEMESYS: Network Message Syntax Reverse Engineering using Neural Networks." NDSS, 2023.

[13] Duchêne, F., et al. "Protocol Reverse Engineering Using Shannon Entropy." IEEE Transactions on Information Forensics and Security, 2018.

[14] Pearce, H., et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." IEEE Symposium on Security and Privacy, 2022.

[15] Huang, L., Zhao, P., Chen, H., Ma, L. "On the Challenges of Fuzzing Techniques via Large Language Models: A Survey." arXiv preprint arXiv:2402.00350, 2024. https://arxiv.org/abs/2402.00350

[16] Firecracker MicroVM. AWS, 2025. https://firecracker-microvm.github.io/

[17] Sun, Y., Luo, Q., Wang, Y., et al. "SemFuzz: A Semantics-Aware Fuzzing Framework for Network Protocol Implementations." Proceedings of the ACM Web Conference 2026 (WWW '26), 2026. https://doi.org/10.1145/3774904.3792541

[18] Qin, S., Hu, F., Ma, Z., et al. "NSFuzz: Towards Efficient and State-Aware Network Service Fuzzing." ACM Transactions on Software Engineering and Methodology (TOSEM), 2023.

[19] Wang, Y., Zhang, Z., Yao, D., Qu, B., Guo, L. "Inferring Protocol State Machine from Network Traces: A Probabilistic Approach" (Veritas). 2011.

[20] Wei, H., Chen, L., Du, Z., et al. "Unleashing the Power of LLM to Infer State Machine from the Protocol Implementation" (ProtocolGPT). arXiv:2405.00393, 2024. https://arxiv.org/abs/2405.00393
