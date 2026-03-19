# HỌC VIỆN CÔNG NGHỆ BƯU CHÍNH VIỄN THÔNG

## KHOA AN TOÀN THÔNG TIN

**BÁO CÁO BÀI TẬP LỚN**

* **HỌC PHẦN:** HỆ ĐIỀU HÀNH WINDOWS VÀ LINUX/UNIX
* **MÃ HỌC PHẦN:** INT1487
* **ĐỀ TÀI:** NGHIÊN CỨU CÁC CÔNG CỤ SINH DỮ LIỆU TẤN CÔNG MẠNG, CỤ THỂ NHẮM VÀO DNS VÀ DHCP
* **Sinh viên thực hiện:** B23DCAT190 Hà Quang Minh
* **Tên nhóm:** D23G01N02
* **Tên lớp:** INT1487-20251-01
* **Giảng viên hướng dẫn:** TS. Quản Trọng Thế

**HÀ NỘI 2025**

---

## MỤC LỤC

* MỤC LỤC 2
* DANH MỤC CÁC HÌNH VẼ 3
* DANH MỤC CÁC BẢNG BIỂU 3
* DANH MỤC CÁC TỪ VIẾT TẮT 4
* CHƯƠNG 1. DÒ TÌM LƯU LƯỢNG GÓI TIN YÊU CẦU TRUY VẤN DNS DỰA TRÊN BẢN GHI TÀI NGUYÊN NS VÀ HOẠT ĐỘNG TẤN CÔNG TỪ ĐIỂN SSH. 5
  * 1.1 Giới thiệu 5
  * 1.2 Các quan sát 6
    * 1.2.1 Hệ thống Mạng và Ghi lại Gói Truy vấn DNS, và Ước tính Entropy Lưu lượng DNS 6
  * 1.3 Kết quả và thảo luận 6
    * 1.3.1 Thay đổi Entropy trong Lưu lượng Gói Truy vấn DNS Tổng số, A- và PTR-RRs từ Internet 7
    * 1.3.2 Lưu lượng Gói Truy vấn DNS NS-RR từ Internet 8
    * 1.3.3 Một Trường hợp Mới cho Hoạt động Tấn công Ngẫu nhiên 10
  * 1.4 Kết luận 11
* TÀI LIỆU THAM KHẢO 13

---

## DANH MỤC CÁC HÌNH VẼ

* Hình 1. Sơ đồ mạng lưới được quan sát trong nghiên cứu này. 6
* Hình 2. Sự thay đổi Entropy trong lưu lượng gói tin yêu cầu truy vấn DNS dựa trên các bản ghi tài nguyên (RRs) tổng thể, A và PTR từ mạng lưới khuôn viên đến máy chủ DNS tên miền cấp cao nhất (tDNS) từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009. Các đường liền nét và đường đứt nét lần lượt thể hiện entropy dựa trên các địa chỉ IP nguồn duy nhất và từ khóa truy vấn DNS duy nhất (đơn vị ngày−1). 8
* Hình 3. Bot spam ngẫu nhiên và tấn công từ điển SSH ngẫu nhiên Mô hình hoạt động 11

## DANH MỤC CÁC BẢNG BIỂU

* Bảng 1. Các từ khóa truy vấn duy nhất hàng đầu/thứ 2 được dò tìm và tần suất của chúng từ ngày 17 tháng 1 đến ngày 1 tháng 2 năm 2009. (đơn vị ngày−1). 9
* Bảng 2. Phân tích thành phần dựa trên bản ghi tài nguyên (RR) của DNS trên tổng lưu lượng gói truy vấn DNS từ Internet bao gồm ký hiệu gốc “.” làm từ khóa truy vấn tại hai đỉnh, ngày 17 và 20 tháng 1 năm 2009. (đơn vị ngày−1). 9
* Bảng 3. Các địa chỉ IP nguồn duy nhất hàng đầu, thứ 2 và thứ 3 được dò tìm và tần suất của chúng từ ngày 17 tháng 1 đến ngày 1 tháng 2 năm 2009. (đơn vị ngày−1). 10
* Bảng 4. Các địa chỉ IP hàng đầu, thứ 2 và thứ 3 được dò tìm làm từ khóa truy vấn và tần suất của chúng từ ngày 9 tháng 3 năm 2009 (đơn vị ngày−1)

---

## DANH MỤC CÁC TỪ VIẾT TẮT

| Từ viết tắt | Thuật ngữ tiếng Anh/Giải thích | Thuật ngữ tiếng Việt/Giải thích |
| :--- | :--- | :--- |
| **RR** | Resource Record | Bản ghi tài nguyên |
| **NS** | Name Server | Máy chủ tên miền |
| **A RR** | Address Resource Record | Bản ghi địa chỉ (IPv4) |
| **PTR RR** | Pointer Resource Record | Bản ghi trỏ (phân giải ngược IP) |
| **MX RR** | Mail Exchange Resource Record | Bản ghi trao đổi thư |
| **tDNS** | Top-level Domain Name Server | Máy chủ DNS tên miền cấp cao nhất |
| **FQDN** | Fully Qualified Domain Name | Tên miền đầy đủ |
| **UDP** | User Datagram Protocol | Giao thức gói dữ liệu người dùng |
| **SSH** | Secure Shell | Giao thức kết nối bảo mật từ xa |
| **DoS** | Denial of Service | Tấn công từ chối dịch vụ |
| **HS** | Host Search | Hoạt động tìm kiếm máy chủ |
| **TA** | Targeted Attack | Hoạt động tấn công có mục tiêu |
| **RA** | Random Attack | Hoạt động tấn công ngẫu nhiên |
| **RSB** | Random Spam Bot | Bot spam ngẫu nhiên |
| **PC** | Personal Computer | Máy tính cá nhân |

*(Bảng danh mục các từ viết tắt dựa trên tài liệu gốc)*

---

## DÒ TÌM LƯU LƯỢNG GÓI TIN YÊU CẦU TRUY VẤN DNS DỰA TRÊN BẢN GHI TÀI NGUYÊN NS VÀ HOẠT ĐỘNG TẤN CÔNG TỪ ĐIỂN SSH

Bài được dịch từ tài liệu Detection of NS Resource Record based DNS Query Request Packet Traffic and SSH Dictionary Attack Activity.

### Tóm tắt

[cite_start]Chúng tôi đã thực hiện một nghiên cứu entropy về lưu lượng truy vấn DNS từ Internet đến máy chủ DNS tên miền cấp cao nhất trong mạng khuôn viên trường đại học từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009[cite: 47]. [cite_start]Các kết quả thu được là: (1) Chúng tôi đã quan sát thấy sự khác biệt về thay đổi entropy giữa lưu lượng truy vấn DNS dựa trên tổng số, A-, và các bản ghi tài nguyên (RRs) PTR từ Internet từ ngày 17 tháng 1 đến ngày 1 tháng 2 năm 2009[cite: 47]. (2) [cite_start]Chúng tôi đã tìm thấy lưu lượng truy vấn DNS lớn dựa trên NS RR chỉ bao gồm từ khóa “.” trong tổng lưu lượng truy vấn DNS từ Internet[cite: 47, 48]. (3) [cite_start]Chúng tôi cũng thấy rằng entropy lưu lượng DNS PTR dựa trên địa chỉ IP nguồn duy nhất đã tăng nhẹ, trong khi entropy dựa trên từ khóa truy vấn DNS duy nhất đã giảm mạnh vào ngày 9 tháng 3 năm 2009[cite: 49]. [cite_start]Chúng tôi đã tìm thấy một máy chủ IP cụ thể là một máy tính Linux cổ điển đã bị chiếm quyền điều khiển thực hiện cuộc tấn công từ điển SSH vào các trang web Internet vào ngày 9 tháng 3 năm 2009[cite: 49]. [cite_start]Từ những kết quả này, chúng ta có thể phát hiện lưu lượng DNS bất thường dựa trên NS RR và các cuộc tấn công từ điển SSH chỉ bằng cách theo dõi lưu lượng truy vấn DNS từ Internet[cite: 49, 50].

[cite_start]**Từ khóa:** Dò tìm dựa trên DNS, dò tìm bất thường, tấn công từ điển SSH, mạng bot, bot[cite: 51].

### Giới thiệu

[cite_start]Điều quan trọng đáng kể là nâng cao tỷ lệ dò tìm các bot, vì chúng trở thành các thành phần của các mạng bot tập trung–[cite: 53]. [cite_start]Đáng tiếc, cuộc tấn công từ chối dịch vụ (DoS) vào máy chủ DNS và cuộc tấn công từ điển SSH vẫn được sử dụng để phát tán các bot khi chiếm quyền điều khiển các máy chủ mạng dễ bị tổn thương cụ thể trên Internet[cite: 54]. [cite_start]Điều này là do quá trình phân giải tên DNS được thực hiện bằng giao tiếp gói UDP và một số máy chủ mạng có thể dễ dàng bị kết nối bằng các máy khách SSH khi những kẻ tấn công biết ID người dùng và cụm mật khẩu của nó, hoặc nói cách khác, khi chủ tài khoản sử dụng các cụm mật khẩu dễ bị bẻ khóa[cite: 55]. [cite_start]Do đó, việc phát triển các công nghệ dò tìm như biện pháp đối phó chống lại cuộc tấn công từ điển SSH cũng rất quan trọng[cite: 56]. [cite_start]Trong bài báo này, (1) chúng tôi đã thực hiện phân tích entropy trên lưu lượng gói truy vấn DNS dựa trên tổng số, A- và các bản ghi tài nguyên (RRs) PTR từ Internet từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009, và (2) chúng tôi đã đánh giá tỷ lệ dò tìm tấn công bot giữa các entropy đối với lưu lượng gói truy vấn DNS dựa trên tổng số, A-RR, và PTR-RR[cite: 57].

> [cite_start]**Hình 1.** Sơ đồ mạng lưới được quan sát trong nghiên cứu này[cite: 58].

### Các quan sát

#### Hệ thống Mạng và Ghi lại Gói Truy vấn DNS, và Ước tính Entropy Lưu lượng DNS

[cite_start]Chúng tôi đã điều tra về lưu lượng truy cập gói tin yêu cầu truy vấn DNS giữa máy chủ DNS tên miền cấp cao nhất (tDNS) và các máy khách DNS[cite: 61]. [cite_start]Hình 1 cho thấy một hệ thống mạng được quan sát trong nghiên cứu hiện tại và cấu hình tùy chọn của chương trình daemon máy chủ DNS BIND-9.2.6 của máy chủ tDNS[cite: 62]. [cite_start]Các gói truy vấn DNS và từ khóa truy vấn của chúng đã được ghi lại và giải mã bằng tùy chọn ghi nhật ký truy vấn[cite: 63]. [cite_start]Nhật ký truy cập truy vấn DNS đã được ghi lại trong các tệp syslog[cite: 64]. [cite_start]Dòng thông báo syslog bao gồm nội dung của gói truy vấn DNS như thời gian, địa chỉ IP nguồn của máy khách DNS, loại tên miền đủ điều kiện (FQDN) (loại A hoặc AAAA RR), loại địa chỉ IP (PTR RR), loại trao đổi thư (MX RR), loại máy chủ tên [NS](cite: 65).

[cite_start]Chúng tôi đã sử dụng hàm Shannon để tính toán entropy H(X), như sau[cite: 66]:
H(X) = - Σ [P(i) * log2(P(i))] (với i thuộc X)

trong đó X là tập dữ liệu tần suất của các địa chỉ IP hoặc của từ khóa truy vấn DNS trong lưu lượng gói truy vấn DNS từ Internet, và xác suất P(i) được định nghĩa là[cite: 68]:
P(i) = freq(i) / Σ freq(j)

trong đó i và j đại diện cho địa chỉ IP nguồn duy nhất hoặc từ khóa truy vấn DNS duy nhất trong gói truy vấn DNS, và tần suất freq(i) được ước tính bằng chương trình script, như đã báo cáo trong công trình trước đây của chúng tôi[cite: 70]. Chúng tôi cũng nên xác định các ngưỡng để dò tìm ba loại mô hình hoạt động độc hại này, bằng cách đặt là 1,000 gói ngày−1 cho tần suất của mười địa chỉ IP nguồn duy nhất hàng đầu hoặc các từ khóa truy vấn DNS[cite: 71]. Việc đánh giá ngưỡng đã được báo cáo trước đây[cite: 72].

### Kết quả và thảo luận

#### Thay đổi Entropy trong Lưu lượng Gói Truy vấn DNS Tổng số, A- và PTR-RRs từ Internet

Chúng tôi trình bày các entropy dựa trên địa chỉ IP nguồn duy nhất và từ khóa truy vấn DNS duy nhất được tính toán cho lưu lượng gói tin yêu cầu truy vấn DNS dựa trên tổng số, A- và các bản ghi tài nguyên (RRs) PTR từ Internet đến máy chủ DNS tên miền cấp cao nhất (tDNS) từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009, như được hiển thị trong Hình 2[cite: 75].

Trong Hình 2A, chúng tôi có thể tìm thấy mười đỉnh và chúng được phân loại thành ba nhóm, là: {(1), (7), (8), (10)}, {(2)-(6)}, và {(9)}[cite: 76].

* [cite_start]Trong nhóm đỉnh đầu tiên, tất cả các đỉnh đều cho thấy sự giảm entropy dựa trên địa chỉ IP nguồn duy nhất và sự tăng entropy dựa trên từ khóa truy vấn DNS duy nhất, tức là tính năng này cho thấy hoạt động tìm kiếm máy chủ [HS](cite: 77).
* [cite_start]Trong nhóm thứ hai, chúng tôi có thể quan sát năm đỉnh, trong đó tất cả các đỉnh đều cho thấy sự giảm đồng thời entropy dựa trên địa chỉ IP nguồn duy nhất và từ khóa truy vấn DNS duy nhất[cite: 78]. [cite_start]Tính năng này cho thấy các đỉnh (2)-(6) có thể được gán cho mô hình hoạt động tấn công có mục tiêu (TA) như một bot spam có mục tiêu[cite: 79].
* [cite_start]Trong nhóm cuối cùng, chúng tôi chỉ có thể tìm thấy một đỉnh (9) không thể hiện điều gì đáng kể trong entropy dựa trên địa chỉ IP nguồn duy nhất nhưng lại giảm đáng kể trong entropy dựa trên từ khóa truy vấn DNS duy nhất[cite: 80]. [cite_start]Tính năng này sẽ được thảo luận sau[cite: 81].

[cite_start]Trong Hình 2B, đáng ngạc nhiên, chúng tôi chỉ có thể tìm thấy hai đỉnh (1) và [2](cite: 82). [cite_start]Trong đỉnh (1), chúng tôi có thể quan sát sự tăng và giảm nhỏ lần lượt trong entropy dựa trên địa chỉ IP nguồn duy nhất và từ khóa truy vấn duy nhất[cite: 83]. [cite_start]Đỉnh (1) được gán cho ngày 24 tháng 1 năm 2009[cite: 84]. [cite_start]Điều này có lẽ là do chúng tôi đã gặp sự cố phần cứng nửa ngày trong các bộ chuyển mạch lõi mạng khuôn viên trường trong ngày, và sự kiện này có thể ảnh hưởng đến sự thay đổi entropy[cite: 84]. [cite_start]Đỉnh (2) có thể được gán cho cùng tình huống trong đỉnh (9) trong Hình 2A[cite: 85]. [cite_start]Kết quả là, chúng tôi không thể quan sát thấy đỉnh nào tương ứng với các đỉnh cho hoạt động tấn công có mục tiêu (TA) trong Hình 2A[cite: 86].

[cite_start]Trong Hình 2C, chúng tôi có thể tìm thấy tám đỉnh có thể được phân loại thành hai nhóm, là: {(1)-(4), (6), (7)} và {(5)}[cite: 87].

* [cite_start]Trong nhóm đầu tiên, chúng tôi có thể quan sát thấy các đỉnh (1), (3), (4), và (6) tương ứng với các đỉnh (1), (7), (8), và (10), trong Hình 2A[cite: 88]. [cite_start]Điều này có nghĩa là các đỉnh này và các đỉnh khác (2) và (7) có thể được phân bổ cho hoạt động HS[cite: 89].
* [cite_start]Đỉnh (5) tương ứng với các đỉnh (9) và (2) trong Hình 2A và 2B, tương ứng[cite: 90]. [cite_start]Thú vị thay, trong đỉnh (5), entropy dựa trên địa chỉ IP nguồn duy nhất tăng nhẹ, trong khi entropy dựa trên từ khóa truy vấn giảm đáng kể[cite: 91]. [cite_start]Tính năng này cho thấy mô hình hoạt động tấn công ngẫu nhiên [RA](cite: 92). [cite_start]Tuy nhiên, thông thường, chúng tôi có thể quan sát những thay đổi đối xứng rõ ràng trong cả hai entropy DNS cho hoạt động RA như hoạt động bot spam ngẫu nhiên [RSB](cite: 93).

[cite_start]Ngoài ra, trong Hình 2C, chúng tôi không thể tìm thấy đỉnh hoạt động TA nào như các đỉnh (2)-(6) trong Hình 2A[cite: 94]. [cite_start]Do đó, chúng tôi cần điều tra thêm lưu lượng gói truy vấn DNS tổng số tại các đỉnh hoạt động TA (2)-(6) trong Hình 2A và xác nhận khả năng cho thấy một trường hợp mới cho hoạt động RA tại đỉnh (5) trong Hình 2C[cite: 95].

> [cite_start]**Hình 2.** Sự thay đổi Entropy trong lưu lượng gói tin yêu cầu truy vấn DNS dựa trên các bản ghi tài nguyên (RRs) tổng thể, A và PTR từ mạng lưới khuôn viên đến máy chủ DNS tên miền cấp cao nhất (tDNS) từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009[cite: 96].

#### Lưu lượng Gói Truy vấn DNS NS-RR từ Internet

[cite_start]Chúng tôi đã điều tra số liệu thống kê về các từ khóa truy vấn trong lưu lượng gói tin yêu cầu truy vấn DNS từ Internet tại các đỉnh (2)-(6) trong Hình 2A[cite: 98]. [cite_start]Các từ khóa truy vấn hàng đầu đã được thu thập khi tần suất lớn hơn 1,000 gói ngày−1 và các FQDN hoặc địa chỉ IP của các máy chủ mạng bị loại bỏ, như được liệt kê trong Bảng 1[cite: 99].

> [cite_start]**Bảng 1.** Các từ khóa truy vấn duy nhất hàng đầu/thứ 2 được dò tìm và tần suất của chúng từ ngày 17 tháng 1 đến ngày 1 tháng 2 năm 2009. [đơn vị ngày−1](cite: 100).

[cite_start]Trong Bảng 1, từ khóa truy vấn DNS hàng đầu là ký hiệu gốc “.” tại mỗi đỉnh[cite: 101]. [cite_start]Sau đó, chúng tôi đã thực hiện phân tích thành phần dựa trên bản ghi tài nguyên (RR) của DNS trên tổng lưu lượng gói truy vấn DNS từ Internet bao gồm ký hiệu gốc “.” làm từ khóa truy vấn tại các đỉnh (2) và (3) được hiển thị trong Hình 2A[cite: 102, 103]. [cite_start]Thông thường, chúng tôi có thể quan sát thấy lưu lượng gói truy vấn DNS bao gồm ký hiệu gốc “.” chỉ mất khoảng 1,100 gói ngày−1 [một giá trị trung bình bằng cách quan sát từ ngày 8 đến ngày 31 tháng 3 năm 2009](cite: 104, 105).

> [cite_start]**Bảng 2.** Phân tích thành phần dựa trên bản ghi tài nguyên (RR) của DNS trên tổng lưu lượng gói truy vấn DNS từ Internet bao gồm ký hiệu gốc “.” làm từ khóa truy vấn tại hai đỉnh, ngày 17 và 20 tháng 1 năm 2009. [đơn vị ngày−1](cite: 106, 107).

[cite_start]Như được hiển thị trong Bảng 2, tổng lưu lượng gói truy vấn DNS bao gồm ký hiệu gốc “.” bao gồm lưu lượng gói truy vấn DNS NS- và A-RRs vào ngày 17 và 20 tháng 1 năm 2009[cite: 108, 109]. [cite_start]Ngoài ra, chúng tôi có thể quan sát thấy lưu lượng truy vấn DNS dựa trên NS RR mất gần 1,300 gói ngày−1 [một giá trị trung bình bằng cách quan sát từ ngày 8 đến ngày 31 tháng 3 năm 2009](cite: 110). [cite_start]Chúng tôi đã thu thập thêm số liệu thống kê về các địa chỉ IP nguồn trong ký hiệu gốc “.” bao gồm lưu lượng gói truy vấn DNS vào ngày 17 và 20 tháng 1 năm 2009, như được hiển thị trong Bảng 3[cite: 111, 112].

> [cite_start]**Bảng 3.** Các địa chỉ IP nguồn duy nhất hàng đầu, thứ 2 và thứ 3 được dò tìm và tần suất của chúng từ ngày 17 tháng 1 đến ngày 1 tháng 2 năm 2009. [đơn vị ngày−1](cite: 113).

[cite_start]Chúng tôi có thể thấy các địa chỉ IP cụ thể trong Bảng 3, và các địa chỉ IP này có thể được gán cho hoạt động tấn công có mục tiêu tương ứng với các đỉnh (2)-(6) trong Hình 2A[cite: 114].

#### Một Trường hợp Mới cho Hoạt động Tấn công Ngẫu nhiên

[cite_start]Chúng tôi đã thực hiện số liệu thống kê về các từ khóa truy vấn trong tổng lưu lượng gói truy vấn DNS dựa trên bản ghi tài nguyên (RR) PTR từ Internet vào ngày 9 tháng 3 năm 2009, để điều tra thêm đỉnh (5) trong Hình 2C[cite: 116]. [cite_start]Các kết quả được hiển thị trong Bảng 4, trong đó các địa chỉ IP hàng đầu được thu thập khi tần suất lớn hơn hoặc bằng 1,000 gói ngày−1[cite: 117].

> [cite_start]**Bảng 4.** Các địa chỉ IP hàng đầu, thứ 2 và thứ 3 được dò tìm làm từ khóa truy vấn và tần suất của chúng từ ngày 9 tháng 3 năm 2009 [đơn vị ngày−1](cite: 118).

[cite_start]Trong Bảng 4, chúng tôi có thể tìm thấy ba địa chỉ IP hàng đầu là 133.95.s1.62, 133.95.s2.73, và 133.95.s3.163, làm từ khóa truy vấn trong đó địa chỉ IP hàng đầu được gán cho máy tính Linux cũ trong mạng khuôn viên trường[cite: 119]. [cite_start]May mắn thay, chúng tôi đã nhận được một E-mail thông báo tự động, trong đó họ phàn nàn rằng một thiết bị PC trong mạng khuôn viên trường đã thực hiện cuộc tấn công từ điển SSH vào họ và thiết bị này hiển thị cùng địa chỉ IP với địa chỉ hàng đầu[cite: 120]. [cite_start]Do đó, chúng tôi có thể xác định đỉnh (5) tương ứng với hoạt động tấn công từ điển SSH ngẫu nhiên[cite: 121]. [cite_start]Ngoài ra, chúng tôi đã tính tỷ lệ cho địa chỉ IP nguồn duy nhất trong lưu lượng gói truy vấn DNS dựa trên PTR RR bao gồm từ khóa truy vấn “133.95.s1.62”, trong đó tỷ lệ được tính là 11%[cite: 122]. [cite_start]Vào ngày 17 tháng 1 năm 2008, chúng tôi đã dò tìm một bot spam được khởi động bằng đĩa silicon USB, và chúng tôi đã quan sát thấy 11,263 gói ngày−1 đối với lưu lượng gói truy vấn DNS bao gồm địa chỉ IP của thiết bị PC bị bot spam[cite: 123]. [cite_start]Sự khác biệt này có lẽ được giải thích theo khía cạnh sự khác biệt liệu lưu lượng gói truy vấn DNS dựa trên PTR RR từ Internet có bao gồm lưu lượng phân giải ngược DNS từ các máy chủ E-mail trên Internet hay không[cite: 124].

> [cite_start]**Hình 3.** Bot spam ngẫu nhiên và tấn công từ điển SSH ngẫu nhiên Mô hình hoạt động[cite: 125].

### Kết luận

[cite_start]Chúng tôi đã điều tra phân tích entropy trên tổng lưu lượng gói tin yêu cầu truy vấn DNS dựa trên bản ghi tài nguyên (RR) A và PTR từ Internet từ ngày 1 tháng 1 đến ngày 31 tháng 3 năm 2009[cite: 127]. Các kết quả thú vị sau đây được tìm thấy:

* (1) [cite_start]chúng tôi đã quan sát thấy 10, 2, và 8 sự cố trong sự thay đổi entropy trong lưu lượng gói truy vấn DNS dựa trên tổng số, A-, và PTR-RRs, tương ứng[cite: 127]. [cite_start]Trong sự thay đổi entropy lưu lượng gói truy vấn DNS tổng số, chúng tôi đã tìm thấy 4 hoạt động tìm kiếm máy chủ (HS), 5 hoạt động tấn công có mục tiêu (TA), và 1 hoạt động tấn công ngẫu nhiên [RA](cite: 128). [cite_start]Trong sự thay đổi entropy lưu lượng gói truy vấn DNS dựa trên A RR, chúng tôi đã tìm thấy 1 sự cố phần cứng và 1 hoạt động RA[cite: 129]. [cite_start]Trong sự thay đổi entropy lưu lượng gói truy vấn DNS dựa trên PTR, chúng tôi đã khám phá ra 7 hoạt động HS và 1 hoạt động RA[cite: 130].
* (2) [cite_start]Chúng tôi thấy rằng các máy chủ IP cụ thể đã thực hiện cuộc tấn công TA vào máy chủ tên miền cấp cao nhất (tDNS) của khuôn viên trường bằng cách truyền lưu lượng gói truy vấn DNS dựa trên NS RR bao gồm ký hiệu gốc “.” làm từ khóa truy vấn[cite: 131, 132].
* (3) [cite_start]Ngoài ra, chúng tôi đã tìm thấy một trường hợp mới cho hoạt động RA giống như một cuộc tấn công từ điển SSH ngẫu nhiên nhưng không giống như một bot spam ngẫu nhiên [RSB](cite: 132). [cite_start]Điều này là do chúng tôi đã quan sát thấy sự khác biệt trong sự thay đổi entropy dựa trên địa chỉ IP nguồn và tỷ lệ duy nhất đối với địa chỉ IP nguồn trong các cuộc tấn công RSB và từ điển SSH được tính toán lần lượt là 11% và 72%[cite: 133].

[cite_start]Từ những kết quả này, có thể kết luận rằng chúng ta nên chú ý đến các kết quả của phân tích thành phần dựa trên bản ghi tài nguyên (RR) vì chúng tôi đã quan sát thấy sự khác biệt đáng kể giữa các entropy lưu lượng truy vấn DNS dựa trên tổng số, A, và PTR RRs, và chúng tôi có thể dò tìm cuộc tấn công từ chối dịch vụ (DoS) truy vấn DNS dựa trên NS RR và cuộc tấn công từ điển SSH chỉ bằng cách quan sát lưu lượng phân giải DNS từ Internet[cite: 134]. [cite_start]Chúng tôi tiếp tục nghiên cứu thêm để phát triển công nghệ dò tìm bot spam và bot[cite: 135].

---

### TÀI LIỆU THAM KHẢO

[cite_start]Detection of NS Resource Record based DNS Query Request Packet Traffic and SSH Dictionary Attack Activity[cite: 137].
