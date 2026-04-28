# CHƯƠNG TRÌNH MÔ PHỎNG MÃ HÓA VÀ TẤN CÔNG RSA

## 1. GIỚI THIỆU CHUNG

Chương trình "Mô phỏng Mã hóa và Tấn công RSA" là một dự án phần mềm được phát triển bằng ngôn ngữ Python, nhằm mục đích minh họa một cách trực quan và chi tiết toàn bộ vòng đời của hệ mật mã bất đối xứng RSA. Dự án này không chỉ dừng lại ở việc cài đặt các thuật toán cơ bản để mã hóa và giải mã thông điệp, mà còn đi sâu vào khía cạnh an toàn thông tin thông qua việc xây dựng hệ thống mô phỏng các phương pháp bẻ khóa và tấn công mật mã phổ biến.

Dự án được thực hiện nhằm phục vụ cho mục đích học thuật, nghiên cứu và báo cáo đồ án môn học (Đại học Thăng Long). Thông qua việc sử dụng chương trình, người dùng (đặc biệt là sinh viên ngành công nghệ thông tin và an toàn thông tin) có thể hiểu rõ hơn về cách thức hoạt động của RSA bên dưới lớp giao diện người dùng, cũng như nhận thức được những rủi ro bảo mật nghiêm trọng nếu lựa chọn các tham số sinh khóa không đủ an toàn.

## 2. CƠ SỞ LÝ THUYẾT VỀ HỆ MẬT MÃ RSA

Hệ mật mã RSA (được đặt tên theo ba nhà phát minh Ron Rivest, Adi Shamir và Leonard Adleman) là một trong những hệ mật mã khóa công khai đầu tiên và được sử dụng rộng rãi nhất hiện nay để truyền dữ liệu an toàn. Thuật toán này dựa trên độ khó của bài toán phân tích một số nguyên lớn thành các thừa số nguyên tố (Integer Factorization Problem).

### 2.1. Quá trình sinh khóa (Key Generation)
Quá trình sinh khóa RSA bao gồm các bước toán học chặt chẽ sau:
1. Lựa chọn hai số nguyên tố rất lớn p và q một cách ngẫu nhiên và độc lập với nhau. Trong thực tế, các số này thường có độ dài từ 1024 bit trở lên. Chương trình sử dụng thuật toán kiểm tra tính nguyên tố xác suất Miller-Rabin để đảm bảo p và q là số nguyên tố với xác suất chính xác cực kỳ cao.
2. Tính toán mô-đun n = p * q. Giá trị n này sẽ được sử dụng làm mô-đun cho cả khóa công khai và khóa bí mật. Độ dài của n (tính bằng bit) chính là chiều dài của khóa.
3. Tính toán giá trị hàm Euler totient: phi(n) = (p - 1) * (q - 1). Hàm này đếm số lượng các số nguyên dương nhỏ hơn n và nguyên tố cùng nhau với n.
4. Lựa chọn số mũ công khai e sao cho 1 < e < phi(n) và ước chung lớn nhất của e và phi(n) là 1 (tức là e và phi(n) nguyên tố cùng nhau). Thông thường, các giá trị nguyên tố Fermat như 65537 thường được sử dụng để tối ưu hóa tốc độ mã hóa.
5. Tính toán số mũ bí mật d. Giá trị d là nghịch đảo mô-đun của e theo mô-đun phi(n). Điều này có nghĩa là (d * e) đồng dư với 1 theo mô-đun phi(n). Chương trình sử dụng thuật toán Euclid mở rộng (Extended Euclidean Algorithm) để tìm giá trị d này một cách hiệu quả.

Kết quả của quá trình này là một cặp khóa:
- Khóa công khai (Public Key): Bao gồm bộ (e, n). Khóa này được chia sẻ công khai cho bất kỳ ai muốn gửi thông điệp mã hóa đến chủ sở hữu khóa.
- Khóa bí mật (Private Key): Bao gồm bộ (d, n). Khóa này phải được giữ bí mật tuyệt đối bởi chủ sở hữu để dùng cho việc giải mã thông điệp nhận được hoặc tạo chữ ký số.

### 2.2. Quá trình mã hóa và giải mã
- Mã hóa (Encryption): Giả sử Alice muốn gửi một thông điệp m (được biểu diễn dưới dạng số nguyên sao cho 0 <= m < n) cho Bob. Alice sử dụng khóa công khai (e, n) của Bob để tính toán bản mã c theo công thức: c = m^e mod n.
- Giải mã (Decryption): Khi Bob nhận được bản mã c, anh ta sử dụng khóa bí mật (d, n) của mình để khôi phục lại thông điệp ban đầu m theo công thức: m = c^d mod n. Tính đúng đắn của quá trình này được bảo đảm bởi Định lý Euler.

## 3. KIẾN TRÚC VÀ CẤU TRÚC THƯ MỤC DỰ ÁN

Dự án được phân chia thành các mô-đun độc lập, giúp dễ dàng bảo trì, mở rộng và phát triển tính năng.

Cấu trúc cây thư mục của dự án:
- display.py: Tệp mã nguồn thực thi chính cho Giao diện người dùng đồ họa (GUI) phần mã hóa, giải mã và sinh khóa. Nó quản lý toàn bộ tương tác của người dùng với hệ thống RSA tiêu chuẩn.
- src.py: Chứa các thuật toán toán học cốt lõi phục vụ cho hệ RSA, bao gồm thuật toán Euclid mở rộng, kiểm tra số nguyên tố Miller-Rabin, sinh số nguyên tố ngẫu nhiên và các hàm mã hóa/giải mã cơ sở.
- attack_ui.py: Giao diện người dùng dành riêng cho phân hệ mô phỏng tấn công. Nơi này cho phép nhập dữ liệu và chọn các phương thức bẻ khóa khác nhau.
- attack_src.py: Chứa logic toán học của các cuộc tấn công thông thường, bao gồm tấn công vét cạn bản rõ, phân tích thừa số qua phép thử chia, và tấn công Wiener dựa trên liên phân số.
- quadratic_sieve/: Thư mục chứa mã nguồn chuyên biệt cho thuật toán Sàng toàn phương (Quadratic Sieve) - một trong những thuật toán phân tích thừa số nguyên tố hiện đại và mạnh mẽ nhất cho các số nguyên dưới 100 chữ số thập phân.
- requirements.txt: Danh sách các thư viện phụ thuộc cần thiết (bao gồm cả thư viện tiêu chuẩn và thư viện ngoài như numpy, sympy) để chạy hệ thống.
- README.md: Tài liệu hướng dẫn sử dụng và giới thiệu dự án (chính là tệp tin này).

## 4. CHI TIẾT TÍNH NĂNG VÀ THUẬT TOÁN

### 4.1. Phân hệ Hệ thống RSA tiêu chuẩn (Mô-đun display.py và src.py)
Phân hệ này cung cấp một môi trường tương tác để người dùng trải nghiệm quy trình chuẩn của mật mã RSA.

1. Chức năng sinh khóa tùy chỉnh:
- Người dùng có thể chỉ định kích thước khóa tính bằng bit (từ 8 bit cho đến 4096 bit hoặc lớn hơn).
- Hệ thống áp dụng thuật toán Miller-Rabin với độ chính xác cao để tìm p và q.
- Giao diện cung cấp cửa sổ chi tiết hiển thị toàn bộ quá trình sinh toán học: từ giá trị của p, q, n, phi(n) cho đến việc thiết lập e và tính toán d.
- Hỗ trợ xuất khóa công khai ra tệp văn bản (public_key.txt) để giả lập quá trình phân phối khóa.

2. Chức năng mã hóa thông điệp:
- Chuyển đổi văn bản hoặc số nguyên đầu vào thành khối dữ liệu số (Message Block).
- Kiểm tra tính hợp lệ của khối dữ liệu so với mô-đun n. Nếu kích thước thông điệp lớn hơn n, hệ thống sẽ tự động đề xuất giảm giá trị thông điệp theo mô-đun n nhằm ngăn chặn lỗi tràn số.
- Tính toán bản mã thông qua phép lũy thừa mô-đun tốc độ cao.
- Hỗ trợ xuất bản mã ra tệp tin (ciphertext.txt).

3. Chức năng giải mã tự động hóa:
- Cung cấp hai phương thức nạp khóa bí mật: Nhập thủ công các giá trị d và n, hoặc tự động tải tệp khóa bí mật (key.txt) kết hợp cùng bản mã.
- Tự động thực thi thuật toán giải mã và kiểm chứng tính toàn vẹn của kết quả bằng cách so sánh đối chiếu nếu có sẵn tham số gốc.

### 4.2. Phân hệ Mô phỏng Tấn công (Mô-đun attack_ui.py, attack_src.py và quadratic_sieve)
Đây là phân hệ nâng cao, minh họa các rủi ro bảo mật nếu RSA bị triển khai với cấu hình yếu hoặc không tuân thủ các tiêu chuẩn an toàn (như chuẩn FIPS hay khuyến cáo của NIST).

1. Tấn công vét cạn bản rõ (Brute-Force Message Attack):
- Cơ chế: Tấn công giả định thông điệp gốc M là một số nhỏ hoặc nằm trong một không gian tìm kiếm cực kỳ hạn hẹp. Kẻ tấn công mã hóa liên tục các giá trị M dự đoán bằng khóa công khai (e, n) và đối chiếu với bản mã C thu được.
- Mục tiêu: Khôi phục M mà không cần biết khóa bí mật d hoặc phân tích n.
- Cài đặt: Hàm brute_force_message_attack thiết lập một vòng lặp tuần tự. Mặc dù vô dụng với thông điệp dài, phương pháp này rất hiệu quả nếu nạn nhân dùng RSA để mã hóa một con số nhỏ (ví dụ: mã PIN 4 chữ số) mà không áp dụng kỹ thuật chèn đệm (Padding) như OAEP.

2. Phân tích thừa số qua phép chia thử (Trial Division Factorization):
- Cơ chế: Thuật toán kinh điển nhất trong lý thuyết số để phân tích một hợp số n. Thuật toán kiểm tra khả năng chia hết của n cho tất cả các số lẻ bắt đầu từ 3 cho tới căn bậc hai của n.
- Cài đặt: Dễ cài đặt nhất nhưng độ phức tạp thời gian là hàm mũ theo độ dài bit của n. Thuật toán này chỉ có thể phá được khóa RSA khi tham số n rất nhỏ (dưới 64 bit). Trong ứng dụng, nó minh họa mức độ kém an toàn của các khóa ngắn.

3. Tấn công Wiener (Wiener's Attack):
- Cơ chế: Lợi dụng điểm yếu khi số mũ bí mật d được lựa chọn quá nhỏ nhằm tăng tốc độ giải mã. Định lý Wiener chứng minh rằng nếu d nhỏ hơn (1/3) * n^(1/4), kẻ tấn công có thể xác định d hiệu quả từ khóa công khai (e, n).
- Toán học áp dụng: Sử dụng chuỗi liên phân số (Continued Fractions). Phân số e/n được biểu diễn dưới dạng liên phân số. Các giản phân (convergents) của liên phân số này sẽ cung cấp các giá trị ứng cử viên cho phân số k/d. Từ đó, d có thể được suy ra mà không cần phân tích n.
- Cài đặt: Chương trình cài đặt thuật toán khai triển liên phân số và thử nghiệm từng giản phân để khôi phục khóa d.

4. Tấn công Sàng toàn phương (Quadratic Sieve - QS):
- Cơ chế: Sàng toàn phương là một trong những thuật toán nhanh thứ hai trên thế giới hiện nay dành cho bài toán phân tích thừa số nguyên tố (chỉ đứng sau Sàng trường số - General Number Field Sieve). QS sử dụng ý tưởng đồng dư bình phương của thuật toán Dixon nhưng tối ưu hóa thông qua cơ chế "sàng" để thu thập dữ liệu.
- Cài đặt: Thư mục quadratic_sieve độc lập chứa mã nguồn phức tạp để thực hiện các bước: chọn cơ sở nhân tử (Factor Base), tiến hành sàng (Sieving), thu thập ma trận và giải hệ phương trình tuyến tính trên trường GF(2) để trích xuất p và q. Thuật toán này minh họa sức mạnh của toán học hiện đại trong việc bẻ gãy các khóa RSA vừa và nhỏ (lên đến 100 chữ số thập phân).

## 5. HƯỚNG DẪN CÀI ĐẶT VÀ KHỞI CHẠY

Hệ thống được thiết kế để dễ dàng triển khai trên nhiều nền tảng hệ điều hành khác nhau.

### 5.1. Yêu cầu môi trường
- Ngôn ngữ: Python phiên bản 3.6 trở lên (khuyến nghị sử dụng bản 64-bit để tối ưu bộ nhớ khi tính toán số lớn).
- Thư viện Python tiêu chuẩn: Hầu hết dự án sử dụng các module nội tại như tkinter, math, random, time, os, textwrap, threading.
- Thư viện ngoài: Đối với thuật toán Sàng toàn phương (Quadratic Sieve), cần cài đặt thêm hai thư viện phục vụ ma trận và toán học đại số.

### 5.2. Hướng dẫn cài đặt
1. Tải toàn bộ mã nguồn của dự án về máy tính địa phương.
2. Mở cửa sổ dòng lệnh (Terminal hoặc Command Prompt) và di chuyển đến thư mục gốc của dự án.
3. Chạy lệnh cài đặt các gói phụ thuộc (nếu bạn dự định chạy tính năng Sàng toàn phương):
   pip install -r requirements.txt

### 5.3. Sử dụng tính năng Sinh khóa, Mã hóa và Giải mã
1. Chạy tệp tin giao diện chính:
   python display.py
2. Tại giao diện phần mềm, thực hiện theo luồng sau:
   - Bước 1 (Nhập dữ liệu): Nhập chuỗi số hoặc văn bản cần bảo mật vào trường văn bản đầu tiên và nhấn nút xác nhận.
   - Bước 2 (Quản lý khóa): Nhập độ dài bit mong muốn cho khóa (ví dụ: 1024 hoặc 2048) và nhấn nút Sinh khóa. Hệ thống sẽ hiển thị một cửa sổ thông tin chi tiết về từng bước tạo khóa toán học. Thay vì tạo khóa mới, người dùng cũng có thể chọn "Tải từ file" để đọc khóa công khai đã lưu trước đó.
   - Bước 3 (Mã hóa): Nhấn nút Mã hóa số đã nhập. Kết quả bản mã sẽ được tạo ra, bọc trong một cửa sổ cảnh báo an toàn và có thể xuất ra file ciphertext.txt để truyền tải.
   - Bước 4 (Giải mã): Kích hoạt chế độ giải mã, nạp khóa bí mật d và mô-đun n (bằng tay hoặc qua tính năng tự động tải file) và chờ hệ thống khôi phục bản rõ.

### 5.4. Sử dụng tính năng Mô phỏng Tấn công
1. Chạy tệp tin giao diện tấn công độc lập:
   python attack_ui.py
2. Tại giao diện này, người dùng cần cung cấp các tham số:
   - Nhập thông số số mũ công khai e.
   - Nhập giá trị mô-đun n.
   - Nhập bản mã c cần phá.
   - Tối ưu nhất, sử dụng tính năng "Tải từ file" để hệ thống tự động quét và nạp dữ liệu từ các file public_key.txt và ciphertext.txt do phần mềm display.py sinh ra.
3. Chọn một trong các phương thức tấn công được cung cấp trên giao diện (Phân tích thừa số, Tấn công Wiener, hoặc Brute-force).
4. Hệ thống sẽ chạy ngầm, hiển thị thanh tiến trình và cuối cùng in ra báo cáo tổng kết chi tiết về kết quả bẻ khóa, thời gian tiêu tốn và các tham số khôi phục được.

## 6. LƯU Ý VỀ MẶT BẢO MẬT VÀ ỨNG DỤNG THỰC TẾ

Ứng dụng này mang tính chất minh họa học thuật. Trong môi trường doanh nghiệp và thực tế:
- RSA không bao giờ được sử dụng trực tiếp để mã hóa dữ liệu văn bản lớn nguyên bản (Textbook RSA) vì nó chậm và dễ bị tấn công suy diễn.
- Thực tế, người ta kết hợp RSA với mã hóa đối xứng (như AES) trong mô hình Mã hóa lai (Hybrid Encryption). RSA được dùng để mã hóa và phân phối khóa AES bí mật, trong khi AES đảm nhận việc mã hóa dữ liệu gốc.
- Các chuẩn chèn đệm an toàn như PKCS#1 v1.5 hoặc cao hơn là OAEP luôn phải được sử dụng để chống lại các cuộc tấn công cấu trúc bản mã.
- Việc lựa chọn tham số RSA cần đặc biệt cẩn trọng. Tránh việc sinh p và q quá gần nhau, không sử dụng chung mô-đun n cho nhiều thực thể, và dứt khoát không sử dụng số mũ d nhỏ nhằm mục tiêu tăng tốc phần cứng.

Dự án này là minh chứng trực quan nhất cho thấy rằng, mặc dù nền tảng toán học của RSA là vô cùng vững chắc, nhưng một sơ suất nhỏ trong khâu triển khai và tùy chỉnh tham số cũng có thể dẫn đến việc phá vỡ toàn bộ hệ thống mật mã.
