# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1 (`gitleaks version`).
- Commit chứa token giả: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`).
- File, rule và kết quả quét lịch sử: File `lab-fake-secret.txt`, rule id `lab24-synthetic-token` cấu hình trong `.gitleaks.toml`. Kết quả quét lịch sử (`gitleaks git --config .gitleaks.toml --redact --verbose .`) phát hiện 1 finding chứa chuỗi `LAB24_FAKE_TOKEN=LAB24-DEMO-...` với exit code 1 như dự kiến.
- Kết quả quét file hiện tại: Lệnh `gitleaks dir --config .gitleaks.toml .` báo cáo `no leaks found` (exit code 0), xác nhận trạng thái HEAD sạch sẽ, không còn token giả trong working tree hiện tại.
- Nếu đây là credential thật, cần xử lý thế nào: Phải lập tức thực hiện quy trình thu hồi (revoke) và xoay vòng (rotate) credential trực tiếp trên hệ thống/nhà cung cấp dịch vụ quản lý token đó; đồng thời kích hoạt kiểm toán rà soát toàn bộ log truy cập để phát hiện các hành vi khai thác trái phép kể từ thời điểm commit `1bdd849` được tạo.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  1. Xóa file khỏi HEAD không xóa được dữ liệu khỏi lịch sử Git (Git object database). Bất kỳ ai clone repo hoặc truy cập commit cũ đều có thể đọc được secret nếu credential chưa được thu hồi/rotate.
  2. Pin dependency và hash lock (`requirements.lock`) chỉ bảo vệ tính toàn vẹn của chuỗi cung ứng mã nguồn thứ ba, hoàn toàn không có khả năng vô hiệu hóa một credential đã bị lộ lọt ra bên ngoài.
