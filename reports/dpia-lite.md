# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - Dữ liệu cá nhân (PII): Căn cước công dân (`VN_CCCD` - 12 chữ số), Số tài khoản ngân hàng (`VN_BANK_ACCOUNT` - 8-16 chữ số), Số điện thoại (`VN_PHONE` - 10 chữ số đầu 0), Thư điện tử (`EMAIL`).
   - Phân loại dữ liệu:
     - `restricted`: Hồ sơ khách hàng chứa PII (`data/customers.json`).
     - `internal`: Tài liệu trao đổi và nội dung ticket nghiệp vụ (`corpus/`).
     - `public`: Dữ liệu chính sách công khai chung.

2. Mục đích xử lý và principal:
   - Mục đích xử lý: `summarize-tickets` (tổng hợp danh sách ticket), `support-reply` (tra cứu thông tin phục vụ xử lý phản hồi khách hàng), `billing-reconciliation`, `privacy-audit`.
   - Principal (vai trò mô phỏng từ `data/principals.json`):
     - `support_l1`: Hỗ trợ cấp 1, chỉ được dùng `search_docs` trên dữ liệu `internal`; bị cấm đọc hồ sơ khách hàng `read_customer`.
     - `dpo`: Cán bộ bảo vệ dữ liệu, được phép dùng `search_docs` và `read_customer` cho mục đích kiểm toán và đối soát hợp lệ.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - Run A (`lab24-agent/run-a`): Gọi tool `search_docs` để đọc tài liệu trong `corpus/`. Tách lọc và sanitize hoàn toàn text, chỉ truyền typed `ticket_id: list[int]` trích xuất từ tên file sang Run B.
   - Run B (`lab24-agent/run-b`): Nhận typed `ticket_id`, đối chiếu trường `related_tickets` trong `data/customers.json` để xác định danh tính khách hàng hợp lệ (không bao giờ lấy customer ID từ free text của attacker). Đánh giá PEP trước khi gọi `read_customer`.
   - Endpoint: Đích gửi ra ngoài `http://127.0.0.1:10024/reconcile` bị PEP chặn hoàn toàn tại cổng gọi `http_post` vì dữ liệu mang nhãn `restricted`. Dữ liệu PII không bao giờ đi qua network boundary.

4. Bằng chứng deny/allow và giới hạn của mock:
   - Bằng chứng:
     - `reports/attack-after.log` rỗng hoàn toàn (0 byte).
     - `reports/ledger.jsonl` ghi nhận `read_customer` allow cho `dpo`, deny cho `support_l1`; `http_post` bị deny với lý do: `"Egress network access is strictly prohibited for restricted data"`.
     - Toàn bộ chuỗi hash chain trong ledger hợp lệ (`ledger.verify() == True`).
   - Giới hạn của mock: Toàn bộ dữ liệu là synthetic; token kiểm thử là token giả `LAB24-DEMO`; `--as` chỉ là mô phỏng danh tính, chưa thay thế được hệ thống xác thực (Authentication) và phân quyền IAM production thực tế.
