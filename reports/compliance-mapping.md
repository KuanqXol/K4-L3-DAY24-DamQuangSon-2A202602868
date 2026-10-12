# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | PII Detection & Redaction đối với CCCD, STK, SĐT, Email; kiểm soát quyền truy cập dữ liệu nhạy cảm theo vai trò OBO và cấm egress dữ liệu restricted. | `agent/pii.py:L26-L65`, `agent/policy.py:L48-L51`, `agent/runner.py:L94-L125` | Dữ liệu tổng hợp (synthetic); cơ chế nhận diện regex giản lược; `--as` chỉ là mô phỏng, chưa tích hợp xác thực IAM production; chưa xác minh điều khoản chi tiết. |
| NĐ 356/2025/NĐ-CP | Phân loại dữ liệu (`data_classification`), kiểm soát mục đích (`request_purpose`), ghi nhật ký kiểm toán toàn vẹn phát hiện sửa đổi (Tamper-evident ledger hash chain). | `agent/policy.py:L41-L53`, `agent/ledger.py:L21-L77`, `reports/ledger.jsonl:L1-L23` | Hash chain chỉ nằm trên file cục bộ, không phát hiện được việc viết lại toàn bộ chuỗi nếu thiếu mốc thời gian ngoài; chưa xác minh điều khoản chi tiết. |
| Luật AI 134/2025/QH15 | Kiểm soát ranh giới thực thi của agent; kiến trúc Trifecta Split tách biệt việc xử lý văn bản không tin cậy (Run A) với dữ liệu riêng tư (Run B), ngăn ngừa hành vi tự ý ra lệnh của AI. | `agent/runner.py:L40-L150`, `agent/policy.py:L48-L86` | Thử nghiệm trên fake LLM deterministic; môi trường lab đơn máy; chưa xác minh điều khoản chi tiết. |
| OWASP ASI01, ASI03, ASI04 | **ASI01** (Prompt Injection): Trifecta split cô lập prompt injection không chạm private store; **ASI03** (Excessive Agency): PEP kiểm tra OBO/delegation trước tool execution; **ASI04** (Insecure Egress): Chặn tuyệt đối network egress đối với dữ liệu restricted. | `agent/runner.py:L40-L150`, `agent/policy.py:L48-L86`, `reports/ledger.jsonl:L23` | Chỉ thử nghiệm mô phỏng local exfil sink trên `127.0.0.1:10024`; chưa bao quát toàn bộ các vector tấn công nâng cao khác. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
