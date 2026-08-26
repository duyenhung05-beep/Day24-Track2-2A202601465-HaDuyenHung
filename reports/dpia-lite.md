# DPIA-lite: Đánh giá tác động bảo vệ dữ liệu (Data Protection Impact Assessment)

## 1. Dữ liệu gì (Data Inventory)

Hệ thống Agent xử lý các nhóm dữ liệu theo từng công cụ (`tool`):

1. **`search_docs(query)` (Untrusted Content Store - `corpus/*.md`):**
   - **Nội dung ticket hỗ trợ:** Tiêu đề, mô tả vấn đề kỹ thuật/dịch vụ của khách hàng.
   - **Dữ liệu PII thô có thể xuất hiện:** Tên khách hàng, mã định danh `customer_id`, và các nội dung chỉ thị tự do (free-text).
   - **Phân loại dữ liệu:** `Internal` / `Untrusted`.

2. **`read_customer(customer_id)` (Private Customer Store - `data/customers.json`):**
   - **Thông tin định danh cá nhân (PII):** Họ và tên đầy đủ (`name`), Số Căn cước công dân 12 chữ số (`cccd`), Số điện thoại liên hệ (`phone`), Địa chỉ thư điện tử (`email`).
   - **Thông tin tài chính nhạy cảm:** Số tài khoản ngân hàng (`bank_account`).
   - **Metadata quản trị:** Danh sách ticket liên quan (`related_tickets`).
   - **Phân loại dữ liệu:** `Restricted` (Dữ liệu cá nhân nhạy cảm & bảo mật cao).

---

## 2. Mục đích gì (Processing Purpose)

1. **Tổng hợp & Tra cứu ticket hỗ trợ:** Cho phép nhân viên/khách hàng tra cứu nhanh danh sách và tình trạng các ticket đang mở trong tuần để nâng cao hiệu suất chăm sóc khách hàng.
2. **Đối soát & Xác thực thông tin khách hàng:** Tra cứu thông tin chủ tài khoản/khách hàng tương ứng với ticket để xác minh quyền sở hữu, phục vụ quy trình hỗ trợ kỹ thuật và đối soát giao dịch tài chính.
3. **Nguyên tắc giảm thiểu dữ liệu (Data Minimization):** Agent chỉ truy vấn hồ sơ khách hàng dựa trên mối liên kết đã được kiểm chứng (`related_tickets` $\leftrightarrow$ `customer_id`), không đọc thông tin của khách hàng không liên quan.

---

## 3. Chảy đi đâu (Data Flow & Egress Control)

1. **Sổ cái kiểm toán nội bộ (`reports/ledger.jsonl`):**
   - Mọi hành vi gọi tool (tham số đã băm SHA256 `args_hash`, quyết định `decision`, lý do `reason`) được lưu vết dưới dạng chuỗi băm tamper-evident để phục vụ giám sát và kiểm toán nội bộ.
   - Dữ liệu PII thô không bị ghi vào ledger.

2. **Môi trường nhận dữ liệu bên ngoài (Sink Server - `localhost:9999`):**
   - Trong baseline chưa có bảo vệ, PII bị rò rỉ qua `http_post`.
   - **Cơ chế kiểm soát (Egress Control):** Sau khi áp dụng kiến trúc **Trifecta Split** và **Policy Enforcement Point (PEP)** tại `agent/policy.py`, mọi yêu cầu gửi dữ liệu cá nhân (`restricted`) ra ngoài mạng (`egress_enabled=True`) đều bị từ chối dứt điểm (`DENY`). Dữ liệu bị chặn tuyệt đối không thể gửi tới Sink Server.

3. **Chuyển dữ liệu xuyên biên giới (Cross-border Transfer theo NĐ 356/2025):**
   - **Chế độ mặc định (`--mock`):** Hoạt động hoàn toàn cục bộ (local deterministic LLM), không có luồng dữ liệu nào gửi ra ngoài ranh giới hệ thống nội bộ.
   - **Khi sử dụng mô hình thật (`--model claude-...`):** Toàn bộ ngữ cảnh ticket tóm tắt gửi tới API của Anthropic (máy chủ đặt tại nước ngoài) cấu thành hành vi chuyển dữ liệu cá nhân ra nước ngoài theo quy định của Nghị định 356/2025. Cần áp dụng **PII Redaction Gate** (`agent/pii.py:redact()`) trước khi gửi context sang LLM và duy trì hồ sơ đánh giá tác động 60 ngày theo quy định pháp luật.
