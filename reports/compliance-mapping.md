# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo — không phải mô tả chung.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement (xem stretch goal #3: delete cascade khỏi `data/customers.json`) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory và đánh giá luồng truyền dữ liệu cho LLM API call | [`reports/dpia-lite.md` (§3)](dpia-lite.md) |
| ASI03 — Privilege Abuse | Per-agent identity (`agent_owner`, `run_id`), phân quyền PEP và ghi vết audit | [`agent/policy.py:L14-L56`](../agent/policy.py), [`agent/ledger.py:L22-L55`](../agent/ledger.py), [`reports/ledger.jsonl`](ledger.jsonl) |
| ASI01 — Goal Hijack | Kiến trúc Trifecta Split cô lập untrusted content khỏi private data ingestion | [`agent/runner.py:L34-L125`](../agent/runner.py), [`reports/attack-after.log`](attack-after.log) |
| ISO 42001 Clause 5-6 | Policy-as-Code có quản lý phiên bản qua Git commit | Git log của [`agent/policy.py`](../agent/policy.py) (Commit `9d510f2`) |
