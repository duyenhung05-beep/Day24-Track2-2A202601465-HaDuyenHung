"""BƯỚC 3c — trifecta split + egress allowlist (13').

Kiến trúc Trifecta Split:
- Run A (Untrusted Ingestion): Đọc untrusted content từ search_docs, trích xuất
  ticket_id từ TÊN FILE (metadata tin cậy), phát hiện injection để kiểm soát.
  Không có quyền đọc private data hay egress.
- Run B (Private Data Retrieval): Nhận ticket_id đã xác thực từ Run A, tra cứu
  customer_id từ field `related_tickets` trong customers.json (nguồn tin cậy).
  Không nhận free text từ attacker.

Mọi tool call đều đi qua Policy Enforcement Point (PEP) và ghi vào Audit Ledger.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from agent import ledger, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_ID_RE = re.compile(r"ticket-(\d+)")


def _hash_args(args: dict | list | str) -> str:
    """Tạo hash SHA256 cho tham số đầu vào của tool."""
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Xử lý yêu cầu người dùng qua kiến trúc Trifecta Split."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH

    # =========================================================================
    # RUN A: UNTRUSTED INGESTION
    # =========================================================================
    # 1. Policy check cho search_docs trong Run A
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="search-untrusted-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy.check(ctx_search)

    # Ghi nhận vào ledger
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu tìm kiếm tài liệu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # 2. Trích xuất typed ticket_id từ TÊN FILE (metadata tin cậy)
    # Tuyệt đối không trích xuất customer_id từ free text do attacker viết!
    valid_ticket_ids: list[int] = []
    for d in docs:
        filename = d.get("id", "")
        match = _TICKET_ID_RE.search(filename)
        if match:
            valid_ticket_ids.append(int(match.group(1)))

    # 3. Quét phát hiện injection trên toàn bộ context tài liệu
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: PRIVATE DATA RETRIEVAL (ISOLATED & VERIFIED)
    # =========================================================================
    # Nguồn tin cậy: Tra cứu customer_id từ customers.json dựa trên related_tickets
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_to_customer: dict[int, str] = {}
    for c in customers_data:
        cid = str(c["customer_id"])
        for tid in c.get("related_tickets", []):
            ticket_to_customer[int(tid)] = cid

    # Tìm tập hợp customer_id hợp lệ gắn liền với các ticket tìm thấy
    target_customer_ids = sorted(
        {ticket_to_customer[tid] for tid in valid_ticket_ids if tid in ticket_to_customer}
    )

    collected_records = []
    for cid in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-verified-ticket",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, reason_read = policy.check(ctx_read)

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
            },
            ledger_path,
        )

        if allow_read:
            try:
                record = tools.read_customer(cid)
                collected_records.append(record)
            except tools.ToolError:
                continue

    # =========================================================================
    # EGRESS POLICY ENFORCEMENT
    # =========================================================================
    # Nếu có chỉ thị injection cố gắng gửi dữ liệu ra bên ngoài (exfiltration)
    if injected is not None:
        ctx_egress = PolicyContext(
            data_classification="restricted",
            request_purpose="exfiltration-attempt",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url}),
                "classification": "restricted",
                "decision": "allow" if allow_egress else "deny",
                "reason": reason_egress,
            },
            ledger_path,
        )

        # Vì allow_egress là False (DENY), tuyệt đối KHÔNG gọi tools.http_post

    return llm.summarize(docs)
