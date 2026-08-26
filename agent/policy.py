"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute.

Rule TỐI THIỂU bắt buộc:
    classification == "restricted" and egress_enabled is True  ->  DENY

reason KHÔNG BAO GIỜ được để trống — cả khi allow=True và allow=False.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str   # "public" | "internal" | "restricted"
    request_purpose: str       # "reconciliation", "support-reply", "summarize-tickets"
    agent_owner: str           # "run-a", "run-b", ...
    delegation_depth: int      # 0 = gọi trực tiếp, >0 = agent gọi agent
    egress_enabled: bool       # run hiện tại có được phép gọi network không


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi thực thi tool.

    Trả về (allow: bool, reason: str).
    """
    # 1. Rule tối thiểu: Không cho phép truy cập dữ liệu restricted khi có quyền egress (chống data exfiltration)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Chặn truy cập dữ liệu restricted khi môi trường có quyền egress (nguy cơ rò rỉ dữ liệu)"

    # 2. Dữ liệu restricted trong môi trường cô lập không có egress
    if context.data_classification == "restricted":
        return True, f"ALLOW: Cho phép truy cập dữ liệu restricted cho {context.agent_owner} với mục đích '{context.request_purpose}' trong môi trường không có egress"

    # 3. Dữ liệu internal
    if context.data_classification == "internal":
        return True, f"ALLOW: Cho phép truy cập dữ liệu internal cho {context.agent_owner} với mục đích '{context.request_purpose}'"

    # 4. Dữ liệu public
    if context.data_classification == "public":
        return True, f"ALLOW: Dữ liệu public được phép truy cập tự do cho mục đích '{context.request_purpose}'"

    # Fallback mặc định
    return False, f"DENY: Phân loại dữ liệu không xác định '{context.data_classification}'"
