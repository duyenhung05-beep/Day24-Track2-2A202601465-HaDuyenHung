"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex-based PII recognizer cho dữ liệu tiếng Việt:
- VN_CCCD: 12 chữ số
- VN_PHONE: 10 chữ số bắt đầu bằng 0
- VN_BANK_ACCOUNT: 8-16 chữ số, sau từ khoá STK / số tài khoản
- EMAIL: định dạng email chuẩn
"""
from __future__ import annotations

import re

# Regex patterns
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BANK_RE = re.compile(r"(?i)(?:\bSTK|\bsố\s+tài\s+khoản|\btài\s+khoản)\s*[:\s]\s*(\d{8,19})\b")
_CCCD_RE = re.compile(r"\b\d{12}\b")
_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản tiếng Việt.
    
    Trả về danh sách: [{"type": str, "start": int, "end": int}]
    """
    entities: list[dict] = []
    occupied_spans: list[tuple[int, int]] = []

    def _is_overlapping(start: int, end: int) -> bool:
        for s, e in occupied_spans:
            if start < e and s < end:
                return True
        return False

    # 1. EMAIL
    for match in _EMAIL_RE.finditer(text):
        start, end = match.span()
        entities.append({"type": "EMAIL", "start": start, "end": end})
        occupied_spans.append((start, end))

    # 2. BANK ACCOUNT (ưu tiên nhận diện khi có keyword STK / số tài khoản)
    for match in _BANK_RE.finditer(text):
        # group 1 là dãy số tài khoản
        start, end = match.span(1)
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied_spans.append((start, end))

    # 3. CCCD (12 chữ số)
    for match in _CCCD_RE.finditer(text):
        start, end = match.span()
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied_spans.append((start, end))

    # 4. PHONE (10 chữ số bắt đầu bằng 0)
    for match in _PHONE_RE.finditer(text):
        start, end = match.span()
        if not _is_overlapping(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied_spans.append((start, end))

    # Sắp xếp theo thứ tự start index
    entities.sort(key=lambda e: (e["start"], e["end"]))
    return entities


def redact(text: str) -> str:
    """Ẩn danh toàn bộ PII tìm thấy bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    if not entities:
        return text

    # Thay thế từ cuối văn bản về đầu để không làm lệch offset
    chars = list(text)
    for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{ent['type']}]"
        chars[ent["start"] : ent["end"]] = list(replacement)

    return "".join(chars)
