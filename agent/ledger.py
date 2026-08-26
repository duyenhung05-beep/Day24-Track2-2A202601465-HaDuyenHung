"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

Sổ cái kiểm toán bất biến (Hash chain SHA256) ghi nhận mọi tool call.
Mỗi dòng là 1 JSON entry trong ledger.jsonl.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def _compute_hash(record_without_hash: dict) -> str:
    """Tính SHA256 từ nội dung dict (đã sort keys để đảm bảo tính tất định)."""
    serialized = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào ledger với chuỗi băm tamper-evident.
    
    Tự động thêm prev_hash và hash.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Xác định prev_hash từ dòng cuối cùng của file hiện tại
    prev_hash = GENESIS_HASH
    if path.exists() and path.stat().st_size > 0:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            last_line = lines[-1].strip()
            if last_line:
                last_record = json.loads(last_line)
                prev_hash = last_record.get("hash", GENESIS_HASH)

    # 2. Chuẩn bị bản ghi và thêm prev_hash
    record = dict(entry)
    record["prev_hash"] = prev_hash

    # 3. Tính hash cho bản ghi (không bao gồm trường 'hash')
    record_hash = _compute_hash(record)
    record["hash"] = record_hash

    # 4. Ghi nối tiếp vào file JSONL
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của toàn bộ sổ cái ledger.
    
    Trả về True nếu:
      - Mọi dòng đều có `reason` không rỗng
      - `prev_hash` của dòng n khớp với `hash` của dòng n-1 (dòng đầu là '0'*64)
      - `hash` của dòng n khớp với giá trị băm tính lại từ nội dung dòng đó
    """
    path = Path(path)
    if not path.exists():
        return True

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return True

    lines = text.splitlines()
    expected_prev_hash = GENESIS_HASH

    for line_num, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False

        # Kiểm tra reason không được rỗng
        reason = record.get("reason")
        if not reason or not str(reason).strip():
            return False

        # Kiểm tra prev_hash
        stored_prev_hash = record.get("prev_hash")
        if stored_prev_hash != expected_prev_hash:
            return False

        # Kiểm tra hash của dòng
        stored_hash = record.get("hash")
        if not stored_hash:
            return False

        record_to_hash = {k: v for k, v in record.items() if k != "hash"}
        calculated_hash = _compute_hash(record_to_hash)

        if calculated_hash != stored_hash:
            return False

        expected_prev_hash = stored_hash

    return True
