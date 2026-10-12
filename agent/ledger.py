"""BƯỚC 3d — audit ledger append-only, tamper-evident.

JSONL, mỗi tool call một dòng.

Interface bắt buộc:
    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry_without_hash: dict) -> str:
    content = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Append a tool call entry to the hash-chained ledger."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", "0" * 64)
            except Exception:
                pass

    new_entry = dict(entry)
    new_entry.pop("hash", None)
    new_entry["prev_hash"] = prev_hash
    new_entry["hash"] = _compute_hash(new_entry)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(new_entry, ensure_ascii=False) + "\n")

    return new_entry


def verify(path: Path) -> bool:
    """Verify tamper-evidence and audit completeness of the ledger file."""
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Mỗi dòng phải có non-empty reason
        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        # Kiểm tra prev_hash liên kết đúng
        if entry.get("prev_hash") != expected_prev:
            return False

        stored_hash = entry.get("hash")
        copy_entry = dict(entry)
        copy_entry.pop("hash", None)
        computed = _compute_hash(copy_entry)

        if stored_hash != computed:
            return False

        expected_prev = stored_hash

    return True
