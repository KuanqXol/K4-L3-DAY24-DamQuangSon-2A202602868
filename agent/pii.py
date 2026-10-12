"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store.

Interface bắt buộc:
    detect(text: str) -> list[dict]
    redact(text: str) -> str
"""
from __future__ import annotations

import re

# Email: local@domain.tld
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Bank Account: 8-16 digits preceded by STK / Số tài khoản / tài khoản / TK
_BANK_PREFIX_RE = re.compile(r"\b(?:STK|Số tài khoản|số tài khoản|tài khoản|TK|Tk)\s+(\d{8,16})\b", re.IGNORECASE)

# CCCD: 12 digits
_CCCD_RE = re.compile(r"\b\d{12}\b")

# Phone: 10 digits starting with 0
_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Detect PII entities in text: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    def is_free(start: int, end: int) -> bool:
        return not any(max(start, o_start) < min(end, o_end) for o_start, o_end in occupied)

    # 1. Email
    for m in _EMAIL_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "EMAIL", "start": start, "end": end})
            occupied.append((start, end))

    # 2. Bank account (preceded by STK / tài khoản) - capture group 1
    for m in _BANK_PREFIX_RE.finditer(text):
        start, end = m.span(1)
        if is_free(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.append((start, end))

    # 3. CCCD (12 digits)
    for m in _CCCD_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.append((start, end))

    # 4. Phone (10 digits starting with 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.span()
        if is_free(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.append((start, end))

    entities.sort(key=lambda x: (x["start"], x["end"]))
    return entities


def redact(text: str) -> str:
    """Redact detected PII entities with [REDACTED_<TYPE>]."""
    ents = detect(text)
    # Replace from back to front to preserve character offsets
    for e in sorted(ents, key=lambda x: x["start"], reverse=True):
        tag = f"[REDACTED_{e['type']}]"
        text = text[: e["start"]] + tag + text[e["end"] :]
    return text
