"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call.

Interface bắt buộc:
    check(context: PolicyContext) -> tuple[bool, str]
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_PATH = DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        try:
            return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Evaluate policy for the given PolicyContext.
    
    Always returns (allow, reason) where reason is non-empty.
    """
    # 1. Rule tối thiểu: data restricted + egress enabled -> Luôn DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress network access is strictly prohibited for restricted data"

    # 2. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp_str = context.expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(exp_str)
            now_dt = datetime.now(timezone.utc)
            if now_dt > exp_dt:
                return False, f"Context expired at {context.expires_at}"
        except Exception:
            return False, "Invalid expires_at format"

    # 3. Kiểm tra principal (nếu có principal_id)
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"Unknown principal: '{context.principal_id}'"

        p_info = principals[context.principal_id]
        p_tools = set(p_info.get("allowed_tools", []))
        p_purposes = set(p_info.get("purposes", []))

        # Kiểm tra mục đích (purpose)
        if context.request_purpose and context.request_purpose not in p_purposes:
            return False, f"Purpose '{context.request_purpose}' not allowed for principal '{context.principal_id}'"

        # Tính toán effective scopes
        effective_tools = set(p_tools)
        if context.agent_scopes:
            effective_tools = effective_tools.intersection(set(context.agent_scopes))

        # Kiểm tra delegation: không được mở rộng quyền ngoài parent_scopes
        if context.delegation_depth > 0:
            if context.parent_scopes:
                effective_tools = effective_tools.intersection(set(context.parent_scopes))
            else:
                return False, "Delegation depth > 0 requires valid parent_scopes"

        # Kiểm tra tool được yêu cầu
        if context.requested_tool:
            if context.requested_tool not in effective_tools:
                return False, (
                    f"Tool '{context.requested_tool}' not in effective scopes for "
                    f"principal '{context.principal_id}' (depth={context.delegation_depth})"
                )

    return True, f"Policy check passed for tool '{context.requested_tool or 'action'}'"
