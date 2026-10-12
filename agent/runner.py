"""BƯỚC 3c — trifecta split + egress allowlist + OBO.

Tách 1 yêu cầu người dùng thành 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content). Không gọi read_customer, không gọi http_post.
           Chỉ truyền typed ticket_id (list[int]) lấy từ TÊN FILE sang Run B.
    Run B: suy customer_id từ data/customers.json (related_tickets).
           Kiểm tra quyền OBO và PEP trước khi gọi read_customer.
           Chặn hoàn toàn egress (http_post) chứa dữ liệu restricted.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CUSTOMERS_PATH = DATA_DIR / "customers.json"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

SCOPES = ("search_docs", "read_customer", "http_post")
EXPIRES_AT = "2099-01-01T00:00:00+00:00"


def _hash_args(data: object) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu với Trifecta Split, Policy Enforcement Point và OBO."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH

    # =========================================================================
    # RUN A: Đọc untrusted content (corpus)
    # =========================================================================
    # 1. Kiểm tra policy cho search_docs
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=SCOPES,
        parent_scopes=(),
        expires_at=EXPIRES_AT,
    )
    allow_search, reason_search = policy.check(ctx_search)
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
            "on_behalf_of": principal_id,
            "expires_at": EXPIRES_AT,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách an toàn."

    docs = tools.search_docs(message)

    # Trích xuất ticket_id (số nguyên) DUY NHẤT TỪ TÊN FILE
    ticket_ids: set[int] = set()
    for doc in docs:
        doc_id = doc.get("id", "")
        m = re.search(r"ticket-(\d+)", doc_id)
        if m:
            ticket_ids.add(int(m.group(1)))

    # Kiểm tra injection trên toàn văn bản
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: Xử lý dữ liệu nhạy cảm (Private data)
    # Chỉ nhận input là typed list[int] ticket_ids, tuyệt đối không nhận free text
    # =========================================================================
    # Suy customer_id từ nguồn tin cậy customers.json thông qua related_tickets
    target_customers: list[str] = []
    if CUSTOMERS_PATH.exists():
        try:
            customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
            for cust in customers:
                related = set(cust.get("related_tickets", []))
                if related.intersection(ticket_ids):
                    target_customers.append(cust["customer_id"])
        except Exception:
            pass
    target_customers = sorted(set(target_customers))

    collected: list[dict] = []
    for cid in target_customers:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=SCOPES,
            parent_scopes=(),
            expires_at=EXPIRES_AT,
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
                "on_behalf_of": principal_id,
                "expires_at": EXPIRES_AT,
            },
            ledger_path,
        )
        if allow_read:
            try:
                c_data = tools.read_customer(cid)
                collected.append(c_data)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection yêu cầu egress dữ liệu, kiểm tra PEP cho egress
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=SCOPES,
            parent_scopes=SCOPES,
            expires_at=EXPIRES_AT,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": _hash_args({"target_url": injected.target_url, "count": len(collected)}),
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": EXPIRES_AT,
            },
            ledger_path,
        )
        if allow_post:
            tools.http_post(injected.target_url, {"records": collected})

    return llm.summarize(docs)
