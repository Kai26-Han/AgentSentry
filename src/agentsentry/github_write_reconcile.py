"""只读核对 GitHub Issue 后，补记一次已获批准但结果为 unknown 的写入。"""

import argparse
import re
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from .config import get_settings
from .database import tenant_db_session
from .mcp_remote import _validate_network
from .models import Approval, AuditEvent, ToolCall
from .service import audit, canonical_hash


TOOL = "github_mcp_create_test_issue"


def _eligible(call: ToolCall, approval: Approval | None, has_unknown_audit: bool,
              repository: str) -> bool:
    args = call.arguments
    return bool(
        call.tool == TOOL and call.status == "unknown" and
        call.decision == "require_approval" and
        call.policy_rule == "github_test_issue_needs_review" and
        approval and approval.status == "approved" and
        approval.arguments_hash == canonical_hash(args) and
        call.request_hash == canonical_hash({
            "session_id": call.session_id, "agent_id": call.agent_id,
            "tool": call.tool, "arguments": args,
        }) and has_unknown_audit and
        args.get("repository") == repository and
        isinstance(args.get("title"), str) and
        args["title"].startswith("[AgentSentry Test] ") and
        isinstance(args.get("body"), str) and len(args["body"]) <= 500
    )


def _lookup_exact_issue(token: str, repository: str, arguments: dict,
                        call_created_at: datetime) -> dict:
    """只允许 GET；唯一标题、完整正文和调用时间窗均须吻合。"""
    url = f"https://api.github.com/repos/{repository}/issues"
    _validate_network(url)
    with httpx.Client(headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
    }, timeout=15, follow_redirects=False, trust_env=False) as client:
        response = client.get(url, params={"state": "all", "per_page": 100})
        response.raise_for_status()
        if len(response.content) > 262_144:
            raise RuntimeError("GitHub Issue 列表超出核对上限")
        values = response.json()
    if not isinstance(values, list) or len(values) >= 100:
        raise RuntimeError("GitHub Issue 列表不完整；无法安全核对")
    matches = [value for value in values if isinstance(value, dict) and
               value.get("title") == arguments["title"] and
               value.get("body") == arguments["body"] and
               "pull_request" not in value]
    if len(matches) != 1:
        raise RuntimeError("GitHub 上没有唯一匹配原始审批参数的 Issue")
    issue = matches[0]
    number, issue_id = issue.get("number"), issue.get("id")
    expected_url = f"https://github.com/{repository}/issues/{number}"
    created_raw = issue.get("created_at")
    if not isinstance(created_raw, str):
        raise RuntimeError("GitHub Issue 缺少创建时间")
    created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
    called = call_created_at.replace(tzinfo=timezone.utc) if call_created_at.tzinfo is None else call_created_at
    if (type(number) is not int or number <= 0 or type(issue_id) is not int or issue_id <= 0 or
            issue.get("html_url") != expected_url or
            created < called - timedelta(minutes=2) or created > datetime.now(timezone.utc) + timedelta(minutes=2)):
        raise RuntimeError("GitHub Issue 身份或创建时间不匹配")
    return {"issue_id": str(issue_id), "issue_number": number,
            "html_url": expected_url, "title": arguments["title"]}


def reconcile(call_id: str) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", call_id):
        raise ValueError("call_id 格式错误")
    settings = get_settings()
    if not settings.agentsentry_github_mcp_write_enabled:
        raise RuntimeError("GitHub 受控写入配置未启用")
    with tenant_db_session("default") as session:
        call = session.get(ToolCall, call_id)
        if call is None:
            raise RuntimeError("原始调用不存在")
        approval = session.scalar(select(Approval).where(Approval.call_id == call_id))
        unknown = session.scalar(select(AuditEvent.id).where(
            AuditEvent.call_id == call_id, AuditEvent.event_type == "tool_unknown"))
        if not _eligible(call, approval, bool(unknown), settings.github_mcp_test_repo):
            raise RuntimeError("原始调用不满足只读核对条件")
        arguments = dict(call.arguments)
        created_at = call.created_at
    result = _lookup_exact_issue(settings.github_mcp_write_pat,
                                 settings.github_mcp_test_repo, arguments, created_at)
    result["_remote"] = {"endpoint_id": "github", "protocol": "streamable-http",
                         "manifest_sha256": settings.github_mcp_create_issue_schema_sha256}
    with tenant_db_session("default") as session:
        call = session.scalar(select(ToolCall).where(ToolCall.call_id == call_id).with_for_update())
        approval = session.scalar(select(Approval).where(Approval.call_id == call_id))
        unknown = session.scalar(select(AuditEvent.id).where(
            AuditEvent.call_id == call_id, AuditEvent.event_type == "tool_unknown"))
        if not call or not _eligible(call, approval, bool(unknown), settings.github_mcp_test_repo):
            raise RuntimeError("核对期间调用状态发生变化，未更新")
        if call.arguments != arguments:
            raise RuntimeError("核对期间调用参数发生变化，未更新")
        call.status = "completed"
        call.result = result
        call.reason = "GitHub 只读核对确认已创建；原返回解析失败"
        audit(session, call_id, "tool_result", {
            "tool": TOOL, "status": "completed", "arguments": arguments,
            "result": result, "reconciled_after_unknown": True,
            "remote_endpoint_id": "github", "remote_protocol": "streamable-http",
            "remote_manifest_sha256": settings.github_mcp_create_issue_schema_sha256,
        })
        session.commit()
    return {"call_id": call_id, "status": "completed", "issue_number": result["issue_number"],
            "html_url": result["html_url"], "reconciled_after_unknown": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--call-id", required=True)
    args = parser.parse_args()
    print(reconcile(args.call_id))


if __name__ == "__main__":
    main()
