import uuid
from datetime import timedelta
import pytest

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentsentry.capability import issue, revoke
from agentsentry.models import Approval, AuditEvent, CapabilityGrant, ExternalMessage, Task, ToolCall
from agentsentry.schemas import CapabilityRequest, ToolCallRequest
from agentsentry.service import decide_approval, submit_call
from agentsentry import service
from agentsentry.runtime_analysis import start_session
from agentsentry.runtime_binding import session_token
from agentsentry.schemas import RuntimeSessionStart


def grant(db, store, tool, resources, uses=1):
    item, token = issue(db, store, CapabilityRequest(
        agent_id="demo-agent", tool=tool, resources=resources,
        ttl_seconds=600, max_uses=uses,
    ))
    return item, token


def request(tool, arguments, call_id=None):
    return ToolCallRequest(
        call_id=call_id or uuid.uuid4(), session_id="test-session",
        tool=tool, arguments=arguments,
    )


def bound(db):
    row = start_session(db, "demo-agent", "test-session", RuntimeSessionStart(
        transport="http", capture_mode="metadata"))
    return session_token("default", "demo-agent", row)


def test_scope_and_revocation_deny(lab):
    db, store, policy = lab
    _, token = grant(db, store, "read_document", ["public-guide"])
    _, result = submit_call(db, store, policy, request("read_document", {"document_id": "private-notes"}), token)
    assert result["status"] == "denied"
    item, token = grant(db, store, "read_document", ["private-notes"])
    revoke(db, store, item)
    _, result = submit_call(db, store, policy, request("read_document", {"document_id": "private-notes"}), token)
    assert result["status"] == "denied"


def test_idempotency_and_exhaustion(lab):
    db, store, policy = lab
    binding = bound(db)
    _, token = grant(db, store, "create_task", ["main"])
    call = request("create_task", {"title": "One task", "list_id": "main"})
    status, first = submit_call(db, store, policy, call, token, runtime_token=binding)
    status, second = submit_call(db, store, policy, call, token, runtime_token=binding)
    assert first == second
    assert db.scalar(select(func.count()).select_from(Task)) == 1
    _, third = submit_call(db, store, policy, request("create_task", {"title": "Another", "list_id": "main"}), token,
                           runtime_token=binding)
    assert third["status"] == "denied"
    changed = request("create_task", {"title": "Changed", "list_id": "main"}, call.call_id)
    status, _ = submit_call(db, store, policy, changed, token, runtime_token=binding)
    assert status == 409


def test_approval_is_bound_to_arguments_and_grant(lab):
    db, store, policy = lab
    binding = bound(db)
    _, token = grant(db, store, "send_external", ["demo-inbox"])
    _, pending = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "Meeting summary"},
    ), token, runtime_token=binding)
    assert pending["status"] == "pending_approval"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
    call = db.get(ToolCall, pending["call_id"])
    call.arguments = {"destination_id": "demo-inbox", "content": "Tampered"}
    db.commit()
    status, _ = decide_approval(db, pending["approval_id"], "approve")
    assert status == 409
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0


def test_rejection_and_approval(lab):
    db, store, policy = lab
    binding = bound(db)
    _, token = grant(db, store, "send_external", ["demo-inbox"])
    _, pending = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "Meeting summary"},
    ), token, runtime_token=binding)
    _, result = decide_approval(db, pending["approval_id"], "reject")
    assert result["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
    _, token = grant(db, store, "send_external", ["demo-inbox"])
    _, pending = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "Meeting summary"},
    ), token, runtime_token=binding)
    _, result = decide_approval(db, pending["approval_id"], "approve")
    assert result["status"] == "completed"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 1
    assert db.scalar(select(func.count()).select_from(AuditEvent)) >= 4


def test_policy_deny_precedes_capability(lab):
    db, store, policy = lab
    _, token = grant(db, store, "send_external", ["demo-inbox"])
    _, result = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "api_key=synthetic"},
    ), token)
    assert result["status"] == "denied"
    assert result["policy_rule"] == "prohibit_secret_marker"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0


def test_audit_commit_failure_never_runs_tool(lab, monkeypatch):
    db, store, policy = lab
    binding = bound(db)
    _, token = grant(db, store, "create_task", ["main"])
    original_commit = db.commit

    def unavailable():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(db, "commit", unavailable)
    status, _ = submit_call(db, store, policy, request(
        "create_task", {"title": "Must not exist", "list_id": "main"},
    ), token, runtime_token=binding)
    monkeypatch.setattr(db, "commit", original_commit)
    assert status == 503
    assert db.scalar(select(func.count()).select_from(Task)) == 0


def test_revocation_invalidates_pending_approval(lab):
    db, store, policy = lab
    binding = bound(db)
    item, token = grant(db, store, "send_external", ["demo-inbox"])
    _, pending = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "Meeting summary"},
    ), token, runtime_token=binding)
    revoke(db, store, item)
    _, result = decide_approval(db, pending["approval_id"], "approve")
    assert result["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0


def test_approval_refreshes_preloaded_state(lab):
    """模拟另一管理员等待期间，已预读的审批被第一个事务完成。"""
    db, store, policy = lab
    binding = bound(db)
    _, token = grant(db, store, "send_external", ["demo-inbox"])
    _, pending = submit_call(db, store, policy, request(
        "send_external", {"destination_id": "demo-inbox", "content": "公开通知"}),
        token, runtime_token=binding)
    with Session(db.get_bind(), expire_on_commit=False) as waiting:
        cached_approval = waiting.get(Approval, pending["approval_id"])
        cached_call = waiting.get(ToolCall, pending["call_id"])
        waiting.commit()  # 保留对象缓存；释放 SQLite 的读取事务。
        assert cached_approval.status == "pending"
        assert cached_call.status == "pending_approval"
        assert decide_approval(db, pending["approval_id"], "approve")[1]["status"] == "completed"
        status, _ = decide_approval(waiting, pending["approval_id"], "approve")
        assert status == 409
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 1


def test_revocation_refreshes_cached_grant_when_redis_cleanup_fails(lab, monkeypatch):
    db, store, policy = lab
    binding = bound(db)
    item, token = grant(db, store, "create_task", ["main"])
    assert item.revoked is False
    def unavailable(*args):
        raise RuntimeError("injected Redis cleanup failure")
    monkeypatch.setattr(store, "delete", unavailable)
    with Session(db.get_bind(), expire_on_commit=False) as admin:
        revoke(admin, store, admin.get(CapabilityGrant, item.id))
    _, result = submit_call(db, store, policy, request(
        "create_task", {"title": "吊销后不得创建", "list_id": "main"}),
        token, runtime_token=binding)
    assert result["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(Task)) == 0


@pytest.mark.parametrize("phase", ["submit", "approval"])
def test_expiry_during_security_checks_never_executes(lab, monkeypatch, phase):
    db, store, policy = lab
    binding = bound(db)
    tool = "create_task" if phase == "submit" else "send_external"
    _, token = grant(db, store, tool, ["main" if phase == "submit" else "demo-inbox"])
    args = {"title": "不应创建", "list_id": "main"} if phase == "submit" else {
        "destination_id": "demo-inbox", "content": "不应发送"}
    req = request(tool, args)
    if phase == "approval":
        _, pending = submit_call(db, store, policy, req, token, runtime_token=binding)
        assert pending["status"] == "pending_approval"
    original = service.runtime_evaluate
    future = service.utcnow() + timedelta(hours=1)
    def slow_check(db, call, tenant):
        result = original(db, call, tenant)
        monkeypatch.setattr(service, "utcnow", lambda: future)
        return result
    monkeypatch.setattr(service, "runtime_evaluate", slow_check)
    if phase == "submit":
        _, result = submit_call(db, store, policy, req, token, runtime_token=binding)
    else:
        _, result = decide_approval(db, pending["approval_id"], "approve")
    assert result["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(Task)) == 0
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
