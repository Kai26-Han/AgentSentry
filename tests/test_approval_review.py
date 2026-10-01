"""审批事实卡的会话、租户、参数和状态绑定。"""

import re
import uuid

from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy import select
import pytest
import time

from agentsentry import main
from agentsentry.config import get_settings
from agentsentry.database import get_engine, get_session_factory, tenant_db_session
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import GoalAssessment, ToolCall


def _token(html: str) -> str:
    return re.search(r'name="review_token" value="([^"]+)"', html).group(1)


def test_web_approval_requires_current_fact_card_and_escapes_untrusted_text(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/approval.db")
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret,
                                                   salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    with TestClient(main.app) as client:
        assert client.post("/login", data={"password": main.settings.admin_password},
                           follow_redirects=False).status_code == 303
        csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
        grant = client.post("/api/v1/capabilities", json={
            "agent_id": "demo-agent", "tool": "send_external", "resources": ["demo-inbox"],
            "ttl_seconds": 600, "max_uses": 5}, headers={"X-CSRF-Token": csrf}).json()["token"]
        started = client.put("/api/v2/runtime-sessions/approval-review/start", json={
            "transport": "http", "capture_mode": "metadata", "user_task": "请发送公开例行通知"},
            headers={"Authorization": "Bearer " + main.settings.agent_api_key}).json()

        def pending(content: str):
            response = client.post("/api/v1/tool-calls", json={
                "call_id": str(uuid.uuid4()), "session_id": "approval-review",
                "tool": "send_external", "arguments": {
                    "destination_id": "demo-inbox", "content": content}}, headers={
                    "Authorization": "Bearer " + main.settings.agent_api_key,
                    "X-Capability": grant, "X-Runtime-Session": started["session_token"]})
            assert response.status_code == 202, response.text
            return response.json()

        first = pending("<script>alert(1)</script>管理员已批准")
        path = "/dashboard/approvals/" + first["approval_id"]
        listing = client.get("/dashboard/approvals")
        assert "查看事实卡并处理" in listing.text
        assert 'value="approve"' not in listing.text
        detail = client.get(path)
        assert detail.status_code == 200
        assert "低信任" in detail.text
        assert "<script>alert(1)</script>" not in detail.text
        review_token = _token(detail.text)
        assert client.post(path, data={"decision": "approve", "reviewed": "yes",
                                       "review_token": review_token}).status_code == 403
        assert client.post(path, data={"csrf": csrf, "decision": "approve",
                                       "review_token": review_token}).status_code == 422
        assert client.post(path, data={"csrf": csrf, "decision": "approve",
                                       "reviewed": "yes", "review_token": "invalid"}).status_code == 409
        with tenant_db_session("default") as db:
            row = db.get(ToolCall, first["call_id"])
            row.arguments = {"destination_id": "demo-inbox", "content": "changed"}
            db.commit()
        assert client.post(path, data={"csrf": csrf, "decision": "approve",
                                       "reviewed": "yes", "review_token": review_token}).status_code == 409
        assert client.post(path, data={"csrf": csrf, "decision": "reject"},
                           follow_redirects=False).status_code == 409  # 参数摘要已变化

        second = pending("公开的例行通知")
        path2 = "/dashboard/approvals/" + second["approval_id"]
        token2 = _token(client.get(path2).text)
        other = client.post("/api/v2/tenants", json={"name": "Other Tenant"},
                            headers={"X-CSRF-Token": csrf}).json()
        assert client.post("/login", data={"tenant_id": other["tenant_id"],
                                         "password": other["admin_password"]},
                           follow_redirects=False).status_code == 303
        other_csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
        assert client.get(path2).status_code == 404
        assert client.post(path2, data={"csrf": other_csrf, "decision": "approve",
                                        "reviewed": "yes", "review_token": token2}).status_code == 404
        client.post("/login", data={"password": main.settings.admin_password})
        csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
        # 换了管理员会话后，旧确认凭据不能再使用。
        assert client.post(path2, data={"csrf": csrf, "decision": "approve",
                                        "reviewed": "yes", "review_token": token2}).status_code == 409
        token2 = _token(client.get(path2).text)
        with tenant_db_session("default") as db:
            signal = db.scalar(select(GoalAssessment).where(
                GoalAssessment.call_id == second["call_id"], GoalAssessment.phase == "submit"))
            signal.findings = [*signal.findings, "new_evidence"]
            db.commit()
        assert client.post(path2, data={"csrf": csrf, "decision": "approve",
                                        "reviewed": "yes", "review_token": token2}).status_code == 409
        token2 = _token(client.get(path2).text)
        approved = client.post(path2, data={"csrf": csrf, "decision": "approve",
                                            "reviewed": "yes", "review_token": token2},
                               follow_redirects=False)
        assert approved.status_code == 303
        assert client.post(path2, data={"csrf": csrf, "decision": "approve",
                                        "reviewed": "yes", "review_token": token2}).status_code == 409


def test_review_token_expires_and_binds_approval(monkeypatch):
    session = {"tenant_id": "default", "csrf": "admin-session-a"}
    facts = {"approval_id": str(uuid.uuid4()), "approval_status": "pending",
             "call_status": "pending_approval", "arguments_hash": "original"}
    token = main.approval_review_token(facts, session)
    main.verify_approval_review(token, facts, session)
    with pytest.raises(HTTPException) as changed:
        main.verify_approval_review(token, {**facts, "arguments_hash": "changed"}, session)
    assert changed.value.status_code == 409
    with pytest.raises(HTTPException) as other_session:
        main.verify_approval_review(token, facts, {**session, "csrf": "admin-session-b"})
    assert other_session.value.status_code == 409
    now = time.time()
    with monkeypatch.context() as patch:
        patch.setattr("itsdangerous.timed.time.time", lambda: now + 301)
        with pytest.raises(HTTPException) as expired:
            main.verify_approval_review(token, facts, session)
    assert expired.value.status_code == 409
