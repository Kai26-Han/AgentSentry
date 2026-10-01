"""运行时安全规则需要证明副作用前的处置，而不是只比较规则字符串。"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from agentsentry import main
from agentsentry.capability import issue
from agentsentry.config import get_settings
from agentsentry.database import get_engine, get_session_factory
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import AuditEvent, RuntimeDecision, RuntimeIncident, Task, ToolCall
from agentsentry.runtime_analysis import finish_session, start_session
from agentsentry.runtime_binding import session_token
from agentsentry.runtime_guard import set_control
from agentsentry.runtime_lab import CASES, run as run_runtime_cases
from agentsentry.schemas import CapabilityRequest, RuntimeSessionFinish, RuntimeSessionStart, ToolCallRequest
from agentsentry.service import decide_approval, submit_call


def _grant(db, store, tool, resources, uses=5):
    _, token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool=tool,
        resources=resources, ttl_seconds=600, max_uses=uses))
    return token


def _call(db, store, policy, tool, arguments, token, session_id="runtime-test"):
    row = start_session(db, "demo-agent", session_id, RuntimeSessionStart(
        transport="http", capture_mode="metadata"))
    return submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id=session_id, tool=tool, arguments=arguments), token,
        runtime_token=session_token("default", "demo-agent", row))[1]


def test_normal_read_then_write_stays_allowed(lab):
    db, store, policy = lab
    read = _call(db, store, policy, "read_document", {"document_id": "public-guide"},
                 _grant(db, store, "read_document", ["public-guide"]))
    write = _call(db, store, policy, "create_task", {"title": "Review", "list_id": "main"},
                  _grant(db, store, "create_task", ["main"]))
    assert read["status"] == "completed" and write["status"] == "completed"
    assert "read_then_write_review" in write["runtime_findings"]
    assert db.scalar(select(func.count()).select_from(Task)) == 1


def test_suspicious_source_steps_up_before_side_effect(lab):
    db, store, policy = lab
    read = _call(db, store, policy, "read_document", {"document_id": "injected-guide"},
                 _grant(db, store, "read_document", ["injected-guide"]))
    assert read["status"] == "completed"
    write = _call(db, store, policy, "create_task", {"title": "Unexpected", "list_id": "main"},
                  _grant(db, store, "create_task", ["main"]))
    assert write["status"] == "pending_approval"
    assert "instruction_source_before_write" in write["runtime_findings"]
    assert db.scalar(select(func.count()).select_from(Task)) == 0
    assert db.scalar(select(func.count()).select_from(RuntimeIncident)) >= 1
    assert db.scalar(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.call_id == write["call_id"], AuditEvent.event_type == "runtime_decision")) == 1


def test_uncertain_action_cannot_be_replayed_with_new_call_id(lab):
    db, store, policy = lab
    token = _grant(db, store, "create_task", ["main"], 2)
    first = _call(db, store, policy, "create_task", {"title": "Maybe done", "list_id": "main"}, token)
    db.get(ToolCall, first["call_id"]).status = "unknown"
    db.commit()
    second = _call(db, store, policy, "create_task", {"title": "Maybe done", "list_id": "main"}, token,
                   session_id="new-session")
    assert second["status"] == "denied" and second["runtime_effect"] == "deny"
    assert "uncertain_action_repeat" in second["runtime_findings"]
    assert db.scalar(select(func.count()).select_from(Task)) == 1


def test_admin_pause_rechecks_approved_call(lab):
    db, store, policy = lab
    pending = _call(db, store, policy, "send_external",
        {"destination_id": "demo-inbox", "content": "review"},
        _grant(db, store, "send_external", ["demo-inbox"]))
    assert pending["status"] == "pending_approval"
    set_control(db, "demo-agent", "runtime-test", True, "人工调查")
    _, final = decide_approval(db, pending["approval_id"], "approve")
    assert final["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(RuntimeDecision).where(
        RuntimeDecision.call_id == pending["call_id"])) == 2
    set_control(db, "demo-agent", "runtime-test", False, "调查完毕")
    allowed = _call(db, store, policy, "create_task", {"title": "Safe", "list_id": "main"},
                    _grant(db, store, "create_task", ["main"]))
    assert allowed["status"] == "completed"


def test_enrolled_session_binding_is_required_and_bound_to_identity(lab, monkeypatch):
    db, store, policy = lab
    monkeypatch.setenv("AGENTSENTRY_RUNTIME_BINDING_REQUIRED", "true")
    get_settings.cache_clear()
    try:
        row = start_session(db, "demo-agent", "bound", RuntimeSessionStart(transport="http"))
        token = session_token("default", "demo-agent", row)
        grant = _grant(db, store, "create_task", ["main"], 5)
        def request(session_id):
            return ToolCallRequest(call_id=uuid.uuid4(), session_id=session_id,
                tool="create_task", arguments={"title": "Bound", "list_id": "main"})
        assert submit_call(db, store, policy, request("bound"), grant)[1]["status"] == "denied"
        assert submit_call(db, store, policy, request("wrong"), grant,
            runtime_token=token)[1]["status"] == "denied"
        good = submit_call(db, store, policy, request("bound"), grant,
            runtime_token=token)[1]
        assert good["status"] == "completed"
        finish_session(db, "demo-agent", "bound", RuntimeSessionFinish(status="completed"))
        closed = submit_call(db, store, policy, request("bound"), grant,
            runtime_token=token)[1]
        assert closed["status"] == "denied"
        assert "session_closed" in closed["runtime_findings"]
        assert db.scalar(select(func.count()).select_from(Task)) == 1
    finally:
        get_settings.cache_clear()


def test_fixed_runtime_corpus_blocks_side_effects_without_false_blocks():
    assert len(CASES) == 30
    report = run_runtime_cases("policies/default.yaml")
    assert report["passed"] == report["total"] == 30
    assert report["forbidden_side_effects"] == 0
    assert report["audit_missing"] == 0
    assert report["attack_cases"] == 20 and report["normal_cases"] == 10


def test_runtime_control_api_requires_csrf_and_prevents_tool_effect(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/runtime-api.db")
    get_settings.cache_clear(); get_engine.cache_clear(); get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    try:
        with TestClient(main.app) as client:
            client.post("/login", data={"password": main.settings.admin_password})
            csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
            admin_headers = {"X-CSRF-Token": csrf}
            agent_headers = {"Authorization": "Bearer " + main.settings.agent_api_key}
            started = client.put("/api/v2/runtime-sessions/guard-api/start",
                headers=agent_headers, json={"transport": "http", "capture_mode": "metadata"})
            assert started.status_code == 200
            binding = started.json()["session_token"]
            grant = client.post("/api/v1/capabilities", headers=admin_headers, json={
                "agent_id": "demo-agent", "tool": "create_task", "resources": ["main"],
                "ttl_seconds": 600, "max_uses": 2}).json()["token"]
            control = {"agent_id": "demo-agent", "session_id": "guard-api",
                "scope": "session", "paused": True, "reason": "管理员调查"}
            assert client.post("/api/v2/runtime-controls", json=control).status_code == 403
            assert client.post("/api/v2/runtime-controls", headers=admin_headers,
                json=control).status_code == 200
            request = {"call_id": str(uuid.uuid4()), "session_id": "guard-api",
                "tool": "create_task", "arguments": {"title": "Should not exist", "list_id": "main"}}
            response = client.post("/api/v1/tool-calls", headers={**agent_headers,
                "X-Capability": grant, "X-Runtime-Session": binding}, json=request)
            assert response.json()["status"] == "denied"
            incidents = client.get("/api/v2/runtime-incidents").json()["items"]
            assert any(item["rule_id"] == "administrator_paused" for item in incidents)
            assert "运行时安全规则" in client.get("/dashboard/alerts").text
            assert client.get("/api/v2/runtime-decisions/" + request["call_id"]).json()["items"]
            incident_id = next(item["id"] for item in incidents if item["rule_id"] == "administrator_paused")
            assert client.post(f"/api/v2/runtime-incidents/{incident_id}/ack").status_code == 403
            assert client.post(f"/api/v2/runtime-incidents/{incident_id}/ack",
                headers=admin_headers).json()["status"] == "acknowledged"
            assert client.post("/api/v2/runtime-controls", headers=admin_headers,
                json={**control, "paused": False, "reason": "调查完成"}).status_code == 200
            request["call_id"] = str(uuid.uuid4())
            assert client.post("/api/v1/tool-calls", headers={**agent_headers,
                "X-Capability": grant, "X-Runtime-Session": binding},
                json=request).json()["status"] == "completed"
    finally:
        get_session_factory.cache_clear()
        get_engine().dispose(); get_engine.cache_clear(); get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer
