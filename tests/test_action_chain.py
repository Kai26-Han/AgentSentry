"""行动链预算须由网关而非 Agent 循环次数决定。"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from agentsentry import main
from agentsentry.action_chain import (AGENT_HOURLY_WRITE_LIMIT, SESSION_WRITE_LIMIT,
                                     TASK_MODEL_LIMIT, TOOL_LIMIT)
from agentsentry.action_chain_lab import CASES, run as run_action_chain_cases
from agentsentry.capability import issue
from agentsentry.config import get_settings
from agentsentry.data_flow import check_model
from agentsentry.database import get_engine, get_session_factory
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import (ActionChainDecision, AuditEvent, Outbox, RuntimeControl,
                                Task, ToolCall)
from agentsentry.runtime_analysis import start_session
from agentsentry.runtime_binding import session_token
from agentsentry.runtime_guard import set_control
from agentsentry.schemas import CapabilityRequest, ModelEgressCheckRequest, RuntimeSessionStart, ToolCallRequest
from agentsentry.service import submit_call
from agentsentry.service import decide_approval


def _session(db, name):
    row = start_session(db, "demo-agent", name, RuntimeSessionStart(
        transport="http", capture_mode="metadata", user_task="核对合成任务"))
    return session_token("default", "demo-agent", row)


def _grant(db, store, tool, resources, uses=100):
    return issue(db, store, CapabilityRequest(agent_id="demo-agent", tool=tool,
        resources=resources, ttl_seconds=600, max_uses=uses))[1]


def _call(db, store, policy, session_id, binding, token, tool, arguments, call_id=None):
    request = ToolCallRequest(call_id=call_id or uuid.uuid4(), session_id=session_id,
                              tool=tool, arguments=arguments)
    return submit_call(db, store, policy, request, token, runtime_token=binding)[1]


def test_gateway_tool_budget_and_replay_do_not_duplicate_effect(lab):
    db, store, policy = lab
    binding = _session(db, "chain-tools")
    token = _grant(db, store, "read_document", ["public-guide"])
    for _ in range(TOOL_LIMIT):
        result = _call(db, store, policy, "chain-tools", binding, token,
                       "read_document", {"document_id": "public-guide"})
        assert result["status"] == "completed"
    extra_id = uuid.uuid4()
    blocked = _call(db, store, policy, "chain-tools", binding, token,
                    "read_document", {"document_id": "public-guide"}, extra_id)
    assert blocked["status"] == "denied" and "tool_budget_exceeded" in blocked["reason"]
    again = _call(db, store, policy, "chain-tools", binding, token,
                  "read_document", {"document_id": "public-guide"}, extra_id)
    assert again == blocked
    assert db.scalar(select(func.count()).select_from(ToolCall).where(
        ToolCall.session_id == "chain-tools")) == TOOL_LIMIT + 1
    event = db.scalar(select(AuditEvent).where(AuditEvent.call_id == str(extra_id),
        AuditEvent.event_type == "action_chain_decision"))
    assert event and db.scalar(select(Outbox).where(Outbox.audit_event_id == event.id))


def test_write_budget_reserves_unknown_and_rolls_across_sessions(lab):
    db, store, policy = lab
    token = _grant(db, store, "create_task", ["main"])
    for index in range(1, AGENT_HOURLY_WRITE_LIMIT + 1):
        name = f"chain-write-{(index - 1) // SESSION_WRITE_LIMIT}"
        binding = _session(db, name)
        item = _call(db, store, policy, name, binding, token,
                     "create_task", {"title": f"Synthetic {index}", "list_id": "main"})
        assert item["status"] == "completed"
        if index == 1:
            db.get(ToolCall, item["call_id"]).status = "unknown"
            db.commit()
    name = "chain-write-last"
    binding = _session(db, name)
    blocked = _call(db, store, policy, name, binding, token,
                    "create_task", {"title": "Over agent budget", "list_id": "main"})
    assert blocked["status"] == "denied"
    assert "agent_write_budget_exceeded" in blocked["reason"]
    assert db.scalar(select(func.count()).select_from(Task)) == AGENT_HOURLY_WRITE_LIMIT


def test_distinct_denied_resources_pause_until_admin_resumes(lab):
    db, store, policy = lab
    name = "chain-probe"
    binding = _session(db, name)
    token = _grant(db, store, "read_document", ["public-guide"])
    for index in range(4):
        denied = _call(db, store, policy, name, binding, token,
                       "read_document", {"document_id": f"ungranted-{index}"})
        assert denied["status"] == "denied"
    assert db.get(RuntimeControl, f"session:demo-agent:{name}").paused
    blocked = _call(db, store, policy, name, binding, token,
                    "read_document", {"document_id": "public-guide"})
    assert blocked["status"] == "denied" and "paused" in blocked["reason"].lower()
    assert db.get(RuntimeControl, f"session:demo-agent:{name}").paused
    set_control(db, "demo-agent", name, False, "已核实为测试误配")
    recovered = _call(db, store, policy, name, binding, token,
                      "read_document", {"document_id": "public-guide"})
    assert recovered["status"] == "completed"


def test_resource_probe_without_capability_still_pauses_bound_session(lab):
    db, store, policy = lab
    name = "chain-no-capability-probe"
    binding = _session(db, name)
    for index in range(4):
        result = _call(db, store, policy, name, binding, "",
                       "read_document", {"document_id": f"ungranted-{index}"})
        assert result["status"] == "denied"
    assert db.get(RuntimeControl, f"session:demo-agent:{name}").paused


def test_model_budget_is_idempotent_and_stops_ninth_send(lab):
    db, _, _ = lab
    name = "chain-model"
    binding = _session(db, name)
    destinations = {"local": "http://127.0.0.1:11434/v1"}
    first = None
    for index in range(TASK_MODEL_LIMIT + 1):
        body = ModelEgressCheckRequest(request_id=uuid.uuid4(), destination_id="local",
            model="fixture", purpose="task", messages=[{"role": "user", "content": "合成问题"}])
        result = check_model(db, "default", "demo-agent", name, binding, body, destinations)
        if index == 0:
            first = (body, result)
        assert result["outcome"] == ("allow" if index < TASK_MODEL_LIMIT else "deny")
        if index == TASK_MODEL_LIMIT:
            assert "model_budget_exceeded" in result["findings"]
            assert result["approved_messages"] == []
    assert check_model(db, "default", "demo-agent", name, binding,
                       first[0], destinations) == first[1]
    assert db.scalar(select(func.count()).select_from(ActionChainDecision).where(
        ActionChainDecision.session_id == name,
        ActionChainDecision.phase == "model:task")) == TASK_MODEL_LIMIT + 1


def test_pending_approvals_reserve_budget_and_rejection_releases_it(lab):
    db, store, policy = lab
    name = "chain-pending"
    binding = _session(db, name)
    token = _grant(db, store, "mcp_record_note", ["demo-notes"])
    pending = []
    for index in range(SESSION_WRITE_LIMIT):
        result = _call(db, store, policy, name, binding, token,
                       "mcp_record_note", {"note_id": f"note-{index}", "text": "合成笔记"})
        assert result["status"] == "pending_approval"
        pending.append(result)
    blocked = _call(db, store, policy, name, binding, token,
                    "mcp_record_note", {"note_id": "over", "text": "不应写入"})
    assert blocked["status"] == "denied"
    assert "session_write_budget_exceeded" in blocked["reason"]
    assert decide_approval(db, pending[0]["approval_id"], "reject")[1]["status"] == "denied"
    replacement = _call(db, store, policy, name, binding, token,
                        "mcp_record_note", {"note_id": "replacement", "text": "合成笔记"})
    assert replacement["status"] == "pending_approval"


def test_action_chain_dashboard_and_api_are_tenant_scoped(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/web.db")
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret,
                                                 salt="agentsentry-admin")
    monkeypatch.setattr(main, "get_redis", lambda: MemoryRedis())
    try:
        with TestClient(main.app) as client:
            assert client.get("/api/v3/action-chains").status_code == 401
            assert client.post("/login", data={
                "password": main.settings.admin_password}).status_code == 200
            started = client.put("/api/v2/runtime-sessions/chain-web/start",
                headers={"Authorization": "Bearer " + main.settings.agent_api_key},
                json={"transport": "http", "capture_mode": "metadata"})
            assert started.status_code == 200
            data = client.get("/api/v3/action-chains").json()["items"]
            assert any(item["session_id"] == "chain-web" for item in data)
            page = client.get("/dashboard/action-chains")
            assert page.status_code == 200 and "会话调查 · 行动链" in page.text
            detail = client.get("/dashboard/runtime-sessions/detail",
                                params={"agent_id": "demo-agent", "session_id": "chain-web"})
            assert detail.status_code == 200 and "action-chain-v1" in detail.text
    finally:
        get_session_factory.cache_clear()
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer


def test_fixed_action_chain_corpus_is_repeatable():
    assert len(CASES) == 30
    report = run_action_chain_cases()
    assert report["stable"] and report["passed"] == 30
    assert report["attacks"] == 20 and report["normals"] == 10
    assert report["forbidden_side_effects"] == report["audit_missing"] == 0
