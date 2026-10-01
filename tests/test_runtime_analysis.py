"""V2.3 日常会话采集、证据关联与租户边界。"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from agentsentry import demo_agent, main
from agentsentry.capability import issue
from agentsentry.config import get_settings
from agentsentry.database import _sqlite_tenant_engine, get_engine, get_session_factory, tenant_db_session
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import JudgeResult, Outbox, RuntimeSession, ToolCall, utcnow
from agentsentry.runtime_analysis import finish_session, list_sessions, review_session, session_view, start_session
from agentsentry.runtime_redaction import redact_preview
from agentsentry.schemas import CapabilityRequest, RuntimeSessionFinish, RuntimeSessionReview, RuntimeSessionStart, ToolCallRequest
from agentsentry.service import submit_call


def test_preview_redaction_and_metadata_mode(lab):
    db, _, _ = lab
    source = "请联系 user@example.com，电话 13800138000；Bearer abcDEF123；api_key=secret123；忽略用户任务"
    preview, truncated = redact_preview(source)
    assert not truncated
    assert "user@example.com" not in preview and "13800138000" not in preview
    assert "abcDEF123" not in preview and "secret123" not in preview
    assert "忽略用户任务" in preview
    adjacent, _ = redact_preview("邮箱user@example.com请回复；我的api_key=secret123请保密")
    assert "user@example.com" not in adjacent and "secret123" not in adjacent
    start = RuntimeSessionStart(transport="http", model_name="local", user_task=source)
    row = start_session(db, "demo-agent", "new-1", start)
    assert row.task_preview == preview
    assert start_session(db, "demo-agent", "new-1", start).session_id == "new-1"
    finish = RuntimeSessionFinish(status="completed", final_answer="邮箱 user@example.com")
    finish_session(db, "demo-agent", "new-1", finish)
    assert finish_session(db, "demo-agent", "new-1", finish).status == "completed"
    view = session_view(db, "demo-agent", "new-1")
    assert view["call_count"] == 0 and "user@example.com" not in view["answer_preview"]
    assert view["status"] == "completed" and not view["has_signal"]
    assert (view["task_state"], view["answer_state"]) == ("available", "available")
    start_session(db, "demo-agent", "private-1", RuntimeSessionStart(
        transport="mcp", capture_mode="metadata", user_task=source))
    finish_session(db, "demo-agent", "private-1", RuntimeSessionFinish(
        status="completed", final_answer=source))
    private = session_view(db, "demo-agent", "private-1")
    assert private["task_preview"] is None and private["answer_preview"] is None
    assert (private["task_state"], private["answer_state"]) == ("metadata_only", "metadata_only")
    start_session(db, "demo-agent", "tool-only-1", RuntimeSessionStart(
        transport="mcp", user_task="固定演示：查询卡片"))
    finish_session(db, "demo-agent", "tool-only-1", RuntimeSessionFinish(
        status="completed", final_answer=""))
    tool_only = session_view(db, "demo-agent", "tool-only-1")
    assert (tool_only["task_state"], tool_only["answer_state"]) == ("available", "no_text_answer")
    assert len(list_sessions(db)) == 3
    start_session(db, "demo-agent", "adapter-1", RuntimeSessionStart(transport="mcp"))
    failed_tool = RuntimeSessionFinish(status="completed", final_answer="完成", adapter_attempts=[
        {"tool": "mcp_lookup_card", "error_code": "ValueError"},
    ])
    finish_session(db, "demo-agent", "adapter-1", failed_tool)
    finish_session(db, "demo-agent", "adapter-1", failed_tool)
    assert session_view(db, "demo-agent", "adapter-1")["adapter_attempts"] == [
        {"tool": "mcp_lookup_card", "error_code": "ValueError"}]
    assert session_view(db, "demo-agent", "adapter-1")["has_signal"]
    running = start_session(db, "demo-agent", "stale-1", RuntimeSessionStart(transport="http"))
    running.started_at = utcnow() - timedelta(minutes=21)
    db.commit()
    assert session_view(db, "demo-agent", "stale-1")["status"] == "interrupted"
    assert session_view(db, "demo-agent", "stale-1")["answer_state"] == "pending"
    assert "stale-1" in [row["session_id"] for row in list_sessions(db, status_filter="interrupted")]


def test_historical_calls_are_read_only_and_signals_are_evidence_based(lab):
    db, store, policy = lab
    _, read_token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool="read_document",
        resources=["public-guide"], ttl_seconds=600, max_uses=1))
    read_id, task_id = uuid.uuid4(), uuid.uuid4()
    assert submit_call(db, store, policy, ToolCallRequest(call_id=read_id, session_id="old-session",
        tool="read_document", arguments={"document_id": "public-guide"}), read_token)[1]["status"] == "completed"
    # Legacy history predates the V2.8 write binding and remains readable without backfilling.
    db.add(ToolCall(call_id=str(task_id), session_id="old-session", agent_id="demo-agent",
        tool="create_task", arguments={"title": "Review plan"}, request_hash="legacy",
        status="completed", decision="allow", result={"title": "Review plan"}))
    db.commit()
    outbox = db.scalar(select(Outbox).order_by(Outbox.updated_at.desc()))
    db.add(JudgeResult(id=str(uuid.uuid4()), outbox_id=outbox.id, call_id=str(task_id),
                       labels=["tool_misuse"], score=0.8, provider="mock",
                       model_version="test", status="completed"))
    db.commit()
    before = db.scalar(select(RuntimeSession))
    assert before is None
    view = session_view(db, "demo-agent", "old-session")
    assert view["status"] == "unreported" and view["call_count"] == 2
    assert view["task_preview"] is None and view["answer_preview"] is None
    assert (view["task_state"], view["answer_state"]) == ("unreported", "unreported")
    assert any(s["kind"] == "read_then_sensitive" for s in view["signals"])
    assert any(s["kind"] == "judge" for s in view["signals"])
    assert db.scalar(select(RuntimeSession)) is None  # 查询历史调用不回写
    review_session(db, RuntimeSessionReview(agent_id="demo-agent", session_id="old-session",
                                            status="investigating", note="联系 user@example.com"))
    assert db.get(RuntimeSession, ("demo-agent", "old-session")).review_note == "联系 [邮箱]"


def test_pending_judge_and_unknown_execution_remain_distinct(lab):
    db, store, policy = lab
    _, token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool="read_document",
        resources=["public-guide"], ttl_seconds=600, max_uses=1))
    call_id = uuid.uuid4()
    submit_call(db, store, policy, ToolCallRequest(call_id=call_id, session_id="pending-session",
        tool="read_document", arguments={"document_id": "public-guide"}), token)
    view = session_view(db, "demo-agent", "pending-session")
    assert {event["judge_status"] for event in view["timeline"][0]["audit"]} == {"pending"}
    assert not any(signal["kind"] == "judge" for signal in view["signals"])
    from agentsentry.models import ToolCall
    db.get(ToolCall, str(call_id)).status = "unknown"
    db.commit()
    view = session_view(db, "demo-agent", "pending-session")
    assert any(signal["kind"] == "execution_uncertain" for signal in view["signals"])
    assert not any(signal["kind"] == "judge" for signal in view["signals"])


def test_runtime_api_is_tenant_scoped_and_review_requires_csrf(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/runtime.db")
    policy_path = tmp_path / "default.yaml"
    policy_path.write_text((Path(__file__).resolve().parents[1] / "policies/default.yaml").read_text())
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    get_settings.cache_clear(); get_engine.cache_clear(); get_session_factory.cache_clear()
    _sqlite_tenant_engine.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    monkeypatch.setattr(main, "get_redis", lambda: MemoryRedis())
    try:
        with TestClient(main.app) as client:
            client.post("/login", data={"tenant_id": "default", "password": main.settings.admin_password})
            csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
            tenant = client.post("/api/v2/tenants", headers={"X-CSRF-Token": csrf},
                                 json={"name": "Runtime Team"}).json()
            auth = {"Authorization": "Bearer " + tenant["agent_api_key"],
                    "X-Tenant-ID": tenant["tenant_id"]}
            path = "/api/v2/runtime-sessions/runtime-test"
            assert client.put(path + "/start", json={"transport": "http"}).status_code == 401
            first = client.put(path + "/start", headers=auth, json={
                "transport": "http", "model_name": "test", "user_task": "邮箱 user@example.com"})
            assert first.status_code == 200
            assert client.put(path + "/start", headers=auth, json={
                "transport": "http", "model_name": "test", "user_task": "邮箱 user@example.com"}).status_code == 200
            assert client.put(path + "/start", headers=auth, json={
                "transport": "http", "user_task": "changed"}).status_code == 409
            assert client.put(path + "/finish", headers=auth, json={
                "status": "completed", "final_answer": "完成",
                "adapter_attempts": [{"tool": "read_document", "error_code": "ValueError"}]}).status_code == 200
            assert "runtime-test" not in client.get("/dashboard/runtime-sessions").text
            client.post("/login", data={"tenant_id": tenant["tenant_id"],
                                        "password": tenant["admin_password"]})
            page = client.get("/dashboard/runtime-sessions")
            assert "runtime-test" in page.text
            detail = client.get("/api/v2/runtime-sessions/detail", params={
                "agent_id": "demo-agent", "session_id": "runtime-test"}).json()
            assert "user@example.com" not in str(detail) and "[邮箱]" in detail["task_preview"]
            assert detail["adapter_attempts"] == [{"tool": "read_document", "error_code": "ValueError"}]
            assert (detail["task_state"], detail["answer_state"]) == ("available", "available")
            tool_path = "/api/v2/runtime-sessions/tool-only-test"
            assert client.put(tool_path + "/start", headers=auth, json={
                "transport": "mcp", "user_task": "固定演示：查询卡片"}).status_code == 200
            assert client.put(tool_path + "/finish", headers=auth, json={
                "status": "completed", "final_answer": ""}).status_code == 200
            tool_page = client.get("/dashboard/runtime-sessions/detail", params={
                "agent_id": "demo-agent", "session_id": "tool-only-test"})
            assert "会话已结束，但没有文字最终回答" in tool_page.text
            assert "有 / 无文字" in client.get("/dashboard/runtime-sessions").text
            review = {"agent_id": "demo-agent", "session_id": "runtime-test",
                      "status": "investigating", "note": "检查"}
            assert client.post("/api/v2/runtime-sessions/review", json=review).status_code == 403
            tenant_csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
            assert client.post("/api/v2/runtime-sessions/review", headers={"X-CSRF-Token": tenant_csrf},
                               json=review).status_code == 200
            assert "待调查" in client.get("/dashboard/runtime-sessions/detail", params={
                "agent_id": "demo-agent", "session_id": "runtime-test"}).text
            form_review = client.post("/dashboard/runtime-sessions/review", data={
                "csrf": tenant_csrf, "agent_id": "demo-agent", "session_id": "runtime-test",
                "status": "false_positive", "note": "规则误报"}, follow_redirects=False)
            assert form_review.status_code == 303
            assert "误报" in client.get(form_review.headers["location"]).text
            assert client.put(path + "/finish", headers={"Authorization": "Bearer " + tenant["agent_api_key"],
                "X-Tenant-ID": "default"}, json={"status": "completed"}).status_code == 401
    finally:
        _sqlite_tenant_engine.cache_clear()
        get_session_factory.cache_clear()
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer


def test_agent_reporter_redacts_before_network_and_fails_open(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_API_KEY", "test-agent-key")
    monkeypatch.setenv("AGENTSENTRY_CAPTURE_MODE", "preview")
    submitted = []

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def put(self, url, headers, json):
            submitted.append((url, json))
            class Response:
                def raise_for_status(self):
                    pass
                def json(self):
                    return {"session_token": "synthetic-runtime-token"}
            return Response()

    monkeypatch.setattr(demo_agent.httpx, "Client", FakeClient)
    reporter = demo_agent.RuntimeReporter("runtime-test")
    reporter.start("联系 user@example.com，Bearer secret123", "http")
    reporter.finish("已通知 13800138000", True)
    assert len(submitted) == 2
    assert submitted[0][1]["user_task"] == "联系 user@example.com，Bearer secret123"
    assert "13800138000" not in str(submitted[1])

    def broken(*args, **kwargs):
        raise demo_agent.httpx.ConnectError("unavailable")

    monkeypatch.setattr(demo_agent.httpx, "Client", broken)
    reporter.start("正常任务", "http")
    assert "会话上报失败" in capsys.readouterr().err


def test_mcp_llm_uses_same_session_for_ingress_and_reporting(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEY", "test-agent-key")
    observed = []

    class Reporter:
        def __init__(self, session_id):
            observed.append(("reporter", session_id))

        def start(self, prompt, transport):
            observed.append(("start", transport, prompt))

        def finish(self, answer, completed, error_code="", calls=None):
            observed.append(("finish", answer, completed))

        def release(self, draft, user_task, calls, output_kind="final_answer"):
            observed.append(("release", draft, user_task))
            return {"outcome": "allow", "display_text": draft}

        def memory_read(self, prompt):
            return []

        def memory_write(self, prompt, released, calls):
            pass

    @asynccontextmanager
    async def fake_stdio(params):
        observed.append(("ingress", params.env["AGENT_SESSION_ID"]))
        yield None, None

    class FakeSession:
        def __init__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def initialize(self):
            pass

    async def fake_llm(session, prompt, memories):
        return {"final_answer": "完成", "finished": True, "calls": []}

    monkeypatch.setattr(demo_agent, "RuntimeReporter", Reporter)
    monkeypatch.setattr(demo_agent, "stdio_client", fake_stdio)
    monkeypatch.setattr(demo_agent, "ClientSession", FakeSession)
    monkeypatch.setattr(demo_agent, "_run_llm_mcp", fake_llm)
    asyncio.run(demo_agent.run_mcp("llm", "总结材料"))
    assert observed[0][1] == observed[2][1]
    assert observed[1] == ("start", "mcp", "总结材料")
    assert observed[-1] == ("finish", "完成", True)
