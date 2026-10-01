"""Tenant boundaries across authentication, policy, data, and background events."""

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from agentsentry import dispatcher, main
from agentsentry.config import get_settings
from agentsentry.database import _sqlite_tenant_engine, get_engine, get_session_factory, tenant_db_session
from agentsentry.evaluation import MemoryRedis
from agentsentry.judge import worker
from agentsentry.judge.adapters import MockJudge, Verdict
from agentsentry.models import AuditEvent, Document, JudgeResult, Outbox, Task, ToolCall


def test_tenants_do_not_read_or_control_each_other(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/v2.db")
    test_policy = tmp_path / "default.yaml"
    test_policy.write_text((Path(__file__).resolve().parents[1] / "policies/default.yaml").read_text())
    monkeypatch.setenv("POLICY_PATH", str(test_policy))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    _sqlite_tenant_engine.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)

    def login(client, tenant_id, password):
        response = client.post("/login", data={"tenant_id": tenant_id, "password": password},
                               follow_redirects=False)
        assert response.status_code == 303
        return main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]

    try:
        with TestClient(main.app) as client:
            root_csrf = login(client, "default", main.settings.admin_password)
            headers = {"X-CSRF-Token": root_csrf}
            first = client.post("/api/v2/tenants", headers=headers, json={"name": "Team A"})
            second = client.post("/api/v2/tenants", headers=headers, json={"name": "Team B"})
            assert first.status_code == second.status_code == 200
            a, b = first.json(), second.json()
            assert a["tenant_id"] != b["tenant_id"]
            assert len(client.get("/api/v2/tenants").json()["tenants"]) == 3

            with tenant_db_session(a["tenant_id"]) as db:
                db.get(Document, "public-guide").content = "Team A private copy"
                db.commit()
            with tenant_db_session(b["tenant_id"]) as db:
                assert db.get(Document, "public-guide").content != "Team A private copy"

            csrf_a = login(client, a["tenant_id"], a["admin_password"])
            monkeypatch.setattr(main, "settings", main.settings.model_copy(update={"jev_api_key": "synthetic-key"}))
            a_runtime = client.get("/api/v1/judge-runtime").json()
            assert a_runtime["provider"] == "mock"
            assert client.put("/api/v1/judge-runtime", json={
                "provider": "jev", "expected_revision": a_runtime["revision"],
            }, headers={"X-CSRF-Token": csrf_a}).status_code == 200
            assert client.get("/api/v2/tenants").status_code == 403
            grant_a = client.post("/api/v1/capabilities", headers={"X-CSRF-Token": csrf_a}, json={
                "agent_id": "demo-agent", "tool": "create_task", "resources": ["main"],
                "ttl_seconds": 600, "max_uses": 1,
            }).json()
            mcp_grant_a = client.post("/api/v1/capabilities", headers={"X-CSRF-Token": csrf_a}, json={
                "agent_id": "demo-agent", "tool": "mcp_lookup_card", "resources": ["public-guide"],
                "ttl_seconds": 600, "max_uses": 1,
            }).json()
            call_id = str(uuid.uuid4())
            started = client.put("/api/v2/runtime-sessions/v2-test/start", headers={
                "Authorization": "Bearer " + a["agent_api_key"],
                "X-Tenant-ID": a["tenant_id"],
            }, json={"transport": "http", "capture_mode": "metadata"})
            assert started.status_code == 200
            call = client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + a["agent_api_key"],
                "X-Tenant-ID": a["tenant_id"], "X-Capability": grant_a["token"],
                "X-Runtime-Session": started.json()["session_token"],
            }, json={"call_id": call_id, "session_id": "v2-test", "tool": "create_task",
                     "arguments": {"title": "Only Team A"}})
            assert call.status_code == 200 and call.json()["status"] == "completed"
            assert client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + a["agent_api_key"], "X-Tenant-ID": b["tenant_id"],
                "X-Capability": grant_a["token"],
            }, json={"call_id": str(uuid.uuid4()), "session_id": "v2-test", "tool": "create_task",
                     "arguments": {"title": "Wrong tenant"}}).status_code == 401

            csrf_b = login(client, b["tenant_id"], b["admin_password"])
            assert client.get("/api/v1/judge-runtime").json()["provider"] == "mock"
            assert "Only Team A" not in client.get("/dashboard").text
            assert "tenant_sandbox_unavailable" in client.get("/api/v1/policy").json()["yaml"]
            assert client.get("/dashboard/calls/" + call_id).status_code == 404
            assert client.get("/api/v1/tool-calls/" + call_id, headers={
                "Authorization": "Bearer " + b["agent_api_key"], "X-Tenant-ID": b["tenant_id"],
            }).status_code == 404
            assert client.delete("/api/v1/capabilities/" + grant_a["grant_id"],
                                 headers={"X-CSRF-Token": csrf_b}).status_code == 404
            assert client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + b["agent_api_key"],
                "X-Tenant-ID": b["tenant_id"], "X-Capability": grant_a["token"],
            }, json={"call_id": str(uuid.uuid4()), "session_id": "v2-test", "tool": "create_task",
                     "arguments": {"title": "Stolen Team A token"}}).json()["status"] == "denied"
            assert client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + b["agent_api_key"],
                "X-Tenant-ID": b["tenant_id"], "X-Capability": mcp_grant_a["token"],
            }, json={"call_id": str(uuid.uuid4()), "session_id": "v2-mcp-test", "tool": "mcp_lookup_card",
                     "arguments": {"card_id": "public-guide"}}).json()["status"] == "denied"
            assert client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + b["agent_api_key"], "X-Tenant-ID": b["tenant_id"],
            }, json={"call_id": str(uuid.uuid4()), "session_id": "v2-test", "tool": "run_shell",
                     "arguments": {"command": "pwd"}}).json()["policy_rule"] == "tenant_sandbox_unavailable"
            b_policy = client.get("/api/v1/policy").json()["yaml"]
            import yaml
            policy = yaml.safe_load(b_policy)
            policy["rules"].insert(0, {"id": "team_b_block", "effect": "deny", "tool": "create_task"})
            assert client.put("/api/v1/policy", headers={"X-CSRF-Token": csrf_b},
                              json={"yaml": yaml.safe_dump(policy)}).status_code == 200
            assert "team_b_block" in client.get("/api/v1/policy").json()["yaml"]
            login(client, a["tenant_id"], a["admin_password"])
            assert "team_b_block" not in client.get("/api/v1/policy").json()["yaml"]
            with tenant_db_session(a["tenant_id"]) as db:
                assert db.scalar(select(Task).where(Task.title == "Only Team A"))
                assert db.get(ToolCall, call_id)
                assert db.scalar(select(AuditEvent).where(AuditEvent.call_id == call_id))
                outbox = db.scalar(select(Outbox).join(AuditEvent).where(AuditEvent.call_id == call_id))
                assert outbox
                outbox_id = outbox.id
            queued = []
            monkeypatch.setattr(dispatcher.judge_event, "delay", lambda *args: queued.append(args))
            assert dispatcher.dispatch_once(a["tenant_id"]) >= 1
            assert (outbox_id, a["tenant_id"]) in queued
            monkeypatch.setattr(worker, "settings", get_settings().model_copy(update={"jev_api_key": "synthetic-key"}))
            class SelectedJudge:
                def __init__(self, provider):
                    self.provider = provider
                def evaluate(self, event_data, event_id):
                    result = MockJudge().evaluate(event_data, event_id)
                    return Verdict(result.labels, result.score, self.provider, "synthetic-model")
            monkeypatch.setattr(worker, "build_judge", lambda settings: SelectedJudge(settings.judge_provider))
            worker.judge_event.run(outbox_id, a["tenant_id"])
            with tenant_db_session(a["tenant_id"]) as db:
                assert db.scalar(select(JudgeResult).where(JudgeResult.outbox_id == outbox_id))
            with tenant_db_session(b["tenant_id"]) as db:
                assert db.scalar(select(Task).where(Task.title == "Only Team A")) is None
                assert db.get(ToolCall, call_id) is None
                assert db.scalar(select(JudgeResult)) is None
    finally:
        if "a" in locals() and "b" in locals():
            _sqlite_tenant_engine(a["tenant_id"]).dispose()
            _sqlite_tenant_engine(b["tenant_id"]).dispose()
        _sqlite_tenant_engine.cache_clear()
        get_session_factory.cache_clear()
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer
