import asyncio
import sqlite3
import sys
import uuid
from pathlib import Path
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from sqlalchemy import select

from agentsentry import main
from agentsentry.config import get_settings
from agentsentry.database import db_session, get_engine, get_session_factory
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import AuditEvent, Outbox, ToolCall, utcnow
from agentsentry.capability import issue
from agentsentry.schemas import CapabilityRequest, ToolCallRequest
from agentsentry.service import decide_approval, submit_call
from agentsentry.runtime_analysis import start_session
from agentsentry.runtime_binding import session_token
from agentsentry.schemas import RuntimeSessionStart


def test_mcp_result_limit_counts_utf8_bytes(tmp_path, monkeypatch):
    """正式 MCP 返回少于 4096 字符、超过 4096 字节的中文结果须拒绝。"""
    from agentsentry import mcp_backend
    fixture = Path(__file__).resolve().parents[1] / "scripts/deep_mcp_fixture.py"
    counter = tmp_path / "counter.db"
    def parameters(**ignored):
        return StdioServerParameters(command=sys.executable,
            args=[str(fixture), "oversized-utf8"], env={"DEEP_MCP_COUNTER": str(counter)})
    monkeypatch.setattr(mcp_backend, "StdioServerParameters", parameters)
    with pytest.raises(Exception):
        mcp_backend.execute_local_mcp("mcp_lookup_card", {"card_id": "public-guide"},
                                      str(uuid.uuid4()), "default")
    with sqlite3.connect(counter) as db:
        assert db.execute("SELECT kind, COUNT(*) FROM effects GROUP BY kind").fetchall() == [("read", 1)]


def _headers(token: str = "", tenant_id: str = "default") -> dict:
    return {"Authorization": "Bearer " + main.settings.agent_api_key,
            "X-Tenant-ID": tenant_id, "X-Capability": token}


def _issue(client: TestClient, csrf: str, tool: str, resources: list[str], uses: int = 1) -> str:
    response = client.post("/api/v1/capabilities", json={
        "agent_id": "demo-agent", "tool": tool, "resources": resources,
        "ttl_seconds": 600, "max_uses": uses,
    }, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    return response.json()["token"]


def _call(client: TestClient, tool: str, arguments: dict, token: str, call_id: str | None = None):
    started = client.put("/api/v2/runtime-sessions/mcp-test/start",
        headers=_headers(), json={"transport": "mcp", "capture_mode": "metadata"})
    assert started.status_code == 200
    return client.post("/api/v1/tool-calls", json={
        "call_id": call_id or str(uuid.uuid4()), "session_id": "mcp-test",
        "tool": tool, "arguments": arguments,
    }, headers={**_headers(token), "X-Runtime-Session": started.json()["session_token"]})


def test_mcp_tools_use_existing_gateway_approval_and_outbox(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/gateway.db")
    monkeypatch.setenv("MCP_DEMO_DIR", str(tmp_path / "mcp-data"))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    try:
        with TestClient(main.app) as client:
            assert client.post("/login", data={"password": main.settings.admin_password}).status_code == 200
            csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]

            read_token = _issue(client, csrf, "mcp_lookup_card", ["public-guide"])
            read = _call(client, "mcp_lookup_card", {"card_id": "public-guide"}, read_token)
            assert read.status_code == 200
            assert read.json()["status"] == "completed"
            assert read.json()["result"]["card_id"] == "public-guide"

            out_of_scope = _call(client, "mcp_lookup_card", {"card_id": "routing-guide"}, read_token)
            assert out_of_scope.json()["status"] == "denied"
            assert _call(client, "mcp_lookup_card", {"card_id": "public-guide"}, "").json()["status"] == "denied"
            invalid = _call(client, "mcp_lookup_card", {"card_id": "public-guide", "extra": "x"}, read_token)
            assert invalid.status_code == 422
            assert client.post("/api/v1/tool-calls", json={
                "call_id": str(uuid.uuid4()), "session_id": "mcp-test",
                "tool": "mcp_unregistered", "arguments": {},
            }, headers=_headers(read_token)).status_code == 422

            note_token = _issue(client, csrf, "mcp_record_note", ["demo-notes"])
            call_id = str(uuid.uuid4())
            note_args = {"note_id": "review-1", "text": "Synthetic review note"}
            pending = _call(client, "mcp_record_note", note_args, note_token, call_id)
            assert pending.status_code == 202
            assert pending.json()["status"] == "pending_approval"
            path = tmp_path / "mcp-data" / "default.db"
            assert not path.exists()
            assert client.get("/api/v1/tool-calls/" + call_id, headers=_headers()).json()["status"] == "pending_approval"
            changed = _call(client, "mcp_record_note", {**note_args, "text": "changed"}, note_token, call_id)
            assert changed.status_code == 409 and not path.exists()

            approved = client.post(
                "/api/v1/approvals/" + pending.json()["approval_id"] + "/decision",
                json={"decision": "approve"}, headers={"X-CSRF-Token": csrf},
            )
            assert approved.status_code == 200
            assert approved.json()["status"] == "completed"
            assert _call(client, "mcp_record_note", note_args, note_token, call_id).json()["status"] == "completed"
            with sqlite3.connect(path) as db:
                assert db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
            expired_token = _issue(client, csrf, "mcp_record_note", ["demo-notes"])
            expired = _call(client, "mcp_record_note", {"note_id": "review-3", "text": "Expire me"}, expired_token)
            assert expired.json()["status"] == "pending_approval"
            with db_session() as db:
                db.get(ToolCall, expired.json()["call_id"]).approval_expires_at = utcnow() - timedelta(seconds=1)
                db.commit()
            expired_decision = client.post(
                "/api/v1/approvals/" + expired.json()["approval_id"] + "/decision",
                json={"decision": "approve"}, headers={"X-CSRF-Token": csrf},
            )
            assert expired_decision.json()["status"] == "denied"
            with sqlite3.connect(path) as db:
                assert db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
            rejected_token = _issue(client, csrf, "mcp_record_note", ["demo-notes"])
            rejected = _call(client, "mcp_record_note", {"note_id": "review-2", "text": "Reject me"}, rejected_token)
            assert rejected.json()["status"] == "pending_approval"
            rejected_decision = client.post(
                "/api/v1/approvals/" + rejected.json()["approval_id"] + "/decision",
                json={"decision": "reject"}, headers={"X-CSRF-Token": csrf},
            )
            assert rejected_decision.json()["status"] == "denied"
            with sqlite3.connect(path) as db:
                assert db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
            with db_session() as db:
                assert db.get(ToolCall, call_id).status == "completed"
                events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call_id)).all()
                assert {event.event_type for event in events} == {"policy_decision", "runtime_decision", "action_chain_decision", "data_flow_decision", "goal_assessment", "approval_decision", "tool_result"}
                assert len(db.scalars(select(Outbox).where(Outbox.audit_event_id.in_([e.id for e in events]))).all()) == len(events)
    finally:
        get_session_factory.cache_clear()
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer


def test_official_mcp_client_sees_only_registered_entry_tools():
    async def run():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "agentsentry.mcp_ingress"],
            env={"AGENT_API_KEY": "synthetic-key", "SENTRY_URL": "http://127.0.0.1:1"},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                assert {tool.name for tool in listed.tools} == {
                    "mcp_lookup_card", "mcp_record_note", "agentsentry_call_status",
                }
                result = await session.call_tool("mcp_lookup_card", arguments={"card_id": "public-guide"})
                assert result.structured_content == {"status": "failed", "reason": "gateway_unavailable"}

    asyncio.run(run())


def test_mcp_failure_before_vs_after_dispatch(tmp_path, monkeypatch):
    from agentsentry import mcp_backend

    with pytest.raises(ValueError, match="Invalid tenant ID"):
        mcp_backend.execute_local_mcp("mcp_lookup_card", {"card_id": "public-guide"}, str(uuid.uuid4()), "../other")

    async def before(*args):
        raise ConnectionError("synthetic before-send failure")

    async def after(tool, arguments, call_id, tenant_id, sent):
        sent["value"] = True
        raise TimeoutError("synthetic after-send timeout")

    monkeypatch.setattr(mcp_backend, "_call_upstream", before)
    assert mcp_backend.execute_local_mcp("mcp_lookup_card", {"card_id": "public-guide"}, str(uuid.uuid4()), "default") == {
        "error": "mcp_upstream_unavailable",
    }
    monkeypatch.setattr(mcp_backend, "_call_upstream", after)
    with pytest.raises(TimeoutError):
        mcp_backend.execute_local_mcp("mcp_record_note", {"note_id": "x", "text": "x"}, str(uuid.uuid4()), "default")


@pytest.mark.parametrize("failure", [TimeoutError, ValueError])
def test_mcp_after_dispatch_failure_remains_unknown(lab, monkeypatch, failure):
    from agentsentry import mcp_backend

    db, store, policy = lab
    _, token = issue(db, store, CapabilityRequest(
        agent_id="demo-agent", tool="mcp_record_note", resources=["demo-notes"],
        ttl_seconds=600, max_uses=1,
    ))
    request = ToolCallRequest(
        call_id=uuid.uuid4(), session_id="mcp-unknown", tool="mcp_record_note",
        arguments={"note_id": "review-unknown", "text": "Synthetic"},
    )
    row = start_session(db, "demo-agent", "mcp-unknown", RuntimeSessionStart(
        transport="mcp", capture_mode="metadata"))
    _, pending = submit_call(db, store, policy, request, token,
        runtime_token=session_token("default", "demo-agent", row))
    assert pending["status"] == "pending_approval"

    async def after(tool, arguments, call_id, tenant_id, sent):
        sent["value"] = True
        raise failure("synthetic MCP result unavailable or malformed")

    monkeypatch.setattr(mcp_backend, "_call_upstream", after)
    _, result = decide_approval(db, pending["approval_id"], "approve")
    assert result["status"] == "unknown"
    _, replay = submit_call(db, store, policy, request, token)
    assert replay["status"] == "unknown"
    events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == str(request.call_id))).all()
    assert "tool_unknown" in {event.event_type for event in events}


def test_mcp_before_dispatch_failure_is_recorded_failed(lab, monkeypatch):
    from agentsentry import mcp_backend

    db, store, policy = lab
    _, token = issue(db, store, CapabilityRequest(
        agent_id="demo-agent", tool="mcp_lookup_card", resources=["public-guide"],
        ttl_seconds=600, max_uses=1,
    ))
    request = ToolCallRequest(
        call_id=uuid.uuid4(), session_id="mcp-failed", tool="mcp_lookup_card",
        arguments={"card_id": "public-guide"},
    )

    async def before(*args):
        raise ConnectionError("synthetic upstream startup failure")

    monkeypatch.setattr(mcp_backend, "_call_upstream", before)
    _, result = submit_call(db, store, policy, request, token)
    assert result["status"] == "failed"
    assert result["result"] == {"error": "mcp_upstream_unavailable"}
    events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == str(request.call_id))).all()
    assert {event.event_type for event in events} == {"policy_decision", "runtime_decision", "goal_assessment", "tool_result"}



def test_local_server_receives_trusted_package_path_without_parent_credentials(monkeypatch):
    import asyncio
    from contextlib import asynccontextmanager
    from pathlib import Path
    from agentsentry import mcp_backend
    captured=[]
    @asynccontextmanager
    async def fake_stdio(params):
        captured.append(params)
        raise RuntimeError("受控启动边界")
        yield
    monkeypatch.setattr(mcp_backend,"stdio_client",fake_stdio)
    with pytest.raises(RuntimeError):
        asyncio.run(mcp_backend._call_upstream("mcp_lookup_card",{"card_id":"public-guide"},
                    str(uuid.uuid4()),"default",{"value":False}))
    assert captured[0].env["PYTHONPATH"]==str(Path(mcp_backend.__file__).resolve().parents[1])
    assert "AGENT_API_KEY" not in captured[0].env and "GITHUB_MCP_PAT" not in captured[0].env
