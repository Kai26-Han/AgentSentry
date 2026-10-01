"""真实第三方写入边界的离线测试；上游 GitHub 调用全部替换为计数桩。"""

import re
import uuid
import json
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentsentry import main, mcp_github
from agentsentry import github_write_reconcile
from agentsentry.config import get_settings
from agentsentry.database import db_session, get_engine, get_session_factory
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import Approval, ToolCall
from agentsentry.policy import PolicyFile
from agentsentry.schemas import TOOL_SCHEMAS, resource_for


REPOSITORY = "demo/agentsentry-test"
TOOL = "github_mcp_create_test_issue"
ARGS = {"repository": REPOSITORY, "title": "[AgentSentry Test] controlled write one",
        "body": "Synthetic review case."}


def _review_token(html: str) -> str:
    match = re.search(r'name="review_token" value="([^"]+)"', html)
    assert match, "approval detail must contain a bound review token"
    return match.group(1)


def test_created_issue_response_identity_is_checked():
    def response(value):
        return SimpleNamespace(is_error=False, content=[SimpleNamespace(
            type="text", text=json.dumps(value))])

    valid = {"id": "42001", "url": f"https://github.com/{REPOSITORY}/issues/42"}
    assert mcp_github._extract_created_issue(response(valid), REPOSITORY, ARGS)["issue_number"] == 42
    with pytest.raises(ValueError, match="identity"):
        mcp_github._extract_created_issue(response(dict(valid,
            url="https://github.com/other/repo/issues/42")), REPOSITORY, ARGS)
    with pytest.raises(ValueError, match="identity"):
        mcp_github._extract_created_issue(response(dict(valid, id="not-a-number")), REPOSITORY, ARGS)


def test_read_only_reconciliation_requires_exact_prior_approval(tmp_path, monkeypatch):
    from agentsentry.database import Base
    from agentsentry.models import AuditEvent
    from agentsentry.service import canonical_hash

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/reconcile.db")
    monkeypatch.setenv("AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("GITHUB_MCP_WRITE_PAT", "synthetic-write-token")
    monkeypatch.setenv("GITHUB_MCP_PAT", "synthetic-read-token")
    monkeypatch.setenv("GITHUB_MCP_TEST_REPO", REPOSITORY)
    monkeypatch.setenv("GITHUB_MCP_CREATE_ISSUE_SCHEMA_SHA256", "a" * 64)
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    Base.metadata.create_all(get_engine())
    call_id = str(uuid.uuid4())
    with db_session() as session:
        session.add(ToolCall(call_id=call_id, session_id="review-session", agent_id="demo-agent",
            tool=TOOL, arguments=ARGS, request_hash=canonical_hash({
                "session_id": "review-session", "agent_id": "demo-agent", "tool": TOOL,
                "arguments": ARGS}), status="unknown", decision="require_approval",
            policy_rule="github_test_issue_needs_review"))
        session.add(Approval(id=str(uuid.uuid4()), call_id=call_id,
            arguments_hash=canonical_hash(ARGS), status="approved"))
        session.add(AuditEvent(id=str(uuid.uuid4()), call_id=call_id,
            event_type="tool_unknown", payload={"status": "unknown"}))
        session.commit()
    hits = []
    def fake_lookup(token, repository, arguments, created_at):
        hits.append((token, repository, arguments))
        return {"issue_id": "7001", "issue_number": 7,
                "html_url": f"https://github.com/{REPOSITORY}/issues/7", "title": ARGS["title"]}
    monkeypatch.setattr(github_write_reconcile, "_lookup_exact_issue", fake_lookup)
    report = github_write_reconcile.reconcile(call_id)
    assert report["issue_number"] == 7 and len(hits) == 1
    with db_session() as session:
        assert session.get(ToolCall, call_id).status == "completed"
        events = session.scalars(select(AuditEvent).where(AuditEvent.call_id == call_id)).all()
        assert [event.event_type for event in events] == ["tool_unknown", "tool_result"]
        assert events[-1].payload["reconciled_after_unknown"] is True
        assert "arguments" not in events[-1].payload
    with pytest.raises(RuntimeError, match="条件"):
        github_write_reconcile.reconcile(call_id)
    assert len(hits) == 1
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()


def test_upstream_mapping_only_sends_create_and_checks_manifest(monkeypatch):
    calls = []
    definition = SimpleNamespace(name="issue_write", model_dump=lambda **_:
        {"name": "issue_write", "inputSchema": {"type": "object", "required": ["method", "owner", "repo"]}})
    approved_hash = mcp_github._tool_hash(definition)

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def get(self, _url):
            return SimpleNamespace(status_code=200, content=b"{}", raise_for_status=lambda: None,
                json=lambda: {"id": 7001, "number": 7,
                    "html_url": f"https://github.com/{REPOSITORY}/issues/7",
                    "title": ARGS["title"], "body": ARGS["body"]})

    @asynccontextmanager
    async def fake_transport(*_, **__):
        yield None, None

    class FakeSession(FakeClient):
        async def discover(self):
            return None

        async def list_tools(self):
            return SimpleNamespace(next_cursor=None, tools=[definition])

        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return SimpleNamespace(is_error=False, content=[SimpleNamespace(type="text",
                text=json.dumps({"id": "7001",
                    "url": f"https://github.com/{REPOSITORY}/issues/7"}))])

    monkeypatch.setattr(mcp_github, "_pinned_transport", lambda *_, **__: None)
    monkeypatch.setattr(mcp_github.httpx2, "AsyncClient", lambda **_: FakeClient())
    monkeypatch.setattr(mcp_github, "streamable_http_client", fake_transport)
    monkeypatch.setattr(mcp_github, "ClientSession", lambda *_, **__: FakeSession())
    sent = {"value": False}
    result = asyncio.run(mcp_github._create_issue("synthetic", REPOSITORY, approved_hash, ARGS, sent))
    assert result["issue_number"] == 7 and sent["value"] is True
    assert calls == [("issue_write", {"method": "create", "owner": "demo",
                                       "repo": "agentsentry-test", "title": ARGS["title"],
                                       "body": ARGS["body"]})]
    sent = {"value": False}
    with pytest.raises(ValueError, match="schema changed"):
        asyncio.run(mcp_github._create_issue("synthetic", REPOSITORY, "0" * 64, ARGS, sent))
    assert sent["value"] is False and len(calls) == 1


def test_write_requires_review_and_is_idempotent(tmp_path, monkeypatch):
    previous_settings, previous_serializer = main.settings, main.serializer
    policy = yaml.safe_load((Path(__file__).resolve().parents[1] / "policies/default.yaml").read_text())
    policy["rules"].append({"id": "github_test_issue_needs_review",
                            "effect": "require_approval", "tool": TOOL})
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.safe_dump(policy))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/github-write.db")
    monkeypatch.setenv("POLICY_PATH", str(policy_file))
    monkeypatch.setenv("AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("GITHUB_MCP_WRITE_PAT", "synthetic-write-token")
    monkeypatch.setenv("GITHUB_MCP_PAT", "synthetic-read-token")
    monkeypatch.setenv("GITHUB_MCP_TEST_REPO", REPOSITORY)
    monkeypatch.setenv("GITHUB_MCP_CREATE_ISSUE_SCHEMA_SHA256", "a" * 64)
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret,
                                                 salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    hits = []

    async def upstream(token, repository, schema_sha256, arguments, sent):
        hits.append((token, repository, dict(arguments)))
        sent["value"] = True
        if arguments["title"].endswith("uncertain"):
            raise TimeoutError("synthetic lost response")
        number = 100 + len(hits)
        return {"issue_number": number,
                "html_url": f"https://github.com/{repository}/issues/{number}",
                "title": arguments["title"],
                "_remote": {"endpoint_id": "github", "manifest_sha256": schema_sha256}}

    monkeypatch.setattr(mcp_github, "_create_issue", upstream)
    try:
        assert resource_for(TOOL, ARGS) == REPOSITORY
        assert TOOL_SCHEMAS[TOOL].model_validate(ARGS).repository == REPOSITORY
        with pytest.raises(ValueError):
            TOOL_SCHEMAS[TOOL].model_validate(dict(ARGS, repository="another/repo"))
        with pytest.raises(ValueError):
            TOOL_SCHEMAS[TOOL].model_validate(dict(ARGS, title="ordinary issue"))
        with pytest.raises(ValueError):
            PolicyFile.model_validate(dict(policy, rules=[{"id": "unsafe",
                "effect": "allow", "tool": TOOL}]))
        assert mcp_github.execute_github_create_issue("other-tenant", ARGS)["error"] == "github_mcp_write_not_enabled"
        assert hits == []
        with TestClient(main.app) as client:
            assert client.post("/login", data={"password": main.settings.admin_password}).status_code == 200
            csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
            admin = {"X-CSRF-Token": csrf}
            agent = {"Authorization": "Bearer " + main.settings.agent_api_key}
            started = client.put("/api/v2/runtime-sessions/github-write/start", headers=agent,
                json={"transport": "mcp", "capture_mode": "metadata",
                      "user_task": "Create one synthetic test Issue in the approved test repository."})
            assert started.status_code == 200
            agent["X-Runtime-Session"] = started.json()["session_token"]
            grant = client.post("/api/v1/capabilities", headers=admin, json={
                "agent_id": "demo-agent", "tool": TOOL, "resources": [REPOSITORY],
                "ttl_seconds": 600, "max_uses": 8})
            assert grant.status_code == 200
            token = grant.json()["token"]
            body = {"call_id": str(uuid.uuid4()), "session_id": "github-write",
                    "tool": TOOL, "arguments": ARGS}
            unbound = client.post("/api/v1/tool-calls", headers={
                **agent, "X-Capability": token, "X-Runtime-Session": ""},
                json=dict(body, call_id=str(uuid.uuid4())))
            assert unbound.status_code == 200 and unbound.json()["status"] == "denied"
            assert hits == []
            assert client.post("/api/v1/tool-calls", headers=agent,
                json=dict(body, call_id=str(uuid.uuid4()))).json()["status"] == "denied"
            bound = {**agent, "X-Capability": token}
            assert client.post("/api/v1/tool-calls", headers=bound,
                json=dict(body, call_id=str(uuid.uuid4()), arguments=dict(ARGS, repository="other/repo"))).status_code == 422
            assert hits == []
            pending = client.post("/api/v1/tool-calls", headers=bound, json=body)
            assert pending.status_code == 202 and pending.json()["status"] == "pending_approval", pending.json().get("reason")
            approval_id = pending.json()["approval_id"]
            assert hits == []
            assert client.post("/api/v1/tool-calls", headers=bound,
                json=dict(body, arguments=dict(ARGS, body="changed"))).status_code == 409
            assert client.post(f"/api/v1/approvals/{approval_id}/decision", headers=admin,
                json={"decision": "approve"}).status_code == 409
            assert hits == []
            detail = client.get(f"/dashboard/approvals/{approval_id}")
            assert detail.status_code == 200 and REPOSITORY in detail.text
            assert "真实 GitHub 写入" in detail.text
            assert ARGS["body"] in detail.text
            approved = client.post(f"/dashboard/approvals/{approval_id}", data={
                "csrf": csrf, "decision": "approve", "reviewed": "yes",
                "review_token": _review_token(detail.text)}, follow_redirects=False)
            assert approved.status_code == 303
            assert len(hits) == 1 and hits[0][1] == REPOSITORY
            completed = client.post("/api/v1/tool-calls", headers=bound, json=body)
            assert completed.status_code == 200 and completed.json()["status"] == "completed"
            assert completed.json()["result"]["issue_number"] == 101
            assert len(hits) == 1

            rejected_body = dict(body, call_id=str(uuid.uuid4()),
                                 arguments=dict(ARGS, title="[AgentSentry Test] controlled write rejected"))
            rejected = client.post("/api/v1/tool-calls", headers=bound, json=rejected_body)
            assert rejected.status_code == 202
            rejected_id = rejected.json()["approval_id"]
            assert client.post(f"/api/v1/approvals/{rejected_id}/decision", headers=admin,
                               json={"decision": "reject"}).json()["status"] == "denied"
            assert len(hits) == 1

            uncertain_body = dict(body, call_id=str(uuid.uuid4()),
                                  arguments=dict(ARGS, title="[AgentSentry Test] controlled write uncertain"))
            uncertain = client.post("/api/v1/tool-calls", headers=bound, json=uncertain_body)
            assert uncertain.status_code == 202
            uncertain_id = uncertain.json()["approval_id"]
            detail = client.get(f"/dashboard/approvals/{uncertain_id}")
            response = client.post(f"/dashboard/approvals/{uncertain_id}", data={
                "csrf": csrf, "decision": "approve", "reviewed": "yes",
                "review_token": _review_token(detail.text)}, follow_redirects=False)
            assert response.status_code == 303
            with db_session() as db:
                assert db.get(ToolCall, uncertain_body["call_id"]).status == "unknown"
                assert db.scalar(select(Approval).where(Approval.id == uncertain_id)).status == "approved"
            again = client.post("/api/v1/tool-calls", headers=bound, json=uncertain_body)
            assert again.json()["status"] == "unknown"
            assert len(hits) == 2

            for suffix, unsafe_body, expected_rule in [
                ("secret", "api_key=syntheticsecret1234", "write_sensitive_content"),
                ("personal", "Contact test.person@example.com", "github_write_personal"),
            ]:
                unsafe = client.post("/api/v1/tool-calls", headers=bound, json=dict(
                    body, call_id=str(uuid.uuid4()), arguments=dict(ARGS,
                        title=f"[AgentSentry Test] controlled write {suffix}", body=unsafe_body)))
                assert unsafe.status_code == 200
                assert unsafe.json()["status"] == "denied"
                assert expected_rule in unsafe.json()["reason"]
                assert len(hits) == 2

            private_session = "github-write-private"
            started = client.put(f"/api/v2/runtime-sessions/{private_session}/start", headers=agent,
                json={"transport": "mcp", "capture_mode": "metadata",
                      "user_task": "Read a private synthetic document."})
            assert started.status_code == 200
            private_headers = {**bound, "X-Runtime-Session": started.json()["session_token"]}
            read_grant = client.post("/api/v1/capabilities", headers=admin, json={
                "agent_id": "demo-agent", "tool": "read_document", "resources": ["private-notes"],
                "ttl_seconds": 600, "max_uses": 1})
            assert read_grant.status_code == 200
            private_read = client.post("/api/v1/tool-calls", headers={
                **private_headers, "X-Capability": read_grant.json()["token"]}, json={
                    "call_id": str(uuid.uuid4()), "session_id": private_session,
                    "tool": "read_document", "arguments": {"document_id": "private-notes"}})
            assert private_read.status_code == 200
            assert private_read.json()["status"] == "completed"
            after_private = client.post("/api/v1/tool-calls", headers=private_headers,
                json=dict(body, call_id=str(uuid.uuid4()), session_id=private_session))
            assert after_private.status_code == 200
            assert after_private.json()["status"] == "denied"
            assert "github_write_after_private" in after_private.json()["reason"]
            assert len(hits) == 2

            html_title = "[AgentSentry Test] <script>alert(1)</script>"
            html_case = client.post("/api/v1/tool-calls", headers=bound,
                json=dict(body, call_id=str(uuid.uuid4()),
                          arguments=dict(ARGS, title=html_title)))
            assert html_case.status_code == 202
            html_detail = client.get("/dashboard/approvals/" + html_case.json()["approval_id"])
            assert html_detail.status_code == 200
            assert "\\u003cscript\\u003e" in html_detail.text
            assert "<script>alert(1)</script>" not in html_detail.text
            assert len(hits) == 2

        async def preflight_failure(token, repository, schema_sha256, arguments, sent):
            raise ConnectionError("synthetic upstream unavailable before dispatch")

        monkeypatch.setattr(mcp_github, "_create_issue", preflight_failure)
        assert mcp_github.execute_github_create_issue("default", ARGS)["error"] == (
            "github_mcp_write_unavailable_or_drift")
        assert len(hits) == 2
    finally:
        main.settings, main.serializer = previous_settings, previous_serializer
        get_settings.cache_clear()
        get_engine.cache_clear()
        get_session_factory.cache_clear()
