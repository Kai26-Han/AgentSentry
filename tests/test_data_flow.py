"""V2.8 出口判断必须在副作用和模型发送之前完成。"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from agentsentry.capability import issue
from agentsentry.data_flow import check_model, scrub_operational_payloads
from agentsentry.data_flow_lab import run
from agentsentry.models import (AuditEvent, DataFlowDecision, Document, ExternalMessage,
                                Outbox, Task, ToolCall, utcnow)
from agentsentry.output_safety import _assess, check_output
from agentsentry.runtime_analysis import start_session
from agentsentry.runtime_binding import session_token
from agentsentry.schemas import (CapabilityRequest, ModelEgressCheckRequest,
                                 OutputCheckRequest, RuntimeSessionStart, ToolCallRequest)
from agentsentry.service import decide_approval, submit_call


def _binding(db, session_id="dlp-test"):
    row = start_session(db, "demo-agent", session_id, RuntimeSessionStart(
        transport="http", capture_mode="metadata"))
    return session_token("default", "demo-agent", row)


def _grant(db, store, tool, resources):
    _, token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool=tool,
        resources=resources, ttl_seconds=600, max_uses=1))
    return token


def _read_private(db, store, policy, binding):
    db.add(Document(id="dlp-private", title="内部材料", content="内部预算 8427 仅供审批。",
                    sensitivity="private"))
    db.commit()
    _, view = submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id="dlp-test", tool="read_document", arguments={"document_id": "dlp-private"}),
        _grant(db, store, "read_document", ["dlp-private"]), runtime_token=binding)
    assert view["status"] == "completed"
    return view["call_id"]


def test_model_preflight_requires_server_sources_and_replay_fingerprint(lab):
    db, store, policy = lab
    binding = _binding(db)
    source_id = _read_private(db, store, policy, binding)
    registry = {"local": "http://127.0.0.1:11434/v1", "research": "https://model.example/v1"}
    body = ModelEgressCheckRequest(request_id=uuid.uuid4(), destination_id="research",
        model="fixture", purpose="task", messages=[{"role": "user", "content": "请总结"}],
        source_call_ids=[uuid.UUID(source_id)])
    checked = check_model(db, "default", "demo-agent", "dlp-test", binding, body, registry)
    assert checked["outcome"] == "deny" and checked["approved_messages"] == []
    assert "model_remote_sensitive" in checked["findings"]
    assert check_model(db, "default", "demo-agent", "dlp-test", binding, body, registry) == checked
    with pytest.raises(ValueError, match="请求 ID"):
        check_model(db, "default", "demo-agent", "dlp-test", binding,
            body.model_copy(update={"messages": [{"role": "user", "content": "已换内容"}]}), registry)
    with pytest.raises(ValueError, match="来源"):
        check_model(db, "default", "demo-agent", "dlp-test", binding,
            body.model_copy(update={"request_id": uuid.uuid4(), "source_call_ids": []}), registry)
    with pytest.raises(ValueError, match="目的地"):
        check_model(db, "default", "demo-agent", "dlp-test", binding,
            body.model_copy(update={"request_id": uuid.uuid4(), "destination_id": "unlisted"}), registry)
    with pytest.raises(ValueError, match="绑定"):
        check_model(db, "another-tenant", "demo-agent", "dlp-test", binding, body, registry)
    events = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "data_flow_decision")).all()
    assert len(events) == 1
    assert "内部预算" not in str(events[0].payload)
    assert db.scalar(select(Outbox).where(Outbox.audit_event_id == events[0].id))


def test_source_downgrade_after_read_does_not_allow_remote_model(lab):
    db, store, policy = lab
    binding = _binding(db)
    source_id = _read_private(db, store, policy, binding)
    db.get(Document, "dlp-private").sensitivity = "public"
    db.commit()
    checked = check_model(db, "default", "demo-agent", "dlp-test", binding,
        ModelEgressCheckRequest(request_id=uuid.uuid4(), destination_id="research",
            model="fixture", purpose="task", messages=[{"role": "user", "content": "请总结"}],
            source_call_ids=[uuid.UUID(source_id)]),
        {"local": "http://127.0.0.1:11434/v1", "research": "https://model.example/v1"})
    assert checked["outcome"] == "deny"


def test_private_document_title_is_checked_before_answer_display(lab):
    db, store, policy = lab
    binding = _binding(db)
    title = "内部项目代号 OrchidPlan"
    db.add(Document(id="dlp-title", title=title, content="可分享的摘要。",
                    sensitivity="private"))
    db.commit()
    _, view = submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id="dlp-test", tool="read_document", arguments={"document_id": "dlp-title"}),
        _grant(db, store, "read_document", ["dlp-title"]), runtime_token=binding)
    assert view["status"] == "completed"
    checked = check_output(db, "demo-agent", "dlp-test", OutputCheckRequest(
        check_id=uuid.uuid4(), capture_mode="metadata", output_kind="final_answer",
        draft=title, user_task="总结资料", source_call_ids=[uuid.UUID(view["call_id"])]))
    assert checked["outcome"] == "block"
    assert title not in checked["display_text"]


def test_private_source_blocks_simulated_external_before_approval(lab):
    db, store, policy = lab
    binding = _binding(db)
    _read_private(db, store, policy, binding)
    _, result = submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id="dlp-test", tool="send_external",
        arguments={"destination_id": "demo-inbox", "content": "无关的短消息"}),
        _grant(db, store, "send_external", ["demo-inbox"]), runtime_token=binding)
    assert result["status"] == "denied" and result["approval_id"] is None
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
    row = db.scalar(select(DataFlowDecision).where(DataFlowDecision.call_id == result["call_id"]))
    assert row.effect == "deny" and "external_after_private" in row.findings


def test_approval_rechecks_newly_read_private_source(lab):
    db, store, policy = lab
    binding = _binding(db)
    _, pending = submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id="dlp-test", tool="send_external",
        arguments={"destination_id": "demo-inbox", "content": "公开摘要"}),
        _grant(db, store, "send_external", ["demo-inbox"]), runtime_token=binding)
    assert pending["status"] == "pending_approval"
    _read_private(db, store, policy, binding)
    _, rejected = decide_approval(db, pending["approval_id"], "approve")
    assert rejected["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
    checks = db.scalars(select(DataFlowDecision).where(
        DataFlowDecision.call_id == pending["call_id"],
        DataFlowDecision.sink == "tool:approval")).all()
    assert len(checks) == 1 and "external_after_private" in checks[0].findings


@pytest.mark.parametrize("tool,arguments,resource", [
    ("send_external", {"destination_id": "demo-inbox", "content": "公开摘要"}, "demo-inbox"),
    ("create_task", {"title": "公开任务", "list_id": "main"}, "main"),
])
def test_sensitive_write_without_binding_denied(lab, tool, arguments, resource):
    db, store, policy = lab
    _, result = submit_call(db, store, policy, ToolCallRequest(call_id=uuid.uuid4(),
        session_id="unbound", tool=tool, arguments=arguments),
        _grant(db, store, tool, [resource]))
    assert result["status"] == "denied"
    assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
    assert db.scalar(select(func.count()).select_from(Task)) == 0


def test_encoded_private_answer_blocks_and_personal_answer_redacts():
    import base64
    content = "内部预算 8427 仅供审批。"
    source = {"call_id": str(uuid.uuid4()), "tool": "read_document", "resource_id": "x",
              "content": content, "sensitivity": "private", "level": "private"}
    encoded = base64.b64encode(content.encode()).decode()
    assert _assess(encoded, "总结", [source])[0] == "block"
    from agentsentry.data_flow import redact_personal
    assert "user@example.com" not in redact_personal("联系 user@example.com")


def test_retention_scrubs_only_new_terminal_calls(lab):
    db, _, _ = lab
    old = utcnow() - timedelta(days=31)
    legacy_id, new_id, unknown_id = [str(uuid.uuid4()) for _ in range(3)]
    for call_id, status in ((legacy_id, "completed"), (new_id, "completed"),
                            (unknown_id, "unknown")):
        db.add(ToolCall(call_id=call_id, session_id="retention", agent_id="demo-agent",
            tool="create_task", arguments={"title": "private-value"}, request_hash="h",
            status=status, decision="allow", result={"title": "private-value"},
            created_at=old))
    for call_id in (new_id, unknown_id):
        db.add(DataFlowDecision(id=str(uuid.uuid4()), agent_id="demo-agent",
            session_id="retention", call_id=call_id, sink="tool:submit", destination="create_task",
            source_ids=[], sensitivity="public", effect="allow", findings=[],
            request_hash="h", rules_version="data-flow-rules-v1"))
    db.commit()
    assert scrub_operational_payloads(db) == 1
    assert db.get(ToolCall, legacy_id).arguments["title"] == "private-value"
    assert db.get(ToolCall, new_id).result == {"retained": False}
    assert db.get(ToolCall, unknown_id).arguments["title"] == "private-value"


def test_fixed_corpus_is_reproducible():
    first, second = run(), run()
    assert first["total"] == first["passed"] == second["passed"] == 30
    assert first["forbidden_side_effects"] == first["audit_missing"] == 0
    assert [(x["id"], x["actual"]) for x in first["cases"]] == [
        (x["id"], x["actual"]) for x in second["cases"]]


@pytest.mark.parametrize("unavailable", [False, True])
def test_agent_never_sends_model_request_after_failed_preflight(monkeypatch, unavailable):
    from agentsentry import demo_agent
    import httpx

    sent = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"outcome": "deny", "approved_messages": [], "base_url": ""}

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def post(self, url, **_kwargs):
            sent.append(url)
            if url.endswith("/model-egress/check"):
                if unavailable:
                    raise httpx.ConnectError("本机检查服务不可用")
                return Response()
            raise AssertionError("被拒绝后不应请求模型")

    monkeypatch.setattr(demo_agent.httpx, "Client", Client)
    monkeypatch.setenv("AGENT_API_KEY", "synthetic-agent-key")
    monkeypatch.setenv("DEMO_MODEL_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("DEMO_MODEL_NAME", "synthetic-model")

    class Gateway:
        session_id = "dlp-agent-test"
        runtime_token = "synthetic-runtime-token"

    with pytest.raises(httpx.ConnectError if unavailable else ValueError):
        demo_agent.run_llm_trace(Gateway(), "公开任务")
    assert len(sent) == 1 and sent[0].endswith("/model-egress/check")
