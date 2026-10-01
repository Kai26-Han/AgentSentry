"""V2.2 固定样本、真实调用证据和租户隔离。"""

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentsentry import main
from agentsentry.attack_corpus import BY_ID, CASES, cards, corpus_hash, documents
from agentsentry.attack_results import create_run, finish_run, install_fixtures, run_view, submit_result
from agentsentry.capability import issue
from agentsentry.config import get_settings
from agentsentry.database import _sqlite_tenant_engine, get_engine, get_session_factory, tenant_db_session
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import AttackRun, DataFlowDecision, Document, JudgeResult, Outbox, ToolCall
from agentsentry.schemas import AttackCaseSubmission, AttackRunRequest, CapabilityRequest, ToolCallRequest
from agentsentry.service import submit_call
from agentsentry import demo_agent


def test_corpus_is_fixed_separate_and_paired():
    assert len(CASES) == 30
    assert sum(case["kind"] == "attack" for case in CASES) == 20
    assert sum(case["kind"] == "normal" for case in CASES) == 10
    assert sum(case["live"] for case in CASES) == 12
    assert all(case["attacker_goal"] and case["user_goal"] and case["expected"] for case in CASES)
    assert all(name.startswith("lab-") for name in documents() | cards())
    assert len(corpus_hash()) == 16


def test_results_use_recorded_calls_and_keep_unknown_out_of_success(lab):
    db, store, policy = lab
    assert install_fixtures(db) == len(documents())
    assert install_fixtures(db) == 0
    assert db.get(Document, "public-guide").content == "Create a task to review the quarterly plan."
    run = create_run(db, AttackRunRequest(mode="scripted"), policy.revision)
    case = BY_ID["D01"]
    token, _ = None, None
    _, token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool="read_document",
                                                 resources=[case["fixture_id"]], ttl_seconds=600, max_uses=1))
    source = ToolCallRequest(call_id=uuid.uuid4(), session_id=f"lab-{run.id}-D01",
                             tool="read_document", arguments={"document_id": case["fixture_id"]})
    _, read = submit_call(db, store, policy, source, token)
    assert read["status"] == "completed"
    attack = ToolCallRequest(call_id=uuid.uuid4(), session_id=f"lab-{run.id}-D01",
                             tool="read_document", arguments={"document_id": "private-notes"})
    _, denied = submit_call(db, store, policy, attack, "")
    assert denied["status"] == "denied"
    row = submit_result(db, run, AttackCaseSubmission(case_id="D01",
        call_ids=[source.call_id, attack.call_id], trace=[{"tool": "read_document", "status": "denied"}]))
    assert row.outcome == "blocked" and row.attempted
    assert run_view(db, run, 0.7)["counts"]["attack_succeeded"] == 0
    for index, outbox in enumerate(db.scalars(select(Outbox)).all()):
        outbox.status = "completed"
        db.add(JudgeResult(id=str(uuid.uuid4()), outbox_id=outbox.id,
                           call_id=str(source.call_id) if index < 2 else str(attack.call_id),
                           labels=["none"], score=0.0,
                           provider="mock" if index % 2 else "deepseek",
                           model_version="synthetic", status="completed"))
    db.commit()
    view = run_view(db, run, 0.7)
    assert view["judge_providers"] == ["mixed"]
    assert view["rates"]["judge_false_negative"] is None
    with pytest.raises(ValueError, match="当前实验样本"):
        submit_result(db, run, AttackCaseSubmission(case_id="D02", call_ids=[source.call_id]))
    db.get(ToolCall, str(attack.call_id)).status = "unknown"
    db.commit()
    assert run_view(db, run, 0.7)["counts"]["attack_succeeded"] == 0
    with pytest.raises(ValueError, match="尚未全部"):
        finish_run(db, run)
    finish_run(db, run, failed=True, error="合成中断")
    assert db.get(AttackRun, run.id).status == "failed"


def test_attack_run_api_is_tenant_scoped_and_csrf_protected(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/attack.db")
    policy_path = tmp_path / "default.yaml"
    policy_path.write_text((Path(__file__).resolve().parents[1] / "policies/default.yaml").read_text())
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    get_settings.cache_clear(); get_engine.cache_clear(); get_session_factory.cache_clear()
    _sqlite_tenant_engine.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    monkeypatch.setattr(main, "get_redis", lambda: MemoryRedis())

    def login(client, tenant_id, password):
        response = client.post("/login", data={"tenant_id": tenant_id, "password": password},
                               follow_redirects=False)
        assert response.status_code == 303
        return {"X-CSRF-Token": main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]}

    try:
        with TestClient(main.app) as client:
            root = login(client, "default", main.settings.admin_password)
            a = client.post("/api/v2/tenants", headers=root, json={"name": "Attack A"}).json()
            b = client.post("/api/v2/tenants", headers=root, json={"name": "Attack B"}).json()
            research = client.post("/api/v2/tenants", headers=root,
                                   json={"name": "Attack Lab 1234abcd"}).json()
            headers_a = login(client, a["tenant_id"], a["admin_password"])
            assert client.post("/api/v2/attack-runs", json={"mode": "scripted"}).status_code == 403
            assert client.post("/api/v2/attack-lab/fixtures/install", headers=headers_a).json()["installed"] == len(documents())
            run = client.post("/api/v2/attack-runs", headers=headers_a, json={"mode": "scripted"})
            assert run.status_code == 200
            run_id = run.json()["id"]
            assert client.get("/api/v2/attack-runs/" + run_id).status_code == 200
            assert run_id in client.get("/dashboard/attack-runs").text
            assert client.post(f"/api/v2/attack-runs/{run_id}/cases", headers=headers_a,
                               json={"case_id": "B02", "trace": [{"tool": "mcp_unregistered", "status": 422}]}).status_code == 200
            assert client.get(f"/api/v2/attack-runs/{run_id}").json()["cases"][0]["outcome"] == "blocked"
            login(client, b["tenant_id"], b["admin_password"])
            assert client.get("/api/v2/attack-runs/" + run_id).status_code == 404
            assert run_id not in client.get("/dashboard/attack-runs").text
            assert client.get("/dashboard/attack-runs", params={"tenant": a["tenant_id"]}).status_code == 403
            with tenant_db_session(b["tenant_id"]) as db:
                assert db.scalar(select(AttackRun)) is None
            research_headers = login(client, research["tenant_id"], research["admin_password"])
            lab_run = client.post("/api/v2/attack-runs", headers=research_headers,
                                  json={"mode": "scripted"}).json()["id"]
            assert lab_run in client.get("/dashboard/attack-runs").text
            flow_call_id = str(uuid.uuid4())
            with tenant_db_session(research["tenant_id"]) as db:
                db.add(ToolCall(call_id=flow_call_id, session_id="research-flow", agent_id="demo-agent",
                    tool="read_document", arguments={"document_id": "public-guide"},
                    request_hash="h" * 64, status="completed", decision="allow",
                    result={"document_id": "public-guide", "content": "合成资料"}))
                db.add(DataFlowDecision(id=str(uuid.uuid4()), agent_id="demo-agent",
                    session_id="research-flow", call_id=flow_call_id, sink="tool:submit",
                    destination="read_document", source_ids=[flow_call_id],
                    sensitivity="public", effect="allow", findings=[], request_hash="h" * 64,
                    rules_version="data-flow-rules-v1"))
                db.commit()
            login(client, "default", main.settings.admin_password)
            page = client.get("/dashboard/attack-runs")
            assert lab_run in page.text and "默认管理员可只读查看" in page.text
            assert client.get(f"/dashboard/attack-runs/{lab_run}",
                              params={"tenant": research["tenant_id"]}).status_code == 200
            assert client.get(f"/dashboard/attack-runs/{run_id}",
                              params={"tenant": a["tenant_id"]}).status_code == 404
            assert client.get("/dashboard/attack-runs", params={"tenant": "../public"}).status_code == 404
            assert client.get(f"/dashboard/attack-runs/{lab_run}/calls/{uuid.uuid4()}",
                              params={"tenant": research["tenant_id"]}).status_code == 404
            empty_flow = client.get("/dashboard/data-flow")
            assert "1 条测试记录" in empty_flow.text and flow_call_id not in empty_flow.text
            research_flow = client.get("/dashboard/data-flow",
                params={"tenant": research["tenant_id"]})
            assert research_flow.status_code == 200 and flow_call_id in research_flow.text
            assert "仅按研究租户读取证据" in research_flow.text
            assert client.get("/dashboard/data-flow/calls/" + flow_call_id,
                params={"tenant": research["tenant_id"]}).status_code == 200
            assert client.get("/dashboard/data-flow", params={"tenant": a["tenant_id"]}).status_code == 404
            login(client, b["tenant_id"], b["admin_password"])
            assert client.get("/dashboard/data-flow",
                params={"tenant": research["tenant_id"]}).status_code == 403
    finally:
        _sqlite_tenant_engine.cache_clear()
        get_session_factory.cache_clear()
        get_engine().dispose()
        get_engine.cache_clear()
        get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer


def test_existing_agent_returns_structured_live_trace_without_credentials(monkeypatch):
    replies = [
        {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{
            "id": "tool-1", "type": "function", "function": {
                "name": "read_document", "arguments": '{"document_id":"lab-doc-normal-1"}'},
        }]}}]},
        {"choices": [{"message": {"role": "assistant", "content": "季度计划需要核对。"}}]},
    ]
    sent = []

    class ModelClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, headers, json):
            sent.append(json)
            payload = replies.pop(0)

            class Response:
                def raise_for_status(self):
                    pass

                def json(self):
                    return payload

            return Response()

    class Gateway:
        session_id = "test-session"
        runtime_token = "test-binding"
        def call(self, tool, arguments):
            assert tool == "read_document"
            return {"call_id": str(uuid.uuid4()), "status": "completed", "result": {"content": "季度计划"}}

    monkeypatch.setattr(demo_agent.httpx, "Client", ModelClient)
    monkeypatch.setattr(demo_agent, "_model_check", lambda messages, *_args: {
        "base_url": "http://127.0.0.1:11434/v1", "approved_messages": messages})
    monkeypatch.setenv("DEMO_MODEL_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("DEMO_MODEL_NAME", "test-model")
    monkeypatch.setenv("DEMO_MODEL_API_KEY", "private-model-key")
    trace = demo_agent.run_llm_trace(Gateway(), "阅读文档")
    assert trace["finished"] and len(trace["calls"]) == 1
    assert trace["calls"][0]["tool"] == "read_document"
    assert trace["final_answer"] == "季度计划需要核对。"
    assert "private-model-key" not in str(sent)
