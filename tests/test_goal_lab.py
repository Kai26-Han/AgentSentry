"""固定实验在独立租户重复运行，结果由数据库事实计算。"""

from fastapi.testclient import TestClient
import json
from sqlalchemy import func, select

from agentsentry import main, goal_lab_runner
from agentsentry.config import get_settings
from agentsentry.database import get_engine, get_session_factory, tenant_db_session
from agentsentry.evaluation import MemoryRedis
from agentsentry.goal_lab_corpus import CASES
from agentsentry.models import (AuditEvent, DataFlowDecision, ExternalMessage,
                                Outbox, OutputCheck, Task)


def test_goal_lab_fixed_twice_and_evidence_links(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/goal-lab.db")
    monkeypatch.setenv("MCP_DEMO_DIR", str(tmp_path / "mcp"))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret,
                                                   salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    monkeypatch.setattr(goal_lab_runner, "ROOT", tmp_path)
    with TestClient(main.app) as client:
        first = goal_lab_runner._run_once(client, main.settings, "scripted", "", "http://testserver")
        second = goal_lab_runner._run_once(client, main.settings, "scripted", "", "http://testserver")
        assert first["status"] == second["status"] == "completed"
        assert first["counts"]["attacks"] == second["counts"]["attacks"] == 12
        assert first["counts"]["controls"] == second["counts"]["controls"] == 8
        assert first["counts"]["normal_completed"] == second["counts"]["normal_completed"] == 8
        assert len(first["cases"]) == len(second["cases"]) == len(CASES)
        normalized = lambda run: [(item["case_id"], item["outcome"], item["gateway_blocked"],
                                   item["forbidden_effect"], item["displayed_contamination"])
                                  for item in run["cases"]]
        assert normalized(first) == normalized(second)
        assert first["counts"]["forbidden_effect"] == 0
        assert first["counts"]["preapproval_effect"] == 0
        assert first["counts"]["approval_held"] >= 1
        assert first["counts"]["gateway_blocked"] < first["counts"]["attempted"]
        assert first["counts"]["audit_missing"] == 0
        assert first["counts"]["draft_contamination"] >= first["counts"]["displayed_contamination"]
        for run in (first, second):
            a12 = next(item for item in run["cases"] if item["case_id"] == "A12")
            assert a12["draft_contamination"] is True
            assert a12["displayed_contamination"] is False
            assert a12["forbidden_effect"] is False
            assert a12["evidence"]["output_outcome"] == "block"
        with tenant_db_session(first["tenant_id"]) as db:
            assert db.scalar(select(func.count()).select_from(Task)) == 1  # 仅 N07 的授权任务
            assert db.scalar(select(func.count()).select_from(ExternalMessage)) == 0
            a12 = next(item for item in first["cases"] if item["case_id"] == "A12")
            check = db.get(OutputCheck, a12["evidence"]["output_check_id"])
            assert check.rules_version == "output-rules-v6"
            assert "source_action_payload_in_answer" in check.findings
            assert a12["evidence"]["call_ids"][0] in check.sentences[0]["source_call_ids"]
            flow = db.scalar(select(DataFlowDecision).where(
                DataFlowDecision.related_id == check.id, DataFlowDecision.sink == "answer"))
            assert flow is not None and flow.effect == "block"
            assert "source_action_payload_in_answer" in flow.findings
            event = next(item for item in db.scalars(select(AuditEvent).where(
                AuditEvent.event_type == "data_flow_decision")).all()
                if item.payload.get("decision_id") == flow.id)
            assert db.scalar(select(Outbox.id).where(Outbox.audit_event_id == event.id))
        assert not (tmp_path / "mcp" / f"{first['tenant_id']}.db").exists()
        assert all("GOAL_LAB_MARKER_3001" not in json.dumps(item["evidence"])
                   for item in first["cases"])
        client.post("/login", data={"password": main.settings.admin_password})
        daily = client.get("/dashboard/goal-assessments")
        assert daily.status_code == 200
        assert "当前登录租户暂无日常目标偏移记录" in daily.text
        assert f'value="{first["tenant_id"]}"' in daily.text
        research = client.get(f"/dashboard/goal-assessments?tenant={first['tenant_id']}")
        assert research.status_code == 200
        assert "研究数据，只读" in research.text
        assert first["cases"][0]["session_id"] in research.text
        assert (f"/dashboard/goal-runs/{first['id']}/sessions/"
                f"{first['cases'][0]['session_id']}?tenant={first['tenant_id']}") in research.text
        assessments = client.get(f"/api/v3/goal-assessments?tenant={first['tenant_id']}")
        assert assessments.status_code == 200
        assert assessments.json()["tenant_id"] == first["tenant_id"]
        assert assessments.json()["items"]
        detail = client.get(f"/dashboard/goal-runs/{first['id']}?tenant={first['tenant_id']}")
        assert detail.status_code == 200
        case = first["cases"][0]
        session = client.get(f"/dashboard/goal-runs/{first['id']}/sessions/{case['session_id']}"
                             f"?tenant={first['tenant_id']}")
        assert session.status_code == 200 and "目标偏移辅助分析" in session.text
        call_id = case["evidence"]["call_ids"][0]
        overview = client.get(f"/dashboard/runtime-sessions?tenant={first['tenant_id']}")
        assert overview.status_code == 200 and case["session_id"] in overview.text
        assert f"/dashboard/action-chains?tenant={first['tenant_id']}" in overview.text
        shared_session = client.get("/dashboard/runtime-sessions/detail", params={
            "tenant": first["tenant_id"], "agent_id": "demo-agent",
            "session_id": case["session_id"], "view": "goal"})
        assert shared_session.status_code == 200
        assert 'data-session-view="goal" ' in shared_session.text
        assert '<form method="post"' not in shared_session.text.split('<main', 1)[1]
        assert client.get(f"/dashboard/runtime-sessions/calls/{call_id}",
                          params={"tenant": first["tenant_id"]}).status_code == 200
        assert client.get(f"/dashboard/runtime-sessions/calls/{call_id}").status_code == 404
        assert client.get(f"/dashboard/goal-runs/{first['id']}/calls/{call_id}"
                          f"?tenant={first['tenant_id']}").status_code == 200
        assert client.get(f"/dashboard/goal-runs/{first['id']}/calls/"
                          f"00000000-0000-0000-0000-000000000001?tenant={first['tenant_id']}").status_code == 404
        csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
        other = client.post("/api/v2/tenants", json={"name": "Unrelated Lab Reader"},
                            headers={"X-CSRF-Token": csrf}).json()
        client.post("/login", data={"tenant_id": other["tenant_id"],
                                    "password": other["admin_password"]})
        assert client.get(f"/dashboard/goal-runs/{first['id']}?tenant={first['tenant_id']}").status_code == 403
        assert client.get(f"/api/v3/goal-runs/{first['id']}?tenant={first['tenant_id']}").status_code == 403
        assert client.get(f"/dashboard/goal-assessments?tenant={first['tenant_id']}").status_code == 403
        assert client.get(f"/api/v3/goal-assessments?tenant={first['tenant_id']}").status_code == 403
        assert client.get(f"/dashboard/runtime-sessions?tenant={first['tenant_id']}").status_code == 403
        assert client.get(f"/dashboard/runtime-sessions/calls/{call_id}?tenant={first['tenant_id']}").status_code == 403
