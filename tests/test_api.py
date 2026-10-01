import uuid

from fastapi.testclient import TestClient

from agentsentry import main
from agentsentry.database import Base, get_engine, get_session_factory
from agentsentry.data_flow import rule_catalog as data_flow_rule_catalog
from agentsentry.evaluation import MemoryRedis
from agentsentry.runtime_guard import rule_catalog as runtime_rule_catalog


def test_admin_login_and_agent_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    from agentsentry.config import get_settings
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret, salt="agentsentry-admin")
    store = MemoryRedis()
    monkeypatch.setattr(main, "get_redis", lambda: store)
    with TestClient(main.app) as client:
        dashboard = client.get("/dashboard", follow_redirects=False)
        assert dashboard.status_code == 303 and dashboard.headers["location"] == "/login"
        assert client.get("/dashboard/runtime-rules", follow_redirects=False).status_code == 303
        assert client.get("/dashboard").status_code == 200
        assert client.get("/").status_code == 200
        assert client.post("/api/v1/capabilities", json={}).status_code == 401
        assert client.post("/login", data={"password": "wrong"}, follow_redirects=False).status_code == 401
        assert client.post("/login", data={"password": main.settings.admin_password}, follow_redirects=False).status_code == 303
        csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
        pages = ("/dashboard", "/dashboard/runtime-sessions", "/dashboard/goal-assessments",
                 "/dashboard/goal-runs", "/dashboard/activity",
                 "/dashboard/data-flow",
                 "/dashboard/audit",
                 "/dashboard/alerts", "/dashboard/approvals", "/dashboard/memories",
                 "/dashboard/memory-runs", "/dashboard/memory-security-runs",
                 "/dashboard/attack-runs", "/dashboard/judge-samples",
                 "/dashboard/grants", "/dashboard/policy", "/dashboard/runtime-rules",
                 "/dashboard/judge-runtime", "/dashboard/tenants",
                 "/dashboard/system", "/dashboard/resilience")
        for path in pages:
            page = client.get(path)
            assert page.status_code == 200, path
            assert 'aria-label="主目录"' in page.text, path
        assert client.get("/dashboard/alerts").text.count('aria-current="page"') == 1
        rule_page = client.get("/dashboard/runtime-rules")
        assert rule_page.text.count('aria-current="page"') == 1
        assert rule_page.text.count('<tr id="') == (len(runtime_rule_catalog()) +
                                                      len(data_flow_rule_catalog()))
        assert 'id="source_action_payload_in_answer"' in rule_page.text
        assert all(f'<th scope="col">{name}</th>' in rule_page.text for name in (
            "规则名称", "类别", "适用范围", "触发条件", "处置", "告警级别", "更多信息"))
        assert "runtime-rules-v1" in rule_page.text
        assert "最近 10 分钟至少 3 次" in rule_page.text
        assert "前 8192 字符" in rule_page.text
        assert "兼容模式" in rule_page.text
        assert "工具调用策略" in rule_page.text
        assert "运行时安全规则" in client.get("/dashboard/policy").text
        assert "只看有风险线索" in client.get("/dashboard/runtime-sessions").text
        assert "<h2>Judge 结果</h2>" not in client.get("/dashboard/activity").text
        assert "Judge 结果" in client.get("/dashboard/audit").text
        assert "工具调用与审计" in client.get("/dashboard/audit?view=judge").text
        for path, workspace in [("/dashboard/goal-assessments", "会话调查"),
                                ("/dashboard/action-chains", "会话调查"),
                                ("/dashboard/goal-runs", "Agent 攻击实验"),
                                ("/dashboard/runtime-rules", "防护规则")]:
            html = client.get(path).text
            assert html.count('aria-current="page"') == 1
            assert f'aria-label="{workspace}视图"' in html
        assert "待审批" in client.get("/dashboard").text
        from sqlalchemy.orm import Session
        from agentsentry.models import AuditEvent, Outbox
        failed_id = str(uuid.uuid4())
        with Session(get_engine()) as db:
            event = AuditEvent(id=str(uuid.uuid4()), event_type="test", payload={})
            db.add_all([event, Outbox(id=failed_id, audit_event_id=event.id, status="failed",
                                    attempts=3, error="password=synthetic-hidden-old-error")])
            db.commit()
        assert "synthetic-hidden-old-error" not in client.get("/dashboard/resilience").text
        retry_url = f"/dashboard/resilience/judge/{failed_id}/retry"
        assert client.post(retry_url).status_code == 403
        assert client.post(retry_url, data={"csrf": csrf}, follow_redirects=False).status_code == 303
        assert client.post(retry_url, data={"csrf": csrf}).status_code == 409
        assert client.post(f"/dashboard/resilience/tool/{failed_id}/retry", data={"csrf": csrf}).status_code == 404
        assert client.post(f"/dashboard/resilience/judge/{uuid.uuid4()}/retry", data={"csrf": csrf}).status_code == 404
        payload = {
            "agent_id": "demo-agent", "tool": "read_document",
            "resources": ["public-guide"], "ttl_seconds": 600, "max_uses": 1,
        }
        assert client.post("/api/v1/capabilities", json=payload).status_code == 403
        issued = client.post("/api/v1/capabilities", json=payload, headers={"X-CSRF-Token": csrf})
        assert issued.status_code == 200
        assert "仅保存审计，不进入 Judge" in client.get("/dashboard/audit").text
        token = issued.json()["token"]
        call = {
            "call_id": str(uuid.uuid4()), "session_id": "api-test",
            "tool": "read_document", "arguments": {"document_id": "public-guide"},
        }
        assert client.post("/api/v1/tool-calls", json=call).status_code == 401
        response = client.post("/api/v1/tool-calls", json=call, headers={
            "Authorization": "Bearer " + main.settings.agent_api_key,
            "X-Capability": token,
        })
        assert response.status_code == 200
        assert response.json()["result"]["document_id"] == "public-guide"
        assert client.get("/dashboard").status_code == 200
        assert client.get("/dashboard/calls/" + call["call_id"]).status_code == 200
        form = client.post("/dashboard/grants", data={
            "csrf": csrf, "tool": "send_external", "resources": "demo-inbox",
            "ttl_seconds": "600", "max_uses": "1",
        })
        assert form.status_code == 200
        assert "工具调用授权已签发" in form.text
        # The browser form shows the raw token once, but the test uses the API to obtain its own token.
        issued = client.post("/api/v1/capabilities", json={
            "agent_id": "demo-agent", "tool": "send_external",
            "resources": ["demo-inbox"], "ttl_seconds": 600, "max_uses": 1,
        }, headers={"X-CSRF-Token": csrf})
        started = client.put("/api/v2/runtime-sessions/api-test/start", json={
            "transport": "http", "capture_mode": "metadata"}, headers={
                "Authorization": "Bearer " + main.settings.agent_api_key})
        assert started.status_code == 200
        pending = client.post("/api/v1/tool-calls", json={
            "call_id": str(uuid.uuid4()), "session_id": "api-test",
            "tool": "send_external",
            "arguments": {"destination_id": "demo-inbox", "content": "Meeting summary"},
        }, headers={
            "Authorization": "Bearer " + main.settings.agent_api_key,
            "X-Capability": issued.json()["token"],
            "X-Runtime-Session": started.json()["session_token"],
        })
        assert pending.status_code == 202
        import re
        detail = client.get("/dashboard/approvals/" + pending.json()["approval_id"])
        assert detail.status_code == 200
        review_token = re.search(r'name="review_token" value="([^"]+)"', detail.text).group(1)
        assert client.post("/dashboard/approvals/" + pending.json()["approval_id"], data={
            "csrf": csrf, "decision": "approve",
        }).status_code == 422
        approved = client.post(
            "/dashboard/approvals/" + pending.json()["approval_id"],
            data={"csrf": csrf, "decision": "approve", "reviewed": "yes",
                  "review_token": review_token}, follow_redirects=False,
        )
        assert approved.status_code == 303
        assert approved.headers["location"] == "/dashboard/approvals"
        assert client.get("/api/v1/tool-calls/" + pending.json()["call_id"], headers={
            "Authorization": "Bearer " + main.settings.agent_api_key,
        }).json()["status"] == "completed"
        monkeypatch.setattr(main, "settings", main.settings.model_copy(update={
            "judge_provider": "mock", "jev_api_key": "synthetic-jev-key", "deepseek_api_key": "",
        }))
        samples = client.get("/api/v1/judge-samples?provider=jev")
        assert samples.status_code == 200
        assert samples.json()["provider"] == "jev"
        assert samples.json()["runtime_provider"] == "mock"
        sample_id = samples.json()["samples"][0]["id"]
        page = client.get("/dashboard/judge-samples?provider=jev")
        assert page.status_code == 200
        assert 'name="provider" value="jev"' in page.text
        assert "https://api.typesafe.ai" in page.text
        assert client.get("/dashboard/judge-samples?provider=invalid").status_code == 422
        assert client.post(f"/api/v1/judge-samples/{sample_id}/run", json={"provider": "jev"}).status_code == 403
        assert client.post(f"/api/v1/judge-samples/{sample_id}/run", json={"provider": "deepseek"},
                           headers={"X-CSRF-Token": csrf}).status_code == 422
        queued = client.post(f"/api/v1/judge-samples/{sample_id}/run", json={"provider": "jev"},
                             headers={"X-CSRF-Token": csrf})
        assert queued.status_code == 202 and queued.json()["provider"] == "jev"
        assert client.get("/api/v1/judge-samples?provider=jev").json()["metrics"]["evaluated"] == 0
        runtime = client.get("/api/v1/judge-runtime").json()
        assert runtime["provider"] == "mock" and runtime["revision"] == 1
        assert client.post("/dashboard/judge-runtime", data={"provider": "jev", "expected_revision": 1},
                           follow_redirects=False).status_code == 403
        assert client.put("/api/v1/judge-runtime", json={"provider": "jev", "expected_revision": 1}).status_code == 403
        assert client.put("/api/v1/judge-runtime", json={"provider": "deepseek", "expected_revision": 1},
                          headers={"X-CSRF-Token": csrf}).status_code == 422
        switched = client.put("/api/v1/judge-runtime", json={"provider": "jev", "expected_revision": 1},
                              headers={"X-CSRF-Token": csrf})
        assert switched.status_code == 200 and switched.json() == {"provider": "jev", "revision": 2}
        assert client.get("/dashboard/judge-runtime").text.count('aria-current="page"') == 1
        assert client.get("/api/v1/judge-samples").json()["runtime_provider"] == "jev"
        assert client.put("/api/v1/judge-runtime", json={"provider": "mock", "expected_revision": 1},
                          headers={"X-CSRF-Token": csrf}).status_code == 409
        reverted = client.post("/dashboard/judge-runtime", data={
            "csrf": csrf, "provider": "mock", "expected_revision": "2",
        }, follow_redirects=False)
        assert reverted.status_code == 303
        assert client.get("/api/v1/judge-runtime").json()["provider"] == "mock"
    get_session_factory.cache_clear()
    get_engine().dispose()
    get_engine.cache_clear()
    get_settings.cache_clear()
