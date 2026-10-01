"""在本机网关验证 V2.7 的执行前升级审批、暂停和租户隔离。"""

import json
import os
import stat
import uuid
from pathlib import Path

import httpx
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


ROOT = Path(__file__).resolve().parents[1]
CREDS_PATH = ROOT / ".local" / "runtime-smoke.json"


def login(client: httpx.Client, tenant: dict, secret: str) -> dict:
    response = client.post("/login", data={"tenant_id": tenant["tenant_id"],
        "password": tenant["admin_password"]}, follow_redirects=False)
    if response.status_code != 303:
        raise RuntimeError("管理员登录失败")
    csrf = URLSafeTimedSerializer(secret, salt="agentsentry-admin").loads(
        client.cookies["agentsentry_session"])["csrf"]
    return {"X-CSRF-Token": csrf}


def bootstrap(client: httpx.Client, settings) -> dict:
    if CREDS_PATH.exists():
        if stat.S_IMODE(CREDS_PATH.stat().st_mode) & 0o077:
            raise RuntimeError("研究租户凭据文件权限必须为 0600")
        return json.loads(CREDS_PATH.read_text(encoding="utf-8"))
    headers = login(client, {"tenant_id": "default", "admin_password": settings.admin_password},
                    settings.session_secret)
    response = client.post("/api/v2/tenants", headers=headers,
        json={"name": "Runtime Lab " + uuid.uuid4().hex[:8]})
    response.raise_for_status()
    tenant = response.json()
    CREDS_PATH.parent.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(CREDS_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(tenant, handle, ensure_ascii=False)
    return tenant


def main() -> None:
    settings = get_settings()
    settings.validate_runtime()
    url = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    with httpx.Client(base_url=url, timeout=30) as client:
        tenant = bootstrap(client, settings)
        admin = login(client, tenant, settings.session_secret)
        agent = {"Authorization": "Bearer " + tenant["agent_api_key"],
                 "X-Tenant-ID": tenant["tenant_id"]}

        def start(session_id: str) -> str:
            response = client.put(f"/api/v2/runtime-sessions/{session_id}/start",
                headers=agent, json={"transport": "http", "capture_mode": "metadata"})
            response.raise_for_status()
            return response.json()["session_token"]

        def grant(tool: str, resources: list[str]) -> str:
            response = client.post("/api/v1/capabilities", headers=admin, json={
                "agent_id": "demo-agent", "tool": tool, "resources": resources,
                "ttl_seconds": 600, "max_uses": 3})
            response.raise_for_status()
            return response.json()["token"]

        def call(session_id: str, binding: str, tool: str, arguments: dict,
                 capability: str) -> dict:
            response = client.post("/api/v1/tool-calls", headers={**agent,
                "X-Runtime-Session": binding, "X-Capability": capability},
                json={"call_id": str(uuid.uuid4()), "session_id": session_id,
                      "tool": tool, "arguments": arguments})
            response.raise_for_status()
            return response.json()

        first_session = "v27-smoke-" + uuid.uuid4().hex[:16]
        first_binding = start(first_session)
        read = call(first_session, first_binding, "read_document",
                    {"document_id": "injected-guide"}, grant("read_document", ["injected-guide"]))
        if read["status"] != "completed":
            raise RuntimeError("合成恶意文档读取失败")
        title = "v27-protected-" + uuid.uuid4().hex[:12]
        proposed = call(first_session, first_binding, "create_task",
                        {"title": title, "list_id": "main"}, grant("create_task", ["main"]))
        if proposed["status"] != "pending_approval" or "instruction_source_before_write" not in proposed["runtime_findings"]:
            raise RuntimeError("恶意来源后写入未升级审批")
        if title in client.get("/dashboard/system").text:
            raise RuntimeError("审批前已产生任务副作用")
        evidence = client.get("/api/v2/runtime-decisions/" + proposed["call_id"])
        evidence.raise_for_status()
        if not evidence.json()["items"]:
            raise RuntimeError("运行时证据缺失")
        detail = client.get("/dashboard/calls/" + proposed["call_id"])
        if detail.status_code != 200 or "runtime_decision" not in detail.text:
            raise RuntimeError("调用详情缺少运行时审计事件")
        session_detail = client.get("/dashboard/runtime-sessions/detail",
            params={"agent_id": "demo-agent", "session_id": first_session})
        if session_detail.status_code != 200 or proposed["call_id"] not in session_detail.text:
            raise RuntimeError("会话时间线未关联运行时调用")
        rejected = client.post(f"/api/v1/approvals/{proposed['approval_id']}/decision",
            headers=admin, json={"decision": "reject"})
        rejected.raise_for_status()

        second_session = "v27-smoke-" + uuid.uuid4().hex[:16]
        second_binding = start(second_session)
        external_marker = "v27-approval-" + uuid.uuid4().hex[:12]
        pending_external = call(second_session, second_binding, "send_external",
            {"destination_id": "demo-inbox", "content": external_marker},
            grant("send_external", ["demo-inbox"]))
        if pending_external["status"] != "pending_approval":
            raise RuntimeError("模拟外发未进入原有审批")
        control = {"agent_id": "demo-agent", "session_id": second_session,
                   "scope": "session", "paused": True, "reason": "本机处置测试"}
        paused = client.post("/api/v2/runtime-controls", headers=admin, json=control)
        paused.raise_for_status()
        approved_after_pause = client.post(
            f"/api/v1/approvals/{pending_external['approval_id']}/decision",
            headers=admin, json={"decision": "approve"})
        approved_after_pause.raise_for_status()
        if (approved_after_pause.json()["status"] != "denied"
                or external_marker in client.get("/dashboard/system").text):
            raise RuntimeError("暂停后审批仍然执行了原动作")
        blocked_title = "v27-paused-" + uuid.uuid4().hex[:12]
        blocked = call(second_session, second_binding, "create_task",
            {"title": blocked_title, "list_id": "main"}, grant("create_task", ["main"]))
        if blocked["status"] != "denied" or blocked_title in client.get("/dashboard/system").text:
            raise RuntimeError("暂停后仍出现工具副作用")
        resumed = client.post("/api/v2/runtime-controls", headers=admin,
            json={**control, "paused": False, "reason": "测试完成"})
        resumed.raise_for_status()
        incidents = client.get("/api/v2/runtime-incidents").json()["items"]
        if not any(item["rule_id"] == "administrator_paused" for item in incidents):
            raise RuntimeError("运行时告警未记录")

        with httpx.Client(base_url=url, timeout=20) as root:
            login(root, {"tenant_id": "default", "admin_password": settings.admin_password},
                  settings.session_secret)
            if root.get("/api/v2/runtime-decisions/" + proposed["call_id"]).status_code != 404:
                raise RuntimeError("跨租户可读取研究调用的运行时证据")
        print(json.dumps({"tenant_id": tenant["tenant_id"], "approval_call": proposed["call_id"],
            "approval_status": proposed["status"], "paused_call": blocked["call_id"],
            "paused_status": blocked["status"], "runtime_incidents": len(incidents),
            "approval_after_pause": approved_after_pause.json()["status"],
            "cross_tenant_hidden": True, "forbidden_side_effects": 0}, ensure_ascii=False))


if __name__ == "__main__":
    main()
