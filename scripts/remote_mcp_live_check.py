"""通过正式 MCP 客户端验证本机受控远端的读取、审批写入和审计入口。"""

import asyncio
import json
import os
import sys
import uuid

import httpx
from itsdangerous import URLSafeTimedSerializer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentsentry.config import get_settings


async def check() -> dict:
    settings = get_settings()
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}").rstrip("/")
    session_id = "remote-live-" + uuid.uuid4().hex
    with httpx.Client(base_url=base, timeout=20, follow_redirects=False) as admin:
        if admin.post("/login", data={"tenant_id": "default",
                                      "password": settings.admin_password}).status_code != 303:
            raise RuntimeError("管理员登录失败")
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            admin.cookies["agentsentry_session"])["csrf"]
        grants = {}
        for tool, resource in (("remote_mcp_lookup_card", "remote-public-guide"),
                               ("remote_mcp_record_note", "remote-demo-notes")):
            response = admin.post("/api/v1/capabilities", json={
                "agent_id": "demo-agent", "tool": tool, "resources": [resource],
                "ttl_seconds": 600, "max_uses": 1}, headers={"X-CSRF-Token": csrf})
            response.raise_for_status()
            grants[tool] = response.json()["token"]
        agent_headers = {"Authorization": "Bearer " + settings.agent_api_key,
                         "X-Tenant-ID": "default"}
        started = admin.put(f"/api/v2/runtime-sessions/{session_id}/start",
            headers=agent_headers, json={"transport": "mcp", "capture_mode": "metadata"})
        started.raise_for_status()
        params = StdioServerParameters(command=sys.executable,
            args=["-m", "agentsentry.mcp_ingress"], env={
                "SENTRY_URL": base, "AGENT_API_KEY": settings.agent_api_key,
                "AGENT_TENANT_ID": "default", "AGENT_SESSION_ID": session_id,
                "AGENT_RUNTIME_TOKEN": started.json()["session_token"],
                "AGENT_CAPABILITIES_JSON": json.dumps(grants),
                "AGENTSENTRY_REMOTE_MCP_ENABLED": "true"})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as mcp:
                await mcp.initialize()
                tools = {item.name for item in (await mcp.list_tools()).tools}
                assert {"remote_mcp_lookup_card", "remote_mcp_record_note"} <= tools
                read_result = (await mcp.call_tool("remote_mcp_lookup_card", arguments={
                    "card_id": "remote-public-guide"})).structured_content
                assert read_result and read_result["status"] == "completed"
                write_result = (await mcp.call_tool("remote_mcp_record_note", arguments={
                    "note_id": "live-" + session_id[-12:], "text": "Synthetic approved remote note"})).structured_content
                assert write_result and write_result["status"] == "pending_approval"
                pending = (await mcp.call_tool("agentsentry_call_status", arguments={
                    "call_id": write_result["call_id"]})).structured_content
                assert pending and pending["status"] == "pending_approval" and pending["result"] is None
                approved = admin.post("/api/v1/approvals/" + write_result["approval_id"] + "/decision",
                    json={"decision": "approve"}, headers={"X-CSRF-Token": csrf})
                approved.raise_for_status()
                final = (await mcp.call_tool("agentsentry_call_status", arguments={
                    "call_id": write_result["call_id"]})).structured_content
                assert final and final["status"] == "completed" and final["result"]["recorded"] is True
                return {"read_call_id": read_result["call_id"], "read_status": read_result["status"],
                        "write_call_id": write_result["call_id"], "write_status": final["status"],
                        "session_id": session_id}


if __name__ == "__main__":
    print(json.dumps(asyncio.run(check()), ensure_ascii=False, indent=2))
