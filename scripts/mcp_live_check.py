"""Exercise the full local MCP read and approval path with the official client."""

import asyncio
import json
import os
import sys

import httpx
from itsdangerous import URLSafeTimedSerializer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentsentry.config import get_settings


async def check() -> dict:
    settings = get_settings()
    base_url = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}").rstrip("/")
    with httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as admin:
        login = admin.post("/login", data={"tenant_id": "default", "password": settings.admin_password})
        if login.status_code != 303:
            raise RuntimeError("Default administrator login failed")
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            admin.cookies["agentsentry_session"]
        )["csrf"]
        grants = {}
        for tool, resource in (("mcp_lookup_card", "public-guide"), ("mcp_record_note", "demo-notes")):
            response = admin.post("/api/v1/capabilities", json={
                "agent_id": "demo-agent", "tool": tool, "resources": [resource],
                "ttl_seconds": 600, "max_uses": 1,
            }, headers={"X-CSRF-Token": csrf})
            response.raise_for_status()
            grants[tool] = response.json()["token"]

        params = StdioServerParameters(
            command=sys.executable, args=["-m", "agentsentry.mcp_ingress"],
            env={
                "SENTRY_URL": base_url, "AGENT_API_KEY": settings.agent_api_key,
                "AGENT_TENANT_ID": "default", "AGENT_CAPABILITIES_JSON": json.dumps(grants),
            },
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as mcp:
                await mcp.initialize()
                listed = await mcp.list_tools()
                assert {tool.name for tool in listed.tools} == {
                    "mcp_lookup_card", "mcp_record_note", "agentsentry_call_status",
                }
                read_result = (await mcp.call_tool("mcp_lookup_card", arguments={"card_id": "public-guide"})).structured_content
                assert read_result and read_result["status"] == "completed"
                write_result = (await mcp.call_tool("mcp_record_note", arguments={
                    "note_id": "live-review", "text": "Approved synthetic MCP note",
                })).structured_content
                assert write_result and write_result["status"] == "pending_approval"
                call_id = write_result["call_id"]
                pending = (await mcp.call_tool("agentsentry_call_status", arguments={"call_id": call_id})).structured_content
                assert pending and pending["status"] == "pending_approval" and pending["result"] is None
                approval = admin.post(
                    "/api/v1/approvals/" + write_result["approval_id"] + "/decision",
                    json={"decision": "approve"}, headers={"X-CSRF-Token": csrf},
                )
                approval.raise_for_status()
                final = (await mcp.call_tool("agentsentry_call_status", arguments={"call_id": call_id})).structured_content
                assert final and final["status"] == "completed" and final["result"]["recorded"] is True
                return {"listed_tools": sorted(tool.name for tool in listed.tools),
                        "read_call_id": read_result["call_id"], "read_status": read_result["status"],
                        "write_call_id": call_id, "write_status": final["status"]}


if __name__ == "__main__":
    print(json.dumps(asyncio.run(check()), ensure_ascii=False, indent=2))
