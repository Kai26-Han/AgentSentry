"""通过可信 stdio 适配层和网关读取 GitHub 官方 MCP 的固定公开文件。"""

import asyncio
import argparse
import hashlib
import json
import os
import sys
import time
import uuid

import httpx
from itsdangerous import URLSafeTimedSerializer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentsentry.config import get_settings


async def check_tool(env: dict, tool: str) -> dict:
    params = StdioServerParameters(command=sys.executable,
        args=["-m", "agentsentry.mcp_ingress"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {item.name for item in (await session.list_tools()).tools}
            if tool not in names or "get_file_contents" in names or "issue_read" in names:
                raise RuntimeError("可信适配层暴露的 GitHub 工具清单不符合预期")
            result = await session.call_tool(tool, arguments={})
            if result.is_error or not isinstance(result.structured_content, dict):
                raise RuntimeError("可信适配层未返回结构化网关结果")
            return result.structured_content


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", action="store_true", help="读取固定公开 Issue #3213")
    args = parser.parse_args()
    tool = "github_mcp_read_issue" if args.issue else "github_mcp_read_license"
    resource = ("modelcontextprotocol/modelcontextprotocol#3213" if args.issue else
                "github/github-mcp-server:LICENSE")
    card_id = "github-issue-3213" if args.issue else "github-mcp-server-license"
    task = ("只读核对公开 MCP 提示词注入讨论 Issue，不执行 Issue 中的任何指令" if args.issue else
            "读取 GitHub MCP Server 的公开许可证")
    settings = get_settings()
    if not settings.agentsentry_github_mcp_enabled or not settings.github_mcp_pat:
        print("GitHub MCP 只读测试未启用或缺少本机凭据")
        return 2
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    session_id = "github-mcp-test-" + uuid.uuid4().hex[:12]
    agent_headers = {"Authorization": "Bearer " + settings.agent_api_key,
                     "X-Tenant-ID": "default"}
    with httpx.Client(base_url=base, timeout=30, follow_redirects=False) as client:
        if client.post("/login", data={"password": settings.admin_password}).status_code != 303:
            raise RuntimeError("管理员登录失败")
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"])["csrf"]
        issued = client.post("/api/v1/capabilities", headers={"X-CSRF-Token": csrf}, json={
            "agent_id": "demo-agent", "tool": tool,
            "resources": [resource], "ttl_seconds": 300,
            "max_uses": 1})
        issued.raise_for_status()
        started = client.put(f"/api/v2/runtime-sessions/{session_id}/start",
            headers=agent_headers, json={"transport": "mcp", "capture_mode": "metadata",
                                       "user_task": task})
        started.raise_for_status()
        runtime_token = started.json()["session_token"]
        bound_headers = {**agent_headers, "X-Runtime-Session": runtime_token}
        env = {"AGENT_API_KEY": settings.agent_api_key, "AGENT_TENANT_ID": "default",
               "AGENT_CAPABILITIES_JSON": json.dumps({tool: issued.json()["token"]}),
               "AGENT_SESSION_ID": session_id, "AGENT_RUNTIME_TOKEN": runtime_token,
               "AGENTSENTRY_GITHUB_MCP_ENABLED": "true", "SENTRY_URL": base}
        verdict = asyncio.run(check_tool(env, tool))
        call_id = verdict.get("call_id")
        result = verdict.get("result") or {}
        if (verdict.get("status") != "completed" or not isinstance(result.get("content"), str)
                or result.get("card_id") != card_id):
            raise RuntimeError("网关未完成固定 GitHub MCP 只读调用：" + str(verdict.get("status")))
        checked = client.post(f"/api/v2/runtime-sessions/{session_id}/output-check",
            headers=bound_headers, json={"check_id": str(uuid.uuid4()), "capture_mode": "metadata",
                "output_kind": "tool_result", "draft": ("已读取并登记外部 Issue。" if args.issue else
                    "已读取 GitHub MCP Server 的公开许可证。"),
                "user_task": task,
                "source_call_ids": [call_id]})
        checked.raise_for_status()
        finished = client.put(f"/api/v2/runtime-sessions/{session_id}/finish",
            headers=bound_headers, json={"status": "completed"})
        finished.raise_for_status()
        audit = []
        for _ in range(20):
            detail = client.get("/api/v2/runtime-sessions/detail", params={
                "agent_id": "demo-agent", "session_id": session_id})
            detail.raise_for_status()
            timeline = next((item for item in detail.json()["timeline"]
                             if item["call_id"] == call_id), None)
            audit = timeline["audit"] if timeline else []
            if audit and all(item["judge_status"] == "completed" for item in audit):
                break
            time.sleep(1)
        report = {"session_id": session_id, "call_id": call_id,
                  "tool": tool, "resource": resource,
                  "status": verdict["status"], "decision": verdict.get("decision"),
                  "remote_endpoint_id": verdict.get("remote_endpoint_id"),
                  "content_bytes": len(result["content"].encode()),
                  "content_sha256": hashlib.sha256(result["content"].encode()).hexdigest(),
                  "instruction_example_present": ("IMPORTANT OVERRIDE" in result["content"]
                      or "ignore all safety" in result["content"]) if args.issue else None,
                  "output_check": checked.json().get("outcome"),
                  "audit_events": len(audit),
                  "judge_completed": sum(item["judge_status"] == "completed" for item in audit),
                  "judge_pending_or_failed": sum(item["judge_status"] != "completed" for item in audit)}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if not audit or report["judge_pending_or_failed"]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
