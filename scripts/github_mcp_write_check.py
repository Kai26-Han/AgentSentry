"""在固定测试仓库做一次受控 Issue 写入；审批由管理员在 Web 页面手工完成。"""

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
from itsdangerous import URLSafeTimedSerializer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentsentry.config import get_settings


TOOL = "github_mcp_create_test_issue"
TEST_BODY = "Synthetic controlled-write verification. No real user data."


def github_issues(token: str, repository: str, title: str) -> list[dict]:
    url = f"https://api.github.com/repos/{repository}/issues"
    with httpx.Client(headers={"Authorization": "Bearer " + token,
                               "Accept": "application/vnd.github+json"},
                      timeout=15, follow_redirects=False, trust_env=False) as client:
        response = client.get(url, params={"state": "all", "per_page": 100})
        response.raise_for_status()
        items = response.json()
    if not isinstance(items, list) or len(items) >= 100:
        raise RuntimeError("测试仓库的 Issue 数量过多，请使用专用空仓库")
    return [item for item in items if isinstance(item, dict) and
            item.get("title") == title and "pull_request" not in item]


async def guarded_create(env: dict[str, str], title: str, body: str) -> dict:
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "agentsentry.mcp_ingress"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = {tool.name for tool in (await session.list_tools()).tools}
            if TOOL not in names or "issue_write" in names:
                raise RuntimeError("可信适配层工具清单不符合固定映射")
            result = await session.call_tool(TOOL, arguments={"title": title, "body": body})
            if result.is_error or not isinstance(result.structured_content, dict):
                raise RuntimeError("可信适配层没有返回结构化结果")
            return result.structured_content


def prepare(state_dir: Path) -> None:
    settings = get_settings()
    settings.validate_runtime()
    if not settings.agentsentry_github_mcp_write_enabled:
        raise RuntimeError("请先启用固定仓库 GitHub MCP 写入配置")
    title = "[AgentSentry Test] guarded issue " + uuid.uuid4().hex[:12]
    body = TEST_BODY
    if github_issues(settings.github_mcp_write_pat, settings.github_mcp_test_repo, title):
        raise RuntimeError("唯一测试标题已存在")
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    session_id = "github-write-test-" + uuid.uuid4().hex[:12]
    agent_headers = {"Authorization": "Bearer " + settings.agent_api_key,
                     "X-Tenant-ID": "default"}
    with httpx.Client(base_url=base, timeout=30, follow_redirects=False) as client:
        login = client.post("/login", data={"password": settings.admin_password})
        if login.status_code != 303:
            raise RuntimeError("默认管理员登录失败")
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"])["csrf"]
        grant = client.post("/api/v1/capabilities", headers={"X-CSRF-Token": csrf}, json={
            "agent_id": "demo-agent", "tool": TOOL,
            "resources": [settings.github_mcp_test_repo], "ttl_seconds": 600,
            "max_uses": 1})
        grant.raise_for_status()
        started = client.put(f"/api/v2/runtime-sessions/{session_id}/start",
            headers=agent_headers, json={"transport": "mcp", "capture_mode": "metadata",
                                       "user_task": "Create one synthetic test Issue in the approved repository."})
        started.raise_for_status()
        env = {"AGENT_API_KEY": settings.agent_api_key, "AGENT_TENANT_ID": "default",
               "AGENT_CAPABILITIES_JSON": json.dumps({TOOL: grant.json()["token"]}),
               "AGENT_SESSION_ID": session_id, "AGENT_RUNTIME_TOKEN": started.json()["session_token"],
               "AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED": "true", "SENTRY_URL": base}
        verdict = asyncio.run(guarded_create(env, title, body))
    if verdict.get("status") != "pending_approval" or not verdict.get("approval_id"):
        raise RuntimeError("调用未进入待审批；状态=" + str(verdict.get("status")))
    if github_issues(settings.github_mcp_write_pat, settings.github_mcp_test_repo, title):
        raise RuntimeError("审批前检测到上游 Issue，必须停止实验并检查")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = state_dir / (verdict["call_id"] + ".json")
    payload = {"repository": settings.github_mcp_test_repo, "session_id": session_id,
               "call_id": verdict["call_id"], "approval_id": verdict["approval_id"],
               "title": title, "before_count": 0}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"status": "pending_approval", "repository": payload["repository"],
        "title": title, "call_id": payload["call_id"], "approval_id": payload["approval_id"],
        "before_count": 0, "review_url": base + "/dashboard/approvals/" + payload["approval_id"],
        "verify_command": f".venv/bin/python scripts/github_mcp_write_check.py --verify {path}"},
        ensure_ascii=False, indent=2))


def verify(path: Path) -> None:
    settings = get_settings()
    saved = json.loads(path.read_text(encoding="utf-8"))
    if saved["repository"] != settings.github_mcp_test_repo:
        raise RuntimeError("测试仓库配置与待验证记录不一致")
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    with httpx.Client(base_url=base, timeout=15, follow_redirects=False) as client:
        result = client.get("/api/v1/tool-calls/" + saved["call_id"], headers={
            "Authorization": "Bearer " + settings.agent_api_key,
            "X-Tenant-ID": "default"})
        result.raise_for_status()
        call = result.json()
    issues = github_issues(settings.github_mcp_write_pat, saved["repository"], saved["title"])
    issue_number = (call.get("result") or {}).get("issue_number")
    expected_url = (f"https://github.com/{saved['repository']}/issues/{issue_number}"
                    if type(issue_number) is int else None)
    report = {"call_id": saved["call_id"], "repository": saved["repository"],
              "gateway_status": call.get("status"), "github_exact_title_count": len(issues),
              "issue_number": issue_number, "verified": call.get("status") == "completed"
              and len(issues) == 1 and issues[0].get("number") == issue_number
              and issues[0].get("body") == TEST_BODY
              and issues[0].get("html_url") == expected_url
              and (call.get("result") or {}).get("html_url") == expected_url}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["verified"]:
        raise RuntimeError("网关状态和 GitHub 实际副作用尚未一致；unknown 时不可重试")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path, help="管理员审批后核对状态与 GitHub 实际 Issue")
    parser.add_argument("--state-dir", type=Path, default=Path(".local/github-write-runs"))
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        prepare(args.state_dir)
