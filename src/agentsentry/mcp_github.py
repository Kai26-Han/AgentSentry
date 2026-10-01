"""固定的 GitHub 官方 MCP 测试出口；凭据、仓库和上游工具均来自可信配置。"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .config import get_settings
from .mcp_remote import _pinned_transport


ENDPOINT = "https://api.githubcopilot.com/mcp/x/repos/readonly"
ISSUE_ENDPOINT = "https://api.githubcopilot.com/mcp/x/issues/readonly"
ISSUE_WRITE_ENDPOINT = "https://api.githubcopilot.com/mcp/x/issues"
TOOL_NAME = "get_file_contents"
TOOL_SCHEMA_SHA256 = "37ab6d6cd6da6cb17c63534cdcfd55759e5dbc48d5c91cbba49c64cf9f4526d6"
ISSUE_TOOL_NAME = "issue_read"
ISSUE_WRITE_TOOL_NAME = "issue_write"
ISSUE_TOOL_SCHEMA_SHA256 = "f6e785464d9e479d02d8d11ad683152d547bd9028d129c588e827097269edf56"
CARD_ID = "github-mcp-server-license"
ARGUMENTS = {"owner": "github", "repo": "github-mcp-server", "path": "LICENSE"}
ISSUE_CARD_ID = "github-issue-3213"
ISSUE_RESOURCE = "modelcontextprotocol/modelcontextprotocol#3213"
ISSUE_ARGUMENTS = {"method": "get", "owner": "modelcontextprotocol",
                   "repo": "modelcontextprotocol", "issue_number": 3213}


def _tool_hash(tool) -> str:
    raw = json.dumps(tool.model_dump(mode="json", by_alias=True, exclude_none=True),
                     ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _extract_result(response) -> str:
    if response.is_error:
        raise ValueError("GitHub MCP tool returned an error")
    resources = [item.resource for item in response.content if item.type == "resource"]
    if len(resources) != 1 or not isinstance(getattr(resources[0], "text", None), str):
        raise ValueError("GitHub MCP resource result shape changed")
    content = resources[0].text
    if not content or len(content.encode("utf-8")) > 8192:
        raise ValueError("GitHub MCP resource result exceeds the approved size")
    return content


def _extract_issue(response) -> str:
    if response.is_error or len(response.content) != 1 or response.content[0].type != "text":
        raise ValueError("GitHub MCP issue result shape changed")
    raw = response.content[0].text
    if len(raw.encode("utf-8")) > 16_384:
        raise ValueError("GitHub MCP issue response too large")
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("number") != ISSUE_ARGUMENTS["issue_number"]
            or value.get("html_url") != "https://github.com/" + ISSUE_RESOURCE.replace("#", "/issues/")
            or not isinstance(value.get("title"), str) or not isinstance(value.get("body"), str)):
        raise ValueError("GitHub MCP issue identity or fields changed")
    title, body = value["title"], value["body"]
    if not title or not body or len(title.encode("utf-8")) > 300 or len(body.encode("utf-8")) > 8192:
        raise ValueError("GitHub MCP issue content exceeds approved size")
    return title + "\n" + body


def _extract_created_issue(response, repository: str, arguments: dict) -> dict:
    if response.is_error or len(response.content) != 1 or response.content[0].type != "text":
        raise ValueError("GitHub MCP issue_write result shape changed")
    raw = response.content[0].text
    if len(raw.encode("utf-8")) > 32_768:
        raise ValueError("GitHub MCP issue_write result too large")
    value = json.loads(raw)
    issue_id = value.get("id") if isinstance(value, dict) else None
    url = value.get("url") if isinstance(value, dict) else None
    prefix = f"https://github.com/{repository}/issues/"
    match = re.fullmatch(re.escape(prefix) + r"([1-9][0-9]*)", url) if isinstance(url, str) else None
    if (not isinstance(issue_id, str) or not issue_id.isascii() or
            not issue_id.isdecimal() or int(issue_id) <= 0 or not match):
        raise ValueError("GitHub MCP issue_write result identity changed")
    return {"issue_id": issue_id, "issue_number": int(match.group(1)),
            "html_url": url, "title": arguments["title"]}


async def _verify_created_issue(token: str, repository: str, arguments: dict, result: dict) -> None:
    """Read the single created Issue; an uncertain readback must not trigger a write retry."""
    url = f"https://api.github.com/repos/{repository}/issues/{result['issue_number']}"
    transport = _pinned_transport([url], True, asynchronous=True)
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json"},
        timeout=httpx2.Timeout(10, read=10), follow_redirects=False, trust_env=False,
        transport=transport,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        if len(response.content) > 32_768:
            raise ValueError("GitHub created issue readback too large")
        value = response.json()
    if (not isinstance(value, dict) or str(value.get("id")) != result["issue_id"] or
            value.get("number") != result["issue_number"] or
            value.get("html_url") != result["html_url"] or
            value.get("title") != arguments["title"] or
            value.get("body") != arguments["body"] or "pull_request" in value):
        raise ValueError("GitHub created issue readback differs from approved parameters")


async def _read(token: str) -> dict:
    transport = _pinned_transport([ENDPOINT], True, asynchronous=True)
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token, "X-MCP-Readonly": "true"},
        timeout=httpx2.Timeout(10, read=10), follow_redirects=False,
        trust_env=False, transport=transport,
    ) as client:
        async with streamable_http_client(ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listing = await session.list_tools()
                if listing.next_cursor or len(listing.tools) > 30:
                    raise ValueError("GitHub MCP tool list too large or paginated")
                matches = [tool for tool in listing.tools if tool.name == TOOL_NAME]
                if len(matches) != 1 or _tool_hash(matches[0]) != TOOL_SCHEMA_SHA256:
                    raise ValueError("GitHub MCP approved tool schema changed")
                response = await session.call_tool(TOOL_NAME, arguments=ARGUMENTS)
                content = _extract_result(response)
                # Authenticated third-party content is private until visibility is independently proven.
                return {"card_id": CARD_ID, "content": content, "sensitivity": "private",
                        "_remote": {"endpoint_id": "github", "protocol": "streamable-http",
                                    "manifest_sha256": TOOL_SCHEMA_SHA256}}


async def _read_issue(token: str) -> dict:
    transport = _pinned_transport([ISSUE_ENDPOINT], True, asynchronous=True)
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token, "X-MCP-Readonly": "true"},
        timeout=httpx2.Timeout(10, read=10), follow_redirects=False, trust_env=False,
        transport=transport,
    ) as client:
        async with streamable_http_client(ISSUE_ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listing = await session.list_tools()
                if listing.next_cursor or len(listing.tools) > 30:
                    raise ValueError("GitHub MCP issue tool list too large or paginated")
                matches = [tool for tool in listing.tools if tool.name == ISSUE_TOOL_NAME]
                if len(matches) != 1 or _tool_hash(matches[0]) != ISSUE_TOOL_SCHEMA_SHA256:
                    raise ValueError("GitHub MCP approved issue tool schema changed")
                response = await session.call_tool(ISSUE_TOOL_NAME, arguments=ISSUE_ARGUMENTS)
                return {"card_id": ISSUE_CARD_ID, "content": _extract_issue(response),
                        "sensitivity": "private", "_remote": {
                            "endpoint_id": "github", "protocol": "streamable-http",
                            "manifest_sha256": ISSUE_TOOL_SCHEMA_SHA256}}


async def _create_issue(token: str, repository: str, schema_sha256: str,
                        arguments: dict, sent: dict) -> dict:
    transport = _pinned_transport([ISSUE_WRITE_ENDPOINT], True, asynchronous=True)
    owner, repo = repository.split("/", 1)
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token},
        timeout=httpx2.Timeout(10, read=10), follow_redirects=False, trust_env=False,
        transport=transport,
    ) as client:
        async with streamable_http_client(ISSUE_WRITE_ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listing = await session.list_tools()
                if listing.next_cursor or len(listing.tools) > 40:
                    raise ValueError("GitHub MCP write tool list too large or paginated")
                matches = [tool for tool in listing.tools if tool.name == ISSUE_WRITE_TOOL_NAME]
                if len(matches) != 1 or _tool_hash(matches[0]) != schema_sha256:
                    raise ValueError("GitHub MCP approved create_issue schema changed")
                upstream_arguments = {"method": "create", "owner": owner, "repo": repo,
                                      "title": arguments["title"], "body": arguments["body"]}
                sent["value"] = True
                response = await session.call_tool(ISSUE_WRITE_TOOL_NAME,
                                                   arguments=upstream_arguments)
                result = _extract_created_issue(response, repository, arguments)
                await _verify_created_issue(token, repository, arguments, result)
                result["_remote"] = {"endpoint_id": "github", "protocol": "streamable-http",
                                     "manifest_sha256": schema_sha256}
                return result


def execute_github_read(tenant_id: str) -> dict:
    settings = get_settings()
    if tenant_id != "default" or not settings.agentsentry_github_mcp_enabled or not settings.github_mcp_pat:
        return {"error": "github_mcp_not_enabled", "endpoint_id": "github"}
    try:
        return asyncio.run(asyncio.wait_for(_read(settings.github_mcp_pat), timeout=25))
    except Exception:
        return {"error": "github_mcp_unavailable_or_drift", "endpoint_id": "github",
                "manifest_sha256": TOOL_SCHEMA_SHA256}


def execute_github_issue_read(tenant_id: str) -> dict:
    settings = get_settings()
    if tenant_id != "default" or not settings.agentsentry_github_mcp_enabled or not settings.github_mcp_pat:
        return {"error": "github_mcp_not_enabled", "endpoint_id": "github"}
    try:
        return asyncio.run(asyncio.wait_for(_read_issue(settings.github_mcp_pat), timeout=25))
    except Exception:
        return {"error": "github_mcp_unavailable_or_drift", "endpoint_id": "github",
                "manifest_sha256": ISSUE_TOOL_SCHEMA_SHA256}


def execute_github_create_issue(tenant_id: str, arguments: dict) -> dict:
    settings = get_settings()
    if (tenant_id != "default" or not settings.agentsentry_github_mcp_write_enabled or
            not settings.github_mcp_write_pat or not settings.github_mcp_test_repo or
            not settings.github_mcp_create_issue_schema_sha256 or
            arguments.get("repository") != settings.github_mcp_test_repo):
        return {"error": "github_mcp_write_not_enabled", "endpoint_id": "github"}
    sent = {"value": False}
    try:
        def run_upstream():
            return asyncio.run(asyncio.wait_for(_create_issue(
                settings.github_mcp_write_pat, settings.github_mcp_test_repo,
                settings.github_mcp_create_issue_schema_sha256, arguments, sent), timeout=25))

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return run_upstream()
        # Web approval is an async route; its synchronous gateway execution needs
        # a separate event loop. Wait for completion before committing the result.
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(run_upstream).result()
    except Exception:
        if sent["value"]:
            raise  # The upstream may have created an Issue. Preserve the gateway's unknown status.
        return {"error": "github_mcp_write_unavailable_or_drift", "endpoint_id": "github",
                "manifest_sha256": settings.github_mcp_create_issue_schema_sha256}
