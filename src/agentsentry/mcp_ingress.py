"""Trusted stdio MCP entry point for the existing AgentSentry HTTP gateway."""

import json
import os
import uuid

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent

from .config import get_settings


server = MCPServer("AgentSentry guarded tools", version="3.2")
SESSION_ID = os.environ.get("AGENT_SESSION_ID") or str(uuid.uuid4())


def _result(payload: dict) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
    )


def _settings() -> tuple[str, dict[str, str], dict[str, str]]:
    base_url = os.environ.get(
        "SENTRY_URL", "http://127.0.0.1:" + os.environ.get("AGENTSENTRY_PORT", "8000")
    ).rstrip("/")
    agent_key = os.environ["AGENT_API_KEY"]
    tenant_id = os.environ.get("AGENT_TENANT_ID", "default")
    capabilities = json.loads(os.environ.get("AGENT_CAPABILITIES_JSON", "{}"))
    if not isinstance(capabilities, dict):
        raise ValueError("AGENT_CAPABILITIES_JSON must be an object")
    headers = {"Authorization": "Bearer " + agent_key, "X-Tenant-ID": tenant_id}
    headers["X-Runtime-Session"] = os.environ.get("AGENT_RUNTIME_TOKEN", "")
    return base_url, headers, capabilities


def _call(tool: str, arguments: dict) -> dict:
    base_url, headers, capabilities = _settings()
    headers["X-Capability"] = str(capabilities.get(tool, ""))
    try:
        with httpx.Client(timeout=25) as client:
            response = client.post(base_url + "/api/v1/tool-calls", headers=headers, json={
                "call_id": str(uuid.uuid4()), "session_id": SESSION_ID,
                "tool": tool, "arguments": arguments,
            })
    except httpx.HTTPError:
        return {"status": "failed", "reason": "gateway_unavailable"}
    if response.status_code >= 500:
        return {"status": "failed", "reason": "gateway_unavailable"}
    if response.status_code >= 400:
        return {"status": "denied", "reason": "gateway_rejected_request"}
    return response.json()


@server.tool()
def mcp_lookup_card(card_id: str) -> CallToolResult:
    """Look up a synthetic reference card through AgentSentry security checks."""
    return _result(_call("mcp_lookup_card", {"card_id": card_id}))


@server.tool()
def mcp_record_note(note_id: str, text: str) -> CallToolResult:
    """Request an approved write to the synthetic demo notebook."""
    return _result(_call("mcp_record_note", {"note_id": note_id, "text": text}))


if os.environ.get("AGENTSENTRY_REMOTE_MCP_ENABLED", "false").lower() == "true":
    @server.tool()
    def remote_mcp_lookup_card(card_id: str) -> CallToolResult:
        """Read a synthetic remote card through the registered AgentSentry gateway."""
        return _result(_call("remote_mcp_lookup_card", {"card_id": card_id}))


    @server.tool()
    def remote_mcp_record_note(note_id: str, text: str) -> CallToolResult:
        """Request administrator approval to write a synthetic remote note."""
        return _result(_call("remote_mcp_record_note", {"note_id": note_id, "text": text}))


if os.environ.get("AGENTSENTRY_GITHUB_MCP_ENABLED", "false").lower() == "true":
    @server.tool()
    def github_mcp_read_license() -> CallToolResult:
        """Read the public GitHub MCP Server LICENSE through AgentSentry checks."""
        return _result(_call("github_mcp_read_license", {}))


    @server.tool()
    def github_mcp_read_issue() -> CallToolResult:
        """Read the fixed public MCP security Issue through AgentSentry checks."""
        return _result(_call("github_mcp_read_issue", {}))


if os.environ.get("AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED", "false").lower() == "true":
    @server.tool()
    def github_mcp_create_test_issue(title: str, body: str) -> CallToolResult:
        """Request administrator approval to create an Issue in the fixed test repository."""
        return _result(_call("github_mcp_create_test_issue", {
            "repository": get_settings().github_mcp_test_repo,
            "title": title, "body": body}))


@server.tool()
def agentsentry_call_status(call_id: str) -> CallToolResult:
    """Read the status of a call waiting for administrator approval."""
    try:
        call_id = str(uuid.UUID(call_id))
    except ValueError:
        return _result({"status": "failed", "reason": "invalid_call_id"})
    base_url, headers, _ = _settings()
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(base_url + "/api/v1/tool-calls/" + call_id, headers=headers)
    except httpx.HTTPError:
        return _result({"status": "failed", "reason": "gateway_unavailable"})
    if response.status_code != 200:
        return _result({"status": "failed", "reason": "call_unavailable"})
    return _result(response.json())


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
