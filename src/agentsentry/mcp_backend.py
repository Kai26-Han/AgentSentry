"""Call only the pinned tools of the local MCP server after gateway approval."""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import get_settings
from .database import tenant_schema


UPSTREAM_TOOLS = {
    "mcp_lookup_card": ("lookup_card", {"card_id"}),
    "mcp_record_note": ("record_note", {"note_id", "text", "operation_id"}),
}


async def _call_upstream(tool: str, arguments: dict, call_id: str, tenant_id: str, sent: dict) -> dict:
    upstream_name, fields = UPSTREAM_TOOLS[tool]
    directory = Path(get_settings().mcp_demo_dir)
    path = directory / f"{tenant_id}.db"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentsentry.mcp_local_server"],
        env={"MCP_DEMO_DB_PATH": str(path),
             "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            candidates = [item for item in listed.tools if item.name == upstream_name]
            if len(candidates) != 1:
                raise ValueError("Pinned MCP tool is unavailable")
            schema = candidates[0].input_schema
            properties = schema.get("properties", {})
            if (set(properties) != fields or set(schema.get("required", [])) != fields
                    or any(properties[name].get("type") != "string" for name in fields)):
                raise ValueError("Pinned MCP tool schema changed")
            upstream_arguments = dict(arguments)
            if tool == "mcp_record_note":
                upstream_arguments["operation_id"] = call_id
            sent["value"] = True
            response = await session.call_tool(upstream_name, arguments=upstream_arguments)
            if response.is_error or not isinstance(response.structured_content, dict):
                raise ValueError("MCP tool returned an error or unstructured result")
            result = response.structured_content
            if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 4096:
                raise ValueError("MCP tool result exceeds 4096 bytes")
            if tool == "mcp_lookup_card" and result == {"error": "card_not_found"}:
                return result
            expected = {"card_id", "content"} if tool == "mcp_lookup_card" else {"note_id", "recorded"}
            if set(result) != expected:
                raise ValueError("MCP tool result schema changed")
            if tool == "mcp_lookup_card":
                if result["card_id"] != arguments["card_id"] or not isinstance(result["content"], str):
                    raise ValueError("MCP card result is invalid")
            elif result["note_id"] != arguments["note_id"] or result["recorded"] is not True:
                raise ValueError("MCP note result is invalid")
            return result


def execute_local_mcp(tool: str, arguments: dict, call_id: str, tenant_id: str) -> dict:
    if tool not in UPSTREAM_TOOLS:
        raise ValueError("Unknown MCP tool")
    tenant_schema(tenant_id)
    sent = {"value": False}
    try:
        return asyncio.run(asyncio.wait_for(
            _call_upstream(tool, arguments, call_id, tenant_id, sent), timeout=12,
        ))
    except Exception:
        if sent["value"]:
            raise  # The tool may have run; the gateway records an unknown outcome.
        return {"error": "mcp_upstream_unavailable"}
