"""核对 GitHub 官方 MCP Issue 只读工具的定义和返回形状，不输出正文。"""

import asyncio
import hashlib
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from agentsentry.config import get_settings
from agentsentry.mcp_github import _tool_hash


ENDPOINT = "https://api.githubcopilot.com/mcp/x/issues/readonly"


async def probe() -> dict:
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + get_settings().github_mcp_pat,
                 "X-MCP-Readonly": "true"},
        timeout=httpx2.Timeout(10, read=10), follow_redirects=False, trust_env=False,
    ) as client:
        async with streamable_http_client(ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listed = await session.list_tools()
                tool = next((item for item in listed.tools if item.name in {"issue_read", "get_issue"}), None)
                if tool is None:
                    return {"status": "tool_unavailable", "listed_tools": sorted(item.name for item in listed.tools)}
                result = await session.call_tool(tool.name, arguments={
                    "method": "get", "owner": "modelcontextprotocol", "repo": "modelcontextprotocol",
                    "issue_number": 3213,
                })
                body = next((item.text for item in result.content if item.type == "text"), "")
                try:
                    parsed = json.loads(body)
                except ValueError:
                    parsed = None
                return {"tool": tool.name, "schema_sha256": _tool_hash(tool),
                        "input_fields": sorted(tool.input_schema.get("properties", {})),
                        "required": sorted(tool.input_schema.get("required", [])),
                        "is_error": result.is_error,
                        "content_blocks": [item.type for item in result.content],
                        "text_bytes": [len(item.text.encode()) for item in result.content
                                       if item.type == "text"],
                        "resource_bytes": [len(item.resource.text.encode()) for item in result.content
                                           if item.type == "resource" and
                                           isinstance(item.resource.text, str)],
                        "structured_keys": sorted(result.structured_content)
                            if isinstance(result.structured_content, dict) else [],
                        "parsed_type": type(parsed).__name__,
                        "parsed_keys": sorted(parsed) if isinstance(parsed, dict) else [],
                        "field_types": {key: type(value).__name__ for key, value in parsed.items()}
                            if isinstance(parsed, dict) else {},
                        "body_bytes": len(parsed.get("body", "").encode()) if isinstance(parsed, dict)
                            and isinstance(parsed.get("body"), str) else None,
                        "response_sha256": hashlib.sha256(json.dumps(result.model_dump(
                            mode="json", by_alias=True, exclude_none=True),
                            sort_keys=True, ensure_ascii=False).encode()).hexdigest()}


if __name__ == "__main__":
    try:
        print(json.dumps(asyncio.run(probe()), ensure_ascii=False, indent=2))
    except Exception as exc:
        def types(error):
            children = getattr(error, "exceptions", ())
            return [type(error).__name__, *(name for child in children for name in types(child))]
        print("GitHub Issue 只读探测失败：" + ",".join(types(exc)))
        raise SystemExit(1)
