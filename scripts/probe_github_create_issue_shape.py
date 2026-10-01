"""仅列出 GitHub MCP issue_write 工具定义；绝不调用写入工具。"""

import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from agentsentry.config import get_settings
from agentsentry.mcp_github import _tool_hash


ENDPOINT = "https://api.githubcopilot.com/mcp/x/issues"


async def probe(token: str) -> dict:
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token},
            timeout=httpx2.Timeout(10, read=10), follow_redirects=False,
            trust_env=False) as client:
        async with streamable_http_client(ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listed = await session.list_tools()
                matches = [item for item in listed.tools if item.name == "issue_write"]
                if len(matches) != 1:
                    return {"status": "unavailable", "tool_count": len(listed.tools),
                            "tool_names": sorted(item.name for item in listed.tools)}
                tool = matches[0]
                return {"status": "available", "tool_count": len(listed.tools),
                        "schema_sha256": _tool_hash(tool),
                        "input_fields": sorted(tool.input_schema.get("properties", {})),
                        "required": sorted(tool.input_schema.get("required", [])),
                        "input_schema": tool.input_schema}


if __name__ == "__main__":
    settings = get_settings()
    token = settings.github_mcp_write_pat or settings.github_mcp_pat
    if not token:
        print("缺少本机 GitHub MCP 凭据")
    else:
        try:
            print(json.dumps(asyncio.run(probe(token)), ensure_ascii=False, indent=2))
        except Exception as exc:
            print("只读工具清单探测失败：" + type(exc).__name__)
