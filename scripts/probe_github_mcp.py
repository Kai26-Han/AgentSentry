"""只读探测 GitHub 托管 MCP；不向 stdout 输出凭据或仓库内容。"""

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ENDPOINT = "https://api.githubcopilot.com/mcp/x/repos/readonly"
TOOL = "get_file_contents"
ARGUMENTS = {"owner": "github", "repo": "github-mcp-server", "path": "LICENSE"}


async def probe(token: str) -> dict:
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token, "X-MCP-Readonly": "true"},
        timeout=httpx2.Timeout(10, read=10),
        follow_redirects=False, trust_env=False,
    ) as client:
        async with streamable_http_client(ENDPOINT, http_client=client) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                await session.discover()
                listing = await session.list_tools()
                matches = [item for item in listing.tools if item.name == TOOL]
                if len(matches) != 1:
                    raise RuntimeError("只读端点未提供预期的 get_file_contents 工具")
                schema = matches[0].model_dump(mode="json", by_alias=True, exclude_none=True)
                schema_hash = hashlib.sha256(json.dumps(
                    schema, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"),
                ).encode()).hexdigest()
                response = await session.call_tool(TOOL, arguments=ARGUMENTS)
                if response.is_error:
                    raise RuntimeError("GitHub MCP 返回工具错误")
                body = json.dumps(response.model_dump(mode="json", by_alias=True,
                    exclude_none=True), ensure_ascii=False, sort_keys=True).encode()
                if len(body) > 2_000_000:
                    raise RuntimeError("GitHub MCP 响应超过探针大小上限")
                return {
                    "endpoint": ENDPOINT,
                    "protocol_version": session.protocol_version,
                    "listed_tools": len(listing.tools),
                    "tool_schema_sha256": schema_hash,
                    "tool_input_fields": sorted(schema.get("inputSchema", {}).get("properties", {})),
                    "read_target": "github/github-mcp-server:LICENSE",
                    "result_blocks": [getattr(item, "type", "unknown") for item in response.content],
                    "result_block_fields": [sorted(item.model_dump(mode="json", by_alias=True,
                        exclude_none=True)) for item in response.content],
                    "resource_fields": [sorted(item.resource.model_dump(mode="json", by_alias=True,
                        exclude_none=True)) for item in response.content
                        if getattr(item, "type", "") == "resource"],
                    "structured_result_fields": sorted(response.structured_content)
                        if isinstance(response.structured_content, dict) else [],
                    "response_bytes": len(body),
                    "response_sha256": hashlib.sha256(body).hexdigest(),
                }


def main() -> int:
    token = os.environ.get("GITHUB_MCP_PAT", "").strip()
    if not token:
        env_path = Path(__file__).resolve().parents[1] / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("GITHUB_MCP_PAT="):
                    token = line.partition("=")[2].strip().strip("\"'")
                    break
    if not token:
        print("未运行认证调用：请在本机 .env 设置 GITHUB_MCP_PAT；不要把令牌发到聊天中。")
        return 2
    try:
        report = asyncio.run(probe(token))
    except Exception as exc:
        # Third-party exceptions may embed a request object; print only the type.
        print("GitHub MCP 只读探测失败：" + type(exc).__name__)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
