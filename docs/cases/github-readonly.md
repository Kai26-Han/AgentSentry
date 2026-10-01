# GitHub 官方 MCP 只读接入实测

[中文](#) · [English](../en/cases/github-readonly.md)

> 按安全问题整理的 2026-09-30 现场事实，不是本次重新执行。复现需自己的凭据与环境；新安装不包含原运行数据库。


## 接入边界

```text
示例 Agent → 可信 stdio 适配层 → AgentSentry 网关 → GitHub 托管 MCP → 固定公开仓库文件
                                    │
                              授权、策略、审计、来源与输出检查
```

此案例只验证固定 GitHub 只读工具。本节记录当时的许可证接入：网关登记 `github_mcp_read_license`，上游固定使用 `https://api.githubcopilot.com/mcp/x/repos/readonly` 的 `get_file_contents`，参数固定为 `github/github-mcp-server` 仓库的 `LICENSE`。Agent 不能指定 URL、仓库、路径或上游工具。GitHub 的其他 12 个已发现工具不会展示给 Agent。后续增补的固定公开 Issue 只读入口及实测见[GitHub Issue 只读实验](github-issue-analysis.md)。

GitHub 凭据只从本机私有 `.env` 的 `GITHUB_MCP_PAT` 读取；适配层、模型上下文、审计与 Judge 不接收 PAT。接口使用 GitHub 官方只读端点和 `X-MCP-Readonly`；网关还要求会话绑定、工具调用授权令牌与默认租户的显式策略。只读工具定义的批准摘要为 `37ab6d6cd6da6cb17c63534cdcfd55759e5dbc48d5c91cbba49c64cf9f4526d6`，定义变化时调用失败，需人工重新核对。

远端返回 MCP `resource` 文本而非本项目演示 Server 的结构化字典。可信出口只接受一条文本资源、限制为 8192 字节，并把它映射成固定来源 ID。虽然当前测试仓库公开，**经认证取得的第三方内容仍按 `private` 处理**，以免将来权限状态变化或服务异常时误把私有材料送往远程模型。内容仍是低信任数据，不能作为指令。

## 运行方式

1. 在本机 `.env` 设置专用 PAT：`GITHUB_MCP_PAT=...`，并设置 `AGENTSENTRY_GITHUB_MCP_ENABLED=true`。不要把 PAT 写入聊天、文档或版本库。
2. 重建 Web：`docker compose up -d --build web`。已有租户先运行 `python scripts/enable_github_mcp_policy.py` 预览，再运行 `python scripts/enable_github_mcp_policy.py --apply` 明确加入固定只读规则。
3. 运行独立协议探针：`python scripts/probe_github_mcp.py`。它只显示协议、工具摘要与结果哈希，不显示正文。
4. 运行网关完整链路：`python scripts/github_mcp_gateway_check.py`。脚本签发一次性工具授权，经正式 MCP 客户端调用可信适配层，并检查输出、审计和 Judge。相关证据也可在“远程 MCP 接入”“工具调用”“审计与 Judge”页面查看。

本地虚拟环境使用 `.venv/bin/python` 替代上文的 `python`。测试只读取固定公开文件，不创建 Issue、PR 或提交。GitHub 远程服务的认证和可用工具可能变化；PAT 必须只具备本次所需的最小权限。更广泛的 GitHub 工具接入需要逐工具定义参数、资源范围、响应结构、审批和重试语义。

## 现场观察与规则差异

- 未认证请求到官方只读端点：TLS 校验成功，HTTP `401`；本机配置 PAT 后，MCP `2026-07-28` 握手成功，发现 13 个工具，并读取 `LICENSE`。
- 最终网关调用：策略决定 `allow`、工具状态 `completed`，资源 1063 字节；4 条审计事件均有已完成的 Judge 结果。
- 输出检查关联 1 个 `private` 来源，结论为 `warn`、命中 `unverified_sentence`：测试脚本使用概述句而非直接引用许可证正文。这是展示前的来源核查提示，不代表 GitHub 工具调用失败。

上述 warn 是该时间点的旧规则结果；当前受限来源会话自由回答会阻断，见[私有泄露案例](private-data-leakage.md)。本次只验证固定只读文件和单一 GitHub 服务。尚未验证 GitHub 写入工具、不同仓库、长期运行下的工具清单变化、跨租户 GitHub 凭据隔离，也没有把这些结果解释为“通用第三方 MCP 接入已完成”。更深入的内容行为分析见[公开 Issue 案例](github-issue-analysis.md)，受控写入见[审批写入案例](github-controlled-write.md)。
