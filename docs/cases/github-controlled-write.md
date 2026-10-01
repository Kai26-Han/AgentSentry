# GitHub MCP 测试仓库受控写入

[中文](#) · [English](../en/cases/github-controlled-write.md)

> 按安全问题整理的 2026-09-30 现场事实，不是本次重新执行。复现需自己的凭据与环境；新安装不包含原运行数据库。


## 目的与边界

这项实验只允许示例 Agent 通过可信 MCP 适配层，在**预先指定的测试仓库**创建合成 Issue。它会产生真实的 GitHub 副作用。仓库、凭据和上游工具来自管理员配置，模型只能提交标题和正文。写入默认关闭，现有只读凭据不会自动获得写权限。

```text
示例 Agent → 固定 stdio 工具 → 安全网关 → 审批事实卡 → GitHub 官方 MCP
                                    │                    │
                              策略、权限、数据流       create_issue
                              会话绑定、审计
```

网关固定调用 GitHub 官方 Issues MCP 端点的 `issue_write`，且只传 `method=create`、固定仓库、标题和正文；`update`、标签等其他参数不会透传。每次连接先读取工具定义并核对管理员批准的 SHA-256；工具新增或定义变化均不能让 Agent 获得新工具。资源必须等于 `GITHUB_MCP_TEST_REPO`。标题须以 `[AgentSentry Test] ` 开头，正文限 500 字。写入策略必须显式设为 `require_approval`；普通管理员 API 不能直接批准此工具，须在 Web 审批事实卡核对完整原始参数与目标仓库。

写入前必须有有效会话绑定；会话读过私有或未知来源、标题或正文包含明确凭据或个人信息时拒绝。审批时重新检查权限、策略、会话状态及数据流。调用 ID 重放只返回已有结果；如果请求可能已经发出但上游响应丢失，网关标记 `unknown`，不得用新调用 ID 自动重试。审计和 Judge 只接收参数摘要等元数据；操作记录会暂存原始参数供审批和幂等核对。

## 没有测试仓库时

代码、离线测试和面板可先完成，保持 `AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED=false`。真实写入验证需要一个**专用空仓库**，建议新建私有仓库，只存合成数据。为它创建独立的 fine-grained PAT，仅授予该仓库 `Issues: Read and write`；不要复用 `GITHUB_MCP_PAT`，也不要把令牌发到聊天或提交进仓库。若账号或组织禁止创建仓库，需要由有权限的管理员提供一个专用测试仓库；此时不能把已有业务仓库当作实验目标。

## 启用与人工验证

在本机私有 `.env` 设置：

```dotenv
GITHUB_MCP_WRITE_PAT=<单独的测试仓库 Issues 凭据>
GITHUB_MCP_TEST_REPO=<owner/repo>
```

先**只列出** GitHub MCP 工具定义，不调用写入工具：

```bash
.venv/bin/python scripts/probe_github_create_issue_shape.py
```

人工核对输出包含唯一 `issue_write`、`method` 只允许 `create` 或 `update`、必需字段为 `method`、`owner`、`repo`，并确认目的地仍是 GitHub 官方端点。把输出的 `schema_sha256` 写入 `.env` 的 `GITHUB_MCP_CREATE_ISSUE_SCHEMA_SHA256`，再设置 `AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED=true`。重建网关后，先预览、再显式启用默认租户审批策略：

```bash
docker compose up -d --build web
.venv/bin/python scripts/enable_github_mcp_write_policy.py
.venv/bin/python scripts/enable_github_mcp_write_policy.py --apply
```

开始一笔真实受控测试：

```bash
.venv/bin/python scripts/github_mcp_write_check.py
```

脚本签发一次性资源授权，创建会话，经正式 MCP 客户端调用适配层，然后独立查询 GitHub：**审批前同标题 Issue 必须为 0**。它输出审批事实卡链接与后续核验命令，绝不自动批准。管理员核对仓库、标题、正文后在 Web 页面批准；脚本生成的命令再查询网关结果和 GitHub 实际 Issue 数量，必须恰好为 1 且编号一致。若状态为 `unknown`，先人工检查 GitHub 与审计，不要再发一次写入。

完成后可在「管理配置 → 工具调用授权」吊销授权，关闭写入开关并撤销测试 PAT。测试 Issue 可在 GitHub 上人工关闭；保留网关审计记录以便追溯。

## 现场观察与 unknown 对账

截至 2026-09-30，独立的 fine-grained PAT 已限定到专用私有测试仓库，授予 `Issues: Read and write`。实际工具清单提供 `issue_write`；固定定义摘要为 `b115e2eddc21dafa4541be62e92bde4590391bea4ed93062caf7b6fb36e44f56`。本机 `.env` 固定仓库、写入开关和定义摘要。默认租户策略显式要求审批；管理员通过 Web 事实卡批准前，独立查询确认同标题 Issue 为 **0**。

用户批准后，GitHub 创建了且仅创建了 一条测试 Issue，标题为 `[AgentSentry Test] guarded issue <运行标识>`，正文为固定的合成测试文字。只读回查确认仓库、标题、完整正文和编号均与原审批参数一致；同标题 Issue 数量为 **1**。

首次网关结果曾是 `unknown`：GitHub 官方 `issue_write` 返回 `{id, url}`，旧版解析器错误地要求 `{number, html_url, title}`。已修复解析器，新增创建后只读回查。对已发生的这笔写入，没有重新调用 `issue_write`；严格核对原批准记录、参数哈希、`tool_unknown` 审计和 GitHub 实际 Issue 后，补记 `tool_result` 并将状态改为 `completed`。原 `tool_unknown` 保留，准确反映当时的不确定状态。该调用的 **10 条审计事件、10 条 Outbox 和 10 条 Judge 结果均已完成**。新解析器的完整成功路径通过协议级离线桩测试；尚未进行第二笔真实写入，不能称其已经由第二次在线写入验证。

离线测试覆盖审批前零写入、批准后一次写入、重放不重复写、拒绝不写、发送后超时保持 `unknown`，以及跨租户、资源替换、私有来源、凭据和个人信息阻断；协议级桩测试核对 `issue_write` 只收到 `method=create` 和固定仓库参数，定义漂移时发送前停止。这只证明本项目显式接入路径和所列测试，不代表任意第三方 MCP 服务均安全。

参考：[GitHub MCP 远程端点配置](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md)、[GitHub fine-grained PAT 权限](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)。
