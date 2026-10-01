# 本地 MCP 接入与演示

[中文](#) · [English](en/local-mcp.md)

## 连接什么

```text
示例 Agent → MCP stdio 可信入口适配器
          → 带身份、会话与工具授权的 HTTP 网关调用
          → 提交安全决定后，由网关发起 MCP stdio
          → 固定本地合成 Server
```

适配器展示 `mcp_lookup_card`、`mcp_record_note` 和 `agentsentry_call_status`；不透传上游的工具清单或描述。Server 是网关启动的固定子进程，没有监听端口，使用租户专属合成 SQLite 存储和受限继承环境；笔记位于 `mcp_demo_data` 卷。Agent 不能从参数选择启动程序、路径或地址。

| 网关工具 | 上游工具 | 授权资源 | 缺省策略 |
| --- | --- | --- | --- |
| `mcp_lookup_card(card_id)` | `lookup_card` | 精确 card_id | 有效授权下允许 |
| `mcp_record_note(note_id, text)` | `record_note` | `demo-notes` | 管理员审批 |

笔记使用网关 call_id 作为唯一 operation_id；同一调用重试查询既有状态。发出前故障记 failed，发出后超时或异常响应记 unknown，不自动重写。结果内容始终是低信任数据。

## 运行固定演示

1. 按 [README](../README.zh-CN.md#快速启动)启动本机服务，核对自己的 `.env`。
2. 新安装使用默认策略；已有安装先预览 `.venv/bin/python scripts/enable_mcp_policy.py`，再明确执行同一命令的 `--apply`。其他租户设置 `TENANT_ADMIN_PASSWORD` 并传 `--tenant <tenant-id>`，不自动改变已有策略。
3. 运行 `.venv/bin/python scripts/mcp_demo.py`，脚本签发一次性卡片授权并启动现有 Agent 的 MCP 模式。按结果 ID 在 Web 核对决定、结果、Outbox 与 Judge。
4. 运行 `.venv/bin/python scripts/mcp_demo.py --write` 发起本地笔记审批；在事实卡核对原文后批准或拒绝。审批前不得写入。其他租户同时设置 `TENANT_AGENT_API_KEY` 并传 `--tenant <tenant-id>`。

有模型时先按[本地模型配置](local-model.md)设置可信进程的 `DEMO_MODEL_BASE_URL`、`DEMO_MODEL_NAME`、`AGENT_API_KEY` 和 `AGENT_CAPABILITIES_JSON`，再运行：

```bash
.venv/bin/agentsentry-demo --transport mcp --scenario llm --prompt '通过 MCP 读取 public-guide 并概述'
```

模型只看到工具定义和结果，不接收身份密钥或授权令牌。

## 边界与案例

这是显式接入，不拦截直接网络、进程内部函数或其他 MCP 连接。子进程与租户文件分离不是强化沙箱。同一个 call_id 幂等；重新发起 MCP tools/call 通常是新请求，不能假定所有第三方 Server 都有操作去重。

协议异常、审批与结果大小的事实见[MCP 边界案例](cases/mcp-boundaries.md)，动手步骤见[执行边界章节](learning/05-execution-boundaries.md)。
