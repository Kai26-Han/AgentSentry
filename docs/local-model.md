# 本地模型配置与请求位置

[中文](#) · [English](en/local-model.md)

[项目首页](../README.zh-CN.md) · [敏感数据流章节](learning/08-sensitive-data-flow.md)

固定工具演示与离线学习不需要模型。本页用于之后的真实模型实验；模型服务须由学习者自行启动，模型名须实际存在。

## 先确认是谁发出请求

| 请求 | 实际发送者 | 地址怎样配置 |
| --- | --- | --- |
| 示例 Agent 任务、MCP 模式任务、记忆摘要 | 运行示例 Agent 的进程 | `DEMO_MODEL_BASE_URL` 与网关的 `AGENTSENTRY_MODEL_LOCAL_BASE_URL` 一致 |
| 可选输出语义提示 | 网关进程 | `OUTPUT_LOCAL_MODEL_BASE_URL`、`OUTPUT_LOCAL_MODEL_NAME`，默认关闭 |
| 可选目标偏移语义提示 | 网关进程 | `GOAL_LOCAL_MODEL_BASE_URL`、`GOAL_LOCAL_MODEL_NAME`，默认关闭 |
| 异步 Judge | Worker | 独立的 Judge 配置；不复用 Agent 模型凭据 |

网关在模型出口检查中**登记并返回地址、检查消息**，示例 Agent 的适配层实际发送任务和摘要。Docker 内网关的回环地址与宿主回环地址不同，但网关不会替 Agent 发送这些请求；不能把这类地址机械改成容器地址。

## 推荐：Agent 与模型都在宿主运行

1. 按模型服务的说明启动 OpenAI 兼容接口，确认支持 `/chat/completions`、工具调用；自动记忆摘要还使用 JSON 响应格式。模型不支持这些能力时，记录兼容失败，不当作安全机制失败。
2. `.env` 中网关登记地址保持 `AGENTSENTRY_MODEL_LOCAL_BASE_URL=http://127.0.0.1:11434/v1`，或改为你实际的本机端口。只改文件不会更新已启动的容器环境；改动后运行 `docker compose up -d --force-recreate web`。
3. 在宿主的在线终端设置：

   ```bash
   export SENTRY_URL='http://127.0.0.1:8000'
   export AGENT_API_KEY='替换为自己的 Agent 密钥'
   export AGENT_CAPABILITIES_JSON='{"read_document":"替换为 public-guide 的有效授权"}'
   export DEMO_MODEL_BASE_URL='http://127.0.0.1:11434/v1'
   export DEMO_MODEL_NAME='替换为实际安装的模型名'
   export AGENTSENTRY_MODEL_DESTINATION=local
   .venv/bin/agentsentry-demo --scenario llm --prompt '阅读 public-guide 并总结。'
   ```

   端口和模型名都须替换；如果模型服务需要鉴权，另设置 `DEMO_MODEL_API_KEY`。以上 Agent 配置从进程环境读取，不自动从 `.env` 读取。
4. 在 Web 核对模型出口决定、实际来源、输出检查和最终展示。模型没有提出危险调用时，该类工具阻断率仍是未验证。

实验运行器通常读取本机 `.env` 的管理员设置，随后建立研究租户；仍在终端显式设置 `DEMO_MODEL_BASE_URL` 和 `DEMO_MODEL_NAME`。详见各章的命令，别把运行器与普通 Agent 的配置加载方式混同。

## 网关内的可选语义提示

仅启用 `OUTPUT_LOCAL_MODEL_*` 或 `GOAL_LOCAL_MODEL_*` 时，网关才会自己请求这些分析端点。Docker Desktop 中可使用 `http://host.docker.internal:11434/v1` 访问宿主，但还要确认名称解析、服务监听地址及防火墙允许容器访问。Linux Docker 的宿主地址映射可能需要额外配置，当前 Compose 未自动配置它。

这些提示默认关闭，并非基础学习前提。它们只提供线索，不能扩大权限或跳过同步控制；连接失败记录分析失败。

## 常见问题

| 现象 | 核对方法 |
| --- | --- |
| 模型目的地与本地配置不一致 | 比较网关登记 URL 与 Agent URL；除末尾斜线外需一致，不把 `localhost` 和 `127.0.0.1` 混用 |
| Agent 连接拒绝 | 从运行 Agent 的同一环境确认模型端口、路径及模型名；检查本机代理设置 |
| 网关提示连接拒绝 | 确认是哪类提示服务；容器内 `127.0.0.1` 不指向宿主 |
| 新建记录后模型出口被拒 | 查来源、目的地、会话绑定、预算与审计状态；不跳过出口检查 |
| 使用容器运行整个 live 运行器 | 先核对其地址白名单；部分运行器只接受回环主机为本地，不统一支持 `host.docker.internal` |

远程 HTTPS 模型另需显式登记及运行器许可，且有数据外发和可能计费；配置见[数据流专题](data-flow.md)。本页的本地步骤不启用它。
