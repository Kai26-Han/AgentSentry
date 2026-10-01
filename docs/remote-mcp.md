# 远程 MCP 安全接入

[中文](#) · [English](en/remote-mcp.md)


## 实现位置

```text
示例 Agent ──可信 stdio 适配器──> AgentSentry 网关
                                     │ 身份、能力令牌、策略、运行时与数据流检查
                                     │ 远程写入先审批；决定和审计先提交
                                     ▼
                          固定 HTTPS Streamable HTTP 出口
                                     │ 按租户 OAuth 客户端凭据、JWT 签名及声明核验
                                     │ 固定 URL、已批准工具清单 SHA-256、结果结构核验
                                     ▼
                             受控合成远程 MCP Server
                                     │
                          结果作为低信任来源进入模型、输出和记忆检查
```

沿用同一个示例 Agent、网关、审批与审计链。远程工具只有 `remote_mcp_lookup_card(card_id)` 和 `remote_mcp_record_note(note_id, text)`。适配器不会把远端 `tools/list` 的描述或新增工具转给模型；远端连接地址、OAuth 凭据、操作 ID 均由可信代码提供。`remote_mcp_record_note` 的资源是 `remote-demo-notes`，必须人工审批；远端以网关 `call_id` 为唯一操作 ID，避免同一写入重复落库。

网关启动时校验登记数据；每次调用仍检查目标解析地址。默认拒绝 IP 字面量和私有地址，只接受 HTTPS、无内嵌账号、无查询参数和片段的固定地址；系统代理不参与远程请求。可配置本地 CA 文件或公开证书 PEM，TLS 主机名仍须通过验证。仅受控本机演示可显式开启 `AGENTSENTRY_REMOTE_MCP_ALLOW_LOOPBACK_DEMO=true`，只额外允许 `localhost`、`host.docker.internal` 或固定的 `remote-demo` 容器名。连接使用已核验的 IP，并保留原始 TLS 主机名校验，避免预检后再次解析切换地址。生产部署仍应在网络层限制出口；真实公网 DNS 重绑定尚未现场验证。

## 配置与启用

将每个允许接入的租户写入私有 `.env` 中的 `AGENTSENTRY_REMOTE_MCP_REGISTRY`。下面的值全是占位符，不能照搬到真实环境：

```json
{
  "default": {
    "endpoint_id": "remote-demo",
    "url": "https://mcp.example.org/mcp",
    "token_url": "https://auth.example.org/token",
    "jwks_url": "https://auth.example.org/jwks",
    "issuer": "https://auth.example.org",
    "audience": "https://mcp.example.org/mcp",
    "client_id": "REPLACE_ME",
    "client_secret": "REPLACE_ME",
    "manifest_sha256": "REPLACE_WITH_64_HEX_CHARACTERS"
  }
}
```

受控私有 CA 可增设 `"ca_bundle": "/app/certs/remote-ca.pem"`，文件须在网关容器内可读；或使用仅含**公开证书**的 `ca_pem_b64`。两种方式只能选一种。登记按租户隔离，不接受 Agent 或模型提交的地址和凭据。网关向令牌端点申请 `cards.read` 或 `notes.write`，要求签名 JWT 使用已登记 JWKS 的 RS256 密钥，并逐项核验发行方、受众、到期时间和对应 scope。令牌只发给已登记 MCP 资源地址，绝不传给 Agent 上下文、Judge 或管理页。

受控合成 Server 可用 `python -m agentsentry.mcp_remote_server --manifest` 得到当前固定工具清单摘要。管理员应在核对服务身份与工具定义后，将摘要写入登记项；描述、输入或输出结构、额外工具变化都会改变摘要并停止调用。登记信息修改后重新启动网关。已有租户的策略不会自动放行远程工具，可运行 `python scripts/enable_remote_mcp_policy.py --tenant default` 预览，再用 `--apply` 显式启用；随后在“工具调用授权”为相应资源签发单独能力令牌。在适配器进程设 `AGENTSENTRY_REMOTE_MCP_ENABLED=true` 才向示例 Agent 展示这两个固定工具。远程会话使用 MCP `2026-07-28` 发现协议；旧版只支持初始化握手的远端需要单独适配与复测。

受控 Server 使用合成卡片和 SQLite 演示笔记，需要 TLS 证书及 `REMOTE_MCP_DEMO_CLIENT_SECRET`。启动示例：

```bash
REMOTE_MCP_DEMO_CLIENT_SECRET='本机随机值' python -m agentsentry.mcp_remote_server \
  --host 127.0.0.1 --port 9443 --cert /path/to/local.crt --key /path/to/local.key
```

在本机 Docker 演示中，可依次运行：

```bash
python scripts/setup_remote_mcp_demo.py
docker compose --profile remote-mcp-demo up --build -d
python scripts/enable_remote_mcp_policy.py --apply
python scripts/remote_mcp_live_check.py
```

设置脚本把私钥放在被 `.gitignore`、`.dockerignore` 排除的 `.local/remote-demo.env`，只注入受控远端容器；网关登记中仅有公开证书。演示容器不发布宿主端口。切勿把本机演示允许开关用于生产远端。示例 Agent 可用 `agentsentry-demo --transport mcp --scenario remote-mcp-read` 读取公开卡片，或用 `remote-mcp-note` 发起等待审批的写入。配置有模型时继续使用 `--scenario llm`。管理页 `/dashboard/remote-mcp` 只显示端点、协议、清单摘要、实时状态和最近调用，不显示凭据。

## 故障和证据

在 `tools/call` 发出之前，令牌、TLS、网络、工具清单或结构核验失败，网关记录 `failed`，远端无工具副作用。请求发出后发生超时、连接断开或异常结果时保留 `unknown`；该 `call_id` 不能重新执行。管理员需先查远端操作 ID 再人工处理。`tools/list` 清单不符会产生 `remote_mcp_manifest_drift`，可映射到 `TH-010`；一般连接或认证故障不会自动标为攻击。审计与 Judge 事件只保留端点 ID、协议、清单摘要、状态及参数／结果摘要，不发送 OAuth 密钥和原始远端内容。

远端卡片来源由网关固定目录分级：`remote-public-guide` 为 `public`，其余卡片按 `private`，明确凭据提升为 `secret`。远端自称的敏感级别不生效。私有远端内容不能进入远程模型；远程写入在本会话有私有来源、或参数有可识别敏感内容时拒绝。读取结果仍须经过已有输出检查，生成记忆时继承来源级别。清单摘要只能发现**声明的清单变化**，不能证明远端内部实现和返回内容始终可信。

## 验证范围与案例

受控本机 TLS／OAuth 服务验证了签名、受众、scope、读取、审批写入、幂等、资源范围、未知工具、非法参数、会话绑定、清单漂移和敏感来源检查。它是本机不同容器间的合成服务，不等于通用第三方 OAuth 互通验证。

真实第三方证据分为 [GitHub 固定读取](cases/github-readonly.md)、[公开 Issue 分析](cases/github-issue-analysis.md)和[人工审批写入](cases/github-controlled-write.md)。定义变更、固定探针和 IP 选择见[供应链机制](mcp-supply.md)。

真实公网 DNS 变化、第三方长期响应语义、不同 OAuth 服务及网络路径仍需验证；不同路径的结论不能相互替代。
