# 运行时安全规则与处置

[中文](#) · [English](en/runtime-defense.md)


## 作用和边界

工具策略判断单次调用是否被允许；运行时规则再查看本租户、本 Agent 的已提交调用证据，判断这次调用是否需要升级审批或拒绝。它在网关内同步运行，决定和 Outbox 在工具执行前提交。Judge 仍在 Worker 中异步评判，只影响告警与复核，不授权或撤销本次调用。

```text
可信适配层 → 网关：身份、类型化参数、策略、资源权限
                   ↓
              运行时安全规则 → 原效果／升级审批／拒绝
                   ↓
          决定与审计提交 → 审批再次核查 → 模拟工具
                   ↓
           Outbox → Judge → 告警和人工复核
```

仅覆盖显式接入的 HTTP 和 MCP 示例路径。网关不能拦截其他程序直接访问自己的工具，也不能停止已经开始执行的副作用。管理员“暂停”仅阻止后续工具调用，不停止 Agent 的模型进程或收回已显示的回答。

## 固定规则

| 规则 ID | 服务端证据 | 默认处置 |
| --- | --- | --- |
| `read_then_write_review` | 同一会话已完成文档或 MCP 卡片读取，随后请求写入工具 | 只留线索，不自动阻断正常读后写。 |
| `instruction_source_before_write` | 已读取结果的前 8192 字符命中明确指令模式，随后请求写入工具 | 原策略为放行时升级为审批。匹配只是提示，不能证明用户意图。 |
| `repeated_denials_before_write` | 同一 Agent 最近 10 分钟至少 3 次工具拒绝，随后请求写入工具 | 原策略为放行时升级为审批。 |
| `uncertain_action_repeat` | 24 小时内相同 Agent、工具和规范化参数曾处于 `executing` 或 `unknown` | 拒绝新 `call_id` 的重复副作用。需要核实旧动作结果；重试原 `call_id` 仍用已有幂等状态。 |
| `administrator_paused` | 管理员暂停本会话或本 Agent | 拒绝后续工具调用。 |
| `session_closed` | 已上报会话不再处于运行中 | 拒绝后续工具调用。 |
| `session_binding_invalid` | 启用强制绑定时未带有效会话凭据；或提交了无效凭据 | 拒绝新调用。 |

规则版本为 `runtime-rules-v1`。规则只可保持或收紧现有 YAML 工具策略；权限范围与显式拒绝不能被运行时安全规则放宽。审批核对原参数和权限后，会重查当前工具策略、暂停状态及运行时证据；新增需要升级审批的证据使旧申请失效，调用方要重新申请。规则读取的工具结果已有本地审计记录；运行时新审计只保存命中 ID 和关联调用 ID，不复制材料原文。

## 会话绑定与兼容

`PUT /api/v2/runtime-sessions/{session_id}/start` 返回与租户、Agent、会话开始时间绑定的 `session_token`。可信 HTTP／MCP 适配层保存在模型上下文之外，并在工具调用的 `X-Runtime-Session` 请求头提交。凭据由服务端密钥签发，仅在该会话处于运行中且开始时间不超过 8 小时时有效。`session_id` 本身不是授权凭据。

默认 `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false`，以便旧版直接调用网关的客户端继续运行；这些未上报会话会记录 `session_unreported`，页面明确显示兼容模式。把该配置设为 `true` 后，**所有新工具调用**必须先上报运行中的会话并带有效绑定凭据。启用前要升级所有使用该网关的可信适配层和脚本；历史调用不会重放。已有相同 `call_id` 的幂等查询不造成新副作用。Agent API 密钥如果失陷，攻击者仍可自行建立新会话，本机制不防完整凭据失陷。

## 管理与接口

- `POST /api/v2/runtime-controls`：管理员携带 CSRF，按 `scope=session|agent` 暂停或恢复；暂停必须填写原因。变更历史保存脱敏原因、操作者和时间，并产生审计与 Outbox。
- `GET /api/v2/runtime-decisions/{call_id}`：读取当前租户该调用在提交和审批阶段的规则决定。
- `GET /api/v2/runtime-incidents`、`POST /api/v2/runtime-incidents/{id}/ack`：查看及确认运行时告警；确认不自动恢复暂停。
- `/dashboard/runtime-sessions/detail`：查看逐次决定、关联证据及暂停／恢复操作；`/dashboard/alerts` 合并显示 Judge 和运行时安全规则告警，并明确区分来源。
- `/dashboard/runtime-rules`：管理员只读查看当前规则目录、阈值、匹配表达式、处置和局限；页面从网关规则定义读取，不提供修改入口。基础 YAML 工具策略仍在 `/dashboard/policy` 单独管理。

运行时告警存于单独的 `runtime_incidents` 表，当前按 Agent 与规则在 10 分钟内归并；每次调用仍有独立 `runtime_decisions` 及审计证据。既有 Judge `alerts` 和 Webhook 投递表不改写；运行时告警当前只在本地面板显示，不自动发送 Webhook。新表随默认及已有租户的 PostgreSQL schema 在启动时创建，旧记录不回填或重判。

## 运行评测

运行 `.venv/bin/python -m agentsentry.runtime_lab`。固定样本版本 `runtime-cases-v1` 含 20 条攻击与 10 条正常对照，分别覆盖指令来源后的写入、拒绝探测、未知结果重试、管理员暂停、已结束会话、绑定错误，以及正常读后写、少量拒绝、不同动作和恢复。每条使用独立临时 SQLite 和合成数据；报告写入 `.local/runtime-eval-report.json`。它检查**实际任务副作用**及每个决定的审计、Outbox，待审批不自动批准。

启动本机服务后，可运行 `SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python scripts/runtime_smoke.py`。脚本创建或复用独立合成租户，凭据保存于权限为 `0600` 的 `.local/runtime-smoke.json`；它验证网关升级审批、暂停后拒绝、审批执行前重查、面板证据与跨租户隔离，不会批准可疑写入或真实外发。实测统计与限制见[运行时处置案例](cases/runtime-and-budget.md)。

真实模型实验继续复用 `agentsentry-attack-lab --mode live` 的文档和 MCP 路径，分别观察模型是否提出危险调用、网关是否处置及最终回答是否污染。模型输出会变化，应按多次运行分别报告，不能用固定样本结果代替真实模型结论。Judge 误报和漏报单独统计；它没有收到的最终回答不计作漏报。

## 尚未覆盖

确定性模式可能漏掉改写、隐晦或多语言的指令，也可能把正常引用误标为可疑，因此此类命中只升级审批。`session_unreported` 在兼容模式下不自动拒绝；需要强制绑定才关闭这一入口。多个会话共用同一 Agent 密钥时，可按 Agent 关联短时间拒绝，但仍不等于理解了用户真实任务。敏感跨工具与回答出口由[数据流](data-flow.md)和[输出安全](output-safety.md)共同检查，规则命中不替代这些检查。
