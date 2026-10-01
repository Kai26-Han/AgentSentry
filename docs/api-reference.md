# 接口与 Web 入口索引

[中文](#) · [English](en/api-reference.md)

[项目首页](../README.zh-CN.md) · [当前架构](architecture.md)

本页是现有接口的导航，不是完整请求格式说明。启动本机网关后，可在 `/docs` 查看类型化请求与响应；权限要求仍以路由代码为准。管理员写操作要求登录与 CSRF，Agent 凭据不能调用管理员接口。


管理员写 API 使用签名登录会话和 `X-CSRF-Token`。可信适配层使用 `Authorization: Bearer`、`X-Tenant-ID`、工具授权 `X-Capability`，以及适用的 `X-Runtime-Session`。`session_id` 只是关联标识，不能独立授权。

| 方法与路径 | 调用方 | 作用 |
| --- | --- | --- |
| `POST /api/v1/capabilities`、`DELETE /api/v1/capabilities/{grant_id}` | 管理员 | 签发／吊销临时工具授权 |
| `POST /api/v1/tool-calls`、`GET /api/v1/tool-calls/{call_id}` | 可信适配层 | 提交与查询幂等调用 |
| `POST /api/v1/approvals/{approval_id}/decision` | 管理员 | 审批冻结的原动作；GitHub 写入须经事实卡 |
| `GET /api/v1/policy`、`PUT /api/v1/policy`、`POST /api/v1/policy/reload` | 管理员 | 查看、校验、替换或重载本租户工具策略 |
| `GET /api/v1/judge-runtime`、`PUT /api/v1/judge-runtime` | 管理员 | 查看／切换租户 Judge，写入还需配置修订 |
| `GET /api/v1/judge-samples`、`POST /api/v1/judge-samples`、`DELETE /api/v1/judge-samples/{sample_id}` | 管理员 | 管理合成评测样本 |
| `POST /api/v1/judge-samples/{sample_id}/run` | 管理员 | 为样本选择已配置提供方，创建异步评测 |
| `GET /api/v2/tenants`、`POST /api/v2/tenants` | 默认管理员 | 查看／创建租户，一次性展示凭据 |
| `PUT /api/v2/runtime-sessions/{session_id}/start`、`PUT /api/v2/runtime-sessions/{session_id}/finish` | 可信适配层 | 开始／结束上报与会话绑定 |
| `POST /api/v2/runtime-sessions/{session_id}/model-egress/check`、`POST /api/v2/runtime-sessions/{session_id}/output-check` | 可信适配层 | 模型发送前与回答展示前检查 |
| `POST /api/v2/runtime-sessions/{session_id}/memory/read`、`POST /api/v2/runtime-sessions/{session_id}/memory/write` | 可信适配层 | 读取／提交自身记忆 |
| `GET /api/v2/memories`、`POST /api/v2/memories/{memory_id}/decision` | 管理员 | 查看、激活、撤销和清除记忆 |
| `GET /api/v3/goal-assessments`、`GET /api/v3/action-chains`、`GET /api/v3/threat-mappings` | 管理员 | 只读调查目标、连续动作与框架线索 |
| `POST /api/v3/delegations`、`GET /api/v3/delegations/{id}/result` | 父 Agent | 用有效父会话及权限创建委托、领取低信任结果；其他协作接口见[协议表](delegation.md#页面与接口) |

Web 从 `/dashboard` 进入；当前目录和数据租户语义见[导航文档](web-dashboard.md)。工具策略可热更新，运行时安全规则和行动预算仍由代码版本控制；不提供在线调阈值或自动放宽规则。

Web 登录页与页面右上角提供 **中文／English** 切换，默认中文，选择保存在浏览器的界面语言 Cookie 中。切换保留当前页面和研究租户；用户任务、来源材料、记忆文字、原始参数及审计 JSON 保持原文。详见[界面语言说明](web-language.md)。
