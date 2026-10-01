# 租户接入与 Agent 演示

[中文](#) · [English](en/tenant-demo.md)

默认管理员使用租户 `default` 和自己的 `.env` 密码。默认数据位于 PostgreSQL public schema；新租户使用独立 schema，不复制其他租户的调用、记忆或实验。

## 本机演示

1. 按 [README](../README.zh-CN.md#快速启动)启动服务，以默认管理员登录。
2. 在“管理配置 → 租户管理”创建租户，保存一次性显示的租户 ID、管理员密码与 Agent 密钥。
3. 退出，以新租户身份登录；在“工具调用授权”签发 read_document、public-guide 的短时有限授权。
4. 在可信 Agent 终端设置：

   ```bash
   export AGENT_TENANT_ID='替换为新租户ID'
   export AGENT_API_KEY='替换为该租户Agent密钥'
   export AGENT_CAPABILITIES_JSON='{"read_document":"替换为新授权令牌"}'
   export SENTRY_URL='http://127.0.0.1:8000'
   .venv/bin/agentsentry-demo --scenario read-public
   ```

5. 在该租户面板核对调用和 Judge 结果；切回 default 日常调用列表，不应混入新租户记录。研究租户的管理员只读观察另有明确入口，不等于跨租户写权限。

辅助脚本 `.venv/bin/python scripts/tenant_demo.py` 完成新建、授权和示例调用，凭据保存于 `.local/<tenant_id>.json`（0600）；不提交该文件。

## 身份与管理边界

- `POST /api/v2/tenants`、`GET /api/v2/tenants` 仅默认管理员；创建正文为 `{"name":"Team A"}`，凭据只返回一次，管理写入继续校验 CSRF。
- 租户管理员管理自身工具授权、策略、审批、记忆、审计与 Judge 设置。
- Agent 使用自己的 Bearer 密钥、`X-Tenant-ID` 与 `X-Capability`；身份头和密钥必须匹配。省略租户头按 default 兼容处理。
- Outbox 和通知保留租户 ID，Worker 重新打开所属 schema；Judge 日常路由按租户保存，Webhook 目的地仍为平台配置。详见[Judge 运行设置](judge-runtime-switch.md)。
- 新租户拒绝共享 `run_shell`；默认租户仍需授权、有效会话和审批。schema 隔离不等于数据库凭据或宿主隔离。

## 策略与验证

新租户以默认策略为基线，把 run_shell 改成显式拒绝；策略位于配置卷的 `<tenant_id>.yaml`。自定义策略使用其实际文件和相应样本测试，不把默认集的成绩当作自定义集结论。

按[学习环境](learning/README.md#前置条件与命令约定)运行：

```bash
.venv/bin/python -m pytest -q tests/test_v2_tenants.py
.venv/bin/python -m agentsentry.policy_tests --policy policies/default.yaml --cases policy-tests/cases.yaml
```

更多权限、并发审批与限制见[安全案例](cases/tool-permission-and-approval.md)。
