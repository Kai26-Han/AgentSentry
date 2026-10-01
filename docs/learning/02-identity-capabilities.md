# 02 身份、租户与最小权限

[中文](#) · [English](../en/learning/02-identity-capabilities.md)

[手册首页](README.md) · 上一章：[信任边界](01-security-boundaries.md) · 下一章：[工具策略](03-tool-policy.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

## 学习目标

- 区分身份凭据、Capability 和会话凭据。
- 解释资源范围、有效期、次数、吊销和跨租户边界。
- 找到 Redis 原子扣减和 PostgreSQL 吊销的作用。

## 威胁场景与原理

Agent 获准阅读 `public-guide`，却请求 `private-notes`；或者拿租户 A 的令牌访问租户 B。知道调用者是谁，不能证明它获准使用这项资源。

| 凭据／标识 | 回答的问题 | 不能代替什么 |
| --- | --- | --- |
| Agent 身份密钥、`X-Tenant-ID` | 哪个租户的哪个 Agent 在调用？ | 工具与资源授权 |
| `X-Capability` 不透明令牌 | 哪个工具、哪些精确资源、到何时、最多几次？ | 策略、审批及其他同步检查 |
| `X-Runtime-Session` | 是否属于已上报且运行中的会话？ | 工具授权；session_id 自身也不授权 |
| 管理员登录与 CSRF | 谁能管理授权和批准动作？ | 执行前对原动作的再次核验 |

令牌原文只交给可信适配层；数据库和 Redis 用哈希定位。Redis Lua 一次完成租户／Agent／工具／资源核验与次数扣减，避免并发先检查后扣减。数据库中的到期与吊销状态仍须核验；Redis 不可用时不放行工具。

## 项目实现

阅读 [capability.py](../../src/agentsentry/capability.py) 的 `issue`、`CONSUME_SCRIPT`、`consume`、`revoke`，再读 [service.py](../../src/agentsentry/service.py) 对 grant 的复核。发行失败会尝试清掉 Redis 项；已提交的数据库吊销不能因缓存清理失败而失效。

多租户入口见 [tenants.py](../../src/agentsentry/tenants.py)、[database.py](../../src/agentsentry/database.py)；会话签发见 [runtime_binding.py](../../src/agentsentry/runtime_binding.py)。精确资源匹配不由 YAML 正则或模型判断承担。

## 动手实验：授权耗尽、越界与租户隔离

**环境**：按手册离线设置；临时数据库、内存 Redis、FastAPI 测试客户端。结果只在终端和断言，不进入 Web。

```bash
.venv/bin/python -m pytest -q tests/test_service.py::test_scope_and_revocation_deny tests/test_service.py::test_idempotency_and_exhaustion tests/test_v2_tenants.py
```

| 正常／边界 | 观察点 | 预期 |
| --- | --- | --- |
| 一次有效授权＋原样重试 | Task 数量和返回值 | 正常完成一次；原样重试不重复执行 |
| 请求未授权资源／已吊销令牌 | 调用状态 | denied |
| 次数耗尽后新动作 | 新调用与 Task 数量 | denied，无新任务 |
| 两个测试租户访问对方数据与管理接口 | 测试中的身份、策略、背景事件断言 | 对方数据不可读，对方动作不可管理 |

[服务测试](../../tests/test_service.py)的正常对照排除“所有请求都拒绝”的假防御；[租户测试](../../tests/test_v2_tenants.py)核对读写和后台处理范围。到期、跨租户令牌等完整固定用例还可通过[离线安全样本](13-validation-calibration.md)观察，不能把这两个服务测试说成已测所有授权风险。

## Web 对照与配置

“管理配置 → 工具调用授权”签发与吊销；令牌只显示一次。“工具调用与审计”查看拒绝和授权关联。默认管理员在研究页选择数据租户仅用于只读查看，不代表普通租户能跨租户管理。

令牌次数可能在后续安全条件拒绝之前已被扣减，不能从“未执行”推断“令牌未消耗”。默认 `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false` 兼容旧工具客户端；敏感写入和模型出口仍强制绑定，未绑定旧客户端没有行动预算保护。

## 局限与自检

应用使用共享进程与数据库账号，schema 隔离不等同于抵御网关进程失陷。Agent 密钥失陷后，攻击者可能建立新会话；这不自动获得管理员签发授权的能力，但不能把会话签名当作完整身份失陷防护。

1. 有身份密钥和 session_id，能自行签发 Capability 吗？**不能，需要管理员入口**。
2. 能访问 public-guide 的令牌，能访问其他公开文档吗？**不能，仍按精确资源范围**。
3. 应否给学习实验无限次数令牌？**使用足够且有限的次数，观察耗尽和吊销**。

深入阅读：[租户接入](../tenant-demo.md)、[权限与租户案例](../cases/tool-permission-and-approval.md)、[威胁矩阵 TH-003](../threat-framework-mapping.md)。
