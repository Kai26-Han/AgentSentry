# 03 工具策略与参数边界

[中文](#) · [English](../en/learning/03-tool-policy.md)

[手册首页](README.md) · 上一章：[身份与权限](02-identity-capabilities.md) · 下一章：[人工审批](04-approval-safety.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

## 学习目标

- 区分工具登记、类型校验、基础策略和资源授权。
- 解释默认拒绝、拒绝优先与策略安全更新。
- 用相同 call_id 的重试和换内容冲突验证幂等。

## 威胁场景与控制链

攻击者诱导 Agent 提交未知工具、额外参数、越界资源，或者在失败重试时换掉内容。模型生成了看似合法的 JSON，不意味着它符合登记的参数模型或资源授权。

```text
固定工具登记 → 类型与大小校验 → YAML 基础决定
                                ＋ 精确资源 Capability
                                ＋ 运行时／数据流／行动预算
                                → 最终允许、拒绝或审批
```

当前 YAML 按工具匹配，可添加**仅用于拒绝**的字段正则；它不是任意表达式语言，不承担精确资源授权。多个规则命中时，`deny > require_approval > allow`，无命中则 `default_deny`。删除、外发、Shell、MCP 笔记和 GitHub 写入等敏感工具不能通过策略直接设置为 allow。

## 项目实现与配置

| 文件 | 关注点 |
| --- | --- |
| [schemas.py](../../src/agentsentry/schemas.py) | TOOL_SCHEMAS、严格字段、工具参数大小和资源字段 |
| [policy.py](../../src/agentsentry/policy.py) | Rule 校验、decide 优先级、PolicyManager 原子替换 |
| [default.yaml](../../policies/default.yaml) | 当前缺省工具规则，不等于运行中每个租户的策略 |
| [service.py](../../src/agentsentry/service.py) | 规范化请求摘要、幂等返回、409 冲突 |

Web “管理配置 → 防护规则 → 工具调用策略”管理本租户 YAML；“运行时安全规则”是另一类只读规则目录。运行中的策略可能来自 Compose 卷或租户文件，改宿主 `default.yaml` 不代表已有租户已生效。

## 动手实验：策略行为与请求重试

**环境**：离线；读取默认 YAML 与固定用例，测试中的修改只发生在临时文件。不会更改服务策略。

```bash
.venv/bin/python -m agentsentry.policy_tests --policy policies/default.yaml --cases policy-tests/cases.yaml
.venv/bin/python -m pytest -q tests/test_policy_suite.py tests/test_service.py::test_policy_deny_precedes_capability tests/test_service.py::test_idempotency_and_exhaustion tests/test_v15.py::test_policy_hot_reload_is_atomic_on_invalid_candidate
```

| 实验 | 对照／证据 | 预期 |
| --- | --- | --- |
| 默认策略用例 | [cases.yaml](../../policy-tests/cases.yaml)逐条比较效果与规则 ID | 正常公开读、普通任务按预期；敏感动作审批 |
| 含明确秘密标记的模拟外发 | `prohibit_secret_marker` 命中 | denied，无模拟消息 |
| 无效策略更新 | 测试前后的生效修订与决定 | 拒绝候选，原策略仍可用 |
| 原样重试与换标题 | Task 数、返回值、HTTP 状态 | 原样只执行一次；换内容 409 |

核对[策略套件测试](../../tests/test_policy_suite.py)中“没有对应测试的规则”检测：规则存在不代表被有效验证。此命令测试的是传入默认文件，不能代替当前租户实际策略的现场验证。

## 失败与局限

正则只能识别指定字段中的有限模式；语义改写可能漏过。策略允许也仍须满足工具授权与其他同步条件。未知工具／非法参数可能在 HTTP 校验阶段返回 422，尚未产生业务 ToolCall；不能一概把所有入口错误说成有完整审计链。

幂等范围是同租户的同一 `call_id` 和相同请求；新 ID 是新提案。处于 unknown 的副作用不要换 ID 自动再做，见[第 09 章](09-runtime-defense.md)。

## 自检

1. allow 规则排在 deny 前，是否能覆盖 deny？**不能，按效果优先级**。
2. 正则未发现密码，是否证明内容可外发？**不能，还要看来源级别、权限和其他规则**。
3. 为什么换内容不能复用旧 call_id？**否则重试可能改变已批准或已执行的动作**。

深入阅读：[策略回归实现](../../src/agentsentry/policy_tests.py)、[第 08 章](08-sensitive-data-flow.md)、[策略更新与审计案例](../cases/execution-and-audit.md)。
