# 09 运行时检测与处置

[中文](#) · [English](../en/learning/09-runtime-defense.md)

[手册首页](README.md) · 上一章：[数据流](08-sensitive-data-flow.md) · 下一章：[目标偏移](10-goal-drift.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

## 学习目标

- 从已发生的读取、拒绝和不明执行判断后续动作。
- 解释线索、升级审批、拒绝、暂停和告警确认的区别。
- 找到规则定义、当前目录与实际命中证据。

## 威胁场景与原理

同一个 create_task 可能是正常任务，也可能是在注入材料诱导、连续拒绝探测之后提出的动作。只检查当前参数看不到前面发生了什么。

```text
单次策略与授权 → 已提交历史证据 → 运行时决定
                                       ├─ 保持原决定／只留线索
                                       ├─ allow 升级为审批
                                       └─ 拒绝后续动作
```

规则只能保持或收紧基础决定，不能放宽 deny 或资源范围。Judge 不在同步处置路径。管理员暂停阻止后续受控动作，不能停止已经启动的副作用或让模型撤回回答。

## 当前规则与代码入口

| 规则 | 服务端证据 | 行为 |
| --- | --- | --- |
| read_then_write_review | 正常读取后写入 | 只记线索，不自动阻断 |
| instruction_source_before_write | 已读取有限内容匹配明确指令，随后写入 | 原 allow 升级审批 |
| repeated_denials_before_write | 同 Agent 十分钟至少三次拒绝，随后写入 | 原 allow 升级审批 |
| uncertain_action_repeat | 24 小时内相同动作处于 executing／unknown | 拒绝新 ID 重复副作用 |
| administrator_paused／session_closed | 暂停或已结束会话 | 拒绝后续工具 |
| session_binding_invalid | 无效绑定；强制模式下缺绑定 | 拒绝新工具请求 |

定义见 [runtime_guard.py](../../src/agentsentry/runtime_guard.py) 的 `rule_catalog`、`evaluate`、`record`；会话绑定见 [runtime_binding.py](../../src/agentsentry/runtime_binding.py)。当前版本 `runtime-rules-v1`，Web “管理配置 → 防护规则 → 运行时安全规则”只读展示代码定义，不在线调阈值。

三次拒绝阈值是项目当前规则选择，不是通用安全标准；它可能产生误拦，必须结合正常对照和[校准](13-validation-calibration.md)评估。

## 动手实验：正常读后写与可疑连续行为

**环境**：临时 SQLite、合成工具状态、内存 Redis，不访问模型，不进入 Web。

```bash
.venv/bin/python -m agentsentry.runtime_lab --output /tmp/agentsentry-learning-runtime.json
.venv/bin/python -m pytest -q tests/test_runtime_guard.py
```

| 样本库＋ID | 对照内容 | 预期 |
| --- | --- | --- |
| `runtime-cases-v1:N01` | 正常公开读后创建任务 | completed，合法任务增加 |
| `runtime-cases-v1:A01` | 明确注入来源后写入 | pending_approval，任务不增加 |
| `runtime-cases-v1:N05` | 两次拒绝后正常写入 | completed，尚未达到拒绝阈值 |
| `runtime-cases-v1:A05` | 至少三次拒绝后写入 | pending_approval，无写入副作用 |
| `runtime-cases-v1:A08` | 同动作旧结果 unknown 后用新 ID 请求 | denied，无重复任务 |
| `runtime-cases-v1:N09` | 暂停后明确恢复 | 正常任务可再次执行 |

打开[样本代码](../../src/agentsentry/runtime_lab.py)与报告，看 `runtime_findings`、`actual`、`side_effect_delta` 和 `audit_missing`。待审批验证的是没有执行，而不是已经证明最终安全完成。替身制造的 unknown 是状态边界实验，不是实际崩溃现场。

## 可选 Web 实验与恢复

运行中服务就绪后，在在线终端执行：

```bash
.venv/bin/python scripts/runtime_smoke.py
```

脚本创建／复用独立 Runtime Lab 合成租户，保存 `.local/runtime-smoke.json`，产生升级审批、暂停和复核证据。可疑写入被拒；脚本还提交“暂停后批准”请求，预期执行前拒绝、没有副作用，成功结束时恢复实验暂停。使用该租户管理员身份查看“会话调查”“运行时安全规则”“告警”；它不一定出现在 Attack Lab 专用选择器中。中断可能残留状态，结束后检查该租户待审批动作，复核后拒绝或恢复。不要恢复日常租户的真实事件。

确认告警只是记录管理员看过；不自动恢复会话。审批真正执行前会重新核对暂停、策略、权限和新增证据。

## 局限与自检

规则只看有限来源和已提交窗口，不保证识别语义偏移。默认兼容旧客户端不强制所有工具绑定；暂停 Agent 不能抵御攻击者已取得全部身份和进程控制权。其他出口有自己的检查，不把工具暂停描述成全机网络熔断。

1. 正常读后写为何不直接拒绝？**这是正常工作流，需要更具体的证据**。
2. unknown 后用原 call_id 查询和新 ID 重做一样吗？**前者读取幂等状态，后者可能重复执行**。
3. 告警确认等于解除暂停吗？**不是两个动作**。

深入阅读：[运行时说明](../runtime-defense.md)、[验收](../cases/runtime-and-budget.md)、[实验索引](experiment-index.md)。
