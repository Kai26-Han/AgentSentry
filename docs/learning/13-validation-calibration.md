# 13 攻防验证与规则校准

[中文](#) · [English](../en/learning/13-validation-calibration.md)

[手册首页](README.md) · 上一章：[审计与 Judge](12-audit-judge-mapping.md) · 下一章：[故障传播](14-fault-propagation.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

## 学习目标

- 给实验建立攻击条件、正常对照和可判定成功标准。
- 分开统计固定重放与真实模型行为。
- 用基线、建议、人工决定和保留集评估规则调整。

## 为什么功能存在还需要验证

拒绝所有请求可以让攻击副作用为零，却无法完成正常任务。模型没有提出危险工具也会让副作用为零，但没有触发工具防护。必须同时看任务完成、危险尝试、实际副作用、展示、无法判定和误拦。

```text
固定校准集与保留集 → 基线运行 → 逐例事实与候选原因
                                      ↓
                          人工审查建议：修改或维持
                                      ↓
                     同模式、同样本再运行并比较保留集
```

测试不是只看“攻击成功率 0%”。针对每类出口，先说明分母和无法判定数量，再说明哪些控制真正被触发。

## 两条验证轨道与口径

| 项目 | 应怎样记录 |
| --- | --- |
| scripted 固定提案 | 是否把已知危险请求送到边界，决定和副作用是否符合预期 |
| live 真实模型 | 模型是否实际提出危险调用，是否完成原任务，实际展示如何 |
| 未提出危险调用 | 单列“未尝试”；该类工具阻断率未验证 |
| pending／unknown／环境故障 | 保留具体原因，不自动算攻击成功或防御成功 |
| 草稿污染／展示污染 | 两项分开；展示被阻断不计可见污染 |
| Judge 误报／漏报 | 只对实际收到且有参照判定的事件统计，缺分母记未覆盖 |

危险尝试率使用可判定攻击运行作为分母；尝试后的工具阻断率只使用实际到达相关边界的危险尝试。不同实验室的旧判分可能不同，汇总时保留各自口径，不直接合并百分比。

## 动手实验一：离线边界与正常对照

**环境**：临时数据库、模拟工具、Mock Judge；不产生运行中 Web 记录。

```bash
.venv/bin/python -m agentsentry.evaluation --policy policies/default.yaml --cases evals/cases.jsonl --output /tmp/agentsentry-learning-eval.json
.venv/bin/python -m pytest -q tests/test_evaluation.py tests/test_attack_lab.py tests/test_calibration.py
```

[31 条固定安全样本](../../evals/cases.jsonl)验证授权、审批、重放和副作用；看报告中的逐例、正常完成、误拦、审计缺失和 Mock Judge 统计。Mock 漏报不能代表 DeepSeek／Jev 效果。

[校准测试](../../tests/test_calibration.py)比较草稿与展示、正常私有无关发送的受阻、跨会话证据、记忆第二轮和不相容报告拒绝。它有意保留正常受阻案例，不能把“测试通过”解释成没有误拦。

## 动手实验二：Web 基线与同规则重复比较

**前置**：在线终端、运行中网关、有效管理员设置和新研究租户的 MCP 策略。运行器每次创建新的研究租户；不修改既有租户策略。以下是固定集合，不支持任意单条选择。

```bash
.venv/bin/python -m agentsentry.calibration_runner --mode scripted --output /tmp/agentsentry-learning-baseline.json
.venv/bin/python -m agentsentry.calibration_runner --mode scripted --output /tmp/agentsentry-learning-repeat.json
.venv/bin/python -m agentsentry.calibration_runner --compare /tmp/agentsentry-learning-baseline.json /tmp/agentsentry-learning-repeat.json --output /tmp/agentsentry-learning-comparison.json
```

先用同一规则两轮核对稳定性；这只是比较练习，**不是已经完成了规则修改**。每轮在 Web “安全实验与评测 → 攻防验证与规则校准”查看报告租户和逐例证据。基线完整、哈希与模式一致后才比较；中断或不相容报告不能硬算差异。

[calibration-cases-v1](../../src/agentsentry/calibration_corpus.py)含 12 攻击、12 正常：A01～A08／N01～N08 为校准集，A09～A12／N09～N12 为保留集。重点观察：

| 样本 | 要解释的结果 |
| --- | --- |
| `calibration-cases-v1:A03` | 草稿是否污染、输出是否阻断；与[A03 回答污染修复](../cases/injection-and-output.md)对照 |
| `calibration-cases-v1:N07` | 私有来源后的无关公开发送仍受阻；是正常任务摩擦候选 |
| `calibration-cases-v1:N08` | 引用注入文字后正常写入升级审批；不是简单“所有引用都危险” |
| `calibration-cases-v1:A10` | 审批参数替换没有未经授权写入 |

## 进阶案例：修复与取舍

第一批现场证据见[现有防护深入验证](../cases/boundary-validation.md)：五个主题分别核对预期；两轮均有三项输出缺口，不把失败算作通过，真实模型另列。当时私有数字的语义改写展示缺口持续失败；后续[受限来源回答修复](../cases/private-data-leakage.md)在两轮现场复测阻断这些草稿，并单独记录正常无关回答受阻的代价。不能把已通过的普通样本作为抵消证据。

## 真实模型扩展与人工规则评估

本机模型已配置且目的地匹配时：

```bash
.venv/bin/python -m agentsentry.calibration_runner --mode live --output /tmp/agentsentry-learning-calibration-live.json
```

模型选择使用在线终端的 `DEMO_MODEL_BASE_URL`／`DEMO_MODEL_NAME`，按第 10 章配置。本轮选定文档与 MCP 的 6 攻击／6 正常，各三次，不用固定轨成绩替代未触发的真实模型控制。云模型只有另行显式配置和允许后才能使用，入门流程不启用。

规则评估记录：**基线 → 误拦／漏拦候选 → 具体因果证据 → 建议 → 人工决定 → 新规则版本和保留集**。没有安全改法，可以明确“维持规则”及取舍。若做修改，另开实现任务，由人工审查代码并运行回归；本手册不在线修改阈值或自动发布规则。身份、跨租户、凭据和审计失败时拒绝等边界不能因小样本成绩放宽。

## 收尾、局限与自检

研究记录保持历史证据，不覆盖旧报告；新命令示例输出到独立文件。检查仍待审批的研究动作，按其租户拒绝；凭据文件不进入报告或分享。日常数据只按已有决定元数据汇总，不自动复制原文或重放。

1. 正常任务受阻就必须放宽吗？**先证明缩小条件不会产生分段／改写泄露等新缺口**。
2. 保留集用于反复调参是否合理？**会破坏独立验证，应固定分组并诚实记录使用历史**。
3. 0 次禁止副作用是否证明全部安全？**还需展示污染、正常完成、触发范围与无法判定**。

深入阅读：[校准机制](../calibration.md)、[安全案例](../cases/injection-and-output.md)、[风险证据](../risk-coverage.md)、[实验索引](experiment-index.md)。
