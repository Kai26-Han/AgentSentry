# 进阶安全案例

[中文](#) · [English](../en/cases/README.md)

从[项目入口](../../README.zh-CN.md)和[安全学习手册](../learning/README.md)完成基础练习后，用这些案例学习如何发现缺口、核对副作用、修复并说明取舍。无需阅读开发历史。

每个案例包含问题、控制、实测事实、复现入口和局限。修复前的失败与修复后的结果同时保留；固定重放、真实模型和现场测试分别标明，不合并为笼统覆盖率。

## 按安全问题选择

| 安全问题 | 案例 | 重点 |
| --- | --- | --- |
| 并发授权与审批 | [权限、审批与竞争条件](tool-permission-and-approval.md) | 同一动作、吊销、到期与提交失败 |
| 执行与可靠审计 | [沙箱、Outbox 与 Judge](execution-and-audit.md) | 隔离与授权不同，异步失败如何留证 |
| MCP 协议和不可信结果 | [MCP 工具边界](mcp-boundaries.md) | 定义漂移、异常响应和 unknown |
| 提示词注入 | [A03／A12 回答污染与展示阻断](injection-and-output.md) | 草稿污染和实际展示必须分开 |
| 跨会话污染 | [记忆投毒与存储完整性](memory-poisoning.md) | 来源核验、隔离、读取与撤销 |
| 敏感数据泄露 | [改写泄露与保守阻断](private-data-leakage.md) | 数词绕过、四类出口及正常任务代价 |
| 连续行为 | [运行时处置与行动预算](runtime-and-budget.md) | 固定阈值、并发计数与模型未尝试 |
| Agent 间协作 | [单跳委托安全边界](delegation-boundaries.md) | 缩减权限、封签与低信任结果 |
| 多边界验证 | [故障注入与交叉验证](boundary-validation.md) | 从失败断言找修复目标 |
| 第三方只读 MCP | [GitHub 固定文件读取](github-readonly.md) | 真实服务连接与工具登记 |
| 第三方内容分析 | [GitHub 公开 Issue](github-issue-analysis.md) | 没有危险尝试不能算工具阻断成功 |
| 第三方受控写入 | [GitHub 人工审批写入](github-controlled-write.md) | 外部副作用核对与 unknown 对账 |

## 如何使用案例

1. 先读问题和预期，预测自己的环境会得到什么决定。
2. 优先运行链接到的离线测试；在线、模型和第三方操作按专题说明准备。
3. 核对决定、实际执行、回答展示及审计，不能只看 Judge 分数。
4. 写自己的[学习记录](../learning/personal-assessment.md)，包含日期、模式、样本版本、规则修订与无法判定项。

案例中的样本编号必须带样本库版本，例如 `goal-lab-v1:A12`。固定重放不证明真实模型一定被诱导；测试通过不证明所有语义改写或第三方路径安全。

## 证据约定

[evidence/](evidence/) 中只保留受限、脱敏的事实摘要，不包含凭据、业务原文或可查询的私人运行数据库。摘要帮助核对案例；自己的 Web 证据要由自己的运行器生成。完整场景映射见[威胁矩阵](../threat-framework-mapping.md)，代码与复现入口见各案例。
