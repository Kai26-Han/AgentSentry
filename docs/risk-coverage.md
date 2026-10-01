# 风险覆盖与证据

[中文](#) · [English](en/risk-coverage.md)

本页回答“哪些控制有证据、证据证明了什么、哪里仍有缺口”。能力和定位见[总纲](../AgentSentry%20整体项目方案.md)，检查位置见[架构](architecture.md)，按安全问题深入阅读见[进阶案例](cases/README.md)。

[威胁矩阵](threat-framework-mapping.md)按项目场景关联 OWASP Agentic Top 10 2026、MITRE ATLAS、控制、样本、测试和剩余边界；[日常事件映射](runtime-threat-mapping.md)关联已提交元数据。映射是调查入口，不证明攻击成功；“未关联”也不表示安全。只对注明样本与路径作结论，不计算 Top 10 总体覆盖率。

## 当前结论与学习入口

| 场景 | 证据与当前结论 | 还需验证什么 |
| --- | --- | --- |
| 身份、资源授权与审批 | [权限与并发案例](cases/tool-permission-and-approval.md)：固定与真实数据库验证有范围内证据，吊销竞争和复核到期缺口已修复 | 应用／数据库凭据失陷、人类复核错误及其他身份接入 |
| 提示注入与回答污染，TH-001／TH-002 | [A03／A12 案例](cases/injection-and-output.md)：明确载荷在修复后阻断展示；**部分验证** | 公开来源隐含语义、多语言和能实际触发模型的变体 |
| 固定合成注入来源，TH-012 | 可核实 injected-guide 被读取；只证明载荷进入来源，不证明模型服从 | 分别核对工具提案、草稿与实际展示 |
| 记忆污染与存储篡改，TH-004／TH-005 | [记忆案例](cases/memory-poisoning.md)：写入、读取、撤销和篡改有固定边界证据 | 来源真实性、人工误审核及模型语义污染 |
| 私有数据泄露，TH-006／TH-007 | [改写泄露案例](cases/private-data-leakage.md)：三种数字改写修复后均阻断；**部分验证**，无关正常回答也受阻 | 可核验展示模板、更大模型、来源错误分类和未接入路径 |
| 审批欺骗，TH-008 | 原动作、事实卡与状态重新核验，见[审批案例](cases/tool-permission-and-approval.md) | 人类是否被诱导不能由自动页面测试证明 |
| 沙箱执行，TH-009 | [执行案例](cases/execution-and-audit.md)：固定隔离探针与审批前零副作用 | 容器逃逸、其他操作系统和生产隔离 |
| MCP 供应链，TH-010 | [MCP 边界](cases/mcp-boundaries.md)、[供应链机制](mcp-supply.md)及三类 GitHub 案例：**部分验证** | 真实公网 DNS 重绑定、通用 OAuth、长期响应语义及第三方程序替换 |
| 长期自主偏移，TH-011 | 有固定错误提案与压力实验，尚无充分的无攻击输入长期自主行为证据：**未验证** | 更长正常任务、模型种类和额度内偏离任务的动作 |
| 运行时与行动预算，TH-013 | [连续行为案例](cases/runtime-and-budget.md)：固定预算稳定，真实模型有实际预算拒绝；**部分验证** | 强制全部调用方绑定、更多模型循环和跨 Agent 行为 |
| 故障传播，TH-014 | [边界验证案例](cases/boundary-validation.md)、[故障机制](fault-propagation.md)：租户内熔断、并发与专属队列验证；**部分验证** | 共用基础设施失效、长期压力及跨 Agent 连锁故障 |
| Agent 间委托，TH-015 | [委托案例](cases/delegation-boundaries.md)：独立身份、缩减权限、封签、两进程读取有证据；**部分验证** | 多模型协作、写入、多跳、跨主机和内容真实性 |

完整状态和具体测试引用以矩阵为准。Judge 只评判收到的事件，未收到回答就不能把展示污染计为 Judge 漏报。

## 第三方现场证据为什么分开

| 案例 | 核对事实 | 不能推断 |
| --- | --- | --- |
| [GitHub 固定文件读取](cases/github-readonly.md) | 正式 MCP 握手、登记定义、实际读取及审计关联 | 任意工具、仓库或长期供应链都安全 |
| [GitHub 公开 Issue 分析](cases/github-issue-analysis.md) | 三次模型没有危险提案，正常概述被阻断 | 没有尝试时不能报告工具阻断率；正常受阻不是防护成功 |
| [GitHub 人工审批写入](cases/github-controlled-write.md) | 批准前零 Issue、之后恰好一个；unknown 后只读核对 | 新解析器没有第二笔真实写入验证，一次副作用不证明供应链攻击防护完成 |

## 如何维护证据

主入口说明当前能力；案例保留问题、原因、实验模式、日期、样本／规则版本、修复前后事实和取舍。样本标识必须是“样本库版本＋样本 ID”，如 `goal-lab-v1:A12`。保留失败和无法判定结果，不用其他通过样本抵消。

结构化数据 [threat-framework-map.yaml](threat-framework-map.yaml) 是矩阵唯一来源：

```bash
.venv/bin/python scripts/check_threat_mapping.py --write
.venv/bin/python scripts/check_threat_mapping.py --check
```

证据路径调整不改变日常匹配条件、映射规则版本或框架快照日期。新增分类规则另行更新版本并回归；已匹配的事件保留当时分类。生成文档不要手工修改。
