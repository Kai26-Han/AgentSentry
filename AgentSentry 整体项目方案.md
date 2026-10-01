# AgentSentry 整体项目方案与当前实现总纲

[中文](#) · [English](PROJECT-PLAN.en.md)

> 能力基线：V3.6；更新日期：2026-10-01。软件包版本仍以 `pyproject.toml` 为准。

## 一、项目定位与学习目标

AgentSentry 是面向个人与共同学习的本机自托管 Agent 安全实验平台。通过一个示例 Agent、固定登记工具和可重复运行的合成样本，学习安全机制的原理、实现方式、效果与局限。基础服务使用 Docker Compose 在本机运行，Web 端口绑定回环地址；云端 Judge、登记的模型服务和第三方 MCP 可按配置成为外部目的地。

核心学习过程是：**理解威胁 → 构造实验 → 观察 Agent → 核对网关决定 → 验证实际副作用与展示 → 分析误拦和缺口 → 回归验证**。当前核心运行时机制已经落地，[按安全主题的学习手册](docs/learning/README.md)已建立，部分安全领域仍待深入验证；项目实现和手册交付并不等同于学习者已经掌握全部机制。

同步控制依赖身份、类型化参数、策略、权限、数据流和运行状态等确定性事实。Judge 是异步风险信号；目标偏移与可选本地语义分析是辅助线索。自然语言判断不能扩大权限，管理员批准后仍需执行前复核。

### 三个阅读入口

| 入口 | 内容 |
| --- | --- |
| 本文 | 项目目的、能力全景、当前边界与后续方向 |
| [当前架构](docs/architecture.md) | 组件职责、实际流程、信任边界、状态与留存 |
| [风险覆盖与证据](docs/risk-coverage.md) | 威胁矩阵、样本和实测报告、当前缺口 |

启动与操作从 [README](README.zh-CN.md) 开始；界面目录见 [Web 面板导航](docs/web-dashboard.md)。

按主题学习从[安全学习手册](docs/learning/README.md)开始：15 章按基础边界、内容安全、持续行为、验证调查组织，附[术语表](docs/learning/glossary.md)、[实验索引](docs/learning/experiment-index.md)与[进阶案例](docs/cases/README.md)。手册引用当前实现和实验案例，不重新定义安全保证。

### 面向学习者的使用方式

- **基础机制**：本机离线测试、固定样本与正常对照，不需模型密钥。
- **端到端观察**：启动网关后，在专用研究租户生成新的调用和实验记录。
- **模型与第三方研究**：按需接入本地真实模型或已登记 MCP，明确实际外发与写入副作用。
- **贡献与复核**：分享合成报告和可复现步骤，保留失败、误拦和未验证项，见[贡献指南](CONTRIBUTING.md)。

首次启动步骤见 README。公开副本不包含原作者的数据库、凭据或个人掌握记录；进阶案例提供已保存的实验事实，不能当作新安装的当前结果。

## 二、当前能力全景

| 安全主题 | 当前能力 | 防护位置与效果边界 | 说明与证据 |
| --- | --- | --- | --- |
| 身份与最小权限 | 租户／Agent 身份、临时 Capability、资源范围、到期／次数、原子扣减和吊销 | 网关核验；身份凭据本身不能代替工具授权，令牌不进入模型上下文 | [权限实现](src/agentsentry/capability.py)、[权限案例](docs/cases/tool-permission-and-approval.md) |
| 工具调用策略 | 固定工具、严格参数模型、YAML 默认拒绝、拒绝优先、校验与热更新 | YAML 匹配工具与附加拒绝正则；精确资源授权由 Capability 和类型化参数承担 | [策略实现](src/agentsentry/policy.py)、[策略回归](tests/test_policy_suite.py) |
| 人工审批 | 冻结参数、事实卡、短时确认、过期与重放检查、执行前重查 | 批准只针对原动作；来源声称“已批准”不构成授权 | [审批说明](docs/goal-drift.md)、[审批测试](tests/test_approval_review.py) |
| 执行隔离 | 默认租户的受限 Docker Shell 沙箱 | 容器与进程资源限制；其他租户不能使用共享沙箱，容器逃逸未由实验排除 | [执行边界案例](docs/cases/execution-and-audit.md) |
| 输出安全与来源 | 回答展示前检查、读取来源关联、明确注入载荷与敏感片段检查 | 网关返回可展示内容，适配层负责实际展示；来源关联不证明事实真实 | [输出说明](docs/output-safety.md)、[A03 修复](docs/cases/injection-and-output.md)、[A12 修复](docs/cases/injection-and-output.md) |
| 长期记忆安全 | 自动摘要、来源审核、激活／隔离／撤销、读取再检、完整性签名 | 记忆始终是低信任数据；签名只能保护应用密钥未同时失陷的篡改场景 | [记忆说明](docs/memory.md)、[记忆污染案例](docs/cases/memory-poisoning.md) |
| 敏感数据流 | 来源 public／private／secret 分级，模型、写入、回答与记忆出口检查 | 网关核对来源并判定；模型出口由可信适配层发送，其他程序的流量不受拦截 | [数据流说明](docs/data-flow.md)、[安全案例](docs/cases/private-data-leakage.md) |
| 会话调查与目标偏移 | 日常会话时间线、任务轮廓、来源诱导线索、人工复核 | 辅助调查与审批，不证明自然语言目标已被完整理解 | [日常分析](docs/runtime-analysis.md)、[回答污染案例](docs/cases/injection-and-output.md) |
| 运行时检测与处置 | 可疑读取后写入、连续拒绝、未知结果重复动作、暂停／恢复 | 依据已提交记录保持决定、升级审批或拒绝；作用于后续受控动作 | [运行时说明](docs/runtime-defense.md)、[安全案例](docs/cases/runtime-and-budget.md) |
| 会话行动链 | 工具／模型／摘要预算、单会话与跨会话写入预算、资源探测暂停 | 有效绑定的工具会话受保护；额度内的错误动作仍需其他控制 | [行动链说明](docs/action-chain.md) |
| MCP 接入与供应链 | 本地 stdio、登记的 HTTPS／OAuth 演示端点、GitHub 固定只读与受控写入；远程演示端点有版本化档案、变更审核和合成只读探针 | 显式接入、固定定义和资源；探针不证明远端程序或所有结果可信 | [MCP 边界案例](docs/cases/mcp-boundaries.md)、[远程演示](docs/remote-mcp.md)、[供应链说明](docs/mcp-supply.md)、[GitHub 实测](docs/cases/github-controlled-write.md) |
| Agent 间委托 | 本机单跳独立只读身份、父权限缩减与额度预留、封签、结果和来源复核 | 不提供写入、多跳、跨主机或内容真实性保证 | [委托说明](docs/delegation.md)、[安全案例](docs/cases/delegation-boundaries.md) |
| 故障传播与恢复 | 租户内熔断与并发租约、队列退避、独立通知 Worker、处理代次保护与管理员重投 | 关键检查故障不放行；unknown 不自动重试；共用主机／数据库仍可影响所有租户 | [故障传播说明](docs/fault-propagation.md) |
| Judge、审计与告警 | Mock／OpenAI 兼容／Jev／DeepSeek、事务 Outbox、重试去重、告警归并与可选 Webhook | Judge 按租户运行设置异步评判；Jev 为托管 API，分数不表示攻击成功概率 | [Judge 配置](docs/judge-runtime-switch.md)、[异步审计案例](docs/cases/execution-and-audit.md) |
| 攻防实验与威胁映射 | 固定提案与真实模型双轨、独立判分、校准建议、OWASP／ATLAS 证据矩阵、日常事件关联 | 研究租户保存独立实验；日常流量不自动重放，框架编号不证明防护完成 | [攻击实验](docs/attack-lab.md)、[校准案例](docs/cases/injection-and-output.md)、[威胁矩阵](docs/threat-framework-mapping.md) |

## 三、安全能力实现与验证状态

“已实现”表示代码和接口存在；“已验证”还需说明样本、路径和观察事实。读代码、固定提案、真实模型和现场检查分别提供不同证据，不能相互代替。

| 主题 | 当前状态与证据 | 需要理解的限制 |
| --- | --- | --- |
| 身份、权限与审批 | [授权与并发审批案例](docs/cases/tool-permission-and-approval.md)、[租户测试](tests/test_v2_tenants.py) | 应用层隔离不抵御整个网关进程失陷；批准不替代执行前复核 |
| 工具与执行隔离 | [执行和审计案例](docs/cases/execution-and-audit.md)、[MCP 结果边界](docs/cases/mcp-boundaries.md) | Docker 探针不是逃逸证明；派发后的 unknown 不可自动重做 |
| 提示注入与输出 | [回答污染案例](docs/cases/injection-and-output.md) | 已验证明确载荷；公开来源的隐含语义和错误事实仍可能漏检 |
| 记忆与敏感数据 | [记忆投毒](docs/cases/memory-poisoning.md)、[私有数据泄露](docs/cases/private-data-leakage.md) | 来源审核不证明真实；受限来源回答整体阻断会影响正常任务 |
| 持续行为与目标 | [运行时和预算案例](docs/cases/runtime-and-budget.md)、[目标偏移章节](docs/learning/10-goal-drift.md) | 目标偏移是辅助线索；额度内错误动作和长期自主偏移仍有边界 |
| 第三方 MCP | [固定只读](docs/cases/github-readonly.md)、[受控写入](docs/cases/github-controlled-write.md)、[供应链机制](docs/mcp-supply.md) | 单一服务和一次写入不证明任意 MCP 或长期供应链安全 |
| 故障与委托 | [故障机制](docs/fault-propagation.md)、[委托案例](docs/cases/delegation-boundaries.md) | 共用基础设施、多跳、跨主机和多模型语义污染仍待验证 |
| 审计、Judge 与映射 | [审计案例](docs/cases/execution-and-audit.md)、[威胁矩阵](docs/threat-framework-mapping.md) | Judge 只评价收到的事件；映射不代表攻击成功或整类风险已解决 |

实验结论与计数在案例中注明日期、样本版本和模式。新的安装不会拥有案例中的原运行记录；请用[实验索引](docs/learning/experiment-index.md)生成自己的证据，不以项目测试数量替代个人学习结果。

## 四、当前明确边界与缺口

| 主题 | 当前结论 | 需要继续验证的内容 |
| --- | --- | --- |
| 身份、资源范围、记忆存储篡改 | 注明范围内已有验证 | 外部身份体系、应用与签名密钥同时失陷；见矩阵 TH-003、TH-005 |
| 提示注入与输出污染 | 部分验证 | A03／A12 的明确模式有修复证据；语义改写、多语言和新载荷仍可能漏检；见 TH-001、TH-002 |
| 私有数据流与记忆污染 | 部分验证 | 未知敏感格式、分段／改写泄露；正常操作受阻的误拦取舍；见 TH-004、TH-006、TH-007 |
| 第三方 MCP | 链路已实测，供应链防护部分验证 | 受控 MCP 服务验证接入档案、定义变化、固定探针及连接目标选择；GitHub 固定读取和一次审批写入已实测。不证明任意服务、内部实现漂移或长期清单变化安全；见 TH-010 |
| 自主偏移与行动预算 | 预算部分验证，自主偏移未验证 | 没有攻击输入时的多步骤偏移、额度内错误动作、未绑定旧客户端；见 TH-011、TH-013 |
| Agent 间通信与委托 | 部分验证 | 本机单跳只读协作已实现；真实模型协作、多跳、写入及跨主机未验证；见 [TH-015](docs/delegation.md) |
| 连锁故障 | 部分验证 | 已实现租户内依赖隔离、队列退避、代次保护及恢复；共用基础设施、跨 Agent 及长期压力仍未验证；见 [TH-014](docs/fault-propagation.md) |

以上状态以[威胁矩阵](docs/threat-framework-mapping.md)为证据入口，不计算笼统的 Top 10 覆盖率。当前默认 `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false`；未绑定旧工具客户端不受行动链预算保护，敏感写入、远程 MCP 与模型出口仍有各自强制绑定要求。

`AGENTSENTRY_CAPTURE_MODE=metadata` 只取消任务／回答片段留存。原文仍临时进入网关检查，长期记忆仍保存文字，部分操作原文仍暂存；详见[架构的留存说明](docs/architecture.md#数据留存与隐私)。

## 五、后续方向与完成标准

| 优先级 | 待开展工作 | 完成标准 |
| --- | --- | --- |
| 学习路径 | 按已建立的学习手册完成学习与补证 | [个人验收](docs/learning/personal-assessment.md)提供 15 张任务卡、30 个基础实验单元和人工复核记录；沙箱脚本已适配绑定与人工审批，个人网关链需自行现场完成；自动实验通过不推断个人掌握 |
| 1 | 深化现有防护的效果验证 | 为受限来源回答设计可核验展示模板或人工复核，减少当前正常误拦；扩充模型与长期正常任务，独立统计危险尝试、副作用、展示污染和误拦；保留可复核的案例事实 |
| 2 | 深化 MCP 与软件供应链证据 | 已完成固定合成服务变更检测；下一步验证真实公网 DNS 变化、第三方实现和长期响应语义 |
| 3 | 深化故障传播与恢复 | 单 Agent 服务链隔离已实现；继续验证长期压力、共用基础设施失效与跨 Agent 传播 |
| 4 | Agent 间安全委托 | 独立只读协作已实现；继续定义语义污染、跨主机和多跳链的实验判据 |

已完成和待开展事项以上表及证据为准。后续能力、策略或样本变化时，需同时更新总纲、架构、风险证据和相关专题说明。

## 六、阅读与文档维护约定

- 当前总纲、架构和学习手册作为主入口；进阶案例解释问题、原理、实验事实、修复取舍和局限。
- 静态威胁结论来自结构化映射数据；中文矩阵由校验工具生成，日常事件保存当时分类版本。
- 证据引用使用“样本库版本＋样本 ID”，不能只写 A12 等编号。未尝试危险调用、待审批、unknown 和环境故障须分别说明。
- 项目不承诺普遍防御效果、生产级容器隔离或未经测量的延迟；只对注明路径和实验作结论。

公开文档只保留两类阅读路径：**主入口**（README、总纲、架构、学习手册及操作说明）与**进阶案例**（按安全问题查阅的实验和修复分析）。实验样本、规则版本和日期保留用于复现，不按开发版本安排学习顺序。
