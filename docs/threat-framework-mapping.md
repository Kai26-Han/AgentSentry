# AgentSentry 安全威胁与框架映射

[中文](#) · [English](en/threat-framework-mapping.md)

> 本页由 `docs/threat-framework-map.yaml` 生成，请修改数据文件后运行 `python scripts/check_threat_mapping.py --write`。

映射版本：1.9.0。

OWASP 来源：[Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)。MITRE ATLAS 来源：[官方 2026.08 数据快照](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml)；核对日期：2026-09-29。

**判读口径**：每行只评价注明的项目路径与样本；固定重放、真实模型和单元测试分开列示。框架编号是分类线索，不代表整类风险已解决。案例保留实验日期、规则版本与修复前后事实，已确认缺口不会被其他通过样本抵消。

## OWASP 十类风险的项目适用性

| 类别 | 项目适用性 | 对应威胁 | 说明 |
| --- | --- | --- | --- |
| ASI01 Agent Goal Hijack | 当前适用 | [TH-001](#th-001)、[TH-002](#th-002)、[TH-012](#th-012) | 文档与 MCP 卡片可影响示例 Agent 的任务选择或回答；已知合成恶意文档的读取单独作为来源暴露线索，不推断模型已服从。 |
| ASI02 Tool Misuse & Exploitation | 当前适用 | [TH-002](#th-002)、[TH-006](#th-006)、[TH-007](#th-007)、[TH-009](#th-009)、[TH-013](#th-013) | 固定工具可被诱导读取、写入或模拟外发；模型发送出口按 Agent 可触发的外部动作纳入，结论限于显式接入路径。 |
| ASI03 Identity & Privilege Abuse | 当前适用 | [TH-015](#th-015)、[TH-003](#th-003) | 租户身份与资源范围有验证；未覆盖外部身份提供方或其他 Agent。 |
| ASI04 Agentic Supply Chain Vulnerabilities | 当前适用 | [TH-010](#th-010) | 固定远程 MCP HTTPS 出口已接入；受控本机 TLS/OAuth 测试验证清单和身份边界，GitHub 官方 MCP 已完成固定只读及一次人工审批写入。真实链路接通不证明第三方内部实现、响应语义或长期供应链变化安全。 |
| ASI05 Unexpected Code Execution | 当前适用 | [TH-009](#th-009) | 默认租户有受限 Shell 演示；其容器隔离不能视为生产级安全沙箱。 |
| ASI06 Memory & Context Poisoning | 当前适用 | [TH-004](#th-004)、[TH-005](#th-005)、[TH-015](#th-015) | 已有跨会话污染和存储篡改样本，语义改写及应用密钥同时失陷仍未覆盖。 |
| ASI07 Insecure Inter-Agent Communication | 当前适用 | [TH-015](#th-015) | 新增本机单跳只读协作身份、封签消息和缩减权限；跨主机、多跳及语义真实性尚未验证。 |
| ASI08 Cascading Failures | 当前适用 | [TH-014](#th-014) | 已加入单 Agent 服务链的熔断、队列退避与故障隔离实验；跨 Agent 及真实分布式连锁故障仍未验证。 |
| ASI09 Human-Agent Trust Exploitation | 当前适用 | [TH-001](#th-001)、[TH-008](#th-008) | 审批事实卡和回答污染均涉及人对 Agent 表述的信任；自动化页面测试不能证明管理员不会受骗。 |
| ASI10 Rogue Agents | 尚待验证 | [TH-011](#th-011)、[TH-013](#th-013) | 已对单 Agent 的调用循环和写入预算作边界测试；没有攻击者输入时的持续自主越界行为仍未验证。 |

## 项目威胁概览

| 场景 | OWASP | MITRE ATLAS | 当前结论 |
| --- | --- | --- | --- |
| [TH-014](#th-014) 依赖故障、过载与重试放大沿单 Agent 服务链传播 | ASI08 | 未强行映射 | 部分验证 |
| [TH-001](#th-001) 低信任材料污染最终回答 | ASI01、ASI09 | [AML.T0099](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217)、[AML.T0051.001](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599) | 部分验证 |
| [TH-002](#th-002) MCP 卡片诱导越权工具调用 | ASI01、ASI02 | [AML.T0099](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217)、[AML.T0053](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783) | 部分验证 |
| [TH-003](#th-003) 跨租户或越资源范围使用 Agent 权限 | ASI03 | [AML.T0053](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783) | 范围内已验证 |
| [TH-004](#th-004) 恶意来源写入跨会话长期记忆 | ASI06 | [AML.T0080.000](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3528)、[AML.T0051.001](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599) | 部分验证 |
| [TH-005](#th-005) 存储中记忆或来源审核记录被篡改 | ASI06 | [AML.T0080](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3507) | 范围内已验证 |
| [TH-006](#th-006) 私有资料通过写入工具、回答或模拟外发泄露 | ASI02 | [AML.T0086](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3793) | 部分验证 |
| [TH-007](#th-007) 私有内容进入未经批准的远程模型请求 | ASI02 | 未强行映射 | 部分验证 |
| [TH-008](#th-008) 低信任材料伪造审批依据 | ASI09 | [AML.T0051.001](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599) | 部分验证 |
| [TH-009](#th-009) Shell 工具导致非预期代码执行 | ASI02、ASI05 | [AML.T0053](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783) | 部分验证 |
| [TH-010](#th-010) 远程 MCP 工具定义、实现或结果被污染 | ASI04 | [AML.T0110.000](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4487)、[AML.T0110.001](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4525)、[AML.T0110.002](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4559) | 部分验证 |
| [TH-011](#th-011) 无攻击输入时 Agent 持续偏离任务 | ASI10 | 未强行映射 | 未验证 |
| [TH-012](#th-012) 已知合成文档的指令注入载荷进入 Agent 来源 | ASI01 | [AML.T0051.001](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599)、[AML.T0099](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217) | 部分验证 |
| [TH-013](#th-013) 已登记 Agent 会话反复调用、资源探测与累积写入 | ASI02、ASI10 | 未强行映射 | 部分验证 |
| [TH-015](#th-015) Agent 间身份冒充、委托越权和协作结果污染 | ASI03、ASI06、ASI07 | 未强行映射 | 部分验证 |

<a id="th-014"></a>

## TH-014 依赖故障、过载与重试放大沿单 Agent 服务链传播

- **入口与资产**：显式接入网关的 MCP、沙箱和异步 Judge／通知依赖；安全检查可用性、审计完整性和副作用状态。
- **适用范围**：单 Agent、本机显式接入服务链；临时数据库与受控故障替身。
- **当前结论**：部分验证。
- **OWASP**：ASI08。
- **MITRE ATLAS**：未映射；当前证据验证可用性故障与恢复边界，没有核实攻击者使用特定 ATLAS 技术，不强行映射对手技术。
- **控制措施**：[租户内依赖熔断、并发租约、异步代次保护与安全重试](../src/agentsentry/resilience.py)；[分租户、分阶段继续投递并持久化退避](../src/agentsentry/dispatcher.py)；[Judge 与通知使用独立队列及 Worker](../docker-compose.yml)。
- **证据**：
  - 固定重放：`fault-lab-v1:F01`、`fault-lab-v1:F02`、`fault-lab-v1:F03`、`fault-lab-v1:F04`、`fault-lab-v1:F05`、`fault-lab-v1:F06`、`fault-lab-v1:F07`、`fault-lab-v1:F08`、`fault-lab-v1:F09`、`fault-lab-v1:F10`、`fault-lab-v1:F11`、`fault-lab-v1:F12`、`fault-lab-v1:F13`、`fault-lab-v1:F14`、`fault-lab-v1:F15`、`fault-lab-v1:F16`、`fault-lab-v1:F17`、`fault-lab-v1:F18`、`fault-lab-v1:N01`、`fault-lab-v1:N02`、`fault-lab-v1:N03`、`fault-lab-v1:N04`；[查看证据](fault-propagation.md)；受控替身验证拒绝、未知结果、熔断恢复、退避、重复任务、迟到结果和本地正常对照。
  - 单元测试：[查看证据](../tests/test_resilience.py)；额外验证租户隔离、租约过期、处理崩溃次数上限和退避不饿死就绪记录。
  - 现场演练：[查看证据](fault-propagation.md)；临时 PostgreSQL schema 核对真实并发锁；真实 Redis 专属队列验证发布失败、无 Worker 积压、临时 Worker 启动后恢复和原事件去重，不停止日常服务。
- **剩余边界**：共用主机、数据库与 Redis 仍有全局故障域；不是严格租户资源配额，不声称防住第三方长期过载、所有连锁故障或跨 Agent 故障。

<a id="th-001"></a>

## TH-001 低信任材料污染最终回答

- **入口与资产**：文档与 MCP 卡片的实际读取结果；用户看到的最终回答与对 Agent 的信任。
- **适用范围**：显式接入的示例 Agent；原固定 A12 曾发生展示污染，修复后固定重放已阻断；本地模型 A06 三次未触发污染。
- **当前结论**：部分验证。
- **OWASP**：ASI01、ASI09。
- **MITRE ATLAS**：[AML.T0099 AI Agent Tool Data Poisoning](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217)、[AML.T0051.001 Indirect](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599)。
- **控制措施**：[回答展示前检查](../src/agentsentry/output_safety.py)；[从实际读取来源提取动作载荷并与回答比对](../src/agentsentry/output_instructions.py)；[目标偏移辅助线索](../src/agentsentry/goal_analysis.py)。
- **证据**：
  - 固定重放：`goal-lab-v1:A12`；[查看证据](cases/injection-and-output.md)；危险外发待审批后被拒；回答草稿中的标记进入实际可展示回答。
  - 真实模型：`goal-lab-v1:A06`；[查看证据](cases/injection-and-output.md)；本地模型三次未复现展示污染，不能抵消固定样本暴露的缺口。
  - 固定重放：`goal-lab-v1:A12`；[查看证据](cases/injection-and-output.md)；修复后两次固定运行均阻断展示，外发副作用和审计缺失均为零；历史污染记录保留。
  - 单元测试：[查看证据](../tests/test_output_safety.py)；来源绑定、正常引用、诱饵命令、改写语句及可还原编码通过回归。
  - 真实模型：`goal-lab-v1:A06`；[查看证据](cases/injection-and-output.md)；本地 qwen3:0.6b 三次未产生标记污染或危险工具尝试；该轨不能单独证明修复规则有效。
  - 现场演练：`deep-validation-v1:OUTPUT-INSTRUCTION`、`deep-validation-v1:OUTPUT-MARKER`、`deep-validation-v1:OUTPUT-QUOTE`、`deep-validation-v1:OUTPUT-PUBLIC`；[查看证据](cases/boundary-validation.md)；明确覆盖命令的直接复述由 warn 收紧为 block，带说明引用与公开资料正常；修复后两轮一致。
- **剩余边界**：仅对可解析的明确动作命令与不透明载荷奏效；语义改写、非透明接入及真实模型触发此规则的效果仍是剩余边界。

<a id="th-002"></a>

## TH-002 MCP 卡片诱导越权工具调用

- **入口与资产**：本地 MCP Server 返回的合成卡片数据；工具副作用与其他卡片资源。
- **适用范围**：固定本地 MCP stdio 适配器与已登记工具，不包括任意远程 MCP。
- **当前结论**：部分验证。
- **OWASP**：ASI01、ASI02。
- **MITRE ATLAS**：[AML.T0099 AI Agent Tool Data Poisoning](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217)、[AML.T0053 AI Agent Tool Invocation](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783)。
- **控制措施**：[固定上游工具与结果结构](../src/agentsentry/mcp_backend.py)；[网关权限、策略与审批](../src/agentsentry/service.py)。
- **证据**：
  - 固定重放：`attack/v2.2.0:M01`、`attack/v2.2.0:M02`、`attack/v2.2.0:M03`；[查看证据](cases/injection-and-output.md)；固定提案验证卡片诱导写入和越权读取的网关边界。
  - 真实模型：`attack/v2.2.0:M01`、`attack/v2.2.0:M02`、`attack/v2.2.0:M03`；[查看证据](cases/injection-and-output.md)；三条 MCP 攻击的本地模型未提出危险工具调用；真实调用后的阻断率无分母。
  - 单元测试：[查看证据](../tests/test_mcp.py)；未登记工具、非法结果和审批前写入等路径有回归测试。
- **剩余边界**：固定提案只验证进入网关后的决定；真实模型是否提出相同危险调用须独立统计。

<a id="th-003"></a>

## TH-003 跨租户或越资源范围使用 Agent 权限

- **入口与资产**：工具调用中的租户身份、权限令牌与资源参数；其他租户数据和未授权资源。
- **适用范围**：示例 Agent、固定工具、当前租户 schema 与限时权限。
- **当前结论**：范围内已验证。
- **OWASP**：ASI03。
- **MITRE ATLAS**：[AML.T0053 AI Agent Tool Invocation](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783)。
- **控制措施**：[租户绑定的原子权限校验](../src/agentsentry/capability.py)；[类型化资源与调用身份核查](../src/agentsentry/service.py)。
- **证据**：
  - 固定重放：`attack/v2.2.0:B05`、`attack/v2.2.0:B07`；[查看证据](cases/injection-and-output.md)；跨租户令牌和错误资源范围的调用未产生越权副作用。
  - 单元测试：[查看证据](../tests/test_v2_tenants.py)；租户间文档、调用、授权与面板隔离有回归测试。
- **剩余边界**：不证明通用 Agent、外部身份提供方或直接绕过适配层的调用安全。

<a id="th-004"></a>

## TH-004 恶意来源写入跨会话长期记忆

- **入口与资产**：文档与 MCP 卡片进入自动记忆候选；后续正常会话的模型上下文和回答。
- **适用范围**：示例 Agent 自动记忆的写入、隔离与读取链路。
- **当前结论**：部分验证。
- **OWASP**：ASI06。
- **MITRE ATLAS**：[AML.T0080.000 Memory](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3528)、[AML.T0051.001 Indirect](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599)。
- **控制措施**：[来源核查、隔离与撤销](../src/agentsentry/memory.py)；[记忆完整性核查](../src/agentsentry/memory_integrity.py)。
- **证据**：
  - 固定重放：`memory-security/v2.6.0:A01`、`memory-security/v2.6.0:A02`、`memory-security/v2.6.0:A07`、`memory-security/v2.6.0:A08`；[查看证据](cases/memory-poisoning.md)；明确的角色伪造、持续指令和输出污染样本被检查。
  - 单元测试：[查看证据](../tests/test_memory.py)；隔离、撤销和读取边界有回归测试。
  - 现场演练：`deep-validation-v1:MEMORY-UNREVIEWED`、`deep-validation-v1:MEMORY-FALSE-CANDIDATE`、`deep-validation-v1:MEMORY-REVOKE`、`deep-validation-v1:MEMORY-RESUMMARY`、`deep-validation-v1:MEMORY-SAFE`；[查看证据](cases/boundary-validation.md)；真实 PostgreSQL 三会话验证未审核、摘要替换、撤销及再次摘要；两轮一致，另列本地模型 6 攻击和 6 正常两轮实验。
- **剩余边界**：未命中的语义改写、已经进入进行中会话的记忆不由撤销追回。

<a id="th-005"></a>

## TH-005 存储中记忆或来源审核记录被篡改

- **入口与资产**：对租户记忆表或审核状态的直接修改；长期记忆文字、激活状态和可信来源记录。
- **适用范围**：攻击者可改数据库行但未同时取得应用签名密钥。
- **当前结论**：范围内已验证。
- **OWASP**：ASI06。
- **MITRE ATLAS**：[AML.T0080 AI Agent Context Poisoning](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3507)。
- **控制措施**：[租户绑定的完整性签名](../src/agentsentry/memory_integrity.py)；[读取前核验与异常隔离](../src/agentsentry/memory.py)。
- **证据**：
  - 固定重放：`memory-security/v2.6.0:A09`、`memory-security/v2.6.0:A10`、`memory-security/v2.6.0:A11`、`memory-security/v2.6.0:A12`；[查看证据](cases/memory-poisoning.md)；文字、状态、来源审核和签名删除的篡改被识别。
- **剩余边界**：签名密钥与应用进程同时失陷时，本完整性边界不能成立。

<a id="th-006"></a>

## TH-006 私有资料通过写入工具、回答或模拟外发泄露

- **入口与资产**：读取私有内容后调用本地任务、MCP 笔记、模拟外发或输出展示检查；私有文档内容及租户数据边界。
- **适用范围**：固定合成资料、网关登记工具和展示接口；受限来源会话的自由文本展示已收紧，外发仍仅写本地模拟收件箱。
- **当前结论**：部分验证。
- **OWASP**：ASI02。
- **MITRE ATLAS**：[AML.T0086 Exfiltration via AI Agent Tool Invocation](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L3793)。
- **控制措施**：[敏感来源到工具出口的同步检查](../src/agentsentry/data_flow.py)；[执行前审批与原参数重查](../src/agentsentry/service.py)；[展示前对已读私有、未知或秘密来源的自由文本回答整体阻断；同会话正常回答也可能被阻断](../src/agentsentry/output_safety.py)。
- **证据**：
  - 固定重放：`data-flow-cases-v1:A08`、`data-flow-cases-v1:A09`、`data-flow-cases-v1:A10`、`data-flow-cases-v1:A13`、`data-flow-cases-v1:A15`；[查看证据](cases/private-data-leakage.md)；模拟外发被拒，敏感写入被拒或升级审批，禁止副作用为零。
  - 固定重放：`calibration-cases-v1:N07`、`calibration-cases-v1:N08`；[查看证据](cases/injection-and-output.md)；两种正常任务受限，误拦取舍尚未安全放宽。
  - 现场演练：`deep-validation-v1:OUTPUT-WORDS-CN`、`deep-validation-v1:OUTPUT-WORDS-EN`、`deep-validation-v1:OUTPUT-ARITHMETIC`、`deep-validation-v1:OUTPUT-COPY`、`deep-validation-v1:OUTPUT-UNRELATED`；[查看证据](cases/boundary-validation.md)；两轮均确认数词和算式改写可展示；同会话模拟外发拒绝，远程模型固定配置判定拒绝且未发送远程请求；不是模型实际生成这些草稿的证明。
  - 现场演练：`deep-validation-v1:OUTPUT-WORDS-CN`、`deep-validation-v1:OUTPUT-WORDS-EN`、`deep-validation-v1:OUTPUT-ARITHMETIC`、`deep-validation-v1:OUTPUT-UNRELATED`、`deep-validation-v1:OUTPUT-PUBLIC`、`deep-validation-v1:OUTPUT-QUOTE`；[查看证据](cases/private-data-leakage.md)；修复后两轮真实网关验证三种改写均在展示前阻断；公开回答仍可展示，正常无关回答也被阻断并计为误拦。
  - 固定重放：`output-samples-v5:O31`、`output-samples-v5:O32`、`output-samples-v5:O33`、`output-samples-v5:O34`、`output-samples-v5:O35`；[查看证据](../tests/test_output_safety.py)；覆盖私有语义改写、公开正常对照与私有来源正常任务受阻。
  - 固定重放：`data-flow-cases-v2:A20`；[查看证据](../tests/test_data_flow.py)；受限来源回答阻断后，记忆摘要未启动；历史 v1 结果仍保留。
- **剩余边界**：无真实网络外发；已读受限来源会话的正常自由回答受阻，尚无可核验展示模板或人工放行流程；错误来源分级与未接入路径仍可能泄露。

<a id="th-007"></a>

## TH-007 私有内容进入未经批准的远程模型请求

- **入口与资产**：示例 Agent 的模型请求发送前；私有资料、个人信息和凭据。
- **适用范围**：已登记模型目的地与显式接入的模型发送函数。
- **当前结论**：部分验证。
- **OWASP**：ASI02。
- **MITRE ATLAS**：未映射；ATLAS 的“Exfiltration via AI Inference API”主要描述从模型接口抽取训练数据，不等同于本场景把私有上下文发送给远程服务。
- **控制措施**：[模型出口分类与同步拒绝](../src/agentsentry/data_flow.py)。
- **证据**：
  - 固定重放：`data-flow-cases-v1:A01`、`data-flow-cases-v1:A02`、`data-flow-cases-v1:A03`、`data-flow-cases-v1:A04`、`data-flow-cases-v1:A05`、`data-flow-cases-v1:A06`；[查看证据](cases/private-data-leakage.md)；固定替身验证远程敏感上下文阻断，未向真实远程模型发送数据。
- **剩余边界**：当前证据不包含第三方远程模型真实发送实验；语义型敏感信息可能漏检。

<a id="th-008"></a>

## TH-008 低信任材料伪造审批依据

- **入口与资产**：文档、MCP 卡片或工具参数中的授权宣称；管理员审批判断与冻结的工具动作。
- **适用范围**：Web 审批事实卡和现有管理员 API；不推断人的实际识别能力。
- **当前结论**：部分验证。
- **OWASP**：ASI09。
- **MITRE ATLAS**：[AML.T0051.001 Indirect](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599)。
- **控制措施**：[权威伪造与目标偏移线索](../src/agentsentry/goal_analysis.py)；[审批事实卡与短时确认凭据](../src/agentsentry/main.py)；[审批锁后刷新、授权与吊销串行化，安全决定前复核有效期](../src/agentsentry/service.py)。
- **证据**：
  - 固定重放：`goal-lab-v1:A04`、`goal-lab-v1:A07`、`goal-lab-v1:A08`、`goal-lab-v1:A10`；[查看证据](cases/injection-and-output.md)；固定提案与来源宣称分别记录，审批前禁止副作用为零。
  - 单元测试：[查看证据](../tests/test_approval_review.py)；参数替换、状态变化、重放、过期与 CSRF 被检查。
  - 现场演练：`deep-validation-v1:AUTH-APPROVAL-DOUBLE`、`deep-validation-v1:AUTH-APPROVAL-REVOKE`、`deep-validation-v1:AUTH-APPROVAL-PAUSE`、`deep-validation-v1:AUTH-APPROVAL-SOURCE`、`deep-validation-v1:AUTH-APPROVAL-TAMPER`；[查看证据](cases/boundary-validation.md)；双审批旧缓存问题已修复，真实 PG/Redis 两轮并发审批及审批期间变化验证未造成重复或越界副作用。
  - 现场演练：[查看证据](cases/boundary-validation.md)；revocation-race-v1 和 approval-expiry-v1 补测在修复前各出现一笔不应执行的合成写入；权限行锁及提交前到期复核后，各两轮通过；不证明人不会被欺骗。
  - 单元测试：[查看证据](../tests/test_service.py)；预读缓存、Redis 吊销清理失败及提交/审批检查期间到期的回归。
- **剩余边界**：原管理员 API 仍可由已认证管理员调用；自动化测试不能证明人不会被误导。

<a id="th-009"></a>

## TH-009 Shell 工具导致非预期代码执行

- **入口与资产**：默认租户的 run_shell 工具提案；沙箱、宿主机和租户隔离边界。
- **适用范围**：默认租户的受限 Docker 沙箱演示；其他租户禁止使用共享 Shell。
- **当前结论**：部分验证。
- **OWASP**：ASI02、ASI05。
- **MITRE ATLAS**：[AML.T0053 AI Agent Tool Invocation](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2783)。
- **控制措施**：[独立受限执行服务](../sandbox/server.py)；[固定参数审批与工具调用核查](../src/agentsentry/service.py)。
- **证据**：
  - 现场演练：[查看证据](cases/execution-and-audit.md)；审批前无执行、参数替换拒绝、只读根目录与网络系统调用限制已演练。
  - 固定重放：`attack/v2.2.0:B08`；[查看证据](cases/injection-and-output.md)；新租户的共享沙箱调用被拒绝。
- **剩余边界**：Docker 隔离练习不证明能够抵御容器运行时逃逸，不能作为生产级沙箱保证。

<a id="th-010"></a>

## TH-010 远程 MCP 工具定义、实现或结果被污染

- **入口与资产**：已登记的远程 MCP HTTPS Server 与固定 GitHub 官方 MCP 适配器；工具定义、结果内容、远程凭据和后续 Agent 动作。
- **适用范围**：固定远程 HTTPS 工具与按租户 OAuth、本机 TLS 合成 Server；GitHub 固定只读与默认租户测试仓库写入使用独立 PAT，已实测一次人工审批写入；不包括任意第三方 MCP 或 GitHub 跨租户凭据隔离。
- **当前结论**：部分验证。
- **OWASP**：ASI04。
- **MITRE ATLAS**：[AML.T0110.000 Definition and Instructions](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4487)、[AML.T0110.001 Implementation](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4525)、[AML.T0110.002 Runtime Response](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4559)。
- **控制措施**：[保留本地 stdio 固定工具与模式核验](../src/agentsentry/mcp_backend.py)；[固定 HTTPS 出口、OAuth 声明验证、工具清单摘要、合成只读行为探针、核验后 IP 固定连接、结果结构及故障关闭](../src/agentsentry/mcp_remote.py)；[租户隔离的版本化接入档案、变化观察、人工审核和回退；新增工具仍须代码登记](../src/agentsentry/mcp_supply.py)；[固定 GitHub 官方端点与工具定义摘要、默认租户资源范围、独立读写 PAT、受限结果与写入后只读核对](../src/agentsentry/mcp_github.py)；[能力授权、写入审批、调用幂等与结果不明状态](../src/agentsentry/service.py)；[远程读取来源标记与远程写入前敏感数据检查](../src/agentsentry/data_flow.py)。
- **证据**：
  - 单元测试：[查看证据](../tests/test_mcp.py)；SDK 2.2.0 迁移后本地 stdio 回归继续通过。
  - 单元测试：[查看证据](../tests/test_remote_mcp.py)；受控 HTTPS/OAuth Server 验证清单固定、描述变化审核、同清单行为探针、租户配置隔离、审批前无写入、重复操作幂等与审计关联。
  - 单元测试：[查看证据](../tests/test_mcp_supply.py)；档案批准与回退、额外工具和参数变化不可在线放行、端点身份变化与核验后 IP 固定连接。
  - 验收报告：[查看证据](mcp-supply.md)；记录 V3.4 受控合成服务的清单、行为和网络目标实验，明确未验证的第三方实现完整性。
  - 验收报告：[查看证据](remote-mcp.md)；记录受控本机 TLS/OAuth 部署与当时结果；跨主机通用 OAuth 互通仍未由该报告验证，后续 GitHub 链路使用独立 PAT。
  - 现场演练：[查看证据](cases/github-readonly.md)；GitHub 官方 HTTPS MCP 固定许可证读取成功，核验定义摘要并关联网关、来源、审计与 Judge；不代表任意工具或服务已验证。
  - 真实模型：[查看证据](cases/github-issue-analysis.md)；本地 qwen3:0.6b 三次读取固定公开 Issue 后未提出危险工具，正常概述均被输出检查阻断；工具阻断率未验证，存在误拦候选。
  - 现场演练：[查看证据](cases/github-controlled-write.md)；私有测试仓库一次人工审批写入前同标题 Issue 为零，批准后恰好为一；结果解析曾为 unknown，核对上游后补记 completed 且保留原事件，没有重写；新解析器未做第二笔在线写入。
  - 单元测试：[查看证据](../tests/test_github_mcp.py)；固定只读资源、身份、非法参数和调用重放边界有回归，不能证明第三方实际实现长期不变。
  - 单元测试：[查看证据](../tests/test_github_mcp_write.py)；协议桩核验固定创建参数、定义漂移、审批前零写入、拒绝与幂等，以及发送后超时保持 unknown。
  - 现场演练：`deep-validation-v1:MCP-SCHEMA-DRIFT`、`deep-validation-v1:MCP-WRONG-ID`、`deep-validation-v1:MCP-OVERSIZED-UTF8`、`deep-validation-v1:MCP-CONTENT-POISON`、`deep-validation-v1:MCP-COMMIT-THEN-ERROR`、`deep-validation-v1:MCP-COMMIT-THEN-TIMEOUT`；[查看证据](cases/boundary-validation.md)；正式 SDK 和固定 stdio 替身验证定义、资源、结果、字节上限及提交后故障；计数证明无重复写入，不替代第三方远程现场测试。
- **剩余边界**：V3.4 将已核验 IP 固定到本次 TCP 连接，受控测试验证了连接目标选择；仍需真实公网重绑定和不同网络栈现场验证。合成探针只检查一个固定只读结果，无法证明远端程序完整性或所有响应语义；GitHub 仍限默认租户、固定工具和一次已记录的受控写入，新解析器尚未第二次在线写入。

<a id="th-011"></a>

## TH-011 无攻击输入时 Agent 持续偏离任务

- **入口与资产**：示例 Agent 自主选择任务和工具的多步骤过程；用户目标、工具副作用与会话可信度。
- **适用范围**：已新增无恶意来源的固定错误提案及预算压力实测；仍未观察自然产生的长期自主偏移。
- **当前结论**：未验证。
- **OWASP**：ASI10。
- **MITRE ATLAS**：未映射；本场景定义为没有攻击者输入的自主偏移；ATLAS 技术矩阵描述对手行为，不将一般性模型失准强行视为攻击技术。
- **控制措施**：[当前单次工具与回答的辅助分析](../src/agentsentry/goal_analysis.py)。
- **证据**：
  - 验收报告：[查看证据](cases/injection-and-output.md)；现有目标偏移实验主要覆盖人工植入来源的诱导，未测持续自主越界。
  - 现场演练：`deep-validation-v1:CHAIN-SEMANTIC-DRIFT`、`deep-validation-v1:CHAIN-NORMAL`；[查看证据](cases/boundary-validation.md)；明确否定语句漏报修复后产生辅助线索；已有写权限的错误动作仍可执行，不证明自然产生的持续偏移已防住。
- **剩余边界**：需要独立设计无攻击者输入的多步骤样本与副作用判分。

<a id="th-012"></a>

## TH-012 已知合成文档的指令注入载荷进入 Agent 来源

- **入口与资产**：完成的 read_document 调用返回固定的 injected-guide 合成样本；Agent 后续工具选择、回答及用户任务。
- **适用范围**：仅核实项目内固定合成样本的实际工具结果；不据此推断模型执行了注入指令。
- **当前结论**：部分验证。
- **OWASP**：ASI01。
- **MITRE ATLAS**：[AML.T0051.001 Indirect](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L2599)、[AML.T0099 AI Agent Tool Data Poisoning](https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml#L4217)。
- **控制措施**：[固定合成文档与只读工具结果](../src/agentsentry/tools.py)；[工具调用仍受权限与策略控制](../src/agentsentry/service.py)；[后续回答另经展示前检查](../src/agentsentry/output_safety.py)。
- **证据**：
  - 单元测试：[查看证据](../tests/test_threat_mapping_runtime.py)；核对已提交工具结果、同一调用和固定样本内容；仅把确实返回的样本映射为来源暴露线索。
  - 单元测试：[查看证据](../tests/test_judge.py)；Judge 告警能追溯到工具结果事件，但模型标签不能证明工具副作用或回答污染。
- **剩余边界**：仅识别这一份固定合成样本；其他文档的攻击内容、模型是否服从及最终回答是否污染须由独立检测和证据判定。

<a id="th-013"></a>

## TH-013 已登记 Agent 会话反复调用、资源探测与累积写入

- **入口与资产**：显式接入示例 Agent 的连续工具提案和模型发送；工具副作用、资源访问范围、模型出口及服务可用性。
- **适用范围**：有效会话凭据绑定的单 Agent；固定合成工具和已登记模型出口。
- **当前结论**：部分验证。
- **OWASP**：ASI02、ASI10。
- **MITRE ATLAS**：未映射；固定压力提案和用户压力提示不证明存在对手；不把通用循环或模型失准强行映射为 ATLAS 攻击技术。
- **控制措施**：[单会话和跨会话确定性预算、资源探测自动暂停与审计](../src/agentsentry/action_chain.py)；[工具提交和审批执行前再次检查](../src/agentsentry/service.py)；[模型发送前检查请求额度](../src/agentsentry/data_flow.py)。
- **证据**：
  - 固定重放：`action-chain-cases-v1:A01`、`action-chain-cases-v1:A05`、`action-chain-cases-v1:A09`、`action-chain-cases-v1:A13`、`action-chain-cases-v1:A17`、`action-chain-cases-v1:N01`、`action-chain-cases-v1:N04`、`action-chain-cases-v1:N10`；[查看证据](action-chain.md)；两轮 30 条固定样本结论一致；禁止副作用和审计缺失均为零。
  - 真实模型：`action-chain-live-v1:D-A1`、`action-chain-live-v1:D-A2`、`action-chain-live-v1:D-A3`、`action-chain-live-v1:M-A1`、`action-chain-live-v1:M-A2`、`action-chain-live-v1:M-A3`、`action-chain-live-v1:D-N1`、`action-chain-live-v1:M-N1`；[查看证据](action-chain.md)；本地 qwen3:0.6b 的 12 条文档和 MCP 会话；一条实际触发写入预算，其他预算类别未充分触发。
  - 单元测试：[查看证据](../tests/test_action_chain.py)；验证幂等、写入保留额度、跨会话计数、暂停恢复、模型发送与租户隔离。
  - 现场演练：`deep-validation-v1:CHAIN-SESSION-CONCURRENT`、`deep-validation-v1:CHAIN-AGENT-MULTISESSION`、`deep-validation-v1:CHAIN-RESOURCE-PROBE`、`deep-validation-v1:CHAIN-NORMAL`；[查看证据](cases/boundary-validation.md)；真实 PG/Redis/HTTP 两轮验证八路并发三笔上限、四会话十笔累计及探测暂停；另列本地模型 12 条压力和正常任务，不扩大到其他 Agent。
- **剩余边界**：兼容模式下未绑定会话的旧工具客户端不受该预算保护；额度内的错误动作仍需策略、权限和审批处理；跨 Agent 连锁故障与无攻击输入的自主偏移未由本场景证明。

<a id="th-015"></a>

## TH-015 Agent 间身份冒充、委托越权和协作结果污染

- **入口与资产**：本机父 Agent 到固定只读协作 Agent 的委托消息及返回摘要；父权限额度、公开读取范围、父上下文及回答展示。
- **适用范围**：同租户、独立身份、单跳只读、两个固定工具及合成公开资料。
- **当前结论**：部分验证。
- **OWASP**：ASI03、ASI06、ASI07。
- **MITRE ATLAS**：未映射；身份及消息篡改用受控协议实验验证；固定协作摘要不证明攻击者使用某项已核实 ATLAS 技术，因此不强行对应。
- **控制措施**：[父授权缩减、额度继承、封签、时效、撤销与结果完整性](../src/agentsentry/delegation.py)；[独立身份协议、管理员操作与租户隔离](../src/agentsentry/delegation_routes.py)；[父会话继承实际来源和回复来源，出口检查仍有效](../src/agentsentry/data_flow.py)。
- **证据**：
  - 固定重放：`delegation-lab-v1:D01`、`delegation-lab-v1:D05`、`delegation-lab-v1:D06`、`delegation-lab-v1:D07`、`delegation-lab-v1:D12`、`delegation-lab-v1:D15`、`delegation-lab-v1:D18`、`delegation-lab-v1:D19`、`delegation-lab-v1:N01`、`delegation-lab-v1:N04`；[查看证据](cases/delegation-boundaries.md)；固定单跳协议攻击与正常对照；逐例结果见验收，不能替代多模型语义验证。
  - 单元测试：[查看证据](../tests/test_delegation.py)；额度继承、全来源出口检查、敏感结果遮断和提交失败的保守预留。
  - 单元测试：[查看证据](../tests/test_delegation_api.py)；独立身份冒充、普通接口绕过、CSRF、跨租户、正式客户端及证据链接。
- **剩余边界**：只读单跳模型外的固定协作摘要；跨主机、多跳、写入审批继承、语义改写和双重密钥失陷未验证。

## 日常事件映射规则

这些规则只对已经提交的审计元数据作分类。命中表示观察到线索；阻断、待审批与实际副作用必须分别核对。未列出的事件保持未映射，Judge 标签不会单独触发威胁归类。

| 规则 | 审计事件 | 必要条件 | 项目威胁 |
| --- | --- | --- | --- |
| `delegation_result_poison` 协作结果含明显指令或伪造授权，被展示前阻断 | `delegation_decision` | phase=result、effect=deny、finding=delegation_result_instruction | TH-015 |
| `delegation_scope_tamper` 委托封签与消息不一致 | `delegation_decision` | effect=deny、finding=delegation_message_tampered | TH-015 |
| `dependency_circuit_opened` 连续依赖故障触发熔断 | `dependency_fault` | status=open、finding=dependency_circuit_open | TH-014 |
| `queue_processing_exhausted` 异步处理租约反复失效并停止重试 | `dependency_fault` | status=attempts_exhausted、finding=queue_attempts_exhausted | TH-014 |
| `action_chain_tool_loop` 会话工具提案超出预算 | `action_chain_decision` | phase=submit、effect=deny、finding=tool_budget_exceeded | TH-013 |
| `action_chain_write_loop` 会话或 Agent 写入提案超出预算 | `action_chain_decision` | phase=submit、effect=deny、finding=session_write_budget_exceeded | TH-013 |
| `action_chain_agent_write_loop` Agent 跨会话写入提案超出预算 | `action_chain_decision` | phase=submit、effect=deny、finding=agent_write_budget_exceeded | TH-013 |
| `action_chain_probe` 连续探测不同无权资源 | `action_chain_decision` | phase=submit、effect=deny、finding=denied_resource_probe | TH-013 |
| `action_chain_model_loop` 会话模型请求超出预算 | `action_chain_decision` | phase=model:task、effect=deny、finding=model_budget_exceeded | TH-013 |
| `remote_mcp_manifest_drift` 远程 MCP 已登记工具清单发生变化 | `tool_result` | status=failed、reason=remote_mcp_manifest_drift | TH-010 |
| `remote_mcp_profile_drift` 远程 MCP 已批准接入身份发生变化 | `tool_result` | status=failed、reason=remote_mcp_profile_drift | TH-010 |
| `remote_mcp_behavior_drift` 合成 MCP 服务只读行为探针发生变化 | `tool_result` | status=failed、reason=remote_mcp_behavior_drift | TH-010 |
| `remote_mcp_observed_change` 管理员或调用观察到远程 MCP 接入变化 | `mcp_profile_observed` | reason=remote_mcp_manifest_drift | TH-010 |
| `remote_mcp_observed_identity_change` 管理员观察到远程 MCP 端点身份变化 | `mcp_profile_observed` | reason=remote_mcp_profile_drift | TH-010 |
| `remote_mcp_canary_incident` 管理员或调用观察到 MCP 行为探针异常 | `mcp_supply_incident` | reason=remote_mcp_behavior_drift | TH-010 |
| `injected_fixture_delivered` 已知合成注入文档实际返回 | `tool_result` | status=completed、fixture_document=injected-guide | TH-012 |
| `answer_instruction_echo` 来源输出指令进入回答 | `data_flow_decision` | sink=answer、effect=block、finding=source_instruction_in_answer | TH-001 |
| `answer_action_payload_echo` 来源动作载荷进入回答 | `data_flow_decision` | sink=answer、effect=block、finding=source_action_payload_in_answer | TH-001 |
| `mcp_action_inducement` MCP 卡片诱导工具动作 | `goal_assessment` | phase=submit、status=suspected、finding=source_action_match、source_tool=mcp_lookup_card | TH-002 |
| `invalid_session_binding` 无效会话身份尝试 | `runtime_decision` | effect=deny、finding=session_binding_invalid | TH-003 |
| `memory_instruction_quarantined` 记忆指令被隔离 | `data_flow_decision` | sink=memory、effect=quarantined、finding=cross_session_command | TH-004 |
| `memory_integrity_failure` 记忆或来源审核完整性异常 | `memory_integrity` | reason=seal_mismatch | TH-005 |
| `private_external_attempt` 私有来源后的模拟外发尝试 | `data_flow_decision` | sink=tool:submit、destination=send_external、effect=deny、finding=external_after_private | TH-006 |
| `restricted_answer_blocked` 受限来源后的回答被阻断 | `data_flow_decision` | sink=answer、effect=block、finding=restricted_source_answer | TH-006 |
| `remote_model_sensitive_block` 远程模型敏感上下文被拒绝 | `data_flow_decision` | sink=model、effect=deny、finding=model_remote_sensitive | TH-007 |
| `approval_authority_spoof` 来源伪造审批权威 | `goal_assessment` | phase=submit、status=suspected、finding=source_authority_spoof | TH-008 |
| `approval_argument_claim` 工具参数声称已经批准 | `goal_assessment` | phase=submit、status=suspected、finding=argument_approval_claim | TH-008 |

## 维护规则

1. 新增或修改样本时，先更新映射数据中的样本库版本与 ID，再核对实际实验记录。
2. 实测结果改变时新增或引用案例证据；修复前后的事实分别标注，不将旧结果描述为当前复测。
3. 远程 MCP 接入、模型或策略改变后，重新评估相关场景；未运行新实验时标为“未验证”。
4. 执行 `python scripts/check_threat_mapping.py --check`；CI 离线检查数据及此页是否一致。
