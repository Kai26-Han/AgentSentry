# 05 沙箱与 MCP 执行边界

[中文](#) · [English](../en/learning/05-execution-boundaries.md)

[手册首页](README.md) · 上一章：[审批](04-approval-safety.md) · 下一章：[输入与输出安全](06-input-output-safety.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

## 学习目标

- 区分“允许执行”和“限制执行环境”。
- 解释 MCP 固定登记、工具清单核验和类型化结果。
- 正确处理上游请求发出前失败与发出后结果不明。

## 单元一：沙箱限制获准动作的影响

Shell 即使有授权和批准，也可能访问文件、网络或消耗资源。因此网关之外需要受限执行环境。当前 `run_shell` 只供默认租户演示，经过授权、审批、会话和其他检查后，发给独立 Docker sandbox 服务。

```text
工具授权与审批 → 网关执行前复核 → 受限沙箱执行 → 结果或 unknown
                                     ├─ 只读根文件系统与有限可写空间
                                     ├─ 丢弃能力、禁止新增权限
                                     └─ 进程、内存、网络与执行时间限制
```

查看 [docker-compose.yml](../../docker-compose.yml)、[sandbox 入口](../../sandbox/server.py)、[工具执行](../../src/agentsentry/tools.py)和[现场演练脚本](../../scripts/sandbox_drill.py)。这里的 Compose 内部网络、应用限制和容器资源配置共同形成边界，不等于内核级容器逃逸被排除，也不是每租户独立执行平台。

**入门观察**：阅读[沙箱现场历史报告](../cases/execution-and-audit.md)，把只读根、网络访问、宿主挂载和超时分别对应到脚本断言。报告是 2026-09-27 的现场证据，不能记成今天重跑通过。

**当前现场入口**：2026-10-01 已将 `scripts/sandbox_drill.py` 改为先上报独立会话并附 `X-Runtime-Session`，随后申请固定合成动作，等待你在事实卡批准或拒绝。`--phase prepare` 不自动批准；决定后 `--phase verify --record ...` 核对写入次数、重放并清理本轮标记及授权。待审批、执行中或 unknown 不伪造完成、不自动重做。

`--phase isolation` 从 Web 容器直连沙箱执行固定探针，只能证明指定执行限制，不能证明网关授权或不存在逃逸。完整个人实操须分别完成网关链与探针；步骤见[个人验收 S02](personal-assessment.md#第二层本机证据链实操)。历史报告保持原样，新的人工审批链未执行时仍标待完成。

## 单元二：MCP 是协议接入，不是执行沙箱

```text
同一个 Agent → MCP stdio 入口适配器 → HTTP 安全网关
                                        ↓ 提交安全决定之后
                              固定本地 MCP Server / 已登记远程 Server
```

入口只展示项目登记的定义，不把上游新增工具／描述直接交给模型。本地 Server 是网关启动的固定子进程，处理租户专属合成笔记存储。远程 HTTPS／OAuth 接入核验地址、凭据范围和批准的工具清单；V3.4 增加租户接入档案、变化审核、合成只读行为探针和已核验 IP 的连接固定。GitHub 使用单独的固定工具与 PAT 路径，仍未进入合成端点的档案审核流程。

本地 MCP 子进程不是受限 Shell 沙箱。内容即使经过协议和结构校验，也仍是低信任数据，须接受输出、记忆和敏感数据流检查。

## 动手实验：正常协议调用与上游变化

**环境**：本机合成测试；本地 stdio 子进程和临时演示存储。部分远程 MCP 测试启动临时本机 HTTPS／OAuth Server，需要允许监听回环端口；其余使用响应替身，不访问真实第三方。不会向 GitHub 写入，不进入运行中 Web。

```bash
.venv/bin/python -m pytest -q tests/test_mcp.py tests/test_remote_mcp.py tests/test_mcp_supply.py tests/test_github_mcp.py tests/test_github_mcp_write.py
```

| 单元 | 正常对照 | 攻击／故障边界 |
| --- | --- | --- |
| 本地 MCP | 官方客户端 list／call，审批后写入一次 | 审批前计数为 0，同 call_id 不重复；结果异常不自动重发 |
| 远程 MCP | 固定清单、档案与结果通过核验 | 地址违规、增加工具、结构或行为探针漂移被拒；发出后不明保留 unknown |
| GitHub 固定工具 | 精确资源与批准写入的模拟响应 | 清单、仓库、Issue 身份不符，确认或批准不足，均不越界 |

在[本地测试](../../tests/test_mcp.py)看上游执行次数和无效提案的拦截；在[远程测试](../../tests/test_remote_mcp.py)看清单漂移及失败阶段；在[GitHub 写入测试](../../tests/test_github_mcp_write.py)看冻结审批和只读对账约束。第三方响应替身测试不能当成第三方现场实测。

### 结果状态为什么重要

| 状态 | 实际含义 | 下一步 |
| --- | --- | --- |
| failed（发送前） | 能确认尚未向上游派发 | 查看连接／配置故障，处理后重新提出动作 |
| unknown（发送后） | 上游可能执行，但没有足够结果证据 | 查询原 call_id，独立只读核对上游；不要换 ID 自动重做 |
| completed | 获得并记录经核验的结果 | 仍按来源和保密规则使用内容 |

本地 Server 对 operation_id 有去重约束，不表示任意第三方 Server 都有同样保障。

## 可选现场证据与局限

[本地 MCP 演示](../local-mcp.md)和[实验索引 E05](experiment-index.md#e05-本地-mcp-人工审批)可观察真实网关记录。[GitHub 只读](../cases/github-readonly.md)、[公开 Issue 实验](../cases/github-issue-analysis.md)、[人工审批写入](../cases/github-controlled-write.md)是已有特定路径的现场证据。一次连通和一次写入不能证明供应链安全；第三方内部实现变化、持续漂移和通用 OAuth 仍有边界，TH-010 保持部分验证。

## 自检

1. MCP 协议校验是否能消除卡片注入？**不能，内容依然低信任**。
2. 沙箱被批准是否允许扩大资源范围？**不能，授权和执行隔离各管一层**。
3. 超时后新 call_id 重试为何危险？**旧动作可能已执行，造成重复副作用**。

深入阅读：[远程 MCP](../remote-mcp.md)、[供应链变更检测](../mcp-supply.md)、[威胁矩阵 TH-009／TH-010](../threat-framework-mapping.md)。
