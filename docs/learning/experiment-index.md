# 学习实验索引

[中文](#) · [English](../en/learning/experiment-index.md)

> 本索引列出可复现入口，不表示你已经执行。开始前按[环境约定](README.md#前置条件与命令约定)区分离线与在线终端；首次运行优先选择离线实验。

[手册首页](README.md) · [术语表](glossary.md) · [进阶安全案例](../cases/README.md)

> 命令入口更新至 V3.6，日期 2026-10-01。命令索引不代表现场已经执行，个人验收见[指南](personal-assessment.md)。

## 先选择环境，再运行

| 编号 | 主题与命令入口 | 环境／结果 | 副作用与收尾 |
| --- | --- | --- | --- |
| E01 | [信任边界](01-security-boundaries.md)：服务正常与 commit 故障测试 | 临时 DB／终端 | 合成任务，pytest 清临时目录；无 Web 数据 |
| E02 | [身份与权限](02-identity-capabilities.md)：服务与租户测试 | 临时 DB、Redis 替身、测试客户端 | 临时身份和策略；不改业务租户 |
| E03 | [策略](03-tool-policy.md)：policy_tests、幂等与热更新测试 | 本地 YAML、临时文件／终端 | 候选策略只在临时文件；不发布运行中规则 |
| E04 | [审批](04-approval-safety.md)：服务与 Web 事实卡测试 | 临时 DB／终端 | 测试批准合成模拟消息；无真实外发 |
| E05 | [本地 MCP 人工审批](#e05-本地-mcp-人工审批) | 在线专用租户／调用、审批与审计 Web | 签发授权、合成笔记；未决动作由所属管理员拒绝 |
| E06 | [沙箱](#e06-沙箱执行边界与人工审批) | 当前会话绑定、人工审批与固定隔离探针 | prepare 不自动批准；verify 核对后清理，unknown 不自动重做 |
| E07 | [输出](06-input-output-safety.md)：output_samples 与测试 | 规则函数／终端 | 不发送模型消息；不进入 Web |
| E08 | [跨会话记忆](07-memory-security.md)：测试或 memory_lab_runner | 离线临时库；在线研究租户／Web | 在线安装材料、写入、读取、撤销或清文字；复用租户不得存日常记忆 |
| E09 | [记忆存储安全](#e09-研究租户的记忆存储安全) | 现有研究租户／存储安全实验 Web | 直接改合成记忆／审核记录，结束清合成文字；不得指向日常租户 |
| E10 | [数据流](08-sensitive-data-flow.md)：data_flow_lab 与测试 | 临时库、发送计数替身／JSON | 不访问真实模型，不出现在 Web |
| E11 | [运行时](09-runtime-defense.md)：runtime_lab；可选 runtime_smoke | 临时库／JSON；在线 Runtime Lab／Web | 在线有暂停与审批复核，成功时恢复；异常后复核残留 |
| E12 | [目标偏移](10-goal-drift.md)：测试、goal_lab_runner | 临时库；在线每轮新研究租户／JSON 与 Web | scripted 两个新租户；live 一个；合成调用，不自动批准攻击 |
| E13 | [行动链](11-action-chain.md)：action_chain_lab／live | 临时库两轮／JSON；live 新研究租户／Web | 合法合成任务占额度，待审批攻击被拒；不直接改阈值 |
| E14 | [审计与 Judge](12-audit-judge-mapping.md)：替身测试与映射 check | 临时库／终端 | 不直连云 Judge、Webhook；不重新分类历史业务事件 |
| E15 | [校准](13-validation-calibration.md)：离线 eval、测试、在线两轮 compare | 临时库；在线每次新租户／JSON 与 Web | compare 只读报告；不自动修改／发布规则 |
| E16 | [第三方证据阅读](#e16-第三方现场证据阅读) | 既有专项报告 | 只阅读；新实测须另行配置与授权 |
| E17 | [故障隔离](14-fault-propagation.md)：fault_lab、PG／队列扩展 | 临时库；在线临时 schema／专属队列 | 不停止日常服务；专属 Worker、队列和 schema 收尾清理 |
| E18 | [单跳委托](15-delegation.md)：delegation_lab、双进程演示 | 临时库；在线独立研究身份／Web | 只读合成数据；现场身份停止后停用，残留授权吊销 |

离线报告默认示例使用 `/tmp/agentsentry-learning-*.json`，避免覆盖 `.local/` 历史结果。临时目录可能由操作系统清理，需保留时只复制合成报告和脱敏结论，**不复制凭据文件**。用新的文件名保存后续轮次，避免报告被覆盖。

## E05 本地 MCP 人工审批

**前置**：Compose 网关、Redis、PostgreSQL 正常；已创建专用演示租户；你持有它的管理员密码和 Agent 密钥；本机 `.env` 中共享 SESSION_SECRET 与网关一致。实验只读／写本地合成存储，不使用第三方 MCP。

在在线终端设置以下占位符的实际值，不写进文档或聊天：

```bash
export SENTRY_URL='http://127.0.0.1:8000'
export TENANT_ADMIN_PASSWORD='替换为演示租户管理员密码'
export TENANT_AGENT_API_KEY='替换为演示租户 Agent 密钥'
.venv/bin/python scripts/enable_mcp_policy.py --tenant '替换为演示租户ID'
```

最后一条只预览政策补充。若缺少本地 MCP 规则，经你核对后显式执行同命令加 `--apply`，只改变该演示租户策略；已有租户不会自动放行。

正常读取和审批写入分别运行：

```bash
.venv/bin/python scripts/mcp_demo.py --tenant '替换为演示租户ID'
.venv/bin/python scripts/mcp_demo.py --tenant '替换为演示租户ID' --write
```

1. 正常读取输出真实 call_id，用该租户管理员打开“工具调用与审计”。
2. 写入返回待审批时，用该租户身份在“审批”查看固定 `demo-notes` 资源、note_id 和合成 text。
3. 先保持待审批；上游计数为 0 的自动证明见 `tests/test_mcp.py`，页面 pending 本身不是副作用计数。
4. 需要完成正常写入对照时，管理员核对原参数后按事实卡批准；拒绝对照则直接拒绝。脚本不会替管理员批准。
5. 观察原调用状态及审计、Outbox；批准留下合成笔记，保留作为学习证据，不代表自动删除。

脚本最长等待约十分钟；终端取消不会自动取消网关审批。若中断，登录所属租户检查并拒绝残留申请。默认管理员研究详情只读访问不代替该租户写操作身份。纯新演示租户不一定属于 Attack Lab 选择器，直接使用其登录身份。

## E06 沙箱执行边界与人工审批

阅读 [执行与审计案例](../cases/execution-and-audit.md)、[sandbox_drill.py](../../scripts/sandbox_drill.py)、[server.py](../../sandbox/server.py)、[exec.py](../../sandbox/exec.py)与 [Compose](../../docker-compose.yml)。对应正常打印、审批前文件不存在、禁止根写、socket 拒绝、宿主挂载不存在和超时断言。

当前脚本已改为 `learning-sandbox-v2`，建立独立会话并附绑定。默认租户新申请一笔固定合成动作；不修改正式策略、不自动批准。命令如下：

```bash
.venv/bin/python scripts/sandbox_drill.py --phase prepare
# 按终端事实卡链接核对并批准／拒绝；用本轮实际 private.json 路径替换占位符：
.venv/bin/python scripts/sandbox_drill.py --phase verify --record '.local/learning-sandbox/替换为本轮UUID.private.json' --report /tmp/learning-sandbox-verify.json
.venv/bin/python scripts/sandbox_drill.py --phase isolation --report /tmp/learning-sandbox-isolation.json
```

审批最长十分钟；prepare 返回不表示动作已经执行，终端退出不取消审批。verify 遇到 pending、executing、unknown 标无法判定，不重做；终止状态时核对并清临时标记、结束会话、吊销本轮授权、删除有限期凭据文件。异常后在所属租户核对未决审批。isolation 从 Web 容器直连内部沙箱，仅检指定执行限制。自己的本轮网关审批链未完成前不能称现场通过。

第 05 章的离线 MCP／远程测试覆盖执行派发与结果边界，不能代替 Docker 逃逸、seccomp 或当前沙箱现场验收。

## E09 研究租户的记忆存储安全

**先完成**在线 `memory_lab_runner --mode scripted`，确保 `.local/attack-lab.json` 对应研究租户已创建、策略和材料就绪。研究文件含凭据，只在本机读其中 `lab.tenant_id`，不要输出整个文件。

把 ID 填入下列命令：

```bash
docker compose exec -T web python -m agentsentry.memory_security_lab --tenant '替换为Attack Lab研究租户ID'
```

运行器只接受现有 Attack Lab 研究租户，版本 `v2.6.0`，12 攻击／6 正常；其中 A09～A12 直接改数据库里的合成记忆或来源审核，检查读取时不返回篡改内容。它修改实际研究存储，结束清合成记忆文字，保留实验元数据；中断需查看该研究租户残留。不要手工扩展为任意 SQL 或日常租户改写。

Web “记忆安全 → 记忆实验 → 存储安全”查看结果。合成来源有专用详情，预置的读取证据不等于实际 MCP 调用，因此没有普通调用的 Judge／Outbox 链。第二轮未返回记忆也不自动证明真实模型回答没污染。

## E16 第三方现场证据阅读

| 报告 | 学习任务 | 结论边界 |
| --- | --- | --- |
| [GitHub 只读](../cases/github-readonly.md) | 找固定资源、工具定义、凭据范围、输出核验 | 特定只读工具连通，不证明所有 GitHub 工具 |
| [公开 Issue 真实模型](../cases/github-issue-analysis.md) | 区分公开材料、模型危险尝试和正常误拦 | 未提出危险工具则阻断率未验证 |
| [受控写入](../cases/github-controlled-write.md) | 找审批前 0、批准后 1、原 unknown 与只读对账 | 一次已批准 Issue；对账不能伪造旧结果或重写第二次 |

真实 GitHub 写入有外部持久副作用、独立写 PAT 和指定测试仓库，必须在具体参数经管理员核对后进行。学习手册不运行已有写脚本，不为练习自动创建第二个 Issue。

## 常见问题定位

| 现象 | 先检查什么 |
| --- | --- |
| 命令通过但 Web 无数据 | 是否为临时 DB／规则函数；是否选对数据租户 |
| 点 call_id 显示 not found | 是否来自临时库、合成来源专页或其他研究租户；不要拼造普通链接 |
| 日常目标偏移列表为空 | 实验记录属于新研究租户；未评估旧会话不会回填 |
| 真实模型无法连接 | 服务是否启动、模型是否存在、Agent 与网关目的地是否一致 |
| 模型请求被拒 | 查来源级别、消息中凭据、目的地登记、绑定和审计提交，不绕过预检 |
| 正常样本 pending | 可能是保守升级审批；不是任务已经完成，不自动批准攻击 |
| Judge 尚无结果 | Outbox 路由、积压、失败和事件是否本来就不进入 Judge |
| 比较报告失败 | 模式、样本哈希、逐例键和完成状态是否相容 |
| 远程 MCP 测试报 bind PermissionError | 当前执行环境是否允许临时监听 127.0.0.1；这是测试服务无法启动，不是防护断言失败 |

没有证据时写“未验证／无法判定”，不根据页面为空推断没有攻击或测试未做。

## 故障隔离实验

`python -m agentsentry.fault_lab` 在临时 SQLite 与受控替身中运行 22 条故障／正常样本；在线保存使用 `docker compose exec -T web python -m agentsentry.fault_lab --persist`；只有 `--persist` 才保存到配置数据库。查看“系统与演示数据 → 故障隔离与恢复”。实验不关闭日常服务，不请求真实第三方。PostgreSQL 并发锁验证在 Compose 中使用 `docker compose exec -T web python scripts/check_resilience_postgres.py`，临时 schema 在结束后清除。见[第 14 章](14-fault-propagation.md)。


## 单跳委托实验

`python -m agentsentry.delegation_lab` 运行 26 条隔离样本；在线用 `docker compose exec -T web python -m agentsentry.delegation_lab --persist` 保存摘要，查看“运行分析 → Agent 安全委托”。正式双进程演示使用现有 `agentsentry-demo --scenario delegation` 和独立 `agentsentry-reader`，仅公开合成读取。PG／Redis 并发验证脚本创建并清除独立 schema；HTTP 现场脚本新增独立研究租户、读取和阻断证据，不写 GitHub。详见[第 15 章](15-delegation.md)及[委托案例](../cases/delegation-boundaries.md)。
