# 14 故障传播、熔断与恢复

[中文](#) · [English](../en/learning/14-fault-propagation.md)

[手册首页](README.md) · 上一章：[规则校准](13-validation-calibration.md) · 下一章：[委托安全](15-delegation.md)

> 开始前：按[手册环境约定](README.md#前置条件与命令约定)安装依赖并选择离线／在线终端。先预测，再运行；仅执行临时合成数据实验。在线扩展另需服务、专用租户与有效凭据。

学习目标：解释依赖失败为何会成为安全问题，区分哪些操作可以重试，哪些操作必须先核对副作用。

## 先理解边界

一个 MCP 服务变慢，会占用网关的执行资源；持续重试会加重压力。通知接收器变慢若和 Judge 共用执行槽，还会延迟风险信号。更严重的错误是授权存储故障后默认放行，或者把写入超时当作“没有执行”再写一次。

项目的安全要求是：关键检查失败就不放行新动作；非关键分析与通知故障可退避；结果不明保留 unknown。熔断只暂时停止依赖请求，恢复后仍必须满足原权限、策略、审批和来源检查。

## 实验与证据

```bash
.venv/bin/python -m agentsentry.fault_lab --output /tmp/agentsentry-learning-fault.json
.venv/bin/python -m pytest -q tests/test_resilience.py
```

先观察正常对照 N02：远程依赖熔断后，本地公开资料读取仍能完成。再观察 F01 与 F02：权限存储和安全决定提交故障时，执行次数为零。F03 中请求可能已写入，后续重复原 ID 只返回 unknown，不能自动执行第二次。

| 对照 | 观察事实 | 预期 |
| --- | --- | --- |
| N02 远程依赖熔断 | 本地公开读取及执行计数 | 正常读取仍可完成 |
| F01／F02 关键检查故障 | 权限与决定提交、工具执行计数 | 不放行，执行次数 0 |
| F03 派发后结果不明 | 原调用状态、重试次数 | unknown，不重复写入 |

F04～F09 检查熔断、半开和并发槽。F10～F16 检查 Broker 退避、重复处理与旧代次。样本在临时库执行，不影响日常服务。需要 Web 记录时，在运行中的容器执行 `docker compose exec -T web python -m agentsentry.fault_lab --persist`，摘要报告进入配置数据库，在“系统与演示数据 → 故障隔离与恢复”查看；临时调用 ID 不能用作日常详情链接。

真正的并发锁保证需在 PostgreSQL 上验证。服务运行后，在项目根目录执行 `docker compose exec -T web python scripts/check_resilience_postgres.py` 创建独立临时 schema，四并发请求检验两个名额、半开仅一个探测、重复分析仅一个结果；最后删除该 schema。它不调用真实 MCP 或云端 Judge，也不停止数据库与 Redis。

`scripts/check_resilience_queue.py` 进一步使用真实 Redis 的专属队列及临时 Worker，核对发布失败后原事件仍在、无 Worker 时积压、启动后恢复。Compose 中运行 `docker compose exec -T web python scripts/check_resilience_queue.py`；不要为练习停止日常 Redis 或 Worker。

## 代码入口与限制

| 入口 | 观察内容 |
|---|---|
| [resilience.py](../../src/agentsentry/resilience.py) | 租户锁、熔断状态、租约、代次、重试范围 |
| [service.py](../../src/agentsentry/service.py) | 先提交决定与租约，再执行；unknown 不自动重试 |
| [dispatcher.py](../../src/agentsentry/dispatcher.py) | 有限批次、持久化退避、各租户及各阶段独立继续 |
| [worker.py](../../src/agentsentry/judge/worker.py) | 原路由、旧代次不能提交、错误只存类别 |
| [专题验收](../fault-propagation.md) | 实测环境、具体阈值与未覆盖范围 |

目前共用数据库、Redis、主机和 Judge Worker，不能据此宣称严格的租户资源配额。通知按至少一次方式发送，接收方需要自行去重。固定替身通过不表示所有分布式故障组合都已解决。

## 自检

1. 为什么 Judge 不可用仍能完成普通读取，而权限 Redis 不可用不能放行？
2. 为什么不能用新 call_id 重试超时的写入？
3. 熔断恢复是否意味着权限、审批和工具定义检查可以跳过？
4. 处理代次能防止数据库旧结果覆盖，为什么不能保证 Webhook 只到达一次？
5. 如何证明两个并发槽真的跨进程有效？SQLite 的串行实验有什么局限？

完成标准：运行一个正常对照和一个故障样本，核对执行次数与审计，并指出至少一个仍共用的故障域。
