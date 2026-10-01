# 11 · Session action chains and action budgets

[English](#) · [中文](../../learning/11-action-chain.md)

## The security question

An Agent may loop or probe resources while each request appears individually plausible. The gateway limits cumulative actions using committed tenant, Agent and session records. This is a deterministic budget, not semantic understanding of the user’s goal.

Current version: `action-chain-v1`.

| Budget | Limit | Boundary |
| --- | --- | --- |
| Tool proposals per session | 20 | Proposal 21 denied |
| Task-model send checks per session | 8 | Check 9 denied |
| Memory-summary send checks per session | 3 | Check 4 denied |
| Write proposals per session | 3 | Pending, executing, unknown and completed writes consume budget |
| Agent writes across sessions | 10 in a rolling hour | Tenant/Agent transaction serialization |
| Different denied resources | Fourth within ten minutes in one session | Session paused for review |

An identical tool `call_id` or model request ID is not charged again; changed content conflicts. A new proposal after a denial is reevaluated. [action_chain.py](../../../src/agentsentry/action_chain.py) contains `evaluate_tool`, `evaluate_model` and `record`. PostgreSQL transaction locks serialize cross-session write decisions, with decision and evidence committed together. Approval rechecks the original action against current budget. No committed decision means no tool execution or model send.

## Offline exercise

```bash
.venv/bin/python -m agentsentry.action_chain_lab --output /tmp/agentsentry-learning-action-chain.json
.venv/bin/python -m pytest -q tests/test_action_chain.py
```

`action-chain-cases-v1` has 20 pressure/boundary cases and ten controls. Compare N03 with A01 at the 20/21 tool boundary; N06 checks three legitimate writes, A09 the Agent-wide write limit, and A13 resource probing. N10’s eight successful model checks are not eight actual model network sends.

Inspect `target_status`, the control, `side_effects`, `forbidden_side_effects`, and `audit_missing`. Legitimate task creation is a side effect but is not a forbidden one. Pending or unknown results do not become normal completion.

## Optional live exercise

```bash
.venv/bin/python -m agentsentry.action_chain_live --model 'YOUR_INSTALLED_MODEL' --model-base http://127.0.0.1:11434/v1 --output /tmp/agentsentry-learning-action-live.json
```

This runner creates a dedicated research tenant and executes its 12 fixed model tasks. It does not use a generic `--mode live` flag. Record actual attempts and threshold hits; a threshold the model never reaches is unverified. See [action-chain operation](../action-chain.md) and [observed behavior](../cases/runtime-and-budget.md).

## Self-check and limits

Session overview answers what happened; goal drift asks why the action may mismatch the task; the action chain shows cumulative decisions and budgets. They are views of the same session.

Explain how an unknown write occupies budget, why changing `call_id` is not an identical retry, and why an eight-check fixture is not live model evidence. Vary the number of pending writes in synthetic tests and predict a later approval’s budget.

The default `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false` preserves compatibility. Only tool calls with valid session binding receive this budget protection; model preflight requires binding independently. Quotas do not establish task alignment, universal rate limiting or autonomous goal-drift resistance.


## Continue learning

[Previous chapter](10-goal-drift.md) · [Handbook](README.md) · [Next chapter](12-audit-judge-mapping.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
