# Session Action Chains and Action Budgets

[English](#) · [中文](../action-chain.md)

## Position in the architecture

The adapter receives a session credential at task start. Before a tool proposal/model send, and again before an approved write executes, the gateway calculates committed tenant/Agent/session budgets. Goal clues remain advisory; budgets cannot expand authority or replace policy/capability/data-flow/approval.

```text
Agent → session credential → identity/policy/capability/data flow
                          → cumulative budget and pause → execution / approval
                          → committed audit and Outbox → Judge / alerts
```

## Deterministic response

`action-chain-v1` allows 20 tool proposals, eight task-model sends and three memory-summary sends per session; next requests are denied. At most three write proposals per session and ten per Agent in a rolling hour. Pending/executing/unknown/completed writes occupy budget; denied new proposals are recalculated. The fourth different denied resource in ten minutes pauses the session for administrator review. Identical tool/model request IDs do not charge twice; different content conflicts.

PostgreSQL tenant/Agent transaction locks serialize cross-session writes. Decisions, counts, IDs and Outbox commit together; failure means no execution/send. Approval checks original content and current budget. Unknown is never inferred successful.

Web: Runtime analysis → Session investigation → Action chain. Research tenant evidence stays read-only for default-admin observers. New sessions are recorded; old sessions are not backfilled.

## Experiments

```bash
.venv/bin/python -m agentsentry.action_chain_lab --output .local/action-chain-report.json
SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python -m agentsentry.action_chain_live --model qwen3:0.6b
```

`action-chain-cases-v1` has 20 pressure/boundary proposals and ten controls in isolated synthetic databases. Fixed proposals do not predict model behavior. `action-chain-live-v1` contains three document and three MCP pressure tasks plus six controls. Live mode creates a dedicated research tenant, keeps credentials in `.local/` (`0600`) and reports model/sample hash/actual attempts to `.local/action-chain-live-report.json`. Untriggered thresholds are unverified; see [behavior evidence](cases/runtime-and-budget.md).

## Limits

Default compatibility allows legacy unbound clients. Only valid bound tool calls receive action budgets; set `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=true` after upgrading every caller if you want mandatory coverage. Model egress already requires binding. Pressure prompts from a user are not evidence of attacker-free autonomous drift (`TH-011`). Budgets (`TH-013`) constrain counts, not task semantics, all cross-Agent behavior or full overload. Resume cannot recall started effects. Daily mapping is a clue, Judge is retrospective. See [chapter 11](learning/11-action-chain.md).
