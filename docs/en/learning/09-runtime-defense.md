# 09 · Runtime detection and response

[English](#) · [中文](../../learning/09-runtime-defense.md)

## The security question

A call can be individually authorized yet become concerning after repeated denials, an instruction-bearing source, or an earlier uncertain action. The gateway evaluates committed history before execution. Response can preserve an existing decision, require approval, deny a repeat, or respect a pause. It cannot expand resource access or override a policy denial.

## Rules and evidence

Current catalog: `runtime-rules-v1`. These thresholds are initial engineering choices for a local lab, not thresholds prescribed by OWASP.

| Rule | Evidence | Response |
| --- | --- | --- |
| `read_then_write_review` | Reading followed by writing | Investigation clue |
| `instruction_source_before_write` | An actually read source contains a matched instruction before a related write | Step up to approval |
| `repeated_denials_before_write` | At least three denials for the same Agent within ten minutes | Step up a subsequent write |
| `uncertain_action_repeat` | Same Agent, tool and normalized arguments already executing or unknown within 24 hours | Deny a new-ID repeat |
| `administrator_paused` / `session_closed` | Administrative pause or closed session | Deny subsequent actions |
| `session_binding_invalid` | Invalid binding, or missing binding when required | Deny |

Inspect [runtime_guard.py](../../../src/agentsentry/runtime_guard.py), especially `rule_catalog`, `evaluate` and `record`, and [runtime_binding.py](../../../src/agentsentry/runtime_binding.py). Web: Administration → Protection rules → Runtime security rules; session evidence appears in Runtime analysis.

## Reproduce a normal case and a boundary

In the separate offline terminal:

```bash
.venv/bin/python -m agentsentry.runtime_lab --output /tmp/agentsentry-learning-runtime.json
.venv/bin/python -m pytest -q tests/test_runtime_guard.py
```

`runtime-cases-v1` includes N01 (ordinary public reading and task creation), A01 (an instruction-bearing source followed by a write), N05 (two denials before an otherwise valid write), A05 (three or more denials), A08 (a new-ID repeat of an unknown action), and N09 (a valid action after administrative resume).

Predict the difference between N05 and A05. Check `runtime_findings`, the original tool status, `side_effect_delta`, and `audit_missing`. A pending action should have zero write effects; an `unknown` action requires independent reconciliation. A finding alone is not an execution result.

## Optional online exercise

[Runtime defense](../runtime-defense.md) describes `scripts/runtime_smoke.py`. It creates or reuses a dedicated Runtime Lab tenant and stores credentials in `.local/runtime-smoke.json`. This tenant may not appear in the Attack Lab selector. The drill exercises pauses and approval rechecks, and restores its pause state on successful completion. After interruption, inspect remaining approvals and pauses yourself; do not resume daily sessions indiscriminately.

Acknowledging an alert does not resume an Agent or session. Resuming does not skip capability, policy, source or approval checks. Approval must reevaluate the frozen action against current state.

## Self-check and limits

1. Why is a normal read-then-write workflow not automatically an attack?
2. How does querying the original `call_id` differ from submitting a new one after a timeout?
3. Why does alert acknowledgement leave a pause intact?
4. Which event establishes the counting window and which record proves a side effect?

Write one variation using only synthetic data: change the number of preceding denials and predict the approval transition. Limited patterns can miss paraphrases and can flag legitimate workflows. Boundaries depend on correct session binding; a runtime clue does not demonstrate attacker intent. See [continuous behavior cases](../cases/runtime-and-budget.md) and the [experiment index](experiment-index.md).


## Continue learning

[Previous chapter](08-sensitive-data-flow.md) · [Handbook](README.md) · [Next chapter](10-goal-drift.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
