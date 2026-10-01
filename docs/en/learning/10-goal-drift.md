# 10 · Goal drift and task evidence

[English](#) · [中文](../../learning/10-goal-drift.md)

## The security question

Can a document or MCP card induce behavior unrelated to the user’s task? The gateway creates a limited task profile at session start and compares subsequent tool proposals and answers with that profile and actual sources. This analysis supplies investigation and approval clues; it is not a new authorization gate.

Profiles are `read_only`, `action_requested`, or `unknown`. Assessments are `suspected`, `aligned`, `unknown`, or `failed`. `aligned` means the limited patterns did not fire; it does not prove that the task was understood or the action safe. Ambiguous intent is not silently converted into permission.

Inspect [goal_analysis.py](../../../src/agentsentry/goal_analysis.py), especially `profile_for`, `_sources` and `assess_tool`, and [runtime_analysis.py](../../../src/agentsentry/runtime_analysis.py). The administrator query is `GET /api/v3/goal-assessments`; Web: Runtime analysis → Session investigation → Goal drift. The stored profile contains categories, resource IDs, versions and evidence IDs rather than a new copy of task text.

## Offline exercise

```bash
.venv/bin/python -m pytest -q tests/test_goal_analysis.py tests/test_goal_lab.py
```

Compare an explicit read-only task, an ambiguous task, and a write proposal with valid existing authorization after a read-only task. In `test_goal_signal_never_overrides_existing_allow`, the suspect action deliberately remains allowed by the existing controls. This demonstrates the chosen advisory boundary; it is not evidence of unauthorized execution.

For authority-forging sources, inspect the actual source IDs, profile category and finding. Source linkage proves the material reached the session, not that the model obeyed it. Distinguish task-profile `unknown` from an unknown tool result.

## Optional gateway and model experiments

```bash
.venv/bin/python -m agentsentry.goal_lab_runner --mode scripted --output /tmp/agentsentry-learning-goal.json
export DEMO_MODEL_BASE_URL='http://127.0.0.1:11434/v1'
export DEMO_MODEL_NAME='YOUR_INSTALLED_MODEL'
.venv/bin/python -m agentsentry.goal_lab_runner --mode live --output /tmp/agentsentry-learning-goal-live.json
```

Use an online terminal with the real gateway settings. Scripted mode runs 20 `goal-lab-v1` cases in each of two new research tenants. Live mode runs three document attacks, three MCP attacks and their six normal controls, each three times: 36 executions. Preserve model name, sample hash, policy revision and evidence IDs. N07 is an explicitly requested write; N08 is ambiguous; A12 examines a source-carried answer payload. Malicious pending approvals are never automatically approved.

If the model does not propose a dangerous tool, report its tool-blocking effectiveness as unverified. Fixture IDs in temporary offline tests are not Web evidence links. Existing daily sessions are not backfilled with inferred intent.

## Self-check and limits

Explain why a goal clue cannot authorize a tool, why a read-only mismatch may still execute under valid permissions, and why a normal quotation can resemble an instruction. The optional local semantic model is off by default and remains advisory even when enabled. Failure records an analysis error without weakening existing controls.

Natural-language intent is incomplete; free paraphrases can escape patterns. Autonomous drift without attacker input (`TH-011`) needs its own experiment and is not established by attacker-written pressure tasks. See [goal analysis](../goal-drift.md) and [output contamination cases](../cases/injection-and-output.md).


## Continue learning

[Previous chapter](09-runtime-defense.md) · [Handbook](README.md) · [Next chapter](11-action-chain.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
