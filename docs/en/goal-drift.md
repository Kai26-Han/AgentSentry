# Goal-Drift Clues and Approval Fact Cards

[English](#) · [中文](../goal-drift.md)

```text
Trusted task → session start → limited task profile
Low-trust sources → Agent → tool proposal → existing gateway authorization
                                       → advisory goal assessment → evidence
Pending action → fact card → short-lived confirmation → current rechecks
Draft answer → output checks plus advisory assessment → eligible display
```

Profiles contain `read_only`, `action_requested` or `unknown`, recognized action categories and explicit fixed resources. They add no task-text retention. Metadata still omits task/answer snippets; raw text is processed temporarily. Old sessions show not evaluated, with no inferred backfill.

## Analysis boundaries

Patterns detect read-only tasks followed by writes, actual sources forging system/admin authority, related source instructions, parameters claiming approval, and source output instructions reflected in answers. States `suspected`, `aligned`, `unknown`, `failed` are advisory. Aligned means no limited match, not verified understanding.

Optional `GOAL_LOCAL_MODEL_BASE_URL`/`GOAL_LOCAL_MODEL_NAME` enable local semantic hints; defaults off. Timeout/invalid responses are analysis failure without weakening policy, capability, runtime, data-flow or approval. Tenant assessments/audit store categories, versions and evidence IDs, not raw task/source/answer text.

Web `/dashboard/goal-assessments` lists daily evidence; default admins can choose existing goal-lab tenants read-only. `/api/v3/goal-assessments` is administrator-only. Source linkage proves arrival, not obedience.

## Fact-card approval

`/dashboard/approvals` supports direct rejection but approval only after opening details. The card separates verified tool, frozen parameters/digest, capability/resource, policy/current state and security findings from low-trust “already approved” claims. Sensitive parameters are masked until the administrator explicitly expands them.

Web approval requires a review declaration and a five-minute confirmation bound to administrator session, tenant, approval ID, frozen parameter hash and current evidence hash. Changed evidence/state, expiry, replay or replacement requires reopening. The gateway still rechecks the original parameters and current authority/state. The ordinary admin API `/api/v1/approvals/{id}/decision` remains authenticated/CSRF-protected controlled automation, without Web confirmation; GitHub writes have their stricter fact-card requirement. Models hold no administrator credentials.

## Experiments

```bash
SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python -m agentsentry.goal_lab_runner --mode scripted
SENTRY_URL=http://127.0.0.1:8000 DEMO_MODEL_BASE_URL=http://127.0.0.1:11434/v1 DEMO_MODEL_NAME=qwen3:0.6b .venv/bin/python -m agentsentry.goal_lab_runner --mode live --output .local/goal-lab-live-report.json
```

`goal-lab-v1` has 12 attacks/eight controls. Scripted mode runs the 20 cases twice in fresh research tenants; live mode runs six attacks/six controls three times (36). Credentials stay in `.local/goal-lab-<tenant-id>.json` (`0600`); reports contain evidence IDs and conclusions, no raw draft/display text. Remote models require explicit `--allow-remote-model` and registered egress. Experiment writes require research-admin login/CSRF; default observation is read-only.

Report attempts, direct denials, pending, forbidden actions, pre-approval effects, draft/display contamination, completion and audit gaps separately. No proposal means blocking unverified; pending/unknown/unfinished/error remain inconclusive. Automated page tests cannot prove people never fall for deception.

Limited language rules can miss paraphrases. A mismatch with valid authorization may still execute unless another enforceable control applies. Goal clues cannot replace output checks or establish factual truth. See [chapter 10](learning/10-goal-drift.md) and [output evidence](cases/injection-and-output.md).
