# Capabilities, Approval and Race Conditions

[English](#) · [中文](../../cases/tool-permission-and-approval.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Question and controls

Identity is not unlimited authority; an approval does not establish that its capability remains valid at execution. Check identity/tenant/typed resources, atomic token uses, ID/content idempotency, frozen approval parameters and current expiry/state/sources. Fact-card confirmations cannot be replaced by source claims. Commit failure before execution yields no action; result-commit failure after execution can be unknown.

## Observed evidence

2026-09-30, `deep-validation-v1` identity/approval group: two rounds of 13 checks using actual PostgreSQL/Redis/HTTP. Eight different proposals sharing two uses produced two writes; eight concurrent copies of one `call_id` executed once. Parameter replacement, pause, revoke-before-approve and pre-execution commit failure produced no unauthorized effects.

| Gap | Before | Fix and qualified result |
| --- | --- | --- |
| Stale approval ORM state | One write but another concurrent approval could return 500 | Refresh after row lock; success/conflict, one write |
| Revoke/approve lacked shared serialization | A synthetic write occurred after committed revoke | Shared capability row lock: revoke-first denies; valid execution-qualified approval-first may finish, and later revoke cannot undo it |
| Expiry during recheck | A 2.2-second delay allowed an expired capability’s write | Final expiry check before decision commit; both retests denied, zero writes |

Last two probes are `revocation-race-v1` and `approval-expiry-v1`. Do not claim revoke cancels every in-flight execution. [Redacted observations](../../cases/evidence/boundary-observations.json) retain before/after facts.

## Reproduce and limits

Use the handbook’s [offline environment](../learning/README.md#prerequisites-and-command-conventions):

```bash
.venv/bin/python -m pytest -q tests/test_service.py tests/test_approval_review.py tests/test_v2_tenants.py
```

Follow [identity](../learning/02-identity-capabilities.md) and [approval](../learning/04-approval-safety.md) exercises. Actual concurrency needs PostgreSQL, not serial SQLite proof. Shared DB/host compromise and human deception are not ruled out; the gateway must still recheck frozen parameters and state.
