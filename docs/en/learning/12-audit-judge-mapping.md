# 12 · Audit, Judge, alerts and threat mapping

[English](#) · [中文](../../learning/12-audit-judge-mapping.md)

## Three different questions

Execution records establish what happened. Judge supplies an asynchronous risk signal about an event it actually received. Threat mapping links typed evidence to project scenarios and framework references. Neither a Judge score nor a taxonomy label proves attack success or changes a completed authorization decision.

Trace [service.py](../../../src/agentsentry/service.py) → [dispatcher.py](../../../src/agentsentry/dispatcher.py) → [worker.py](../../../src/agentsentry/judge/worker.py). Judge adapters and tenant routes are in [judge.py](../../../src/agentsentry/judge/adapters.py), [judge_runtime.py](../../../src/agentsentry/judge/runtime.py); classification uses [threat_mapping.py](../../../src/agentsentry/threat_mapping.py) and [structured mapping data](../../threat-framework-map.yaml).

Before execution, the decision, audit event and applicable Outbox row commit in one transaction. A failed commit prevents execution. Some administrative events intentionally have no Judge delivery. Authentication and parameter errors can occur before business audit creation, so this is not a complete network-request log.

## Interpret Judge correctly

Scores range from 0 to 1 and are provider-specific signals for the submitted event. They are not calibrated probabilities, overall session safety scores, or directly comparable measurements across models. For ordinary non-sample events, a non-`none` label and score at or above `JUDGE_SCORE_THRESHOLD` (default 0.7) can produce an alert. Jev’s typed-label mapping has its own threshold semantics.

Provider, model, destination and configuration revision are frozen when the Outbox event is created. A setting change affects new events; retries keep their original route. Timeouts, malformed output or destination mismatch are failures, not an implicit switch to another provider. An answer never submitted to Judge is outside its denominator, not a missed detection.

## Offline exercise

```bash
.venv/bin/python -m pytest -q tests/test_dispatcher.py tests/test_judge.py tests/test_judge_adapters.py tests/test_judge_runtime.py tests/test_v15.py tests/test_threat_mapping_runtime.py
.venv/bin/python scripts/check_threat_mapping.py --check
```

Inspect duplicate delivery: one original Outbox should yield at most one persisted Judge result and deduplicated alert. Broker failures retain the event for retry. Webhook transport is at least once, and recipients must deduplicate using `Idempotency-Key`. Test doubles prove these assertions, not a real cloud service’s current availability.

## Map evidence without inventing certainty

The [framework matrix](../threat-framework-mapping.md) is a curated scenario/control/test reference. The daily threat-evidence list is a projection of committed typed event metadata. It can legitimately be empty or unmatched. Judge labels alone do not supply a technique match. Existing event snapshots keep their classification when mapping rules change; a projection failure must not change tool authorization.

Check tenant, source ID, rule ID, mapping version and the original event for a linked record. Framework references are investigation aids, not proof that an entire OWASP category is solved. See [daily mapping](../runtime-threat-mapping.md), [Judge settings](../judge-runtime-switch.md), and [execution/audit cases](../cases/execution-and-audit.md).

## Self-check and limits

Explain event loss versus a queued or deliberately undelivered event, why provider changes cannot rewrite old results, and why alert acknowledgement is not a security state reset. Try a synthetic event with no matching rule and expect an explicit unmatched state.

The database is not an independent tamper-proof log against an attacker with the same write privileges. Queue isolation is not complete capacity backpressure. Cloud reliability and semantic accuracy require separate experiments; Mock results are not cloud-model performance.


## Continue learning

[Previous chapter](11-action-chain.md) · [Handbook](README.md) · [Next chapter](13-validation-calibration.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
