# 14 · Failure propagation, circuit breakers and recovery

[English](#) · [中文](../../learning/14-fault-propagation.md)

## The security question

Slow dependencies and retries can amplify failures. Critical authorization and pre-execution audit must fail closed; noncritical asynchronous analysis can retry. An uncertain dispatched action must not be retried automatically.

| Failure | Current response | Recovery condition |
| --- | --- | --- |
| Capability Redis or decision commit | No new execution | Reestablish the original checks |
| Repeated MCP/sandbox failures | Tenant/dependency breaker; bounded execution leases | One authorized half-open probe after cooldown |
| Broker | Keep original Outbox; backoff | Deliver the same event, not the tool action |
| Judge/notification failure | Separate queues and retries | Original route, bounded new processing generation |
| Late worker result | Reject obsolete generation | Current lease may finish |
| Dispatched action with no confirmed result | `unknown` | Independent upstream reconciliation |

Inspect [resilience.py](../../../src/agentsentry/resilience.py), [service.py](../../../src/agentsentry/service.py), [dispatcher.py](../../../src/agentsentry/dispatcher.py) and [worker.py](../../../src/agentsentry/judge/worker.py). Initial limits are three failures, 30-second cooldown and two execution leases per tenant/dependency; these are engineering settings, not standardized production thresholds.

## Offline exercise

```bash
.venv/bin/python -m agentsentry.fault_lab --output /tmp/agentsentry-learning-fault.json
.venv/bin/python -m pytest -q tests/test_resilience.py
```

`fault-lab-v1` has 18 failure and four normal cases. N02 verifies local reading remains possible when a remote dependency is open. F01/F02 require zero executions on capability or commit failure. F03 preserves unknown and does not repeat on the original ID. F04–F09 exercise breaker/lease transitions; F10–F16 exercise broker backoff and processing generations.

SQLite exercises serial logic. It does not establish cross-process PostgreSQL locking. Persisted fixture summaries are not real daily call records.

## Optional PostgreSQL and queue exercises

```bash
docker compose exec -T web python -m agentsentry.fault_lab --persist
docker compose exec -T web python - < scripts/check_resilience_postgres.py
docker compose exec -T web python - < scripts/check_resilience_queue.py
```

The PostgreSQL script uses temporary schemas and tests two leases under four competing requests, one half-open probe and deduplication. The queue script uses a dedicated queue and temporary worker; it observes accumulation without that worker and recovery of one original event. Both clean their dedicated resources without stopping daily services. Persisting lab summaries only saves redacted conclusions; do not manufacture session/call links for temporary IDs.

Web: Administration → System and demo data → Failure isolation and recovery. Requeue buttons apply only to terminal analysis/notification tasks, not tool actions. Recovery never bypasses authorization or approval. See [fault-propagation operations](../fault-propagation.md) and [boundary evidence](../cases/boundary-validation.md).

## Self-check and limits

Explain why Judge failure differs from capability Redis failure; why a new call ID after a timeout is dangerous; why half-open probes still need authorization; why generations cannot retract a sent webhook; and what PostgreSQL adds beyond serial fixtures.

Judge and notification workers still share the database, Redis and host. Limits do not provide strict CPU/memory quotas, fair scheduling or complete overload protection. Webhooks remain at least once and need receiver deduplication. A completely unavailable database cannot persist failure evidence, but cannot authorize new uncommitted execution either.


## Continue learning

[Previous chapter](13-validation-calibration.md) · [Handbook](README.md) · [Next chapter](15-delegation.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
