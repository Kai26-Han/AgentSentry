# Sandbox, Outbox and Judge: Isolation and Evidence

[English](#) · [中文](../../cases/execution-and-audit.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Question and controls

Authorized execution still needs host-access constraints; asynchronous outages must not silently lose calls. Judge cannot establish actual effects. The sandbox has a fixed entry, read-only root, network constraints and timeout, with shell only for default tenant. Pre-execution audit/Outbox commits together; retries use stable IDs/deduplication. Unconfirmed effects remain unknown.

## Observed evidence

- 2026-09-27 sandbox probes: read-only root, blocked sockets, no host mounts, timeout and zero pre-approval effects. 2026-10-01 added four independent isolation probes. These are not arbitrary escape tests or the learner’s own human approval completion.
- 2026-09-27 Worker outage: an ordinary authorized tool completed; two audit/Outbox events remained pending without Judge. Recovery processed both and produced one deduplicated alert. This establishes queue recovery/linkage.
- Webhook HMAC/idempotency/retry used doubles, not proof every external recipient deduplicates.
- The 31 offline cases had zero forbidden tool effects for 20 attacks and completion for 11 controls. Mock Judge false negatives were 44.44% under that corpus denominator, not cloud accuracy or attack probability.

## Reproduce and limits

Use [execution exercises](../learning/05-execution-boundaries.md) for prepare/human decision/verify/cleanup and [audit exercises](../learning/12-audit-judge-mapping.md) for transactions/Outbox/dedicated queues. `scripts/recovery_drill.py` stops a real Worker; `scripts/v15_smoke.py` changes/restores policy. They are not routine reading commands—use a separate prepared learning environment.

Sandbox does not replace permissions or prove host safety. Unknown is not completion or permission to retry. Judge failure does not reauthorize a tool. See [architecture](../architecture.md) and [failure recovery](../fault-propagation.md).
