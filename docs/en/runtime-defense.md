# Runtime Security Rules and Response

[English](#) · [中文](../runtime-defense.md)

## Role

After single-call identity, typed parameters, policy and capability checks, the gateway examines committed tenant/Agent history. Rules may preserve or tighten the decision, never widen authority. Decision and applicable Outbox commit before execution. Judge remains asynchronous and cannot authorize or revoke that execution. Pausing prevents later integrated actions, not a running model process or already started effects.

## Fixed catalog: runtime-rules-v1

| Rule | Server evidence | Default response |
| --- | --- | --- |
| `read_then_write_review` | Completed document/MCP read followed by write | Clue only |
| `instruction_source_before_write` | Explicit instruction pattern within first 8,192 result characters before write | Step up allow to approval |
| `repeated_denials_before_write` | At least three same-Agent denials in ten minutes | Step up allow to approval |
| `uncertain_action_repeat` | Same Agent/tool/normalized parameters executing or unknown in 24 hours | Deny new-ID repeat; original-ID query stays idempotent |
| `administrator_paused` | Paused session or Agent | Deny later tools |
| `session_closed` | Reported session not running | Deny later tools |
| `session_binding_invalid` | Invalid supplied binding, or absent under mandatory mode | Deny new call |

Approval rechecks frozen parameters, capability, current policy, pause and runtime evidence; new step-up evidence invalidates the old request and requires resubmission. Audit records finding/source IDs, not duplicate source text. Rules and thresholds are engineering baselines, not prescribed OWASP numbers.

## Binding and compatibility

Session start returns `session_token` bound to tenant/Agent/start time. Adapters keep it outside model context and submit `X-Runtime-Session`. It is valid only for a running session within eight hours. The ID alone is not authority.

`AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false` preserves legacy direct calls, explicitly marked `session_unreported`. Set true only after updating all trusted callers. New calls then require start plus credential; old calls are not replayed, and identical-ID queries add no effects. A stolen Agent key can establish new sessions; binding does not solve full credential compromise.

## Management

- `POST /api/v2/runtime-controls`: admin + CSRF, `scope=session|agent`, pause/resume; pause needs a reason. Store redacted reason, actor, time and audit.
- `GET /api/v2/runtime-decisions/{call_id}`: submission/approval findings.
- `GET /api/v2/runtime-incidents`; `POST /api/v2/runtime-incidents/{id}/ack`: incident view/acknowledgement. Ack does not resume.
- `/dashboard/runtime-sessions/detail`: evidence and controls; `/dashboard/alerts`: distinguish Judge and runtime sources.
- `/dashboard/runtime-rules`: read-only current conditions/thresholds/patterns/effects/limits. Tool YAML is separate `/dashboard/policy`.

`runtime_incidents` merge same-Agent/rule observations within ten minutes; each call retains its own decision/audit. Existing Judge alerts/Webhook are separate. Runtime incidents are local-only and not automatically sent through Judge Webhook. Startup creates tables without historical reclassification.

## Reproduce

```bash
.venv/bin/python -m agentsentry.runtime_lab
SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python scripts/runtime_smoke.py
```

Offline `runtime-cases-v1` has 20 attacks/ten controls in temporary SQLite, reports `.local/runtime-eval-report.json`, checks effects and required audit/Outbox, and never approves pending attacks. The online smoke runner creates/reuses a dedicated synthetic tenant, saving `.local/runtime-smoke.json` (`0600`), and tests step-up, pause, approval recheck, evidence and isolation without real external sending. Inspect leftover state after interruption. Live model work uses the attack-lab paths, with separate attempt/display facts and observed-event Judge metrics.

Finite patterns can miss paraphrases or flag legitimate quotations. Compatibility unreported calls are not denied unless binding is mandatory. Shared identity is not understanding of the task. [Data flow](data-flow.md) and [output checks](output-safety.md) independently protect exits. See [chapter 09](learning/09-runtime-defense.md).
