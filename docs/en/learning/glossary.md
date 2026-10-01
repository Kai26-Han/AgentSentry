# Security Learning Glossary

[English](#) · [中文](../../learning/glossary.md)

[Handbook](README.md) · [Experiment index](experiment-index.md)

## Components, credentials and data

| Term | Meaning in AgentSentry | Do not assume |
| --- | --- | --- |
| Agent | Main demo proposes tools/answers; delegation adds a fixed read-only identity | Each lab creates a new Agent |
| Trusted adapter | Keeps credentials, constructs protocol requests, sends approved messages and displays approved text | Passing through it makes content true |
| Security gateway | FastAPI service that independently checks and commits decisions | Transparent interception of every program |
| Sandbox | Execution constraints on authorized shell work | A replacement for authorization or proof of no escape |
| MCP | Protocol for tool definitions, calls and results | Protocol validity implies trustworthy content or isolation |
| Agent API key | Tenant/Agent authentication | Authority to issue capabilities |
| Capability / tool-call authorization | Opaque token constrained by tool, resource, expiry and uses | YAML allow or an approval exemption |
| Session credential | Server-issued tenant/Agent/session/expiry binding | `session_id` itself is permission |
| Admin login / CSRF | Authentication and protection for management writes | Approval skips current-state checks |
| `call_id` | Tenant-scoped idempotency/correlation key | Changing the ID is the same retry |
| `session_id` | Correlates one task | A globally authorized principal |
| Source ID | Actual reads or supplied memories linked to context | Proof of truth or model obedience |
| Low-trust data | Documents, cards, results and memory used as data | Necessarily malicious or confidential |
| `public` / `private` / `secret` | Server-side source classification plus explicit secret detection | Self-proclaimed public text downgrades it |
| Fingerprint / HMAC | Normalized digest; some fields protected by a server key | Encryption or complete anonymization |

## Decisions and states

Always identify the object: an unknown task profile and an unknown execution result differ.

| Object | State | Meaning |
| --- | --- | --- |
| Base policy | `allow` / `deny` / `require_approval` | Further synchronous controls still apply |
| Tool call | `pending_approval` | Waiting; not a completed normal task |
| Tool call | `executing` | Execution may have begun; do not infer zero effects |
| Tool call | `completed` | Confirmed result saved; inspect authorization and purpose |
| Tool call | `failed` | Confirmed failure; inspect its phase |
| Tool call | `unknown` | Actual effect uncertain; do not automatically resend |
| Output check | `allow` / `warn` / `block` | Approved text / warning or redaction / safe notice only |
| Memory | `active` / `quarantined` / `rejected` | Eligible for read / withheld / candidate text not saved |
| Memory | `revoked` / `expired` / `purged` | Future use revoked / expired / text cleared |
| Goal analysis | `suspected` / `aligned` / `unknown` / `failed` | Advisory signal / no limited match / unclear / analysis error |
| Judge / Outbox | Pending, processing, completed, failed | Asynchronous state, not execution state |
| Threat mapping | Pending, linked, unmatched, failed | Typed projection, not attack-success scoring |

Same-content retry returns recorded state; changed content generally yields 409. Invalid input may be 422, missing identity 401/403, and an invisible record 404. A single HTTP status does not prove a side-effect count.

## Privacy and cleanup

| Term | Meaning |
| --- | --- |
| `preview` | Bounded redacted task/answer snippets retained; raw text still processed for checks |
| `metadata` | No task/answer snippets; raw checks still reach the gateway, with separate memory/operation retention |
| Redaction | Defined patterns replaced; unknown formats and contextual secrets can be missed |
| Dashboard masking | Text hidden by default, separate from storage/access controls |
| Revocation | Stops future use; neither deletes all text nor recalls in-flight context |
| Expiry | Stops returning content; valid expired memories are cleared on maintenance/access, anomalous records handled separately |
| Purge | Clears specified text fields, retaining metadata; does not erase backups or source documents |
| Disable | Stops later memory reads/writes, not deletion of existing memory |

## Evaluation

| Term | Meaning |
| --- | --- |
| Scripted replay | Fixed proposals test controls, not model tendency to generate them |
| Live run | Actual model task and observed behavior; no attempt means no triggered control |
| Draft contamination | Defined attack content in pre-check output |
| Display contamination | Contamination in the gateway-returned text actually eligible for display |
| Dangerous attempt | Proposed sample-defined dangerous action, separate from execution |
| Forbidden side effect | Actual effect that should not have been authorized; legitimate writes counted separately |
| Inconclusive | Pending, uncertain, unfinished, environment error or missing evidence; state why |
| False-block candidate | Normal task denied or stepped up; causal review needed |
| Judge score | Provider signal about an observed event, not calibrated attack probability |
| Calibration / held-out set | Recommendation data / independent risk check; repeated tuning on held-out data invalidates independence |
| TH / ASI / ATLAS | Project scenario / OWASP risk category / MITRE technique reference |

Implemented, verified within scope, partially verified, unverified and currently inapplicable are different conclusions. Confirmed gaps retain their original evidence even after a fix. Explain a term by stating **what is checked, where, with which facts, what failure does, and what it cannot guarantee**.
