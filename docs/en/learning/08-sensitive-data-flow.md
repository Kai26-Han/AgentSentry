# 08 Sensitive data flow and leakage prevention

[English](#) · [中文](../../learning/08-sensitive-data-flow.md)

[Handbook](README.md) · [Previous: 07](07-memory-security.md) · [Next: 09](09-runtime-defense.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Separate confidentiality from instruction trust, understand pre-send enforcement, and verify sending/write/display facts plus conservative false blocks.

## Sources and exits

Permission to read private material does not authorize cloud sending, writing elsewhere, answering, or remembering. Source claims and URL/Base64/segmented transforms cannot establish public status.

```text
Documents / MCP / results / memory → verified source classification → Agent context
→ model preflight / tool-write check / pre-display check / memory check
```

Service-side resources and actual reads establish public/private/secret; unknown is private and credentials elevate risk. Public malicious instructions and private legitimate data are separate dimensions.

| Exit | Control |
| --- | --- |
| Local model | private permitted; clear credentials denied; preflight failure means no send |
| Remote model | Registered HTTPS only; private/unknown/secret or credentials/PII denied |
| Simulated external send | Any restricted session source denies; no approval override |
| Local tasks/notes | Secrets denied, private content steps up to approval; sensitive writes require binding |
| Answer | Restricted-source free-form output blocked; credentials/sensitive encodings blocked; permitted direct PII redacted |
| Memory | Secret rejected; private quarantined; activation does not lift outbound restrictions |

Read source_context, check_model, check_tool, record in [data_flow.py](../../../src/agentsentry/data_flow.py), sending in [demo_agent.py](../../../src/agentsentry/demo_agent.py). model-egress/check returns decision, registered URL, and permitted messages. Adapter sends only that response; changed-ID content conflicts and failed audit commit prevent sending.

## Exercise

Temporary SQLite, Redis stub and model-send counter, no real endpoint:

```bash
.venv/bin/python -m agentsentry.data_flow_lab --output /tmp/agentsentry-learning-data-flow.json
.venv/bin/python -m pytest -q tests/test_data_flow.py
```

[Current corpus](../../../src/agentsentry/data_flow_lab.py): 20 attacks/10 controls:

| Sample | Situation | Expected |
| --- | --- | --- |
| data-flow-cases-v2:A01 | Remote model after private source | deny, send counter zero |
| data-flow-cases-v2:N03 | Local private-data review | local allowed |
| data-flow-cases-v2:A09/A10 | Segmented simulated send | denied, zero messages |
| data-flow-cases-v2:A17 | Base64 private answer | block |
| data-flow-cases-v2:N05 | Ordinary task without sensitive source | completed authorized task |

Inspect per-case facts, not totals. Extra tests cover source downgrade, forgery, new private reads before approval, unbound writes, failed preflight and cleanup eligibility.

## Web evidence and retention

Runtime analysis → Sensitive data flow shows current-tenant records; select the report's data tenant for research. Chapter 10 generates some real exits, not every leakage class for every model.

Decisions retain IDs/destination/level/rules/digests, not request text. Operation rows temporarily retain needed arguments/results. Dispatcher clears text only where a data-flow decision exists, created_at is older than 30 days, and state is completed/denied/failed. pending/executing/unknown and older unrelated records remain. Cleanup does not delete backups; capture mode does not mean a text-free database.

## Tradeoffs and self-check

external_after_private blocks unrelated public sending after private reads. Session-level provenance cannot prove segmented/paraphrased content has no leakage; do not weaken just for completion scores. Finite rules do not cover arbitrary semantics or unintegrated traffic.

Cloud analysis is an external exit even if not published. Source text cannot self-declassify. Passing offline reports and an empty dashboard are compatible: separate databases.

[Guide](../data-flow.md) · [Leakage case](../cases/private-data-leakage.md) · [TH-006/007](../threat-framework-mapping.md)
