# 04 Human approval and approval deception

[English](#) · [中文](../../learning/04-approval-safety.md)

[Handbook](README.md) · [Previous: 03](03-tool-policy.md) · [Next: 05](05-execution-boundaries.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Distinguish a source's "already approved" claim from server facts. Explain frozen arguments, short confirmation, and final rechecks. Prove zero pre-approval effects by counting them.

## Threat and review

A read task encounters material claiming the administrator authorized sending. Or arguments, grants, and source evidence change after review. Approval must bind the real action, not a persuasive model explanation.

```text
Freeze action → pending, no execution → inspect fact card
→ confirmation bound to admin session/tenant/approval/digest
→ recheck original arguments and current safety state
→ execute original action, or refuse changed/expired action
```

Separate untrusted text from gateway facts and escape HTML. Web confirmation lasts five minutes; it establishes review of this card, not that the human cannot be deceived.

Read `approval_review_token`/`verify_approval_review` in [main.py](../../../src/agentsentry/main.py), `decide_approval` in [service.py](../../../src/agentsentry/service.py), and the [fact-card guide](../goal-drift.md). Rechecks cover digest, grant validity, policy, runtime, data flow and applicable budget. Ordinary admin API supports authenticated/CSRF-controlled automation without the same Web card; GitHub writes require the dedicated human path.

## Exercise

Offline synthetic approvals; send_external is a database inbox:

```bash
.venv/bin/python -m pytest -q tests/test_service.py::test_rejection_and_approval tests/test_service.py::test_approval_is_bound_to_arguments_and_grant tests/test_service.py::test_revocation_invalidates_pending_approval tests/test_approval_review.py
```

| Case | Inspect | Expected |
| --- | --- | --- |
| Reject / approve normal request | ExternalMessage count | 0 / 1 |
| Replace pending arguments | Digest/count | 409, still 0 |
| Revoke pending grant | Grant state/effects | denied, no effect |
| Approval claim and script tags | Card/escaped markup | Low-trust text, no approval or HTML execution |
| Missing CSRF/ack, stale session/evidence, expiry/replay | Client responses | Confirmation refused |

409 is a recheck signal, not execution success. Read [service assertions](../../../tests/test_service.py) and [Web review tests](../../../tests/test_approval_review.py).

## Optional manual MCP observation

Prepare gateway, explicit local MCP policy, and dedicated tenant following [E05](experiment-index.md#e05-local-mcp-human-approval). Run mcp_demo.py --write, leave pending and inspect the absence of a successful write result. Actual upstream counters in Chapter 05 prove no write; lack of a result alone does not.

Approve/reject only after reviewing synthetic parameters. The script waits about ten minutes; closing a terminal does not cancel server approval. Reject remaining requests before leaving. This step writes local synthetic storage, not GitHub.

## Limits and self-check

Humans can approve incorrectly; an authorized action can still be wrong. Approval does not replace output/sandbox control or undo completed effects. Gateway records verify claims. Expired grants cannot execute. Changed evidence invalidates an otherwise unexpired confirmation; reopen the card.

[Concurrency case](../cases/tool-permission-and-approval.md) · [TH-008](../threat-framework-mapping.md#th-008)
