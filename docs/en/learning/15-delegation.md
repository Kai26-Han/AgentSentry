# 15 · Delegation identity, authority and result contamination

[English](#) · [中文](../../learning/15-delegation.md)

## The security question

A parent Agent must not turn delegation into copied authority or treat a collaborator’s response as a system instruction. The project uses the existing parent and a fixed, separately authenticated read-only `reader-agent`. This is a single-hop local protocol, not a general multi-Agent platform.

The parent submits an authenticated, bound session plus existing capability. The gateway reserves a smaller resource/use/time scope, seals it, and establishes a child session. The independent reader uses the same tool gateway to read public synthetic documents or MCP cards. Its summary passes output and authority-forgery checks. The parent retrieves a low-trust result only after current identity, scope, expiry, pause, integrity and source-level checks.

Inspect [delegation.py](../../../src/agentsentry/delegation.py), [reader_agent.py](../../../src/agentsentry/reader_agent.py), [capabilities.py](../../../src/agentsentry/capability.py), and [data_flow.py](../../../src/agentsentry/data_flow.py). A seal establishes unchanged scope or result fields; it does not establish factual truth.

## Offline exercise

```bash
.venv/bin/python -m agentsentry.delegation_lab --report /tmp/agentsentry-learning-delegation.json
.venv/bin/python -m pytest -q tests/test_delegation.py tests/test_delegation_api.py
```

`delegation-lab-v1` has 22 boundary attacks and four normal controls. Each case uses isolated SQLite and fixed MCP responses. N01 is a normal document read. D01/D04 check scope and redelegation; D05/D06 sealing and tenant boundaries; D07/D11 revocation and pause. D15 allows the read but blocks a forged-approval summary. D18 detects a modified saved reply; D19 prevents parent retrieval after source reclassification and invalidates reuse of an old model-egress decision.

Check actual read count, sealed scope, remaining uses, child call status, result-check decision, parent sources and missing audit. Zero forbidden writes does not mean zero legitimate reads.

## Optional independent-process demonstration

```bash
docker compose exec -T web python -m agentsentry.delegation_lab --persist
```

This saves summaries rather than turning fixtures into live events. For actual independent parent/reader processes, follow the [two-terminal demonstration](../delegation.md#two-terminal-demo). Each terminal holds its own credential. The reader holds neither the parent credential nor its raw capability, and cannot call ordinary tools, model egress, memory APIs or redelegate.

Reserving two of three parent uses leaves one parent use. Revocation, expiry or SQL failure does not refund the reservation: Redis and SQL are not one atomic transaction, and avoiding double allocation has an availability cost. Parent action budgets include all reserved child uses. The parent keeps original child-call IDs as sources rather than inventing parent calls.

## Self-check and limits

Explain why reserved authority is not copied permission; why identical retries do not allocate more uses; why identity separation is not operating-system isolation; and why a malicious reply cannot grant write rights but may still contaminate content through unrecognized paraphrases.

Reply text is retained even in metadata mode, masked in the dashboard, and cleared after 30 days while IDs and audit remain. Revocation cannot recall data already delivered. Delegated sources do not automatically enter long-term memory. The reader has no model, and experiments do not verify cross-host or multi-model semantic collaboration, multihop writes, compromised hosts or joint database/key compromise. See [delegation operations](../delegation.md) and [delegation evidence](../cases/delegation-boundaries.md).


## Continue learning

[Previous chapter](14-fault-propagation.md) · [Handbook](README.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
