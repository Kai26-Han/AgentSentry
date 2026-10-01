# Learning Experiment Index

[English](#) · [中文](../../learning/experiment-index.md)

Command baseline: V3.6 · 2026-10-01. These are reproducible entries, not a claim that you have run them. Start offline and follow the [environment conventions](README.md#prerequisites-and-command-conventions).

[Handbook](README.md) · [Glossary](glossary.md) · [Advanced cases](../cases/README.md)

## Select the environment first

| ID | Entry | Environment/result | Effects and cleanup |
| --- | --- | --- | --- |
| E01 | [Trust boundaries](01-security-boundaries.md) | Temporary DB / pytest | Synthetic tasks; no Web data |
| E02 | [Identity and capabilities](02-identity-capabilities.md) | Temporary DB/Redis doubles | Temporary identities/policies |
| E03 | [Policy](03-tool-policy.md) | YAML and temporary candidates | Does not publish live rules |
| E04 | [Approval](04-approval-safety.md) | Temporary DB/Web client | Synthetic inbox only |
| E05 | [Local MCP approval](#e05-local-mcp-human-approval) | Dedicated online tenant / Web | Capability, synthetic note; reject leftover approvals |
| E06 | [Sandbox](#e06-sandbox-execution-and-human-approval) | Bound online session / fixed probes | Human decision; marker/session/grant cleanup |
| E07 | [Output](06-input-output-safety.md) | Rule functions / terminal | No actual model sends |
| E08 | [Cross-session memory](07-memory-security.md) | Offline or research tenant | Read/write/revoke/purge synthetic memory |
| E09 | [Memory storage](#e09-memory-storage-in-a-research-tenant) | Existing research tenant / Web | Synthetic DB edits; no daily tenant |
| E10 | [Data flow](08-sensitive-data-flow.md) | Temporary DB/send counter | No real model or Web records |
| E11 | [Runtime](09-runtime-defense.md) | Offline or Runtime Lab tenant | Pause and recheck; inspect after interruption |
| E12 | [Goal drift](10-goal-drift.md) | Offline or fresh research tenants | No automatic attack approval |
| E13 | [Action chain](11-action-chain.md) | Offline / fresh live tenant | Legitimate writes use budget |
| E14 | [Audit/Judge/mapping](12-audit-judge-mapping.md) | Controlled doubles | No cloud/webhook traffic |
| E15 | [Calibration](13-validation-calibration.md) | Offline or new tenant each run | Compare reads reports; no rule publishing |
| E16 | [Third-party evidence](#e16-read-third-party-evidence) | Dated case documents | Reading only; new writes require concrete approval |
| E17 | [Failure recovery](14-fault-propagation.md) | Temporary DB/schema/queue | Clean dedicated resources; daily services stay running |
| E18 | [Delegation](15-delegation.md) | Offline or independent online identities | Public synthetic reads; deactivate reader afterward |

Use a new report filename for each round. `/tmp` can be cleaned by the operating system; copy only redacted synthetic conclusions if you need persistence, never credential files.

## E05 Local MCP human approval

Prerequisites: running Compose gateway/Redis/PostgreSQL, a dedicated demo tenant, its administrator and Agent credentials, and local `.env` with the gateway’s matching `SESSION_SECRET`.

```bash
export SENTRY_URL='http://127.0.0.1:8000'
export TENANT_ADMIN_PASSWORD='YOUR_DEMO_TENANT_ADMIN_PASSWORD'
export TENANT_AGENT_API_KEY='YOUR_DEMO_TENANT_AGENT_KEY'
.venv/bin/python scripts/enable_mcp_policy.py --tenant 'YOUR_DEMO_TENANT_ID'
.venv/bin/python scripts/mcp_demo.py --tenant 'YOUR_DEMO_TENANT_ID'
.venv/bin/python scripts/mcp_demo.py --tenant 'YOUR_DEMO_TENANT_ID' --write
```

The policy command previews only; add `--apply` after reviewing it if the demo tenant needs MCP rules. The read produces a real call ID. For the write, log in as the owning tenant administrator and inspect `demo-notes`, note ID and synthetic text in its fact card. Keep it pending first; automatic zero-upstream-write proof is in `tests/test_mcp.py`, not inferred solely from a pending label. Approve the original normal control or reject it yourself. The script never approves for you. Observe original call, result, audit and Outbox.

The script waits about ten minutes. Cancelling the terminal does not cancel the server approval; reject residual requests in the owning tenant. Default-admin research observation remains read-only. A new demo tenant may not be in the Attack Lab selector. Approved notes remain synthetic evidence until explicitly cleaned.

## E06 Sandbox execution and human approval

Read [execution/audit cases](../cases/execution-and-audit.md), [sandbox_drill.py](../../../scripts/sandbox_drill.py), [server.py](../../../sandbox/server.py), [exec.py](../../../sandbox/exec.py) and [Compose](../../../docker-compose.yml).

```bash
.venv/bin/python scripts/sandbox_drill.py --phase prepare
.venv/bin/python scripts/sandbox_drill.py --phase verify --record '.local/learning-sandbox/YOUR_RUN_UUID.private.json' --report /tmp/learning-sandbox-verify.json
.venv/bin/python scripts/sandbox_drill.py --phase isolation --report /tmp/learning-sandbox-isolation.json
```

`learning-sandbox-v2` creates a dedicated bound session and fixed synthetic action in the default tenant. Between prepare and verify, open the printed fact-card URL and approve/reject it yourself. Approval expires after at most ten minutes. Prepare or terminal exit does not mean execution or cancellation.

Verify treats pending/executing/unknown as inconclusive and does not repeat. At terminal state it checks and clears the marker, finishes the session, revokes the grant and removes the temporary credential file. On interruption, inspect residual approvals yourself. Isolation calls the internal sandbox from the Web container and proves only its specified root-write/socket/mount/timeout limits. Offline MCP tests do not establish container-escape resistance or your current sandbox’s integrated approval result.

## E09 Memory storage in a research tenant

First run the online scripted memory lab so `.local/attack-lab.json` identifies the prepared research tenant. Read only its `lab.tenant_id` locally; do not print or share the credential file.

```bash
docker compose exec -T web python -m agentsentry.memory_security_lab --tenant 'YOUR_ATTACK_LAB_TENANT_ID'
```

Version `v2.6.0` includes 12 attacks and six controls. A09–A12 directly modify synthetic memory/source-review records to test read-time checks. The runner only accepts an existing Attack Lab tenant, clears synthetic memory text when finished, and exposes no arbitrary SQL/text/address input. Inspect leftovers after interruption.

Web: Memory security → Memory experiments → Storage security. Synthetic sources have dedicated details, not ordinary MCP call audit/Judge chains. A memory not returned in a fixed test does not prove a real answer stayed uncontaminated.

## E16 Read third-party evidence

Read [GitHub read-only](../cases/github-readonly.md), [public Issue analysis](../cases/github-issue-analysis.md) and [controlled write](../cases/github-controlled-write.md). Find fixed resources, pinned tool definitions, credential scope, no-attempt denominators, pre-approval zero and post-approval one effect, and the original unknown plus read-only reconciliation.

A new GitHub write creates a persistent external side effect and needs a dedicated synthetic repository, separate write PAT and human approval of concrete parameters. The handbook does not run write scripts or create another Issue automatically.

## Failure and delegation extensions

`python -m agentsentry.fault_lab` uses temporary SQLite and 22 controlled cases. `docker compose exec -T web python -m agentsentry.fault_lab --persist` saves conclusions to the configured database. View System and demo data → Failure isolation and recovery. PostgreSQL/queue scripts in [chapter 14](14-fault-propagation.md) clean temporary resources.

`python -m agentsentry.delegation_lab` uses 26 isolated cases; the container command with `--persist` saves summaries. Actual two-process work uses `agentsentry-demo --scenario delegation` and `agentsentry-reader`, with independent credentials and public synthetic resources. See [chapter 15](15-delegation.md).

## Troubleshooting

| Symptom | Check first |
| --- | --- |
| Passed command, empty Web | Temporary DB/direct rule function versus online database; selected tenant |
| Call/session not found | Temporary ID, synthetic source page, wrong data tenant; do not invent ordinary links |
| Empty daily goal list | New research tenant and old sessions not backfilled |
| Model unreachable | Service, installed model, sending process and registered address |
| Model preflight denied | Source level, credentials, destination, binding, budget and audit; do not bypass |
| Normal case pending | Conservative step-up, not completion; do not approve attack cases |
| No Judge result | Event applicability, frozen route, backlog or failed delivery |
| Comparison rejected | Mode, sample hash, case keys and completion compatibility |
| Loopback bind `PermissionError` | Local execution permissions; setup failure is not a defense assertion |

Without evidence, state unverified or inconclusive rather than inferring attack absence from an empty page.
