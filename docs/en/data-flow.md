# Sensitive Data Flow and Leakage Prevention

[English](#) · [中文](../data-flow.md)

Current rules: `data-flow-rules-v4`, `output-rules-v6`. Restricted-source sessions have free-text answers blocked, including some unrelated normal answers; see [leakage cases](cases/private-data-leakage.md).

```text
Documents / MCP / sandbox / tasks / memory → server-classified actual sources
   → Agent context → pre-send model check → registered model
                   → tool-write check and approval recheck
                   → answer check → eligible display
                   → memory candidate check
Each decision → tenant audit / Outbox / alerts / Sensitive data flow
```

Only explicitly integrated demo HTTP/MCP paths are protected. `send_external` still writes a local simulated inbox; it does not send real network messages.

## Classification and exits

Documents use server-side sensitivity; MCP cards use a fixed gateway catalog, unknown cards are private; sandbox output/task titles default private; memory inherits source levels. Explicit credentials elevate content to secret. A source’s claim to be public does not alter this. Instruction trust and confidentiality are separate attributes.

| Exit | Synchronous control |
| --- | --- |
| Local model | Public/private allowed; explicit credentials blocked |
| Remote model | Registered HTTPS only; private/unknown/secret sources, credentials or personal information blocked |
| Simulated external send | Any private/unknown/secret source in the session denies sending; public-only still needs normal approval |
| Local task, MCP note, sandbox command | Credentials blocked; private local task/note content steps up approval; all write tools require valid session binding |
| Final answer | Restricted-source free text blocked; secrets/private text/recoverable encodings blocked; direct personal information redacted if no stronger block, encoded personal information blocked |
| Long-term memory | Secret candidates rejected; private-source candidates quarantined; activation grants no remote egress |

These are deterministic controls, not Judge authorization. Literal/URL/limited Base64 checks are not a general semantic detector. Session-wide restrictions also prevent segmented simulated sending, at the cost of false blocks.

## Model destinations and API

HTTP, MCP and memory summaries all call `POST /api/v2/runtime-sessions/{session_id}/model-egress/check` before sending. Submit request ID, destination ID, model, purpose, actual messages and supplied source IDs with Agent and session credentials. The gateway checks exact tenant source linkage and returns decision, check ID, base URL and approved messages. The adapter sends only that content. Same ID/different content conflicts; unavailable checks, failed audit or destination mismatch mean no send. Messages are limited to 64 KiB.

Default local registration: `http://127.0.0.1:11434/v1`. If `DEMO_MODEL_BASE_URL` differs, synchronize gateway `AGENTSENTRY_MODEL_LOCAL_BASE_URL`. Register remote addresses in `AGENTSENTRY_MODEL_REMOTE_DESTINATIONS`, e.g. `{"research":"https://example.invalid/v1"}`; set Agent `AGENTSENTRY_MODEL_DESTINATION=research` and matching base URL. Model keys stay in the adapter, not model messages/preflight records. Judge keys are separate.

## Evidence and retention

`data_flow_decisions` stores IDs, destination, source level, rule, effect and keyed fingerprint, not check-message text. Blocking/quarantine can create tenant leakage alerts. New tool audit/Judge events retain keyed parameter/result hashes, length and necessary flags rather than raw contents.

Operation rows temporarily retain parameters/results for approval, idempotency and source checks, masked by default in Web. Dispatcher clears eligible ended new records after 30 days; pending/unknown records remain. Historical rows are not migrated and show retention warnings. Preview and metadata execute identical checks; metadata omits task/answer snippets but still has separate operation/memory retention.

Web: Runtime analysis → Sensitive data flow, by session and exit. Default admins may read research tenant evidence separately; it is not merged into daily data.

## Run and compatibility

```bash
.venv/bin/python -m agentsentry.data_flow_lab
```

The 30 fixed cases use temporary SQLite and send counters, producing `.local/data-flow-report.json`, no real model calls and no Web data. Read-only legacy calls still work; `create_task`, `send_external`, `mcp_record_note`, `run_shell` require session start and `X-Runtime-Session`. Historical approvals missing required checks must be resubmitted. Live evidence uses the [attack lab](attack-lab.md) document/MCP paths and separately measures sends, effects and display. See [chapter 08](learning/08-sensitive-data-flow.md).
