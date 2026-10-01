# Output Safety and Provenance

[English](#) · [中文](../output-safety.md)

## Check location

HTTP/MCP model answers and fixed demo outputs go through the gateway before display. It verifies actual sources and the original task binding, commits a decision and returns eligible text. The adapter displays only that returned text. Failed checking/commit yields a fixed safety notice, never the unchecked draft.

```text
Task + actual document/MCP/memory/delegation sources → draft → gateway check
   → committed output/source/data-flow evidence → adapter displays approved text
```

This synchronous control differs from asynchronous Judge. Provenance proves arrival, not truth, and cannot undo already executed tools. Only integrated display paths are covered.

## Decisions: output-rules-v6

| Decision | Typical condition | Display |
| --- | --- | --- |
| `block` | Credentials, restricted-source session, private/recoverable encoded sensitive text, forged sources, source output/action payload obedience, analysis limit | Fixed safe notice |
| `warn` | Direct personal information, unverified sentences, suspicious quoted instructions or optional local hints, without stronger block | Returned safe text with warning; personal information redacted |
| `allow` | No existing match | Eligible answer, not truth/safety certification |

Reading private/unknown/secret material blocks the whole free-text answer, including unrelated normal answers. Count that as false blocking, as in [private leakage cases](cases/private-data-leakage.md). Source output/action patterns come from actual reads, not only a fixed attack marker. A quotation exception needs an explicitly bound original user task and attributed quotation; other secret/source controls still apply. [A03/A12 cases](cases/injection-and-output.md) keep draft/display facts separate.

## Request integrity

`POST /api/v2/runtime-sessions/{session_id}/output-check` requires tenant Agent identity/session binding, check ID, draft, task context, capture mode and source IDs. Adapter-supplied actual sources are checked for tenant/Agent/session/completion/content/level. Missing, repeated, forged or cross-session sources fail. Same ID/content is idempotent; changed content conflicts. Session start processes the original task and saves a keyed fingerprint; the check cannot replace it with a task favorable to release. Old unbound tasks get no quote exception or fabricated history.

## Privacy and optional hints

Both modes temporarily deliver required raw draft/task to the local gateway and have identical checks. Preview stores bounded rule-redacted snippets; metadata stores only fingerprints/decisions/rules/sources/status, no task/answer snippets. Raw output requests are not placed in application logs or Judge Outbox. Long-term memory and restricted operation/delegation text have separate retention; see [architecture privacy](architecture.md#data-retention-and-privacy).

Optional `OUTPUT_LOCAL_MODEL_BASE_URL`/`OUTPUT_LOCAL_MODEL_NAME` connect explicitly to a local endpoint; off by default, separate from Judge. Hints do not independently authorize/block. See [sender and Docker addresses](local-model.md).

```bash
.venv/bin/python -m agentsentry.output_samples
```

Use [offline conventions](learning/README.md#prerequisites-and-command-conventions) and [chapter 06](learning/06-input-output-safety.md) controls. Finite patterns can miss semantic/multilingual variants and overblock quotes; no arbitrary truth guarantee or transparent coverage is claimed.
