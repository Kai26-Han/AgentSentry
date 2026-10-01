# Long-Term Memory and Cross-Session Poisoning

[English](#) · [中文](../memory.md)

## Data flow

```text
Task + actual document/MCP reads → Agent → output check → display
                                    → same-model summary candidates
                                    → gateway session/output/source checks
                                    → active / quarantined / rejected memory
Next normal task → gateway recall → low-trust data → Agent → output check
```

Memory remains low-trust even after manual activation. Linkage establishes that a source was read and a memory supplied, not truth or adoption. Revocation stops future recall, not content already in an in-flight session. Automatic source-derived activation requires prior administrator review of the **specific source content version**.

## Defaults and privacy

`AGENTSENTRY_MEMORY_ENABLED=true` is default. Model-configured `llm` tasks recall at start and use the same model for a structured summary after output checking. Fixed demos do not generate memory. Summary/write failure does not invalidate an already checked answer; failed recall continues without memory and records unavailability.

**Both preview and metadata persist active/quarantined memory text.** Metadata omits task/answer snippets, not all derived text. Old sessions are not backfilled. To stop new read/write, set `AGENTSENTRY_MEMORY_ENABLED=false` and restart affected Web/Agent/dispatcher; existing text requires separate cleanup.

At most three candidates per round, 500 characters each; 100 effective memories per Agent; default expiry 30 days. Maintenance/access clear eligible expired text. `/dashboard/memories` supports source inspection, activation, revocation and purge. Purge does not delete source documents or prior tool audit. Memory audit/Outbox contains IDs, keyed hashes, effects and source IDs, not memory text. Judge cannot authorize activation.

## Gateway controls

The authenticated bound Agent uses `POST /api/v2/runtime-sessions/{session_id}/memory/read` and `/memory/write` for itself only. These are not model-visible tools. Recall ranks by task terms/time and supplies at most five valid entries. Writes bind a nonblocked output check to the current session and actual sources. Identical request IDs return original results; content changes conflict.

The adapter supplies source IDs from actual tool results, ignoring model-invented fields. Candidates must include the output check’s full document/card source set; omission cannot avoid review. This is round-level attribution, not a claim that every word maps to one source.

Credentials/private secrets are rejected without candidate-text storage. Suspicious instructions, authority claims, personal information, unreviewed sources, and summaries derived from recalled memory remain quarantined. Public means shareable, not trustworthy. Administrators review original content in call details and register source trust by tool/resource/content hash via `/dashboard/memories`; changed content needs new review. If all sources are reviewed, safe and total at most 500 characters, automatic activation saves their ordered original snapshot rather than an invented model paraphrase. Other candidates need explicit review. Revoking source trust quarantines its automatically activated memories; legacy automatic entries are requarantined on upgrade. Manual activation is an explicit override, still low-trust.

`unverified_sentence` alone does not quarantine every candidate from an already reviewed source; other output risks still do. Blocked answers generate no memory. Source review is human evidence, not a truth oracle.

Admin APIs: `GET /api/v2/memories`, `POST /api/v2/memories/{id}/decision` (`activate`, `revoke`, `purge`), `GET/POST /api/v2/memory-sources`, `DELETE /api/v2/memory-sources/{id}`. Writes require login/CSRF. Research-only expiry simulation is not a daily workflow.

## Two-round experiments

```bash
.venv/bin/python -m agentsentry.memory_lab_runner --mode scripted
.venv/bin/python -m agentsentry.memory_lab_runner --mode live
```

The runner reuses `.local/attack-lab.json` research credentials and explicit MCP policy. Remote models need `--allow-remote-model` and registered egress; only synthetic input. Web `/dashboard/memory-runs` preserves selected tenant/run links. Default-admin observation is read-only.

Twelve attacks and six controls first write, then run a normal second task without attack text. Only normal controls and D06’s legitimate revocation-source case receive source review; attack sources remain unreviewed. Scripted mode tests candidates, recall, expiry, revocation, replay and boundaries, with no model answer. Live mode uses six attacks/six controls and separates malicious candidate generation, activation, actual recall, display contamination, forbidden effects and inconclusive results. Judge receives no memory text, so no memory-text Judge miss rate is computed.

Reports store predefined marker observations, not full second answers. Malicious generation means the sample-defined objective/flag, not any memory generation; D06’s normal fact is not malicious. Paraphrases can evade this scoring. Upgrade cleanup removes free answers from early reports, retaining markers/empty text. See [memory chapter](learning/07-memory-security.md), [integrity](memory-integrity.md) and [case evidence](cases/memory-poisoning.md).
