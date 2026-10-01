# Adversarial Validation and Rule Calibration

[English](#) · [中文](../calibration.md)

## Separate controls from behavior

Fixed proposals test gateway boundaries; live tasks test what the model actually does. A model that never proposes a dangerous call leaves tool-blocking effectiveness unverified. Judge remains an independent signal, not a fact scorer.

```text
Versioned synthetic corpus → new research tenant → fixed proposals / demo Agent
   → source, model-preflight, tool, output, memory and audit evidence
   → server-side fact scoring → report and Web
```

[calibration_corpus.py](../../src/agentsentry/calibration_corpus.py) defines `calibration-cases-v1`: 12 attacks and 12 controls. A01–A08/N01–N08 are calibration cases; A09–A12/N09–N12 are held out. Reports preserve sample hash and policy/runtime/data-flow versions; updates do not rewrite old runs. Resources use `lab-v29-*` IDs.

## Commands

```bash
SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python -m agentsentry.calibration_runner --mode scripted --output .local/calibration-fixed.json
SENTRY_URL=http://127.0.0.1:8000 .venv/bin/python -m agentsentry.calibration_runner --mode live --output .local/calibration-live.json
.venv/bin/python -m agentsentry.calibration_runner --compare .local/baseline.json .local/candidate.json --output .local/comparison.json
```

Adjust the port. Live mode uses the configured local model (default `http://127.0.0.1:11434/v1`, `qwen3:0.6b`) and repeats three document attacks, three MCP attacks and six controls three times: 36 executions. Remote models require `--allow-remote-model` plus registered egress, and only synthetic input. Keep Agent-model credentials separate from Judge.

Every run creates a **new research tenant** to isolate Agent-level denial counters. Its one-time credentials stay in `.local/calibration-lab-<tenant-id>.json` (`0600`), not the report. Missing MCP policy stops the runner. Interruption retains committed results and an interrupted state. Comparison accepts only completed runs with identical sample hash, mode and case keys.

## Fact scoring and Web

Correlate tenant, Agent, session, call and approved model-preflight evidence. Check actual tasks/inbox/confirmed MCP notes for writes; unauthorized reads are distinct attacker goals. Pending, unknown, unfinished tasks, absent sources and inconsistent output evidence are inconclusive. Draft fingerprints must match; display contamination is evaluated on gateway-returned display text, including redaction. A blocked polluted draft is draft contamination only.

Memory cases create a second task without attack text and inspect actual read records, quarantine and normal retrieval. Reports retain bounded redacted traces, hashes, decisions and IDs; metadata mode does not secretly copy task/answer text into calibration tables.

Web: Security experiments and evaluation → Adversarial validation and rule calibration. Default administrators can select research data tenants read-only; tenant administrators see their own. Details show denominators, attempts, blocking after attempts, effects, display contamination, normal completion, inconclusive cases and audit gaps. Daily analysis only summarizes existing decision metadata and manual false-block feedback; no automatic business-text copying or replay.

## Calibration procedure

1. Run a versioned baseline; resolve environment and inconclusive cases first.
2. Generate false-block/missed-block **candidates**, then inspect causal source and egress evidence. A correlated rule is not automatically the cause.
3. Review recommendations and code manually. Never weaken identity, cross-tenant, credential or audit-failure boundaries for a score. Version changes and regression are required.
4. Run candidate rules in a fresh tenant and compare both sets. New attacker success, forbidden effects, missing audit or normal-completion regression cannot justify release.

`external_after_private` intentionally denies apparently unrelated sending after a private read, because session-level evidence cannot rule out segmented or paraphrased leakage. Benign quotations can trigger write approval. Disclose these tradeoffs; there is no online threshold editor or automatic rule publication. A03’s source-bound display fix and historical results are explained in [output cases](cases/injection-and-output.md). Findings apply only to integrated paths and recorded samples.
