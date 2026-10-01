# 07 Long-term memory and storage contamination

[English](#) · [中文](../../learning/07-memory-security.md)

[Handbook](README.md) · [Previous: 06](06-input-output-safety.md) · [Next: 08](08-sensitive-data-flow.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Trace source → candidate → storage → next session; distinguish review, state, read checks and seals; explain revocation, expiry, purge and disable.

## Threat and pipeline

A first-session card induces a persistent fake fact or future bypass instruction. A clean second task can still inherit it. Direct database text/state/review mutation is a separate attack.

```text
Low-trust sources + checked answer → model candidates
→ gateway checks output/sources/content/seals
→ active / quarantined / rejected
→ next session rechecks state/expiry/seal/source
→ at most five low-trust memories → model and output checks
```

Summary model requests also pass preflight. Blocked answers produce no memories; summary failure does not affect a checked answer. Public does not mean trusted; automatic activation requires review of that exact source version.

## Code and retention

Read write_candidates, _classify, read_memories, _safe_active, trust_source, decide_memory in [memory.py](../../../src/agentsentry/memory.py), seals in [memory_integrity.py](../../../src/agentsentry/memory_integrity.py). Trusted code supplies actual IDs, not model-reported IDs.

Credentials are rejected; suspicious/unreviewed/private content quarantined. Manual activation keeps low trust and does not authorize remote sending. Changed reviews invalidate old links; new IDs cannot launder old memory. Reviewed short-source automatic memory stores the reviewed snapshot, not a model rewrite.

Both preview and metadata store memory text. Default expiry is 30 days; valid active/quarantined records clear text during cleanup/access. Integrity failures need separate handling, not automatic "repair" into trusted records. Revoke prevents future reads and usually retains text; purge clears it; disabling stops future reads/writes without deletion. Already delivered context cannot be recalled.

## Exercise

Offline stubs/temporary storage; no real model/daily memory:

```bash
.venv/bin/python -m pytest -q tests/test_memory.py tests/test_memory_api.py tests/test_memory_lab.py tests/test_memory_security_lab.py
```

| Case | Evidence | Expected |
| --- | --- | --- |
| Reviewed normal memory in next session | Entry/read/source version | Returned when valid; absent after revoke |
| Credential/instruction/unreviewed fake fact | State/reason/audit | Reject/quarantine; no raw text in memory audit |
| Forged source, changed replay, stale output | IDs/digest | Refuse/conflict |
| Mutate text/state/review and replay old read | Seal/returned set | Tampered memory absent |

Storage-lab fixtures may precreate completed reads; that is not real MCP transport or model behavior.

## Optional two-session online experiment

Use another terminal with gateway/MCP policy:

```bash
.venv/bin/python -m agentsentry.memory_lab_runner --mode scripted
```

It creates/reuses the research tenant from .local/attack-lab.json, installs synthetic materials, writes then reads, and clears previous case memories. View Memory security → Memory experiments → Cross-session contamination. **Do not keep daily notes in this tenant.** No model answers exist in scripted mode; absent retrieval is not proof of clean generated output.

Use --mode live after model setup. No arbitrary case-ID or --output support; terminal/Web hold results. Storage-tampering extension [E09](experiment-index.md#e09-memory-storage-in-a-research-tenant) requires an existing research tenant.

## Scoring, limits, self-check

Record malicious generation, activation, retrieval, later displayed contamination, and forbidden effects separately. Any candidate is not automatically malicious; retrieval is not obedience. D06 tests normal-fact revocation and is excluded from malicious-summary counts.

Seals protect database mutation when the signing key remains safe; reviewers can still accept false content. Remote sending remains separately controlled after activation. Revocation cannot remove ongoing context. metadata still stores memory.

[Memory](../memory.md) · [Poisoning case](../cases/memory-poisoning.md) · [Integrity](../memory-integrity.md) · [TH-004/005](../threat-framework-mapping.md)
