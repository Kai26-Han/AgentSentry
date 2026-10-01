# Risk Scope and Evidence

[English](#) · [中文](../risk-coverage.md)

This page separates implemented controls from what their evidence establishes and what remains. See the [project plan](../../PROJECT-PLAN.en.md), [architecture](architecture.md), [advanced cases](cases/README.md), [scenario matrix](threat-framework-mapping.md) and [daily mapping](runtime-threat-mapping.md). No overall Top 10 coverage percentage is calculated; linked/unlinked mapping is not proof of attack/safety.

| Scenario | Current evidence/conclusion | Remaining work |
| --- | --- | --- |
| Identity/resource/approval | [Scope and concurrency cases](cases/tool-permission-and-approval.md); revocation/expiry races remediated within tested path | Compromised application/DB credentials and human error |
| Injection/output, TH-001/002 | [A03/A12](cases/injection-and-output.md) explicit payload display fixed; partially verified | Implicit semantics, languages, variants actually triggered by models |
| Fixed injected source, TH-012 | Verified fixture arrives as a tool result | Proposal, draft and display assessed separately |
| Memory poisoning/tamper, TH-004/005 | [Memory cases](cases/memory-poisoning.md) write/read/revoke/integrity boundaries | Truth, misreview and semantic contamination |
| Private leakage, TH-006/007 | [Paraphrase cases](cases/private-data-leakage.md) three numeric forms blocked after fix; partial, unrelated normal answers also blocked | Verifiable display templates, larger models, misclassification, bypass paths |
| Approval deception, TH-008 | Frozen action/fact card/current-state checks | Automation cannot prove humans resist manipulation |
| Sandbox, TH-009 | [Execution cases](cases/execution-and-audit.md) fixed isolation probes/pre-approval zero effects | Escape, other OS, production isolation |
| MCP supply chain, TH-010 | [MCP](cases/mcp-boundaries.md), [supply controls](mcp-supply.md), three GitHub cases; partial | Public DNS, generic OAuth, long-term semantics/program replacement |
| Autonomous drift, TH-011 | Wrong fixed proposals and pressure tasks exist; unverified | Long attacker-free tasks, more models, within-budget drift |
| Runtime/budgets, TH-013 | [Behavior cases](cases/runtime-and-budget.md) stable fixtures and observed live budget denial; partial | Mandatory caller binding, more loops, cross-Agent behavior |
| Failure cascade, TH-014 | [Boundary cases](cases/boundary-validation.md), [failure mechanisms](fault-propagation.md); partial | Shared infrastructure, sustained load, cross-Agent cascades |
| Delegation, TH-015 | [Independent identity/seal/two-process evidence](cases/delegation-boundaries.md); partial | Multi-model/write/multihop/cross-host/truth |

The matrix is authoritative for exact test references. Judge evaluates received events only; unsubmitted answers are not Judge false negatives.

## Keep third-party evidence separate

[Fixed GitHub reading](cases/github-readonly.md) proves that registered read path at that time, not arbitrary tools/repositories. [Public Issue analysis](cases/github-issue-analysis.md) recorded no dangerous attempts and blocked normal summaries; no-attempt is unverified tool blocking, and normal-task denial is not defense success. [Controlled write](cases/github-controlled-write.md) recorded zero before approval and exactly one afterward, with unknown reconciled read-only; the revised parser has no second real write verification.

## Maintain evidence

Use corpus version plus ID, e.g. `goal-lab-v1:A12`. Cases retain question/cause/mode/date/version, before/after facts and tradeoffs. Preserve failures/inconclusive results. New findings require new evidence, not rewriting past outcomes.

Canonical [mapping YAML](../threat-framework-map.yaml) supplies both matrices:

```bash
.venv/bin/python scripts/check_threat_mapping.py --write
.venv/bin/python scripts/check_english_docs.py --write
.venv/bin/python scripts/check_threat_mapping.py --check
.venv/bin/python scripts/check_english_docs.py --check
```

English prose overlays do not modify daily matching conditions, mapping version or framework snapshot. New classification conditions require separate version/regression; existing matched events retain original snapshots. Do not edit generated matrices manually.
