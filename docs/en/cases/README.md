# Advanced Security Cases

[English](#) · [中文](../../cases/README.md)

After the [project entry](../../../README.md) and [handbook](../learning/README.md), use these cases to investigate gaps, reconcile effects, verify fixes and explain tradeoffs. No development-history reading is needed. Each case retains the original failure and later evidence, separating fixed replay, real model and onsite checks rather than adding them into a coverage score.

## Choose a security question

- [Authorization and races](tool-permission-and-approval.md)
- [Sandbox and reliable audit](execution-and-audit.md)
- [MCP protocol and results](mcp-boundaries.md)
- [A03/A12 display contamination](injection-and-output.md)
- [Cross-session memory poisoning](memory-poisoning.md)
- [Private paraphrase leakage](private-data-leakage.md)
- [Runtime and budgets](runtime-and-budget.md)
- [Single-hop delegation](delegation-boundaries.md)
- [Cross-boundary fault validation](boundary-validation.md)
- [GitHub fixed readonly file](github-readonly.md)
- [GitHub public Issue behavior](github-issue-analysis.md)
- [GitHub approved write](github-controlled-write.md)

## Study a case

Predict from the question/control, run linked offline tests first, then prepare online/model/third-party work separately. Check actual execution/display/audit, not only Judge. Write your own [assessment record](../learning/personal-assessment.md) with date, mode, corpus/rule version and inconclusive items. Use corpus-plus-ID, e.g. `goal-lab-v1:A12`.

Fixed proposals do not establish model inducement; passing cases do not generalize to all paraphrases/third parties. Shared [redacted evidence](../../cases/evidence) contains bounded synthetic facts, no credentials/business text/private database. Some original JSON labels remain Chinese; English cases explain their facts. Generate your own Web records rather than attempting to query an author’s private IDs. See [threat matrix](../threat-framework-mapping.md).
