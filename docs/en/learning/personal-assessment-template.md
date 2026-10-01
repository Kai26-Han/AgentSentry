# Personal Learning Record and Final Summary Template

[English](#) · [中文](../../learning/personal-assessment-template.md)

[Assessment guide](personal-assessment.md)

Copy this into your private local learning directory. `init` provides editable `record.json`. Placeholder text is not completed work. Share only redacted synthetic summaries after checking credentials, browser cookies and one-time tokens; the complete record stays local by default.

## Per-topic review

- Topic ID and task version:
- Prediction recorded through `predict` before execution:
- Normal facts: decision, actual execution/model send, display or memory state:
- Boundary facts: attacker-controlled input, rule and actual effects:
- Evidence: local report plus test node; for online work include tenant/session/call/check IDs:
- Independent explanation: where the check and execution occur:
- Self-check answers, including what Judge actually observed:
- Variation: synthetic change, prediction, observation and evidence:
- Limitation / false block and missing evidence:
- Personal state: not yet studied / needs review / mastered:
- Reviewer, actual date and basis: self or human review:

Edit `review` and `personal_status`; preserve `experiments`, versions and prediction snapshots. The stored enum stays Chinese even with English explanations:

```json
{
  "personal_status": "待复核",
  "review": {
    "explanation": "Explain the check and execution positions in your own words",
    "evidence": ["reports/REPLACE_WITH_CURRENT_REPORT.json"],
    "answers": "Answer each question and cite its basis",
    "variation": "Synthetic change, prediction, observation and evidence",
    "limitation": "One boundary not covered",
    "reviewer": "Self or human reviewer",
    "reviewed_at": "REPLACE_WITH_ACTUAL_REVIEW_DATE"
  }
}
```

`待复核` means needs review; do not replace required enum values with English. Do not include credentials, business source text or full free-form model answers. A call ID alone is insufficient: identify the temporary database or running data tenant.

## Practice record: S01–S05 / L01–L03

- Practice ID, date, environment:
- Corpus version, model/version and policy revision:
- Current evidence location:
- Whether the normal task completed:
- Dangerous proposal / actual effect / display contamination / memory propagation, separately:
- Pending, unknown, no attempt and environment error, separately:
- Your explanation and human review:
- Cleanup: residual approvals/grants, worker/schema and synthetic text:

`record.json.practice` contains human claims only. Its stored status values remain `未执行` / `通过` / `失败` / `无法判定` / `待复核` (not run / passed / failed / inconclusive / needs review), not an automatic pass.

## Final summary

### Foundational mechanism learning

- Topics understood and evidence:
- Reviews or experiments still needed:
- Product problems found:
- False blocks and tradeoffs:
- Self/human conclusion: complete / partial / not yet complete:

### End-to-end practice

- Completed S/L tasks and evidence:
- Incomplete or inconclusive tasks and reasons:
- Real-model attack categories with no dangerous attempt:
- Self/human conclusion: complete / partial / not yet complete:

### Next study round

| Priority | Topic/problem | Next experiment | Decidable fact | Cleanup |
| --- | --- | --- | --- | --- |
| Fill in | Fill in | Fill in | Fill in | Fill in |

Test counts do not measure personal mastery or framework-wide coverage. Explaining a product gap accurately does not turn its failed experiment into a pass.
