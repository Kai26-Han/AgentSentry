# MCP Tool Boundaries and Abnormal Results

[English](#) · [中文](../../cases/mcp-boundaries.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Question and controls

MCP connectivity does not remove added-tool, poisoned-description, invalid-parameter, malformed-result or lost-write-response risks. Expose fixed definitions, choose fixed upstream programs/mappings, authorize before dispatch, validate structure and **UTF-8 bytes**, and never automatically repeat uncertain effects.

## Observed evidence

Formal local SDK client tests covered tools/list, read and approved note: zero before approval, one afterward, same `call_id` no repeated write. Missing token, wrong scope/tenant, unknown tool and invalid parameters had no upstream execution.

2026-09-30, `deep-validation-v1` MCP group matched all nine cases in each of two rounds:

| Upstream behavior | Gateway result | Meaning |
| --- | --- | --- |
| Definition drift before tool dispatch | Failed | Connection/definition failure, no target effect |
| Wrong ID/type/oversize after dispatch | Unknown | Bad result cannot establish zero effects |
| Valid structure with malicious content | Completed, still low-trust | Protocol success is not semantic safety |
| Error/timeout after writing | Unknown; inspect actual note | No automatic resend |

Chinese result size had been checked by characters; it was fixed to UTF-8 bytes. A 4,096-byte limit is not 4,096 Chinese characters. [Observations](../../cases/evidence/boundary-observations.json) preserve fixed failures.

Controlled HTTPS/OAuth checks on the same date recorded review candidates/denied original calls for changed descriptions, rejection of online-added tools, and blocked target writes when card behavior changed under an unchanged manifest. PostgreSQL profile revision locks and pinned-IP selection were tested separately; initial administrator observation saved a snapshot and matched its probe.

## Reproduce and limits

[Local MCP](../local-mcp.md) and [execution chapter](../learning/05-execution-boundaries.md) provide fixed commands. Remote control is described in [remote MCP](../remote-mcp.md) and [supply profiles](../mcp-supply.md); [GitHub cases](README.md#choose-a-security-question) are separate actual services.

Explicit integration does not intercept other paths. A single synthetic probe does not prove third-party semantics, implementation integrity, public-DNS rebinding resistance, generic OAuth interoperability or long-term drift detection.
