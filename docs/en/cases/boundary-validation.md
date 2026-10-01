# Fault Injection and Cross-Boundary Validation

[English](#) · [中文](../../cases/boundary-validation.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Method and baseline

Group identity/approval, output, memory, behavior and MCP boundaries. Specify expected facts before injecting faults in isolated research environments. Do not sum groups into security coverage.

2026-09-30 `deep-validation-v1`: two rounds of 49 actual PostgreSQL/Redis/HTTP cases, each 46 matched/three failed private numeric display. Additional revoke/expiry race probes were each run twice; before fixes each could produce an unauthorized synthetic write. Passing other samples does not cancel confirmed failures.

| Finding | Fix/tradeoff | Detail |
| --- | --- | --- |
| Stale concurrent approval entity | Refresh after row lock | [Authorization](tool-permission-and-approval.md) |
| Revoke/expiry race | Shared serialization and final validity check | [Approval](tool-permission-and-approval.md) |
| Source override command merely warned | Explicit display-block assertion | [Output](injection-and-output.md) |
| Negative task reading intent missed | Better limited profile, still advisory | [Goal drift](../goal-drift.md) |
| Chinese MCP size counted characters | UTF-8 bytes | [MCP](mcp-boundaries.md) |
| Semantic private number remained visible | Whole restricted-session free-text block, with false blocks | [Leakage](private-data-leakage.md) |

[Observations](../../cases/evidence/boundary-observations.json) retain old failures and probes. Separate post-fix output sets have 14 cases twice; never overwrite the baseline three failures.

## Models and failures are separate

Related qwen3:0.6b observations have different denominators: calibration 36, memory 12, action chain 12. Calibration attacks had no dangerous attempts; memory no malicious activation; behavior eight attempts/one budget denial. None substitutes for the fixed fault tests.

[Failure isolation](../fault-propagation.md) tests breakers, leases, generations and recovery; [redacted summary](../../cases/evidence/fault-propagation.json) preserves its fixed scope. Unknown effects are not replayed, and Judge/broker failures do not reauthorize tools. Shared-infrastructure cross-Agent cascades need more work.

## Reproduce

Choose a theme from the [experiment index](../learning/experiment-index.md), run offline assertions first, then prepare independent DB/model work. Use [calibration](../learning/13-validation-calibration.md) to record baseline/failure/recommendation/human decision/held-out result. Include one normal control, one boundary assertion and actual effects. Pending/unknown/unfinished/environment errors are not defense success.
