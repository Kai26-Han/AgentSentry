# 03 Tool policy and argument boundaries

[English](#) · [中文](../../learning/03-tool-policy.md)

[Handbook](README.md) · [Previous: 02](02-identity-capabilities.md) · [Next: 04](04-approval-safety.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Separate registration, type checks, policy, and resource grants. Explain deny precedence and safe reload. Verify unchanged replay versus changed-content conflict.

## Mechanism

Unknown tools, extra arguments, out-of-scope resources, and modified retries are threats even when JSON looks valid.

```text
Registered schema → type/size checks → YAML decision
                      + exact resource capability
                      + runtime/data-flow/action-budget checks
                      → allow / deny / require_approval
```

YAML matches tools with optional deny-only field regex; it is not a general expression language or exact-resource authorization. Precedence: deny > require_approval > allow; unmatched means default_deny. Sensitive delete/send/Shell/MCP-note/GitHub-write tools cannot simply become allow.

Read [schemas.py](../../../src/agentsentry/schemas.py), [policy.py](../../../src/agentsentry/policy.py), [default.yaml](../../../policies/default.yaml), and request digests/idempotency in [service.py](../../../src/agentsentry/service.py). Dashboard Tool policy edits tenant YAML; Runtime security rules is a separate read-only catalog. Editing a host default file does not update every active volume/tenant policy.

## Exercise

Use offline temporary candidates:

```bash
.venv/bin/python -m agentsentry.policy_tests --policy policies/default.yaml --cases policy-tests/cases.yaml
.venv/bin/python -m pytest -q tests/test_policy_suite.py tests/test_service.py::test_policy_deny_precedes_capability tests/test_service.py::test_idempotency_and_exhaustion tests/test_v15.py::test_policy_hot_reload_is_atomic_on_invalid_candidate
```

| Case | Evidence | Expected |
| --- | --- | --- |
| Default cases | Effect and winning rule ID | Normal reads/tasks; approval for sensitive actions |
| Secret-marker simulated send | prohibit_secret_marker and inbox | denied, no message |
| Invalid reload | Active revision before/after | Candidate rejected, old policy usable |
| Same replay / changed title | Task count, result/status | One execution / 409 |

[Suite tests](../../../tests/test_policy_suite.py) detect rules without a case. Testing the default file is not field validation of customized tenant policy.

## Limits and self-check

Regex misses semantic rewrites; allow still needs grants and other checks. HTTP validation can reject with 422 before creating ToolCall, so not every input error has a full business audit chain. Idempotency is tenant + call_id + same request. A new ID is new; never automatically repeat unknown effects.

1. Can allow before deny override it? **No, effect precedence applies.**
2. Does no password regex match prove safe sending? **No: inspect source level and authorization.**
3. Why reject changed-content replay? **It must not alter an approved/executed action.**

[Policy runner](../../../src/agentsentry/policy_tests.py) · [Data flow](08-sensitive-data-flow.md) · [Reload/audit case](../cases/execution-and-audit.md)
