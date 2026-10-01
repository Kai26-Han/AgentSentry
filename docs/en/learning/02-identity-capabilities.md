# 02 Identity, tenants, and least privilege

[English](#) · [中文](../../learning/02-identity-capabilities.md)

[Handbook](README.md) · [Previous: 01](01-security-boundaries.md) · [Next: 03](03-tool-policy.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Distinguish identity, capability, and session credentials; explain exact scope, expiry, uses, revocation, and tenant isolation; locate atomic Redis consumption and PostgreSQL revocation.

## Threat and credentials

An Agent authorized for public-guide requests private-notes, or tenant A's token is presented in tenant B. Knowing the caller does not establish resource permission.

| Credential | Establishes | Does not replace |
| --- | --- | --- |
| Agent key and X-Tenant-ID | Tenant/Agent identity | Tool/resource grant |
| X-Capability | Tool, exact resources, expiry, use limit | Policy, approval, other checks |
| X-Runtime-Session | Reported, running session membership | Tool authorization; session_id alone grants nothing |
| Admin login and CSRF | Management authority | Execution-time original-action checks |

Raw tokens remain in trusted code; stores locate them by hash. A Redis Lua operation verifies identity/tool/resource and decrements atomically, preventing check-then-consume races. Database expiry/revocation is also checked. Redis failure denies new calls.

Read `issue`, `CONSUME_SCRIPT`, `consume`, `revoke` in [capability.py](../../../src/agentsentry/capability.py), then grant rechecks in [service.py](../../../src/agentsentry/service.py). Failed issuance attempts cache cleanup; committed database revocation remains effective even if cleanup fails. Tenant selection: [tenants.py](../../../src/agentsentry/tenants.py), [database.py](../../../src/agentsentry/database.py). Session issuance: [runtime_binding.py](../../../src/agentsentry/runtime_binding.py). Regex/model judgment does not establish exact resources.

## Exercise: valid, exhausted, revoked, cross-tenant

Offline database, Redis stub, FastAPI test client:

```bash
.venv/bin/python -m pytest -q tests/test_service.py::test_scope_and_revocation_deny tests/test_service.py::test_idempotency_and_exhaustion tests/test_v2_tenants.py
```

| Case | Inspect | Expected |
| --- | --- | --- |
| Valid grant and unchanged replay | Task count/results | Exactly one effect |
| Wrong resource or revoked token | State | denied |
| New action after exhaustion | New call/Task count | denied, no task |
| Two tenants accessing each other | Identity, policy, background assertions | No cross-tenant reading or management |

The normal control rules out "deny everything." These tests alone do not cover every expiry/token attack; also inspect the [fixed corpus](13-validation-calibration.md).

## Dashboard and limits

Tool access grants issue/revoke tokens shown once. Investigation links grants to calls. Default-admin research viewing is read-only, not general cross-tenant management.

Later checks may deny after consuming quota. No execution does not imply no token use. Compatibility defaults to no mandatory binding for all old callers; sensitive writes/model exits still require it, and unbound tools have no action budgets.

Shared process/database credentials mean schema isolation does not survive gateway compromise. A stolen Agent key can establish new sessions, although it cannot itself issue admin grants.

## Self-check

Can identity plus session_id issue a capability? **No.** Does permission for public-guide include other public files? **No, scope is exact.** Use sufficient but finite grants to observe exhaustion/revocation.

[Onboarding](../tenant-demo.md) · [Authorization case](../cases/tool-permission-and-approval.md) · [TH-003](../threat-framework-mapping.md#th-003)
