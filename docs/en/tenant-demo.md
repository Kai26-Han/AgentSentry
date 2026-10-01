# Tenant Onboarding and Agent Demo

[English](#) · [中文](../tenant-demo.md)

Default-admin login uses `default` and your private `.env` password. Its data is PostgreSQL public schema; each new tenant gets an independent server-generated schema, without another tenant’s calls/memories/experiments.

## Local walkthrough

Start with the [quick start](../../README.md#quick-start). Default admin → Administration → Tenants → create. Save the once-only tenant ID, admin password and Agent key. Log out, log into the new tenant and issue a short-lived limited `read_document` capability for `public-guide`.

```bash
export AGENT_TENANT_ID='YOUR_NEW_TENANT_ID'
export AGENT_API_KEY='YOUR_TENANT_AGENT_KEY'
export AGENT_CAPABILITIES_JSON='{"read_document":"YOUR_NEW_CAPABILITY"}'
export SENTRY_URL='http://127.0.0.1:8000'
.venv/bin/agentsentry-demo --scenario read-public
```

Inspect that tenant’s call/Judge evidence; default daily lists must not mix it in. Dedicated read-only research observation does not grant cross-tenant writes. `python scripts/tenant_demo.py` can create/grant/demo and saves credentials locally in `.local/<tenant_id>.json` (`0600`); never commit it.

## Identity and configuration

`GET/POST /api/v2/tenants` is default-admin only; creation body `{"name":"Team A"}`, one-time credentials, CSRF for writes. Tenant admins manage their own capabilities/policy/approval/memory/audit/Judge. Agents use matching Bearer identity, `X-Tenant-ID`, `X-Capability`; omitted tenant header defaults to default for compatibility.

Outbox/notification preserves tenant ID and workers reopen the correct schema. Judge route is tenant-specific; Webhook destination is platform configuration. New tenants explicitly deny shared `run_shell`; default needs capability, binding and approval. Schema isolation does not protect against shared DB/application/host compromise.

Tenant policy derives from default with shell denial, stored as `<tenant_id>.yaml` in the configuration volume. Test your actual custom policy; default scores do not establish custom behavior.

```bash
.venv/bin/python -m pytest -q tests/test_v2_tenants.py
.venv/bin/python -m agentsentry.policy_tests --policy policies/default.yaml --cases policy-tests/cases.yaml
```

Use [offline environment conventions](learning/README.md#prerequisites-and-command-conventions) for tests. See [authorization/approval cases](cases/tool-permission-and-approval.md).
