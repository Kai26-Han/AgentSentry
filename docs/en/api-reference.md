# API and Web Entry Index

[English](#) · [中文](../api-reference.md)

[Project home](../../README.md) · [Architecture](architecture.md)

This is navigation, not the full request specification. Run the gateway and open `/docs` for typed request/response schemas; route code defines authority. Admin writes need signed login and `X-CSRF-Token`; Agent credentials cannot call admin APIs.

Adapters use `Authorization: Bearer`, `X-Tenant-ID`, tool `X-Capability`, and applicable `X-Runtime-Session`. The session ID is a correlation identifier, not authority.

| Method/path | Caller | Purpose |
| --- | --- | --- |
| `POST /api/v1/capabilities`、`DELETE /api/v1/capabilities/{grant_id}` | Administrator | Issue/revoke bounded tool capabilities |
| `POST /api/v1/tool-calls`、`GET /api/v1/tool-calls/{call_id}` | Trusted adapter | Submit/query idempotent calls |
| `POST /api/v1/approvals/{approval_id}/decision` | Administrator | Decide frozen action; GitHub writes require fact card |
| `GET /api/v1/policy`、`PUT /api/v1/policy`、`POST /api/v1/policy/reload` | Administrator | Inspect/validate/replace/reload tenant tool policy |
| `GET /api/v1/judge-runtime`、`PUT /api/v1/judge-runtime` | Administrator | Inspect/switch tenant Judge with expected revision |
| `GET /api/v1/judge-samples`、`POST /api/v1/judge-samples`、`DELETE /api/v1/judge-samples/{sample_id}` | Administrator | Manage synthetic evaluation samples |
| `POST /api/v1/judge-samples/{sample_id}/run` | Administrator | Create asynchronous evaluation with configured provider |
| `GET /api/v2/tenants`、`POST /api/v2/tenants` | Default administrator | List/create tenants; show credentials once |
| `PUT /api/v2/runtime-sessions/{session_id}/start`、`PUT /api/v2/runtime-sessions/{session_id}/finish` | Trusted adapter | Start/finish reporting and session binding |
| `POST /api/v2/runtime-sessions/{session_id}/model-egress/check`、`POST /api/v2/runtime-sessions/{session_id}/output-check` | Trusted adapter | Check before model send and answer display |
| `POST /api/v2/runtime-sessions/{session_id}/memory/read`、`POST /api/v2/runtime-sessions/{session_id}/memory/write` | Trusted adapter | Read/write own memory |
| `GET /api/v2/memories`、`POST /api/v2/memories/{memory_id}/decision` | Administrator | Inspect/activate/revoke/purge memory |
| `GET /api/v3/goal-assessments`、`GET /api/v3/action-chains`、`GET /api/v3/threat-mappings` | Administrator | Read-only goal/budget/threat investigation |
| `POST /api/v3/delegations`、`GET /api/v3/delegations/{id}/result` | Parent Agent | Create restricted delegation / retrieve low-trust result; see delegation protocol |

See [delegation interfaces](delegation.md#interfaces) for collaborator endpoints. Enter Web through `/dashboard`; [navigation](web-dashboard.md) explains login/data tenant scopes. Tool policy can hot-reload; runtime/budget thresholds remain versioned code, without online weakening.

Web offers Chinese/English preference, preserving page/tenant and original task/source/memory/JSON. See [language behavior](web-language.md).
