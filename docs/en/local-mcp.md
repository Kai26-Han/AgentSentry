# Local MCP Integration and Demo

[English](#) · [中文](../local-mcp.md)

```text
Demo Agent → trusted MCP stdio entry adapter
           → authenticated HTTP gateway request
           → committed safety decision → fixed upstream MCP stdio server
```

The adapter exposes only `mcp_lookup_card`, `mcp_record_note` and `agentsentry_call_status`, not upstream-added definitions. The gateway starts a fixed subprocess with a restricted inherited environment and tenant-specific synthetic SQLite storage in `mcp_demo_data`. There is no listening server port. The Agent cannot choose a program, path or address.

| Gateway tool | Upstream | Capability resource | Default policy |
| --- | --- | --- | --- |
| `mcp_lookup_card(card_id)` | `lookup_card` | Exact card ID | Allow with valid capability |
| `mcp_record_note(note_id, text)` | `record_note` | `demo-notes` | Human approval |

Writes use the gateway `call_id` as a unique operation ID. Same-call retry returns recorded state. Failure before dispatch is failed; timeout/unconfirmed result after dispatch is unknown, with no automatic rewrite. Results remain low-trust data.

## Run

Start services using the [quick start](../../README.md#quick-start). New installs have the default policy; for an existing tenant, preview `python scripts/enable_mcp_policy.py`, review, then explicitly add `--apply`. For other tenants, set `TENANT_ADMIN_PASSWORD` and pass `--tenant <tenant-id>`.

```bash
.venv/bin/python scripts/mcp_demo.py
.venv/bin/python scripts/mcp_demo.py --write
```

The read issues a one-time grant and starts the existing Agent in MCP mode. Inspect call, audit, Outbox and Judge IDs. The write waits for a fact-card decision; there must be no note before approval. Other tenants also need `TENANT_AGENT_API_KEY` and `--tenant`.

After [local-model configuration](local-model.md), set trusted-process identity and `AGENT_CAPABILITIES_JSON`, then:

```bash
.venv/bin/agentsentry-demo --transport mcp --scenario llm --prompt 'Read public-guide through MCP and summarize it.'
```

Credentials stay outside model context. This is explicit integration, not interception of other MCP connections or direct network calls. Separate tenant files/subprocesses are not a hardened sandbox. A fresh MCP `tools/call` may be a new gateway call; do not assume upstream servers deduplicate independently. See [MCP cases](cases/mcp-boundaries.md) and [execution exercises](learning/05-execution-boundaries.md).
