# Secure Remote MCP Integration

[English](#) · [中文](../remote-mcp.md)

## Architecture

```text
Demo Agent → trusted stdio adapter → existing security gateway
  → identity/capability/policy/runtime/data-flow/approval; commit first
  → fixed HTTPS Streamable HTTP, tenant OAuth and JWT validation
  → pinned endpoint/approved manifest/typed results → synthetic MCP server
  → low-trust sources → model, output and memory checks
```

Only `remote_mcp_lookup_card(card_id)` and `remote_mcp_record_note(note_id, text)` are exposed. Upstream descriptions/new tools are not forwarded to the model. Trusted code supplies addresses, credentials and operation IDs. Note resource `remote-demo-notes` requires human approval; server operation deduplication uses gateway `call_id`.

Startup validates registrations; every call validates resolved destinations. HTTPS only, no embedded user info/query/fragment, no IP literals/private destinations by default, no environment proxies or redirects. Public CA configuration still requires TLS hostname checks. `AGENTSENTRY_REMOTE_MCP_ALLOW_LOOPBACK_DEMO=true` is restricted to the controlled local demo (`localhost`, `host.docker.internal`, fixed `remote-demo`). The validated IP is used for the actual connection while retaining the registered TLS hostname. Production should independently restrict egress; real public DNS rebinding has not been field-tested.

## Register and enable

Private `.env`, per tenant, contains `AGENTSENTRY_REMOTE_MCP_REGISTRY`. All values below are placeholders:

```json
{
  "default": {
    "endpoint_id": "remote-demo",
    "url": "https://mcp.example.org/mcp",
    "token_url": "https://auth.example.org/token",
    "jwks_url": "https://auth.example.org/jwks",
    "issuer": "https://auth.example.org",
    "audience": "https://mcp.example.org/mcp",
    "client_id": "REPLACE_ME",
    "client_secret": "REPLACE_ME",
    "manifest_sha256": "REPLACE_WITH_64_HEX_CHARACTERS"
  }
}
```

Use either container-readable `ca_bundle` or Base64 **public certificate** `ca_pem_b64`, not both. Agent/model input cannot register addresses or credentials. Client credentials request `cards.read` or `notes.write`; RS256 JWT signature against registered JWKS, issuer, audience, expiry and scope are required. Tokens go only to the registered resource, never model/Judge/UI.

`python -m agentsentry.mcp_remote_server --manifest` prints the controlled server manifest digest. Review identity/definitions before pinning it; description/schema/extra-tool changes alter it and stop calls. Restart the gateway after registration edits. Preview `python scripts/enable_remote_mcp_policy.py --tenant default`, then explicitly `--apply`; issue a separate capability. Adapter `AGENTSENTRY_REMOTE_MCP_ENABLED=true` exposes the fixed tools. Discovery uses MCP `2026-07-28`; initialization-only servers need separate adaptation and retesting.

## Controlled local demo

```bash
REMOTE_MCP_DEMO_CLIENT_SECRET='YOUR_LOCAL_RANDOM_SECRET' python -m agentsentry.mcp_remote_server   --host 127.0.0.1 --port 9443 --cert /path/to/local.crt --key /path/to/local.key
```

Or use the provided container setup:

```bash
python scripts/setup_remote_mcp_demo.py
docker compose --profile remote-mcp-demo up --build -d
python scripts/enable_remote_mcp_policy.py --apply
python scripts/remote_mcp_live_check.py
```

Private keys are excluded in `.local/remote-demo.env` and injected only into the demo container; gateway registration contains public certificate material. The demo container publishes no host port. Never reuse its permissive local switch for production. Agent scenarios `remote-mcp-read` and `remote-mcp-note` use `--transport mcp`; the latter waits for approval. Model tasks use `llm`. `/dashboard/remote-mcp` hides credentials.

## Failure, content and scope

Before `tools/call`, failed token/TLS/network/manifest/schema validation is failed with no target tool effect. After dispatch, timeout/disconnection/malformed results are unknown and never automatically executed again. Reconcile the original operation ID. Manifest drift can link TH-010; ordinary connectivity failure is not automatically an attack. Audit/Judge use endpoint/protocol/digest/status metadata, not credentials/raw upstream content.

`remote-public-guide` is public; other remote cards private; explicit credentials secret. Self-classification does not count. Private context cannot reach a remote model; remote writes with private session sources or detected sensitive parameters are denied. All responses remain low-trust. A manifest hash establishes declarations, not internal code or truth.

Controlled loopback TLS/OAuth tests cover claims/scopes, read, approval, idempotency, resource/parameter/binding boundaries and drift. They are not generic third-party OAuth interoperability. Separate actual evidence: [GitHub read](cases/github-readonly.md), [public Issue](cases/github-issue-analysis.md), [approved write](cases/github-controlled-write.md). See [supply-chain checks](mcp-supply.md); public DNS, long-term third-party semantics and different OAuth/network paths remain incompletely verified.
