# MCP Supply-Chain Integrity and Change Detection

[English](#) · [中文](../mcp-supply.md)

This evaluates the fixed synthetic remote service and existing GitHub adapter. A tool-definition hash is not proof of the remote program.

## Threat and control

A registered service may change endpoint identity, descriptions/schemas, results, or behavior without a manifest change. Only code-registered tools are exposed. The gateway checks an approved profile, changes, fixed read-only probe and pinned connection destination before target dispatch.

```text
Registered HTTPS/OAuth/manifest → initial tenant profile
  → endpoint identity and tools/list check → controlled read-only probe → original tool
                  mismatch → saved candidate → human review, reject or rollback
```

## Implementation

- `mcp_profile_versions` stores public endpoint identity, tool-definition hashes and approved revision. Initial registered deployment becomes revision 1; later environment issuer/audience/client ID/CA changes do not automatically replace approval. Secrets/tokens are not stored in profiles.
- `mcp_profile_changes` stores bounded observed definitions and hashes. Mismatch stops the target call; “Observe again” can scan. GET lists the manifest; the button also runs the controlled probe. Observations are reviewable for ten minutes. Calls recheck current manifest; PostgreSQL shared revision locks prevent switching approval midway through dispatch. Reject leaves approval unchanged; rollback requires the same current endpoint identity. Maintenance clears definition text in old candidates/inactive revisions after 30 days, retaining metadata.
- Online approval permits only the two registered tools and fixed schemas. Added tools/schema changes need code and tests first. Approved descriptions remain low-trust and cannot grant capabilities or change policy.
- `remote-public-guide` has a known synthetic-content digest. Before writes a separate `cards.read` token runs the probe, then `notes.write` executes the frozen action. Probe drift produces `remote_mcp_behavior_drift`/incidents and blocks target writes; a single probe cannot detect all behavior changes.
- HTTPS pins the validated IP for TCP, preserving registered TLS hostname, disabling proxies/redirects. It depends on locked `httpx2`/`httpcore2` transport interfaces and fails closed if unavailable; GitHub uses the same connection method. Containers/CI use `uv.lock`, pinned base-image digests and installer version. Locking is not vulnerability scanning or publisher verification.
- Profile/probe actions emit metadata audit and TH-010 clues; failures keep tool-result/Outbox semantics. A mapping does not establish attacker success.

## Administrator workflow

Open `/dashboard/remote-mcp`, review endpoint, approved revision and digest. For drift/registration change, observe again and inspect low-trust differences. Approve only expected deployment changes; new tool/schema needs code registration. Probe behavior drift cannot be cleared merely by approving a manifest. Unknown writes require upstream reconciliation rather than a new ID.

```bash
python scripts/check_mcp_supply_chain.py
python scripts/check_threat_mapping.py --check
python -m pytest -q tests/test_mcp_supply.py tests/test_remote_mcp.py tests/test_github_mcp.py tests/test_github_mcp_write.py tests/test_threat_mapping_runtime.py
```

## Verification limits

Loopback HTTPS/OAuth regression covers reads, zero pre-approval writes, one approved write, idempotency, manifest review/extra-tool rejection, unchanged-manifest content drift, dispatch uncertainty and IP selection. It does not create a real GitHub Issue, verify real public rebinding or prove a third-party implementation remains unchanged. GitHub definitions use separate code-pinned review rather than this synthetic profile page. Results continue through source/data-flow/output/memory controls. See the dated [MCP cases](cases/mcp-boundaries.md); generate your own profile evidence rather than relying on an author’s container ID.
