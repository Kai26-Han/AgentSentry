# Official GitHub MCP: Fixed Read-Only Integration

[English](#) · [中文](../../cases/github-readonly.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Scope

Recorded on 2026-09-30. The gateway tool `github_mcp_read_license` calls official `https://api.githubcopilot.com/mcp/x/repos/readonly` / `get_file_contents` for `github/github-mcp-server`, path `LICENSE`. The Agent cannot choose URL/repo/path/upstream tool; the other 12 discovered tools are not exposed.

`GITHUB_MCP_PAT` comes from private local `.env`, not model/context/audit/Judge. The official readonly endpoint and `X-MCP-Readonly` are supplemented by binding/capability/explicit default-tenant policy. Approved definition hash: `37ab6d6cd6da6cb17c63534cdcfd55759e5dbc48d5c91cbba49c64cf9f4526d6`; changes fail pending human review.

Accept one MCP text resource, ≤8,192 bytes, mapped to fixed provenance. Authenticated third-party content remains **private** even for this public repo, protecting against visibility/service changes. It is not an instruction.

## Reproduce

Set your own minimum-scope PAT and `AGENTSENTRY_GITHUB_MCP_ENABLED=true`, then:

```bash
docker compose up -d --build web
.venv/bin/python scripts/enable_github_mcp_policy.py
.venv/bin/python scripts/enable_github_mcp_policy.py --apply
.venv/bin/python scripts/probe_github_mcp.py
.venv/bin/python scripts/github_mcp_gateway_check.py
```

The probe prints protocol/digests, not body. Gateway check issues one-time authorization and uses the formal client/adapter to verify output/audit/Judge. No Issue/PR/commit is created. New tools require their own typed parameters/resources/results/approval/retry design.

## Observations and limits

Unauthenticated TLS succeeded with HTTP 401; after PAT setup MCP `2026-07-28` discovery found 13 tools and read LICENSE. Final policy allow/completed, 1,063 bytes, four audits with completed Judge results. Output then warned `unverified_sentence` with one private source because the script summarized rather than directly quoted it. That is an **older** rule result; current restricted-source free text blocks, as in [leakage](private-data-leakage.md).

This verifies one service/fixed read at that time, not all tools/repos, long-term drift or cross-tenant GitHub credential isolation. Later [Issue](github-issue-analysis.md) and [controlled-write](github-controlled-write.md) cases are separate evidence.
