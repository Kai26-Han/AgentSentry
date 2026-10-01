# GitHub Test Repository: Controlled, Approved Write

[English](#) · [中文](../../cases/github-controlled-write.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Goal and boundaries

2026-09-30 tested a synthetic Issue in a preconfigured dedicated private test repository. This is a real persistent external side effect. Write defaults off and uses a separate credential; readonly PAT cannot gain it automatically. The model submits only title/body; trusted code selects repository and upstream.

Gateway calls official Issues endpoint `issue_write` with `method=create`, fixed repo/title/body, never passthrough update/labels. Each connection checks approved tool-definition SHA-256. Resource must equal `GITHUB_MCP_TEST_REPO`, title starts `[AgentSentry Test] `, body ≤500 characters, policy explicitly `require_approval`. Ordinary admin API cannot approve it: complete original parameters/repo must be reviewed in the Web fact card.

Valid session binding is required; private/unknown sources, detected credentials or personal information deny. Approval rechecks capability/policy/session/data flow. Same ID queries existing state; possibly dispatched/unconfirmed writes are unknown with no automatic new-ID retry. Audit/Judge use metadata; operation parameters are temporarily retained for review/idempotency.

## Prepare your own test target

If you have no dedicated repository, code/offline/UI work can proceed with `AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED=false`. For real validation create an empty synthetic-only repository (preferably private), or ask an authorized administrator to provide one. Do not use a business repo. Create a separate fine-grained PAT restricted to its **Issues: Read and write**; do not reuse readonly PAT or share tokens.

Private `.env`:

```dotenv
GITHUB_MCP_WRITE_PAT=<SEPARATE_TEST_REPOSITORY_ISSUES_TOKEN>
GITHUB_MCP_TEST_REPO=<owner/repo>
```

List definitions without a write:

```bash
.venv/bin/python scripts/probe_github_create_issue_shape.py
```

Review unique `issue_write`, `method` create/update enum, required method/owner/repo and official destination. Pin its `schema_sha256` in `GITHUB_MCP_CREATE_ISSUE_SCHEMA_SHA256`, then explicitly enable `AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED=true`.

```bash
docker compose up -d --build web
.venv/bin/python scripts/enable_github_mcp_write_policy.py
.venv/bin/python scripts/enable_github_mcp_write_policy.py --apply
.venv/bin/python scripts/github_mcp_write_check.py
```

The script issues one-time rights, creates a bound session and uses a formal MCP client; independently verifies **zero matching Issues before approval**, prints a fact-card URL and subsequent verify command, and never approves automatically. After you approve frozen repo/title/body, verify exactly one Issue and matching number. Unknown requires original-effect reconciliation, not another write.

Afterward revoke capability, disable writes/revoke test PAT, optionally close the Issue manually, retain audit.

## Observed side effect and unknown reconciliation

The dedicated PAT/repo and explicit approval were used. Approved definition hash: `b115e2eddc21dafa4541be62e92bde4590391bea4ed93062caf7b6fb36e44f56`. Matching title before human approval: zero. After approval: exactly one Issue, `[AgentSentry Test] guarded issue <run-marker>`, synthetic body and number matching original parameters on readonly verification.

Initial result was unknown: upstream returned `{id, url}`, while the old parser expected `{number, html_url, title}`. Parser and post-create readonly verification were fixed. The existing effect was reconciled using original approval/hash/unknown audit and GitHub content, then `tool_result` appended and call marked completed **without another issue_write**. Original `tool_unknown` remains. Ten audits/ten Outbox/ten Judge results completed.

The new full parser success path passed protocol-double tests, but **no second real write was performed**. Offline tests cover pre-approval zero, approved one, replay/reject, dispatched timeout, tenant/resource/private/credential/PII boundaries and definition drift with fixed create-only arguments. This does not establish arbitrary third-party safety.

References: [official remote MCP configuration](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md), [fine-grained PAT permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).
