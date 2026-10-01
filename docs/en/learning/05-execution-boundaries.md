# 05 Sandbox and MCP execution boundaries

[English](#) · [中文](../../learning/05-execution-boundaries.md)

[Handbook](README.md) · [Previous: 04](04-approval-safety.md) · [Next: 06](06-input-output-safety.md)

> Before starting: use the [handbook environment](README.md#prerequisites-and-command-conventions), choose offline or online, and predict before running. Use temporary synthetic data. Online extensions also require services, a dedicated tenant, and valid credentials.

## Learning goals

Separate permission from isolation, MCP registration from content trust, and pre-dispatch failure from post-dispatch uncertainty.

## Sandbox: constrain an authorized action

Authorized Shell can still access files/networks or consume resources. run_shell is default-tenant-only; grant, approval, session, and safety checks precede a separate Docker sandbox with read-only root, bounded writable space, dropped capabilities/no-new-privileges, process/memory/network/time limits.

Read [Compose](../../../docker-compose.yml), [server](../../../sandbox/server.py), [tools](../../../src/agentsentry/tools.py), and [drill](../../../scripts/sandbox_drill.py). These controls do not prove absence of container escapes or provide per-tenant isolated execution.

[Saved sandbox evidence](../cases/execution-and-audit.md) is dated, not today's result. The current drill binds a fresh session, proposes a fixed synthetic action, and waits for human review: --phase prepare never auto-approves; --phase verify --record ... checks effects/replay and cleans the marker/grant. pending/executing/unknown remain unfinished and are not auto-repeated.

--phase isolation runs fixed direct probes from the Web container: execution restrictions only, not gateway authorization. Complete both tracks under [S02](personal-assessment.md#layer-2-local-evidence-chain-practice).

## MCP: protocol integration, not a sandbox

```text
Same Agent → trusted stdio entry → HTTP gateway
                                     ↓ after committed decision
                           fixed local / registered remote MCP
```

Only registered definitions are exposed. Local MCP is a fixed subprocess with tenant synthetic storage. Remote HTTPS/OAuth checks address, credential scope and approved manifest; profiles, changes, fixed probes and connection IP pinning add controls. GitHub has a separate fixed PAT/manifest path. Local MCP is not the Shell sandbox; valid structured content remains low-trust and needs output/memory/data-flow checks.

## Exercise

Local stdio/temporary storage plus some loopback HTTPS/OAuth tests; no third-party writes:

```bash
.venv/bin/python -m pytest -q tests/test_mcp.py tests/test_remote_mcp.py tests/test_mcp_supply.py tests/test_github_mcp.py tests/test_github_mcp_write.py
```

| Path | Normal | Boundary |
| --- | --- | --- |
| Local MCP | Official list/call; one approved note | Zero before approval; no repeat; malformed response not resent |
| Remote MCP | Approved profile/manifest/result | Address, extra tools, structure/probe drift refused; dispatched unknown retained |
| GitHub stubs | Exact resource and approved write | Manifest/repository/Issue identity/review mismatches stop execution |

Inspect upstream counters in [local tests](../../../tests/test_mcp.py), stages in [remote tests](../../../tests/test_remote_mcp.py), reconciliation in [write tests](../../../tests/test_github_mcp_write.py). Stubs are not third-party field evidence.

| State | Meaning | Next step |
| --- | --- | --- |
| failed before dispatch | Confirmed no upstream tool request | Diagnose and propose after recovery |
| unknown after dispatch | Tool may have run without reliable result | Query original ID, read-only reconcile; no new-ID auto-repeat |
| completed | Validated result saved | Continue applying source/confidentiality checks |

Local operation_id uniqueness does not imply every third party deduplicates.

## Field evidence and self-check

[Local demo](../local-mcp.md), [E05](experiment-index.md#e05-local-mcp-human-approval), [GitHub read](../cases/github-readonly.md), [Issue analysis](../cases/github-issue-analysis.md), and [write](../cases/github-controlled-write.md) cover specific paths. One connection/write is not supply-chain safety; TH-010 remains partial.

MCP validation cannot eliminate injection. Sandbox approval cannot enlarge scope. A new ID after timeout can duplicate an executed action.

[Remote MCP](../remote-mcp.md) · [Supply chain](../mcp-supply.md) · [TH-009/010](../threat-framework-mapping.md)
