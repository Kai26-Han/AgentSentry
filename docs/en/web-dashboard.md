# Web Dashboard Navigation

[English](#) · [中文](../web-dashboard.md)

Open `/dashboard` after login. The left sidebar groups workspaces and allows collapse; the current group expands automatically. The browser preserves other collapse choices for the session. Right-side tabs switch related views. On narrow screens, use the menu button.

| Workspace | Contents |
| --- | --- |
| Overview | Pending approvals, unhandled alerts, Outbox, recent concerning sessions |
| Alerts | Judge/runtime sources, acknowledgement and grouped alerts |
| Approvals | Direct rejection; approval through original-action fact card |
| Runtime analysis | Session investigation (overview/goal/action chain), calls/audit/Judge, sensitive data flow, threat associations (events/frameworks), Agent delegation |
| Memory security | Long-term memory, cross-session poisoning and storage-security experiments |
| Security experiments and evaluation | Comprehensive Agent/goal experiments, adversarial validation/calibration, Judge evaluation |
| Management | Tool-call authorizations, tool/runtime rules, remote MCP, Judge settings, system/demo/failure recovery; tenant management for default admin |

The login tenant is the identity scope. Selected research **data tenant** is separate, read-only observation rather than expanded write authority. One-time capability/tenant/reader credentials appear only on their creation result; save them securely. Actions return to their workspace. Navigation omits development versions; experiments retain corpus/hash for reproduction.

## Session and evidence views

Session overview explains what happened; goal drift shows advisory task/source clues; action chain shows cumulative budget decisions. Lists retain the selected data tenant. Detail tabs preserve the same session ID and return path, with capture state, output/memory/timeline/review. Old URLs continue to work. Calls, audit and Judge use related tabs; threat evidence differs from framework reference. Cross-research links are validated by the server, and missing original records are not manufactured into links.

Tool policy supports existing YAML update forms; runtime conditions/budgets are read-only catalogs. Judge/runtime alerts identify their source. Fact-card confirmation binds admin session, tenant, approval, frozen parameters and current evidence; changes require reopening details.

## Judge evaluation versus daily settings

Selecting a provider in Judge evaluation changes the viewing provider; “Evaluate” creates a new asynchronous synthetic-sample run. Existing results are not recomputed. Recent completed per-provider results drive observed-event statistics. Mock is always available; configured Jev/DeepSeek/OpenAI-compatible options show model/destination, never keys. Configured is not proof of connectivity. Sample routes remain fixed on retry and do not change the tenant’s daily Judge settings.

Audit-only management events explicitly say they do not enter Judge. Historical completed events may lack designated route but show their actual result provider. Pending/processing/failed reflect Outbox; missing required routing is flagged separately. Do not submit business data to sample evaluation.

## Remote MCP, recovery and delegation

Remote MCP shows approved profile/current digest/change candidates/probe incidents. GET lists definitions; “Observe again” additionally calls the controlled read-only probe. Approve/reject/rollback limited definitions after review; new tools/schema changes require code. GitHub uses independent pinned definitions. See [supply checks](mcp-supply.md).

`/dashboard/resilience` requeues only terminal Judge/notification tasks with admin/CSRF, never tools. Empty queue is not live worker health. `/dashboard/delegations` separates actual independent-identity tasks from fixture summaries and links genuine child calls and delegation replies with their data tenant.

Language selection is described in [Web language](web-language.md).
