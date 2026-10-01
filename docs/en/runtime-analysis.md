# Daily Session Analysis

[English](#) · [中文](../runtime-analysis.md)

## Purpose

The explicitly connected demo Agent reports session start/finish, while tools use the existing gateway. Tenant/Agent/session IDs join calls, approvals, audit, Outbox, Judge and alerts into a timeline for review. Legacy calls can be grouped by existing session IDs without replaying tools or inventing task text. Experiment sessions are excluded from daily lists by default, with explicit inclusion available.

```text
Task → demo Agent → session start/finish → tenant session record
                 → tools → gateway → execution/audit/Judge
                                      → timeline and manual review
```

Session analysis organizes evidence rather than itself blocking actions. Signals are not attack-success conclusions. Other Agents need explicit gateway/session reporting for complete context; tool-only records show context not reported.

## Why text can be empty

| State | Explanation |
| --- | --- |
| Not reported | Legacy/tool-only client; task and final answer cannot be reconstructed |
| Metadata only | Capture mode does not retain snippets |
| Pending finish / failure without answer | Task has not finished or failed before answering |
| No text answer | Finished fixed-tool demo emitted a tool result, not a model final answer |

Model tasks with successful preview start/finish should show redacted snippets. Old content is never guessed from parameters. Current start additionally processes up to 2,000 characters of raw task temporarily for keyed output binding; metadata does not retain that task. These temporary checks differ from stored preview text.

## Use and privacy

Start services, log in and open `/dashboard/runtime-sessions`. Run the demo normally with its identity/capability/model settings; MCP uses `--transport mcp --scenario llm`. Filter by time/status/clue; detail includes task/answer capture state, timeline, output/memory, Judge and evidence. Administrators can record review status and redacted notes.

Default `AGENTSENTRY_CAPTURE_MODE=preview` locally redacts Bearer tokens, common key assignments, email, phone and identity-number patterns, sends at most 1,000 snippet characters and repeats redaction server-side. Metadata omits task/answer snippets, retaining transport/model/status/IDs; later security APIs still temporarily process raw text. Neither new context report adds task/answer text to Judge Outbox. Pattern redaction may miss names, addresses or contextual secrets; use synthetic or retainable data.

## APIs and interpretation

- `PUT /api/v2/runtime-sessions/{session_id}/start` and `/finish`: authenticated Agent reporting and binding. Identical redacted reports are idempotent; changed content on the same ID conflicts. Report errors emit error type to stderr rather than directly ending the task; required downstream checks still enforce binding.
- `GET /api/v2/runtime-sessions`, `GET /api/v2/runtime-sessions/detail`: tenant-admin queries.
- `POST /api/v2/runtime-sessions/review`: admin/CSRF review status and redacted note.

Denials, pending/rejected approvals, failure/unknown, Judge risk, sensitive proposals after source reads and missing expected audit are review clues. Adapter failures report tool/error types rather than raw parameters and are not recorded as executed tools. Unfinished new sessions over 20 minutes show interrupted. Legacy tool-only sessions show unreported; sessions without tools still appear after successful reporting. Every tenant uses its own schema.

This is not packet capture, universal framework integration or automatic answer-contamination scoring. See [output safety](output-safety.md), [runtime controls](runtime-defense.md) and [Web navigation](web-dashboard.md).
