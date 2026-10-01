# Mapping Daily Events to Threats and Frameworks

[English](#) · [中文](../runtime-threat-mapping.md)

Committed audit metadata with explicit rule hits is projected into project `TH-###` scenarios, OWASP Agentic Top 10 2026 and MITRE ATLAS references. This supports investigation; it neither authorizes tools nor establishes attack success.

```text
Existing tool/model/output/memory controls → committed tenant audit
  → independent typed-field projection → TH / OWASP / ATLAS
  → alert/session/call details and threat evidence
```

## Sources and display

Rules live in `runtime_signals` in [threat-framework-map.yaml](../threat-framework-map.yaml). Registered data-flow/runtime/goal/integrity fields drive matches. MCP induction also checks a completed same-tenant/Agent/session `mcp_lookup_card` source. The fixed `injected-guide` exception verifies actual completed return content against the built-in fixture before linking TH-012: payload arrival, not obedience. Judge labels alone never create a mapping; Judge alerts display a mapping only through their audit event.

Versioned additions include restricted-answer blocking (1.6.0, TH-006), MCP endpoint/manifest/probe drift (1.7.0, TH-010), failure exhaustion/breakers (1.8.0, TH-014/ASI08), and delegation (1.9.0). These are observed clues, not confirmed attacks or leakage.

Snapshots store mapping/event/rule/threat/framework IDs, effect and evidence IDs, without new task/parameters/messages/answers/memory text. No-match is explicitly unmatched; unprocessed is pending; failures/backlog are visible. Local fixture comparison uses existing content transiently. Original record retention remains separate.

Web Runtime analysis → Threat associations separates daily event evidence from framework reference. Scenario and event details are independent pages. Links are only generated when original calls/sessions remain accessible; APIs `GET /api/v3/threat-mappings` and `GET /api/v3/threat-mappings/{id}` require tenant-admin identity.

## Versions and failures

Initial projection considers committed events from the previous 30 days, then new events. Matched snapshots are never rewritten after a rule update. Unmatched/unprocessed events still inside the window can be reevaluated under a newer version. Same-version duplicate projection adds no row; the latest state is shown while old snapshots remain.

Projection is separate from authorization/audit/Judge delivery. Failure cannot alter the original safety decision; delay is not absence of risk. Tenant schema boundaries remain enforced.

## Maintenance

Update canonical YAML, generate both language matrices, validate and run mapping tests:

```bash
python scripts/check_threat_mapping.py --write
python scripts/check_english_docs.py --write
python scripts/check_threat_mapping.py --check
python scripts/check_english_docs.py --check
```

Only registered typed fields/scenario IDs may classify general events; the content exception is limited to the built-in fixture, not arbitrary text. The [matrix](threat-framework-mapping.md) establishes scoped scenario evidence, not whole-category coverage. Unsignalled scenarios stay static rather than appearing as invented daily events. Ordinary network failures do not establish adversary techniques; inspect actual effects separately.
