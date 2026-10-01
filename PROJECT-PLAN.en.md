# AgentSentry: project plan and current implementation

[English](#) · [中文](AgentSentry%20%E6%95%B4%E4%BD%93%E9%A1%B9%E7%9B%AE%E6%96%B9%E6%A1%88.md)

> Capability baseline: V3.6. Updated: 2026-10-01. Package version remains defined in `pyproject.toml`.

## Purpose and learning goals

AgentSentry is a self-hosted security lab for individual and shared learning. A demo Agent, registered tools, synthetic inputs, and reproducible experiments teach mechanisms, implementation, effectiveness, and limitations. Compose services run locally with a loopback Web port. Optional cloud Judge, registered models, and third-party MCP endpoints can be external destinations.

The learning loop is **understand the threat → build an experiment → observe the Agent → inspect the gateway decision → verify effects and display → analyze gaps and false blocks → retest**. Core runtime mechanisms and a thematic handbook exist; deeper validation is still needed. Delivering a feature or handbook does not prove learner mastery.

Synchronous authorization relies on identity, typed parameters, policy, capabilities, data flow, and runtime facts. Judge is asynchronous. Goal and semantic analysis provide hints, not authority. Human approval is followed by execution-time checks.

### Reading entries

| Entry | Question answered |
| --- | --- |
| This plan | Why the project exists, capabilities, limits, and next directions |
| [Architecture](docs/en/architecture.md) | Components, trust boundaries, state, and retention |
| [Risk evidence](docs/en/risk-coverage.md) | Threat matrix, concrete experiments, and remaining gaps |

Start at [README](README.md), then the [15-topic handbook](docs/en/learning/README.md), [glossary](docs/en/learning/glossary.md), [experiment index](docs/en/learning/experiment-index.md), and [advanced cases](docs/en/cases/README.md). The [dashboard guide](docs/en/web-dashboard.md) explains investigation and management.

Use offline tests for foundations, research tenants for new gateway records, and explicitly configured models/MCP for deeper study. Share synthetic evidence according to [contributing](CONTRIBUTING.en.md). The distribution does not contain the author's credentials, database, or personal learning records.

## Capability overview

| Topic | Current implementation | Enforcement and limits | Evidence |
| --- | --- | --- | --- |
| Identity and least privilege | Tenant/Agent identity, time/use/resource-scoped grants, atomic counters, revocation | Gateway verifies; identity alone cannot issue tool authority; tokens stay outside model context | [Capability code](src/agentsentry/capability.py), [case](docs/en/cases/tool-permission-and-approval.md) |
| Tool policy | Registered tools, strict schemas, default-deny YAML, deny precedence, validation and reload | Regex supplements denial; typed extraction and capabilities enforce exact resources | [Policy](src/agentsentry/policy.py), [tests](tests/test_policy_suite.py) |
| Human approval | Frozen parameters, fact card, short confirmation, expiry/replay checks and execution revalidation | Only the original action is approved; source claims do not authorize | [Guide](docs/en/goal-drift.md), [tests](tests/test_approval_review.py) |
| Execution isolation | Restricted Docker Shell for default tenant | Process/container limits; other tenants cannot share it; escape safety is not proven | [Case](docs/en/cases/execution-and-audit.md) |
| Output and provenance | Pre-display checks, actual-source linkage, explicit injection/sensitive-content checks | Gateway returns permitted display; adapter displays it; provenance is not truth | [Guide](docs/en/output-safety.md), [A03/A12](docs/en/cases/injection-and-output.md) |
| Long-term memory | Candidates, source review, activation/quarantine/revocation, read checks, integrity seals | Always low-trust; seals do not protect simultaneous key/database compromise | [Guide](docs/en/memory.md), [case](docs/en/cases/memory-poisoning.md) |
| Sensitive data flow | public/private/secret, model/write/answer/memory exit checks | Gateway verifies sources; adapter sends models; unrelated network programs are not intercepted | [Guide](docs/en/data-flow.md), [case](docs/en/cases/private-data-leakage.md) |
| Sessions and goal drift | Timelines, task profiles, source-induced hints, human review | Assists investigation, not full understanding of user intent | [Sessions](docs/en/runtime-analysis.md), [chapter](docs/en/learning/10-goal-drift.md) |
| Runtime response | Suspicious-read/write sequences, repeated denials, uncertain repeats, pause/resume | Maintains or tightens decisions for later controlled actions | [Rules](docs/en/runtime-defense.md), [case](docs/en/cases/runtime-and-budget.md) |
| Action chains | Tool/model/summary budgets, session and cross-session write limits, resource-probe pause | Bound calls only; permitted-budget mistakes need other controls | [Guide](docs/en/action-chain.md) |
| MCP and supply chain | Local stdio, registered HTTPS/OAuth demo, GitHub fixed reads/controlled write, versioned profiles and probes | Explicit, fixed resources/definitions; a probe does not prove remote implementation safety | [Local](docs/en/local-mcp.md), [remote](docs/en/remote-mcp.md), [supply](docs/en/mcp-supply.md), [GitHub](docs/en/cases/github-controlled-write.md) |
| Delegation | Independent local read-only identity, attenuated single hop, parent quota reservations, seals/source checks | No write, multi-hop, cross-host, or content-truth guarantee | [Guide](docs/en/delegation.md), [case](docs/en/cases/delegation-boundaries.md) |
| Failure containment | Tenant dependency breakers/leases, backoff, separate notification Worker, generations/requeue | Fail closed on critical checks; unknown tools not retried; shared host/database still affect tenants | [Guide](docs/en/fault-propagation.md) |
| Audit/Judge/alerts | Transactional Outbox, retry/dedup, aggregation, optional Webhook; Mock/OpenAI-compatible/Jev/DeepSeek | Per-tenant asynchronous route; Jev is hosted; score is not attack probability | [Judge](docs/en/judge-runtime-switch.md), [case](docs/en/cases/execution-and-audit.md) |
| Experiments and mappings | Scripted/live tracks, factual scoring, calibration suggestions, OWASP/ATLAS matrix and event links | Independent research records; ordinary tasks not automatically replayed; IDs do not prove coverage | [Lab](docs/en/attack-lab.md), [calibration](docs/en/calibration.md), [matrix](docs/en/threat-framework-mapping.md) |

## Implementation and validation status

Implemented means code/interfaces exist. Validated additionally requires a defined sample, path, and observation. Code inspection, fixed proposals, live models, and field checks provide different evidence.

| Area | Evidence | Main limitation |
| --- | --- | --- |
| Identity, grants, approval | [Concurrency case](docs/en/cases/tool-permission-and-approval.md), [tenant tests](tests/test_v2_tenants.py) | Application isolation does not survive gateway compromise; approval still needs rechecks |
| Execution | [Sandbox/audit](docs/en/cases/execution-and-audit.md), [MCP results](docs/en/cases/mcp-boundaries.md) | Probes do not prove escape resistance; post-dispatch unknown cannot safely auto-repeat |
| Injection/output | [Contamination case](docs/en/cases/injection-and-output.md) | Explicit payloads validated; implicit public-source semantics and false facts can remain |
| Memory/data | [Memory](docs/en/cases/memory-poisoning.md), [leakage](docs/en/cases/private-data-leakage.md) | Review is not truth; whole-session restricted output blocks normal tasks too |
| Behavior/goals | [Budget case](docs/en/cases/runtime-and-budget.md), [goal chapter](docs/en/learning/10-goal-drift.md) | Hints, within-budget mistakes, and long autonomous drift remain limited |
| Third-party MCP | [Read](docs/en/cases/github-readonly.md), [write](docs/en/cases/github-controlled-write.md), [supply](docs/en/mcp-supply.md) | One service/one write does not prove general or long-term safety |
| Failure/delegation | [Recovery](docs/en/fault-propagation.md), [delegation](docs/en/cases/delegation-boundaries.md) | Shared infrastructure, multi-hop/host, multi-model contamination remain |
| Audit/Judge/mapping | [Audit case](docs/en/cases/execution-and-audit.md), [matrix](docs/en/threat-framework-mapping.md) | Only received events evaluated; mappings are not attack or whole-category proof |

Cases retain dates, sample versions, and modes. Generate your own records through the experiment index; counts are not personal learning outcomes.

## Current gaps and boundaries

| Area | Conclusion | Further work |
| --- | --- | --- |
| Identity, resources, memory tampering | Validated within stated scope | External identity systems; simultaneous application/signing-key compromise (TH-003/005) |
| Injection/output | Partially validated | Explicit A03/A12 patterns fixed; semantic, language, and novel payload variants (TH-001/002) |
| Data/memory pollution | Partially validated | Unknown formats, segmented/rewritten leakage, usability tradeoffs (TH-004/006/007) |
| Third-party MCP | Real link tested; supply chain partially validated | Controlled profiles/probes and one GitHub write are not arbitrary-service or long-term proof (TH-010) |
| Autonomy/budgets | Budgets partially validated; autonomous drift unvalidated | Long tasks without attack input, within-budget mistakes, unbound legacy paths (TH-011/013) |
| Delegation | Partially validated | Local single-hop reads only; model cooperation, writes, multi-hop/host unvalidated (TH-015) |
| Cascading failure | Partially validated | Tenant-local containment exists; common infrastructure and cross-Agent long-term stress remain (TH-014) |

See the matrix, not an overall Top 10 percentage. Default `AGENTSENTRY_RUNTIME_BINDING_REQUIRED=false` leaves legacy unbound calls outside action budgets; sensitive writes, remote MCP, and model exits have separate required binding.

`metadata` omits stored task/answer excerpts, not temporary gateway checks or all derived text. Memory and some operation text remain; see [retention](docs/en/architecture.md#data-retention-and-privacy).

## Future directions and completion criteria

| Priority | Work | Completion criterion |
| --- | --- | --- |
| Learning path | Use handbook and fill evidence gaps | 15 cards/30 foundation units plus human review; independently complete sandbox and gateway/live-model evidence |
| 1 | Deeper validation | Verifiable restricted-answer templates/review; more models and long normal tasks; separate attempts, effects, display, and false blocks |
| 2 | MCP/software supply chain | Real DNS changes, third-party implementation and long-term response behavior beyond fixed demo changes |
| 3 | Failure propagation | Long pressure, common infrastructure failure, and cross-Agent propagation |
| 4 | Delegation | Explicit semantic-pollution, cross-host, and multi-hop experiment criteria |

Update plan, architecture, evidence, and guides together when capabilities/policies/samples change.

## Documentation maintenance

Main entries explain current capability; cases explain causes, facts, fixes, and tradeoffs. The matrix is generated from structured data; event classification retains its original version. Evidence uses corpus version plus sample ID. No dangerous attempt, pending approval, unknown, and environment failure stay distinct.

Only **main learning entries and advanced cases** are provided. Dates/rule/sample versions support reproducibility, not a development-history curriculum. No universal protection, production isolation, or unmeasured latency claims are made.
