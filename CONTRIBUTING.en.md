# Learn and contribute together

[English](#) · [中文](CONTRIBUTING.md)

[Project home](README.md) · [Handbook](docs/en/learning/README.md)

Welcome documentation fixes, translations, synthetic attacks, normal controls, reproducible reports, and protection improvements. Conclusions must remain scoped to evidence-backed samples and integrations.

## Start with a small question

1. Choose one topic and run a normal and boundary experiment.
2. Explain expected versus actual outcomes and locate code/evidence.
3. Verify doc links/commands; rule or implementation changes need relevant attack and normal regressions.
4. State what changed, why, how verified, and remaining limits. Mark unrun work explicitly; existing case results are not a new run.

Use your own branch and private records. See [offline setup](docs/en/learning/README.md#prerequisites-and-command-conventions); docs contributions need no cloud or third-party credentials.

## Report a problem

```text
Environment: OS, Python, commit or file version
Scope: offline / local gateway / local model / third-party integration
Reproduce: minimal commands, corpus version + sample ID
Expected: property the control should enforce
Facts: decisions, actual effects, drafts, and display separately
Evidence: redacted report or fixed test node
Limits: not attempted, pending, unknown, environment error, untested path
```

Exclude .env, PATs, admin passwords, grant tokens, cookies, .local credentials, and business text. Check screenshots for one-time secrets and expanded parameters. Removing field names is not redaction. Prefer synthetic data and temporary tenants; do not scan unauthorized targets or write to others' repositories. For suspected exploitable issues or real secrets, remove sensitive content and arrange private review with maintainers.

## Documentation sources

| Artifact | Maintenance |
| --- | --- |
| Plan, architecture, chapters, cases | Edit their separate language versions; keep implementation/evidence scope aligned |
| `docs/threat-framework-map.yaml` | Canonical structured matrix, IDs and rules |
| `docs/threat-framework-mapping.md` | Generated Chinese matrix |
| `src/agentsentry/learning_tasks.json` | Canonical tasks/test nodes |
| `scripts/check_learning_assessment.py` | Chinese card layout |
| `docs/learning/assessment/*.md` | Generated Chinese cards |
| `docs/en/learning/task-translations.json` | English task prose; identifiers come from canonical tasks |
| `docs/en/threat-translations.json` | English framework/threat/control/evidence prose |
| `scripts/check_english_docs.py` | English card/matrix generation, counterpart and link checks |

```bash
.venv/bin/python scripts/check_threat_mapping.py --write
.venv/bin/python scripts/check_threat_mapping.py --check
.venv/bin/python scripts/check_learning_assessment.py --write
.venv/bin/python scripts/check_learning_assessment.py --check
.venv/bin/python scripts/check_english_docs.py --write
.venv/bin/python scripts/check_english_docs.py --check
```

Use --write only after changing its source/layout. English and Chinese docs stay in separate files. Interface names, test nodes, versions, and factual counts must agree. Original synthetic input and CLI values may remain in their original language; do not translate a literal that the executable expects.

## Evidence for security changes

Separate scripted boundaries from model behavior, draft from displayed contamination, legal from prohibited effects. Do not loosen identity, cross-tenant, credential, or audit-commit boundaries to improve small-sample scores. Record baseline, suggestions, human decision, new version, and held-out results. No automatic publication or approval of attacks. Sources, seals, and framework IDs do not establish truth or category-wide protection.

See [regressions](README.md#regression-checks), [experiments](docs/en/learning/experiment-index.md), [UI languages](docs/en/web-language.md), and [sharing rules](docs/en/public-sharing.md). No LICENSE is included yet; do not assume or choose authorization on the maintainer's behalf.
