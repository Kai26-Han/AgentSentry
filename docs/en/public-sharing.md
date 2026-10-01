# Public Files and Privacy Conventions

[English](#) · [中文](../public-sharing.md)

Public documentation has two levels: current entry points (README, plan, architecture, handbook and operation guides) and advanced cases (security question, observed facts, fixes and tradeoffs). Learners do not need development-history archives. Chinese and English documentation are separate, linked counterparts.

## Included

Source/templates/demo Agent/fixed tools/MCP adapters/restricted sandbox; tests/security CI/authored synthetic corpora/default policy; Docker/lock files and placeholder-only `.env.example`; current guides, [cases](cases/README.md), bounded redacted fact summaries and threat mapping.

Attack strings, dummy credentials and synthetic identities are learning fixtures, not business data or usable keys. Cases identify mode/date/version. Generate your own records; original private Web evidence is not distributed.

## Excluded

| Material | Handling |
| --- | --- |
| `.env`, admin/model/Judge/GitHub credentials | Local only; no commits/chat/screenshots/build context |
| `.local/` | Research credentials, traces and personal records stay private |
| Databases/logs/volumes/raw business reports | Do not distribute; use bounded synthetic summaries |
| `policies/t_*.yaml` | Exclude generated local tenant policies |
| Virtual environments/caches | Rebuild from lock file |
| Private repository URLs/personal paths/run identifiers | Remove; do not invent queryable evidence links |

Ignore files help Git/build exclusion, but manual folder packaging still requires inspection. Running services create private material outside the public file set. Published dummy passwords are never service credentials.

Start from the [quick start](../../README.md#quick-start) with your own random credentials. Cloud models/Judge/third-party MCP are explicit opt-ins; real GitHub writes need a dedicated synthetic repo, separate PAT and concrete human approval. Contributions preserve failed/inconclusive outcomes and versions rather than copying business text or claiming old results as a new run; see [contribution guide](../../CONTRIBUTING.en.md).

The current file set has no `LICENSE`. The publisher needs to choose a license to specify use/modification/distribution rights.
