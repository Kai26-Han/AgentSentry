# Judge Runtime Settings and Event Routing

[English](#) · [中文](../judge-runtime-switch.md)

## Use

Administration → Judge runtime settings shows the tenant provider, model, destination, revision, actual recent results, Outbox and change history. Saving a configured provider changes **new audit events only**. Stale revision submissions are rejected; refresh before retrying. Switching back is another recorded change.

Security experiments → Judge evaluation selects a provider for one synthetic evaluation and does not change daily settings. Use a synthetic sample to verify an actual Jev/DeepSeek connection; opening or saving settings sends no test automatically.

## Routing and failures

Each tenant has a runtime setting and append-only switch history. Outbox creation freezes provider, model, destination fingerprint and revision in the same transaction. Read/write locks make concurrent switches explainable. Workers use the frozen route, including retries, and validate provider identity. Failures neither alter completed tool decisions nor silently fall back. Destination changes or missing credentials produce a visible failed Outbox.

`JUDGE_PROVIDER` initializes a tenant only; restart does not overwrite the UI selection. Pending legacy events receive routes on upgrade (per-sample choice takes precedence); completed historical results retain their actual provider without invented routes. Keys stay in Web/Worker environment, never tenant tables.

## Interfaces

- `GET /api/v1/judge-runtime`: tenant setting, revision, configured options.
- `PUT /api/v1/judge-runtime`: admin + CSRF, `provider` and `expected_revision`; stale 409, unconfigured 422.
- `GET/POST /dashboard/judge-runtime`: equivalent Web workflow.

Endpoints/keys cannot be entered freely through the UI. Cloud delivery uses preconfigured endpoints and redaction. Configured does not mean currently reachable; inspect actual results. Scores are provider signals, not calibrated probabilities; see [audit/Judge chapter](learning/12-audit-judge-mapping.md).

## Recorded validation scope

The original feature validation recorded 81 automated passes (routing before/after switch, fixed-route retries, switching back, legacy routing, destination changes, isolation, CSRF and credential-safe display), 31/31 offline cases, and then-current default/tenant policy sets of 10/10 each. Local deployment checks found settings for five tenants and zero pending events lacking routes; the existing provider selection was kept. Those dated counts are not today’s full test total. No real Jev/DeepSeek request was made in that validation; test cloud connectivity separately with synthetic samples.
