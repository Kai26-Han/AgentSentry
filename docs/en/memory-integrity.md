# Memory Integrity and Storage-Poisoning Protection

[English](#) · [中文](../memory-integrity.md)

## Threats

Malicious instructions can enter reviewed material, or an attacker can directly edit memory/source-review records. This mechanism targets those security boundaries, not ordinary knowledge freshness, conflict resolution or factual updates.

```text
Source → candidate → session/source checks → content checks → memory + signature
Next session → signature/state/expiry/content recheck → eligible low-trust recall
                                               → integrity incident and audit
```

## Write, storage and recall

Checks are independent of memory `kind`. They match forged system/developer roles, delayed commands, dangerous tools, secret egress, credentials and personal information, including normalized zero-width/spacing/separator forms and bounded valid Base64. Credentials/explicit secret egress are rejected; other suspicious text quarantined. Unknown/unreviewed or memory-derived sources remain quarantined. Manual activation cannot bypass explicit dangerous-content rules.

Tenant-separated HMAC covers identity, text, state, source, expiry and review security fields. Its key is domain-separated from server `SESSION_SECRET`, outside PostgreSQL. Legitimate activation/revocation/expiry/purge updates signatures. Recall verifies integrity and rescans content; changed or newly dangerous text stays out of context. Output checks also verify recalled memory integrity.

Keep `SESSION_SECRET` stable and protected. Replacing it invalidates old signatures; there is no automatic rotation/resigning tool. Plan backup, stopped writes and human review before rotation, not automatic trust in database content.

Legacy unsigned memories are quarantined and old source reviews revoked without automatically signing text. A dedicated historical-review action checks old digest/rules/source and signs only quarantined content; activation is separate. Signed-but-invalid entries can be purged, not activated or overwritten through renewed source trust. Integrity events contain IDs/reasons/version only, not text sent to Judge.

## Independent fixed lab

`agentsentry-memory-security-lab` requires an **existing Attack Lab research tenant**. It uses 12 attacks/six controls: A01–A08 content/role/encoding/kind boundaries; A09–A12 direct edits of synthetic database records; N01–N06 reviewed-safe recall. New write/read sessions are used and synthetic memory text cleared afterward. Interrupted/failed runs stay explicit.

First initialize the attack/memory lab and locally retrieve `lab.tenant_id` from the private `.local/attack-lab.json`, without printing all credentials:

```bash
docker compose exec -T web agentsentry-memory-security-lab --tenant 'YOUR_RESEARCH_TENANT_ID'
```

Only recognized Attack Lab tenants are accepted. Web `/dashboard/memory-security-runs`; tenant-admin API `GET /api/v2/memory-security-runs`. There is no arbitrary SQL/text/external-address UI.

Fixed records call the same memory service but preseed synthetic source reads. Their dedicated source details validate tenant/run/case and are not normal call audit/Judge evidence. No real MCP or model answer is involved, so “not recalled” does not establish uncontaminated display. For actual end-to-end work use `agentsentry-memory-lab --mode live` separately.

## Limits

Finite rules may miss paraphrases, complex encoding and invented facts without instructions. Signatures protect database-only modification while the application key remains uncompromised; combined application/key/database compromise can forge records and delete audit. Revocation cannot retract delivered context. Both capture modes retain memory text; Judge never decides activation. See [memory learning](learning/07-memory-security.md).
