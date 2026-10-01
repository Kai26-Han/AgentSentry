# Single-Hop Delegation: Attenuation and Reply Poisoning

[English](#) · [中文](../../cases/delegation-boundaries.md)

> These are retained, dated experimental facts, reorganized by security question—not new tests performed during translation. Corpus/rule versions limit the conclusion. Your installation has no original private runtime database; generate your own evidence.

## Question and controls

A parent may delegate too much authority, duplicate uses, or treat a child’s approval claim as trusted instruction. Use independent fixed read-only identity, single hop, smaller resources/time, atomic parent reservation, sealed scope/result and actual reads. Reply integrity is not truth; it stays low-trust and passes output checks.

## 2026-10-01 observations

`delegation-lab-v1`: 22 boundaries/four controls repeated twice with matching conclusions, zero unauthorized effects/required audit gaps. Fixed MCP doubles and live integration are distinct:

| Mode | Facts |
| --- | --- |
| Actual PostgreSQL/Redis concurrency | Four competitors for two parent uses: two allowed/two denied; remaining zero |
| Four concurrent identical IDs | One upstream read and one result audit |
| Independent processes/local MCP | Reader completed one document and one MCP read |
| Forged or contaminated reply | Invalid seal rejected; a real-read forged-approval summary blocked and not passed to parent |

The three completed reads had no audit/Outbox gaps. Delegation-specific metadata intentionally not sent to Judge is not a false negative. See [redacted delegation evidence](../../cases/evidence/delegation.json).

Follow [chapter 15](../learning/15-delegation.md) and [protocol](../delegation.md) for offline/onsite reproduction and cleanup. Onsite scripts create dedicated research identities and do not write GitHub.

Independent identity is not OS isolation. Reader produces a fixed read-only summary, with no multi-model semantic experiment. Multihop/writes/cross-host/joint key-and-DB compromise are excluded; seals cannot establish factual truth.
