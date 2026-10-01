# 13 · Adversarial validation and rule calibration

[English](#) · [中文](../../learning/13-validation-calibration.md)

## The security question

A rule that rejects everything can have zero dangerous writes and still make the Agent unusable. Evaluate normal completion, dangerous attempts, actual effects, displayed contamination and inconclusive results separately. Fixed proposals verify boundaries; real models verify behavior. Keep their denominators separate.

## Offline baseline

```bash
.venv/bin/python -m agentsentry.evaluation --policy policies/default.yaml --cases evals/cases.jsonl --output /tmp/agentsentry-learning-eval.json
.venv/bin/python -m pytest -q tests/test_evaluation.py tests/test_attack_lab.py tests/test_calibration.py
```

The 31 baseline cases contain 20 attacks and 11 controls. Mock Judge statistics apply to the mock implementation, not Jev or DeepSeek. Inspect sample versions and the assertions in [calibration.py](../../../src/agentsentry/calibration_results.py), [calibration_corpus.py](../../../src/agentsentry/calibration_corpus.py), and [calibration_runner.py](../../../src/agentsentry/calibration_runner.py).

## Compare two online runs

```bash
.venv/bin/python -m agentsentry.calibration_runner --mode scripted --output /tmp/agentsentry-learning-baseline.json
.venv/bin/python -m agentsentry.calibration_runner --mode scripted --output /tmp/agentsentry-learning-repeat.json
.venv/bin/python -m agentsentry.calibration_runner --compare /tmp/agentsentry-learning-baseline.json /tmp/agentsentry-learning-repeat.json --output /tmp/agentsentry-learning-comparison.json
```

Use the online terminal. Each run creates a new research tenant so prior Agent-level denial counters do not contaminate the next run. Comparing identical rules practices report comparison; it is not a completed rule adjustment. Comparison requires completed runs with compatible mode, sample hash and case keys. Interrupted, pending, unknown, unfinished-model and environment-error cases remain inconclusive.

`calibration-cases-v1` includes 12 attacks and 12 normal controls. A01–A08/N01–N08 are calibration data; A09–A12/N09–N12 are held out. A03 distinguishes draft from display contamination. N07 shows friction when apparently unrelated sending follows a private read. N08 examines benign quotation followed by a write; A10 checks parameter replacement.

## Facts before recommendations

For each case, link session, call, model preflight, output check, memory read/write, side-effect count and audit. A polluted draft blocked before display is not display contamination. A model that never proposes a dangerous call leaves tool-blocking effectiveness unverified. Judge is scored only against its observed events. Source IDs from temporary databases cannot be turned into daily Web links.

Run live mode only after configuring the local model:

```bash
.venv/bin/python -m agentsentry.calibration_runner --mode live --output /tmp/agentsentry-learning-calibration-live.json
```

It executes six attacks and six normal controls three times each: 36 executions, with model/version evidence. Inspect the full fixed collection rather than claiming a single-case filter the runner does not provide.

## A safe calibration cycle

Baseline → causal evidence → proposed change → human decision → versioned code and regression → held-out evaluation. Recommendations never automatically modify or publish rules. Identity, cross-tenant, credential and audit-failure boundaries must not be weakened to improve a sample score. Keep the private-session restriction if narrower logic cannot prevent splitting or paraphrased leakage, and disclose the normal-task cost.

[Boundary validation](../cases/boundary-validation.md) retains the original 49-case evidence, including three failures; subsequent fixes are new evidence rather than rewritten history. [Output cases](../cases/injection-and-output.md) distinguish A03/A12 remediation scopes.

## Self-check and cleanup

Explain why zero forbidden effects alone is insufficient, why pending approval is not normal completion, and why repeatedly tuning on held-out results destroys their independence. Reject remaining malicious research approvals, keep reports under new names, and never replay daily business tasks automatically. See [calibration operation](../calibration.md).


## Continue learning

[Previous chapter](12-audit-judge-mapping.md) · [Handbook](README.md) · [Next chapter](14-fault-propagation.md)

Use the handbook’s [environment conventions](README.md#prerequisites-and-command-conventions). Offline reports do not create records in your running dashboard.
