"""校验独立英文文档，并生成英文学习任务卡及威胁矩阵。"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import unicodedata
from urllib.parse import quote, unquote, urlparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASK_FIELDS = {'title', 'normal_expectation', 'boundary_expectation', 'facts',
               'explanation', 'variation', 'code', 'evidence_location', 'questions', 'limitation'}
STATUS = {'范围内已验证': 'Verified within stated scope', '部分验证': 'Partially verified',
          '已确认缺口': 'Confirmed gap', '未验证': 'Unverified', '当前不适用': 'Currently inapplicable'}
APPLICABILITY = {'当前适用': 'Currently applicable', '未来接入': 'Future integration',
                 '当前范围外': 'Outside current scope', '尚待验证': 'Awaiting verification'}
KIND = {'固定重放': 'Scripted replay', '真实模型': 'Real model', '单元测试': 'Unit test',
        '现场演练': 'Onsite drill', '验收报告': 'Acceptance report'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def english_path(source: Path) -> Path:
    relative = source.relative_to(ROOT)
    roots = {'README.zh-CN.md': 'README.md', 'CONTRIBUTING.md': 'CONTRIBUTING.en.md',
             'AgentSentry 整体项目方案.md': 'PROJECT-PLAN.en.md'}
    if str(relative) in roots:
        return ROOT / roots[str(relative)]
    return ROOT / 'docs/en' / relative.relative_to('docs')


def local_link(path, parent):
    original = ROOT / path
    if original.suffix == '.md' and (path.startswith('docs/') or path in
                                   {'README.zh-CN.md', 'CONTRIBUTING.md', 'AgentSentry 整体项目方案.md'}):
        original = english_path(original)
    return quote(os.path.relpath(original, parent), safe='/.-_')


def language_header(title, original, target):
    cn = quote(os.path.relpath(original, target.parent), safe='/.-_')
    return f'# {title}\n\n[English](#) · [中文]({cn})\n'


def load_overlay(source, path, version_key=None, version=None):
    data = json.loads(path.read_text(encoding='utf-8'))
    require(data.get('source_sha256') == hashlib.sha256(source.read_bytes()).hexdigest(),
            f'{path.relative_to(ROOT)}: source changed; review all translations and update source_sha256')
    if version_key:
        require(data.get(version_key) == version, f'{path.relative_to(ROOT)}: source version mismatch')
    return data


def render_tasks():
    source = ROOT / 'src/agentsentry/learning_tasks.json'
    data = json.loads(source.read_text(encoding='utf-8'))
    overlay = load_overlay(source, ROOT / 'docs/en/learning/task-translations.json',
                           'source_version', data['version'])
    require(set(overlay['topics']) == {t['id'] for t in data['topics']}, 'English task IDs differ')
    outputs = {}
    for task in data['topics']:
        number = task['id']
        translated = overlay['topics'][number]
        require(set(translated) == TASK_FIELDS and all(isinstance(x, str) and x.strip()
                for x in translated.values()), f'Topic {number}: missing/extra English fields')
        t = task | translated
        target = ROOT / f'docs/en/learning/assessment/{number}.md'
        original = ROOT / f'docs/learning/assessment/{number}.md'
        normal = local_link(task['normal_node'].split('::')[0], target.parent)
        boundary = local_link(task['boundary_node'].split('::')[0], target.parent)
        outputs[target] = language_header(f"{number} · {t['title']}: Personal Assessment Card", original, target) + f'''
Task version: `{data['version']}`. Read the [chapter](../{task['chapter']}) and [assessment guide](../personal-assessment.md).

> Generated from the canonical task catalog plus English prose overlay. Edit the overlay, not this file. Install test dependencies using the [quick start](../../../../README.md#quick-start). Run commands from the project root; no Docker/model is required. Existing case results are not your personal assessment.

## Predict before running

Write your own normal/boundary decisions and actual execution/display expectations first. Identify attacker-controlled input and gateway-verified facts; do not copy the hints below as your prediction.

```bash
.venv/bin/python -m agentsentry.learning_assessment predict --directory .local/learning-assessment/first-run --topic {number} --normal 'YOUR OWN NORMAL PREDICTION' --boundary 'YOUR OWN BOUNDARY PREDICTION'
.venv/bin/python -m agentsentry.learning_assessment run --directory .local/learning-assessment/first-run --topic {number}
```

Initialize the directory with `init` first. Passing does not auto-fill predictions; retests preserve prior reports and prediction snapshots.

## Two experiment units

| Unit | Fixed test node | Expected operation/facts |
| --- | --- | --- |
| Normal | `{task['normal_node']}` | {t['normal_expectation']} |
| Boundary | `{task['boundary_node']}` | {t['boundary_expectation']} |

These reuse tests, sometimes with multiple controls or parameterized instances. Their pass count is not a count of independent security capabilities.

- **Environment:** temporary SQLite, Redis doubles and test client; chapter 05 normal case launches actual local stdio MCP. Test credentials/policy, no cloud/GitHub/daily DB.
- **Evidence:** {t['evidence_location']}
- **Check:** {t['facts']}
- **Code:** {t['code']}
- **Effects/cleanup:** temporary synthetic data only; temporary DB/raw JUnit is cleaned. Retain redacted counts, version and node, not fabricated Web records. Interruption is not a pass.

Source: [normal test]({normal}) · [boundary test]({boundary}).

## Explain, vary and state limits

1. **Explanation:** {t['explanation']}
2. **Self-check:** {t['questions']}
3. **Variation:** {t['variation']}
4. **Limit:** write your own first, then compare: {t['limitation']}

Variations belong only in temporary fixtures/files. Predict first. Record unverified product issues without changing live rules to obtain a pass.

## Record and review

For topic `{number}`, fill `review.explanation`, `evidence`, `answers`, `variation`, `limitation`, `reviewer`, `reviewed_at` in `record.json`. Stored `personal_status` values remain `待学习` / `待复核` / `已掌握` (not yet studied / needs review / mastered); do not translate enum values. Cite report paths, fixed nodes and checkable facts, not credentials/business text/full free answers.

Only you or a human reviewer declares understanding after experiments, evidence, explanation, variation and limits. The tool checks completeness, not correctness. Product failures and personal explanations remain separately reviewed.
'''
    return outputs


def render_matrix():
    source = ROOT / 'docs/threat-framework-map.yaml'
    data = yaml.safe_load(source.read_text(encoding='utf-8'))
    overlay = load_overlay(source, ROOT / 'docs/en/threat-translations.json',
                           'mapping_version', data['mapping_version'])
    for key in ('categories', 'threats', 'runtime_signals'):
        require(set(overlay[key]) == {x['id'] for x in data[key]}, f'English {key} IDs differ')
    target = ROOT / 'docs/en/threat-framework-mapping.md'
    techniques = {x['id']: x for x in data['atlas_techniques']}
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    def link(path, label):
        return f'[{label}]({local_link(path, target.parent)})'
    def refs(threat):
        return ', '.join(f"[{x} {techniques[x]['name']}]({techniques[x]['url']})"
                         for x in threat['atlas']) or 'Not forced into a technique'
    atlas = data['frameworks']['atlas']
    owasp = data['frameworks']['owasp']
    lines = [language_header('AgentSentry Threat and Framework Mapping', source.with_name('threat-framework-mapping.md'), target),
             '> Generated from canonical `docs/threat-framework-map.yaml` and `docs/en/threat-translations.json`. Run `python scripts/check_english_docs.py --write`; do not edit this page directly.', '',
             f"Mapping version: {data['mapping_version']}.", '',
             f"OWASP: [Agentic Top 10 2026]({owasp['url']}). MITRE ATLAS: [official {atlas['release']} snapshot]({atlas['source_url']}); checked on {atlas['checked_on']}.", '',
             '**Interpretation:** each row evaluates only its stated path/samples. Scripted replay, real models and tests remain separate. Framework IDs are classification clues, not whole-category remediation. Cases retain dates/versions/before-after facts; passing other cases does not cancel a confirmed gap.', '',
             '## Applicability of all ten OWASP categories', '',
             '| Category | Applicability | Threats | Explanation |', '| --- | --- | --- | --- |']
    for c in data['categories']:
        text = overlay['categories'][c['id']]
        require(set(text) == {'note'} and isinstance(text['note'], str) and text['note'], 'Invalid category translation')
        ids = ', '.join(f'[{x}](#{x.lower()})' for x in c['threat_ids']) or 'None'
        lines.append(f"| {c['id']} {cell(c['name'])} | {APPLICABILITY[c['applicability']]} | {ids} | {cell(text['note'])} |")
    lines += ['', '## Project threat overview', '', '| Scenario | OWASP | MITRE ATLAS | Conclusion |', '| --- | --- | --- | --- |']
    for t in data['threats']:
        en = overlay['threats'][t['id']]
        required = {'title', 'entry', 'asset', 'scope', 'limitation', 'controls', 'evidence'}
        if not t['atlas']:
            required.add('atlas_note')
        require(set(en) == required, f"{t['id']}: missing/extra prose fields")
        require(all(isinstance(en[x], str) and en[x].strip() for x in required - {'controls', 'evidence'}), 'Blank prose')
        for k in ('controls', 'evidence'):
            require(isinstance(en[k], list) and len(en[k]) == len(t[k]) and
                    all(isinstance(x, str) and x.strip() for x in en[k]), f"{t['id']}: {k} translation mismatch")
        lines.append(f"| [{t['id']}](#{t['id'].lower()}) {cell(en['title'])} | {', '.join(t['owasp'])} | {refs(t)} | {STATUS[t['status']]} |")
    for t in data['threats']:
        en = overlay['threats'][t['id']]
        lines += ['', f'<a id="{t["id"].lower()}"></a>', '', f"## {t['id']} · {en['title']}", '',
                  f"- **Entry and asset:** {en['entry']}; {en['asset']}.",
                  f"- **Scope:** {en['scope']}.", f"- **Conclusion:** {STATUS[t['status']]}.",
                  f"- **OWASP:** {', '.join(t['owasp'])}.",
                  f"- **MITRE ATLAS:** {refs(t)}" + ('.' if t['atlas'] else f"; {en['atlas_note']}"),
                  '- **Controls:** ' + '; '.join(link(c['path'], text) for c, text in zip(t['controls'], en['controls'])) + '.',
                  '- **Evidence:**']
        for item, text in zip(t['evidence'], en['evidence']):
            samples = ', '.join(f"`{item['corpus']}:{x}`" for x in item.get('cases', [])) + '; ' if item.get('corpus') else ''
            lines.append(f"  - {KIND[item['kind']]}: {samples}{link(item['path'], 'Evidence')}; {text}")
        lines.append(f"- **Remaining boundary:** {en['limitation']}")
    lines += ['', '## Daily event mapping rules', '', 'Only committed typed audit metadata is classified. A hit is a clue; denial, pending and actual effects differ. Unlisted events remain unmatched, and Judge labels alone do not trigger classification.', '',
              '| Rule | Audit event | Required conditions | Project threats |', '| --- | --- | --- | --- |']
    for signal in data['runtime_signals']:
        en = overlay['runtime_signals'][signal['id']]
        require(set(en) == {'title'} and isinstance(en['title'], str) and en['title'], 'Invalid signal translation')
        condition = ', '.join(f'{k}={v}' for k, v in signal['when'].items())
        lines.append(f"| `{signal['id']}` {cell(en['title'])} | `{signal['event_type']}` | {cell(condition)} | {', '.join(signal['threat_ids'])} |")
    lines += ['', '## Maintenance', '',
              '1. Update canonical corpus/version/IDs and verify actual observations when samples change.',
              '2. Add dated evidence for changed results, retaining failures and distinguishing old records from new retests.',
              '3. Reevaluate relevant scope after MCP/model/policy changes; without new experiments state unverified.',
              '4. Review English overlays and their source hashes; regenerate both matrices/cards and run both offline checkers. English generation never changes runtime classification or framework snapshots.', '']
    return {target: '\n'.join(lines)}


def anchors(path):
    text = re.sub(r'```[^\n]*\n.*?```', '', path.read_text(encoding='utf-8'), flags=re.S)
    result, seen = set(), {}
    for title in re.findall(r'^#{1,6}\s+(.+)$', text, re.M):
        title = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', title).replace('`', '').replace('*', '').lower().strip()
        slug = ''.join(c for c in title if unicodedata.category(c)[0] in 'LNM' or c in '-_ ').replace(' ', '-')
        n = seen.get(slug, 0); seen[slug] = n + 1
        result.add(slug + (f'-{n}' if n else ''))
    result.update(re.findall(r'<a\s+(?:id|name)=["\x27]([^"\x27]+)', text))
    return result


def validate_documents():
    originals = [ROOT / 'README.zh-CN.md', ROOT / 'CONTRIBUTING.md', ROOT / 'AgentSentry 整体项目方案.md']
    originals += [p for p in (ROOT / 'docs').rglob('*.md') if not p.is_relative_to(ROOT / 'docs/en')]
    expected = {english_path(p) for p in originals}
    actual = set((ROOT / 'docs/en').rglob('*.md')) | {ROOT / x for x in ('README.md', 'CONTRIBUTING.en.md', 'PROJECT-PLAN.en.md')}
    require(expected == actual, 'English counterpart inventory differs: ' + ', '.join(str(p.relative_to(ROOT)) for p in expected ^ actual))
    errors, count = [], 0
    for p in sorted(actual):
        text = p.read_text(encoding='utf-8')
        has_title = text.startswith('# ') or (
            p == ROOT / 'README.md'
            and '<h1 align="center">AgentSentry</h1>' in text[:1000]
        )
        require(has_title and '[English](#) · [中文](' in text, f'Missing title/language link: {p}')
        for m in re.finditer(r'(!?)\[([^\]\n]*)\]\(([^)\n]+)\)', text):
            raw = m[3]; u = urlparse(raw)
            if u.scheme or u.netloc or raw == '#':
                continue
            q = (p.parent / unquote(u.path)).resolve() if u.path else p
            count += 1
            if not q.is_relative_to(ROOT) or not q.exists():
                errors.append(f'{p.relative_to(ROOT)}: missing/unsafe {raw}')
            elif q.suffix == '.md':
                if u.fragment and unquote(u.fragment) not in anchors(q):
                    errors.append(f'{p.relative_to(ROOT)}: missing anchor {raw}')
                if m[2] != '中文' and q not in actual:
                    errors.append(f'{p.relative_to(ROOT)}: English navigation points to Chinese {raw}')
        for filename, fn in re.findall(r'(tests/test_[A-Za-z0-9_]+\.py)(?:::([A-Za-z0-9_]+))?', text):
            q = ROOT / filename
            if not q.is_file():
                errors.append(f'{p.relative_to(ROOT)}: missing test {filename}')
            elif fn:
                names = {n.name for n in ast.walk(ast.parse(q.read_text())) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                if fn not in names:
                    errors.append(f'{p.relative_to(ROOT)}: missing node {filename}::{fn}')
        for filename in re.findall(r'\bscripts/[A-Za-z0-9_]+\.py', text):
            if not (ROOT / filename).is_file():
                errors.append(f'{p.relative_to(ROOT)}: missing script {filename}')
        for module in re.findall(r'-m (agentsentry[.a-zA-Z0-9_]+)', text):
            q = ROOT / 'src' / Path(*module.split('.'))
            if not q.with_suffix('.py').is_file() and not (q / '__main__.py').is_file():
                errors.append(f'{p.relative_to(ROOT)}: missing module {module}')
    require(not errors, '\n'.join(sorted(set(errors))))
    return len(actual), count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        generated = render_tasks() | render_matrix()
        for target, text in generated.items():
            if args.write:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding='utf-8')
            else:
                require(target.is_file() and target.read_text(encoding='utf-8') == text,
                        f'{target.relative_to(ROOT)}: generated English content differs; run --write')
        docs, links = validate_documents()
        print(f'English documentation checked: {docs} counterparts, {links} local links, 15 task cards, 15 threat scenarios.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(f'English documentation check failed: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
