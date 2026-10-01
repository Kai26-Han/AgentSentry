"""个人学习结果收集；固定离线测试不会自动证明个人掌握。"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CATALOG = Path(__file__).with_name('learning_tasks.json')
LIMIT = 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def catalog():
    return json.loads(CATALOG.read_text(encoding='utf-8'))


def source_hash():
    """当前源码／测试／策略改变后，旧报告仅作历史证据。"""
    digest = hashlib.sha256()
    paths = [ROOT / 'pyproject.toml', ROOT / 'uv.lock']
    for folder, patterns in [('src/agentsentry', ('*.py', '*.json', '*.html')), ('tests', ('*.py',)),
                             ('scripts', ('*.py',)), ('sandbox', ('*.py',)),
                             ('evals', ('*.jsonl', '*.json', '*.yaml')), ('docs', ('threat-framework-map.yaml',)),
                             ('policies', ('default.yaml',)), ('policy-tests', ('*.yaml',))]:
        for pattern in patterns:
            paths.extend((ROOT / folder).rglob(pattern))
    for path in sorted(set(paths)):
        if path.is_file():
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    # 同目录替换避免中断留下半个报告；不覆盖历史实验文件。
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temp.open('x', encoding='utf-8') as stream:
            os.chmod(temp, 0o600)
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def init(directory):
    path = directory / 'record.json'
    if path.exists():
        raise ValueError('已有学习记录；请继续使用或选择新目录，不能覆盖历史记录')
    if directory.exists() and any(directory.iterdir()):
        raise ValueError('初始化需要空目录')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    c = catalog()
    record = {'version': c['version'], 'catalog_hash': fingerprint(c), 'baseline': c['baseline'],
        'created_at': now(), 'topics': [], 'practice': [
            {'id': x, 'status': '未执行', 'evidence': [], 'explanation': ''}
            for x in ('S01', 'S02', 'S03', 'S04', 'S05', 'L01', 'L02', 'L03')]}
    for topic in c['topics']:
        record['topics'].append({'id': topic['id'], 'prediction': {'normal': '', 'boundary': '', 'recorded_at': None},
            'experiments': {'normal': [], 'boundary': []}, 'personal_status': '待学习',
            'review': {'explanation': '', 'evidence': [], 'answers': '', 'variation': '',
                       'limitation': '', 'reviewer': '', 'reviewed_at': ''}})
    save(path, record)
    summary(directory)
    return record


def load(directory):
    path = directory / 'record.json'
    if path.stat().st_size > LIMIT:
        raise ValueError('学习记录过大')
    record = json.loads(path.read_text(encoding='utf-8'))
    c = catalog()
    if record.get('version') != c['version'] or record.get('catalog_hash') != fingerprint(c):
        raise ValueError('任务卡版本已变化；保留旧记录并为新版本初始化独立目录')
    if [x['id'] for x in record['topics']] != [x['id'] for x in c['topics']]:
        raise ValueError('主题记录不完整')
    return record


def predict(directory, topic_id, normal, boundary):
    if not normal.strip() or not boundary.strip() or max(len(normal), len(boundary)) > 1000:
        raise ValueError('两项预测都需填写，且每项最多 1000 字；不要包含凭据或业务原文')
    record = load(directory)
    row = next(x for x in record['topics'] if x['id'] == topic_id)
    row['prediction'] = {'normal': normal, 'boundary': boundary, 'recorded_at': now()}
    row['personal_status'] = '待复核'
    save(directory / 'record.json', record)
    summary(directory)


def junit(path, node):
    """只读计数，不复制失败原文、stdout 或 XML 到长期学习记录。"""
    if not path.exists() or path.stat().st_size > LIMIT:
        raise ValueError('缺少 JUnit 报告或报告过大')
    data = path.read_bytes()
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('不接受含实体声明的报告')
    root = ET.fromstring(data)
    expected_class = node.split('::')[0][:-3].replace('/', '.')
    expected_test = node.split('::')[1]
    selected = []
    for case in root.iter('testcase'):
        name = case.get('name', '')
        name_matches = name == expected_test or ('[' not in expected_test and name.startswith(expected_test + '['))
        if case.get('classname') == expected_class and name_matches:
            selected.append(case)
    if not selected:
        raise ValueError('报告没有任务卡指定的测试，不能用其他测试冒充')
    counts = {'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
    for case in selected:
        key = ('errors' if case.find('error') is not None else
               'failed' if case.find('failure') is not None else
               'skipped' if case.find('skipped') is not None else 'passed')
        counts[key] += 1
    status = ('失败' if counts['failed'] else '无法判定' if counts['errors'] or counts['skipped'] else '通过')
    return {'status': status, 'counts': counts, 'junit_hash': hashlib.sha256(data).hexdigest()}


def safe_environment(directory):
    policy = directory / 'policies/default.yaml'
    policy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'policies/default.yaml', policy)
    # 使用最小子进程环境和固定测试凭据；Settings 仍可能读取项目 .env，
    # 所有可联网开关／密钥显式覆盖，本工具不会加载或打印 .env。
    env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT') if key in os.environ}
    env.update({'PYTHONPATH': str(ROOT / 'src'), 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
        'POLICY_PATH': str(policy), 'DATABASE_URL': 'sqlite:///' + str(directory / 'fallback.db'),
        'REDIS_URL': 'redis://127.0.0.1:1/0', 'SANDBOX_URL': 'http://127.0.0.1:1',
        'MCP_DEMO_DIR': str(directory / 'mcp'), 'ADMIN_PASSWORD': 'learning-test-admin-only',
        'SESSION_SECRET': 'learning-test-session-secret-at-least-32-chars',
        'AGENT_API_KEY': 'learning-test-agent-secret-at-least-32-chars',
        'JUDGE_PROVIDER': 'mock', 'WEBHOOK_URL': '', 'WEBHOOK_SECRET': '',
        'JUDGE_OPENAI_API_KEY': '', 'JUDGE_OPENAI_BASE_URL': '', 'JEV_API_KEY': '', 'DEEPSEEK_API_KEY': '',
        'OUTPUT_LOCAL_MODEL_BASE_URL': '', 'GOAL_LOCAL_MODEL_BASE_URL': '',
        'AGENTSENTRY_MEMORY_ENABLED': 'true', 'AGENTSENTRY_RUNTIME_BINDING_REQUIRED': 'false',
        'AGENTSENTRY_MODEL_REMOTE_DESTINATIONS': '{}', 'AGENTSENTRY_REMOTE_MCP_REGISTRY': '{}',
        'AGENTSENTRY_REMOTE_MCP_ALLOW_LOOPBACK_DEMO': 'false', 'AGENTSENTRY_GITHUB_MCP_ENABLED': 'false',
        'AGENTSENTRY_GITHUB_MCP_WRITE_ENABLED': 'false', 'GITHUB_MCP_PAT': '', 'GITHUB_MCP_WRITE_PAT': '',
        'GITHUB_MCP_TEST_REPO': '', 'GITHUB_MCP_CREATE_ISSUE_SCHEMA_SHA256': ''})
    return env


def run(directory, topic_id):
    record = load(directory)
    chosen = [x for x in catalog()['topics'] if topic_id == 'all' or x['id'] == topic_id]
    source = source_hash()
    batch = str(uuid.uuid4())
    started = now()
    jobs = []
    for topic in chosen:
        row = next(x for x in record['topics'] if x['id'] == topic['id'])
        for kind in ('normal', 'boundary'):
            name = 'reports/' + batch + '-' + topic['id'] + '-' + kind + '.json'
            item = {'id': batch + '-' + topic['id'] + '-' + kind, 'report': name,
                    'status': '运行中', 'started_at': started, 'node': topic[kind + '_node'],
                    'source_hash': source, 'prediction_before_run': dict(row['prediction'])}
            row['experiments'][kind].append(item)
            jobs.append((row, kind, item))
    save(directory / 'record.json', record)
    # 不使用 shell；命令节点仅来自固定目录，用户不能提交任意程序或 pytest 参数。
    with tempfile.TemporaryDirectory(prefix='agentsentry-learning-') as temp:
        work = Path(temp)
        xml = work / 'junit.xml'
        nodes = list(dict.fromkeys(x[2]['node'] for x in jobs))
        try:
            result = subprocess.run([sys.executable, '-m', 'pytest', '-q', *nodes,
                '--junitxml=' + str(xml), '--basetemp=' + str(work / 'pytest')], cwd=ROOT,
                env=safe_environment(work), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=240, check=False)
            exit_code = result.returncode
            reason = None
        except subprocess.TimeoutExpired:
            exit_code, reason = None, '测试超过 240 秒，未确认完成'
        except OSError:
            exit_code, reason = None, '无法启动测试进程'
        for row, kind, item in jobs:
            try:
                facts = junit(xml, item['node'])
            except (ValueError, ET.ParseError):
                facts = {'status': '无法判定', 'counts': {}, 'reason': '报告缺失／不完整／节点不匹配'}
            if exit_code not in (0, 1) or reason:
                facts['status'] = '无法判定'
                facts['reason'] = reason or '测试收集或执行环境故障'
            item.update(facts, finished_at=now(), process_exit=exit_code)
            report = {**item, 'version': record['version'], 'topic': row['id'], 'kind': kind,
                      'environment': '离线临时数据库／替身；指定 MCP 正常项含本地 stdio 子进程'}
            save(directory / item['report'], report)
            item['report_hash'] = hashlib.sha256((directory / item['report']).read_bytes()).hexdigest()
            print(f'{row["id"]} {"正常" if kind == "normal" else "边界"}：{item["status"]}')
    save(directory / 'record.json', record)
    summary(directory)
    return all(x[2]['status'] == '通过' for x in jobs)


def collect(directory, topic_id, kind, path):
    """人工导入仅证明指定测试结果；无法证明运行前版本或预测。"""
    record = load(directory)
    row = next(x for x in record['topics'] if x['id'] == topic_id)
    topic = next(x for x in catalog()['topics'] if x['id'] == topic_id)
    result = junit(path, topic[kind + '_node'])
    name = 'reports/import-' + str(uuid.uuid4()) + '.json'
    item = {**result, 'report': name, 'node': topic[kind + '_node'], 'started_at': None,
            'finished_at': now(), 'source_hash': None, 'prediction_before_run': None,
            'origin': '人工导入，运行版本与预测时序未核实'}
    save(directory / name, item)
    item['report_hash'] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    row['experiments'][kind].append(item)
    save(directory / 'record.json', record)
    summary(directory)


def current_result(directory, item, current_source):
    if not item:
        return '未执行'
    if item['status'] == '运行中':
        return '无法判定（中断）'
    rel = Path(item['report'])
    path = (directory / rel).resolve()
    if rel.is_absolute() or not path.is_relative_to(directory.resolve()):
        return '无法判定（证据路径越界）'
    if not path.is_file() or path.stat().st_size > LIMIT:
        return '无法判定（报告缺失）'
    if hashlib.sha256(path.read_bytes()).hexdigest() != item.get('report_hash'):
        return '无法判定（报告改变）'
    if item.get('source_hash') is None:
        return item['status'] + '（导入版本未核实）'
    if item['source_hash'] != current_source:
        return '待复测（源码变化）'
    return item['status']


def summary(directory):
    record = load(directory)
    source = source_hash()
    lines = ['# 个人学习验收记录', '', f'任务版本：{record["version"]}；基线：{record["baseline"]}。', '',
        '自动部分只核对指定实验结果；个人掌握由本人／人工复核，未进行语义评分。', '',
        '| 主题 | 正常实验 | 边界实验 | 运行前预测 | 个人自评 | 复核材料 |',
        '|---|---|---|---|---|---|']
    passed = 0
    for topic, row in zip(catalog()['topics'], record['topics']):
        latest = [row['experiments'][kind][-1] if row['experiments'][kind] else None for kind in ('normal', 'boundary')]
        results = [current_result(directory, x, source) for x in latest]
        passed += sum(x == '通过' for x in results)
        predicted = all(x and x.get('prediction_before_run') and
            x['prediction_before_run'].get('normal', '').strip() and
            x['prediction_before_run'].get('boundary', '').strip() for x in latest)
        review = row['review']
        complete = all(review.get(key) for key in ('explanation', 'evidence', 'answers', 'variation', 'limitation', 'reviewer', 'reviewed_at'))
        claimed = row.get('personal_status', '待学习')
        if claimed not in ('待学习', '待复核', '已掌握'):
            claimed = '待复核（自评状态无效）'
        if claimed == '已掌握':
            claimed = '已掌握（人工声明）' if complete and predicted else '待复核（缺预测或复核材料）'
        lines.append(f'| {topic["id"]} {topic["title"]} | {results[0]} | {results[1]} | {"已记录" if predicted else "未记录／未核实"} | {claimed} | {"齐全，内容待人工核对" if complete else "待填写"} |')
    lines += ['', f'当前源码下自动实验通过：**{passed}/30**。该计数不是安全覆盖率或个人掌握率。', '',
        '## 本机与真实模型实操', '', '| 任务 | 人工记录状态 | 证据条数 |', '|---|---|---|']
    for item in record['practice']:
        # 只呈现允许状态；不渲染自由内容、URL 或记录里的凭据。
        status = item.get('status') if item.get('status') in ('未执行', '通过', '失败', '无法判定', '待复核') else '待复核'
        lines.append(f'| {item["id"]} | {status}（人工记录） | {len(item.get("evidence", []))} |')
    lines += ['', '基础机制完成结论与端到端完成结论均需人工填写总结；报告不会自动签发“已掌握”。', '',
        '完整预测和复核内容在 record.json，请勿填写凭据、业务原文或自由回答全文。',
        '报告哈希仅检测普通编辑；本地记录可被人修改，不是独立可信认证或安全证明。', '']
    path = directory / 'summary.md'
    path.write_text('\n'.join(lines), encoding='utf-8')
    os.chmod(path, 0o600)
    return passed


def main():
    parser = argparse.ArgumentParser(description='个人学习验收：固定实验与人工掌握记录分开')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('init', 'predict', 'run', 'collect', 'summary'):
        p = sub.add_parser(name)
        p.add_argument('--directory', type=Path, required=True, help='独立学习记录目录，建议 .local/learning-assessment/日期')
        if name in ('predict', 'run', 'collect'):
            p.add_argument('--topic', choices=[x['id'] for x in catalog()['topics']] + (['all'] if name == 'run' else []), required=True)
        if name == 'predict':
            p.add_argument('--normal', required=True)
            p.add_argument('--boundary', required=True)
        if name == 'collect':
            p.add_argument('--kind', choices=['normal', 'boundary'], required=True)
            p.add_argument('--junit', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init': init(args.directory)
        elif args.command == 'predict': predict(args.directory, args.topic, args.normal, args.boundary)
        elif args.command == 'run':
            if not run(args.directory, args.topic): raise SystemExit(1)
        elif args.command == 'collect': collect(args.directory, args.topic, args.kind, args.junit)
        else: print(f'当前实验通过：{summary(args.directory)}/30；个人状态需人工复核')
        print('记录：' + str((args.directory / 'summary.md').resolve()))
    except (ValueError, OSError, KeyError, json.JSONDecodeError, ET.ParseError) as exc:
        # 不回显异常原文或导入报告，以免带出用户输入／凭据。
        raise SystemExit('收集未完成：记录或报告无效／不匹配，请核对目录、版本和固定节点') from None


if __name__ == '__main__': main()
