"""学习收集不能把缺失、跳过、历史报告或自动测试冒充个人掌握。"""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from agentsentry import learning_assessment as l


def xml(path, name='test_idempotency_and_exhaustion', content='', classname='tests.test_service'):
    path.write_text(f'<testsuites><testsuite><testcase classname="{classname}" name="{name}">{content}</testcase></testsuite></testsuites>')
    return path


def test_init_preserves_history_and_requires_personal_review(tmp_path):
    l.init(tmp_path)
    record = l.load(tmp_path)
    assert len(record['topics']) == 15 and len(record['practice']) == 8
    assert all(x['personal_status'] == '待学习' for x in record['topics'])
    assert (tmp_path / 'record.json').stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError): l.init(tmp_path)
    row = record['topics'][0]
    row['personal_status'] = '已掌握'
    l.save(tmp_path / 'record.json', record)
    assert l.summary(tmp_path) == 0
    assert '待复核（缺预测或复核材料）' in (tmp_path / 'summary.md').read_text()


@pytest.mark.parametrize('body,status', [('', '通过'), ('<failure>synthetic failure</failure>', '失败'),
                                         ('<error>setup unavailable</error>', '无法判定'), ('<skipped/>', '无法判定')])
def test_collector_separates_pass_failure_setup_and_skip(tmp_path, body, status):
    node = l.catalog()['topics'][0]['normal_node']
    assert l.junit(xml(tmp_path / 'junit.xml', content=body), node)['status'] == status


def test_collector_rejects_empty_wrong_node_and_xml_entities(tmp_path):
    node = l.catalog()['topics'][0]['normal_node']
    path = xml(tmp_path / 'junit.xml', name='unrelated_test')
    with pytest.raises(ValueError): l.junit(path, node)
    path.write_text('<testsuites/>')
    with pytest.raises(ValueError): l.junit(path, node)
    path.write_text('<!DOCTYPE x [<!ENTITY token SYSTEM "file:///private-file">]><testsuites/>')
    with pytest.raises(ValueError): l.junit(path, node)


def test_runner_isolated_environment_keeps_automatic_and_personal_states_separate(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_API_KEY', 'must-not-inherit-parent')
    monkeypatch.setenv('GITHUB_MCP_WRITE_PAT', 'must-not-inherit-pat')
    monkeypatch.setenv('JUDGE_PROVIDER', 'deepseek')
    l.init(tmp_path)
    l.predict(tmp_path, '01', '正常执行一个任务', '提交失败时零执行')
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs['env']['AGENT_API_KEY'] != 'must-not-inherit-parent'
        assert kwargs['env']['GITHUB_MCP_WRITE_PAT'] == ''
        assert kwargs['env']['JUDGE_PROVIDER'] == 'mock'
        assert kwargs['env']['DATABASE_URL'].startswith('sqlite:///')
        assert 'HOME' not in kwargs['env'] and 'CODEX_HOME' not in kwargs['env']
        path = Path(next(x.split('=', 1)[1] for x in command if x.startswith('--junitxml=')))
        path.write_text('<testsuites><testsuite>' + ''.join(
            f'<testcase classname="tests.test_service" name="{x.split("::")[1]}"/>'
            for x in command if '::' in x) + '</testsuite></testsuites>')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(l.subprocess, 'run', fake_run)
    assert l.run(tmp_path, '01')
    row = l.load(tmp_path)['topics'][0]
    assert row['personal_status'] == '待复核'
    assert row['experiments']['normal'][0]['prediction_before_run']['normal'] == '正常执行一个任务'
    assert l.summary(tmp_path) == 2
    # 后填预测不能改变已经运行的快照。
    l.predict(tmp_path, '01', '后来更改的预测', '后来更改的边界')
    assert l.load(tmp_path)['topics'][0]['experiments']['normal'][0]['prediction_before_run']['normal'] == '正常执行一个任务'
    monkeypatch.setattr(l, 'source_hash', lambda: 'new-source')
    assert l.summary(tmp_path) == 0
    assert '待复测（源码变化）' in (tmp_path / 'summary.md').read_text()


def test_import_does_not_claim_current_version_and_missing_report_is_not_pass(tmp_path):
    directory = tmp_path / 'assessment'
    l.init(directory)
    path = xml(tmp_path / 'import.xml')
    l.collect(directory, '01', 'normal', path)
    assert l.summary(directory) == 0
    row = l.load(directory)['topics'][0]
    item = row['experiments']['normal'][0]
    report = directory / item['report']
    report.write_text('changed')
    assert '报告改变' in l.current_result(directory, item, l.source_hash())
    report.unlink()
    assert '报告缺失' in l.current_result(directory, item, l.source_hash())
    item['report'] = '../import.xml'
    assert '路径越界' in l.current_result(directory, item, l.source_hash())
    item['status'] = '运行中'
    assert '中断' in l.current_result(directory, item, l.source_hash())


def test_nonzero_collection_exit_cannot_turn_existing_passes_into_completed_run(tmp_path, monkeypatch):
    l.init(tmp_path)
    monkeypatch.setattr(l.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=2))
    assert not l.run(tmp_path, '01')
    record = l.load(tmp_path)
    assert record['topics'][0]['experiments']['normal'][-1]['status'] == '无法判定'
    assert record['topics'][0]['personal_status'] == '待学习'
