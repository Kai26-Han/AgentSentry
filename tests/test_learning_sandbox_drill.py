"""现场辅助脚本必须人工审批；unknown 不自动重做或伪造完成。"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import uuid
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('learning_sandbox_drill', ROOT / 'scripts/sandbox_drill.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class Response:
    def __init__(self, data, code=200): self.data, self.status_code = data, code
    def json(self): return self.data
    def raise_for_status(self): assert self.status_code < 400


def test_prepare_binds_session_leaves_manual_approval_and_private_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(d, 'admin', lambda *a: {'X-CSRF-Token': 'test-only'})
    probes = []
    monkeypatch.setattr(d, 'sandbox', lambda command: probes.append(command) or {'exit_code': 0})
    requests = []
    class Client:
        def put(self, path, **kw):
            requests.append((path, kw)); return Response({'session_token': 'synthetic-binding'})
        def post(self, path, **kw):
            requests.append((path, kw))
            if path == '/api/v1/capabilities': return Response({'grant_id': str(uuid.uuid4()), 'token': 'synthetic-grant'})
            assert path == '/api/v1/tool-calls'
            assert kw['headers']['X-Runtime-Session'] == 'synthetic-binding'
            if kw['json']['arguments']['command'] == 'printf replaced': return Response({}, 409)
            return Response({'status': 'pending_approval', 'result': None, 'approval_id': str(uuid.uuid4())}, 202)
    path, report = d.prepare(Client(), SimpleNamespace(agent_api_key='synthetic-agent'), tmp_path)
    assert report['status'] == '待人工审批' and report['自动批准'] is False
    assert path.stat().st_mode & 0o777 == 0o600
    assert probes == ['test ! -e ' + d.marker(report['call_id'])]
    assert all('/decision' not in x[0] for x in requests)
    assert 'synthetic-grant' not in str(report)


def test_unknown_never_retries_execution_finishes_session_or_removes_evidence(tmp_path, monkeypatch):
    cid = str(uuid.uuid4())
    row = {'version': 'learning-sandbox-v2', 'call_id': cid, 'session_id': 'learning-sandbox-' + cid,
           'grant_id': str(uuid.uuid4()), 'grant_token': 'synthetic', 'session_token': 'synthetic'}
    path = tmp_path / 'private.json'; d.private_write(path, row)
    class Client:
        def get(self, *a, **kw): return Response({'status': 'unknown'})
        def post(self, *a, **kw): raise AssertionError('不能重试')
        def put(self, *a, **kw): raise AssertionError('不能伪造完成')
    monkeypatch.setattr(d, 'sandbox', lambda *a: (_ for _ in ()).throw(AssertionError('不能清理未明证据')))
    result = d.verify(Client(), SimpleNamespace(agent_api_key='synthetic'), path)
    assert result['status'] == '无法判定' and path.exists()


def test_record_cannot_replace_fixed_marker_with_arbitrary_command(tmp_path):
    cid = str(uuid.uuid4())
    p = tmp_path / 'private.json'
    d.private_write(p, {'version': 'learning-sandbox-v2', 'call_id': cid,
                       'session_id': 'other-session', 'grant_id': str(uuid.uuid4())})
    with pytest.raises(ValueError): d.read_record(p)
    assert d.arguments(cid)['command'].endswith('/tmp/learning-approval-' + cid)
    with pytest.raises(ValueError): d.marker('invalid; command')


def test_approved_verify_checks_single_write_and_cleans_only_its_fixed_record(tmp_path, monkeypatch):
    cid = str(uuid.uuid4()); grant = str(uuid.uuid4())
    row = {'version': 'learning-sandbox-v2', 'call_id': cid, 'session_id': 'learning-sandbox-' + cid,
           'grant_id': grant, 'grant_token': 'synthetic', 'session_token': 'synthetic'}
    path = tmp_path / 'private.json'; d.private_write(path, row)
    probes = []
    monkeypatch.setattr(d, 'sandbox', lambda command: probes.append(command) or {'exit_code': 0})
    monkeypatch.setattr(d, 'admin', lambda *a: {'X-CSRF-Token': 'test-only'})
    final = {'status': 'completed', 'result': {'stdout': 'sandbox-ok'}}
    requests = []
    class Client:
        def get(self, *a, **kw): return Response(final)
        def post(self, path, **kw):
            requests.append(path)
            assert path == '/api/v1/tool-calls' and kw['json']['arguments'] == d.arguments(cid)
            return Response(final)
        def put(self, path, **kw):
            assert path.endswith(row['session_id'] + '/finish') and kw['json']['status'] == 'completed'
            return Response({})
        def delete(self, path, **kw):
            assert path == '/api/v1/capabilities/' + grant
            return Response({})
    report = d.verify(Client(), SimpleNamespace(agent_api_key='synthetic'), path)
    assert report['status'] == '通过' and report['实际写入次数'] == 1
    assert len(probes) == 3 and probes[0] == probes[1] and 'wc -c' in probes[0]
    assert probes[2] == 'rm -f ' + d.marker(cid) and not path.exists()
    assert all('/decision' not in x for x in requests)
