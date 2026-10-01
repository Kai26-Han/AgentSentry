"""当前沙箱学习演练：申请、人工审批、事实核验和固定隔离探针。"""
import argparse
import json
import os
import subprocess
import uuid
from pathlib import Path

import httpx
from itsdangerous import URLSafeTimedSerializer
from agentsentry.config import get_settings

ROOT = Path(__file__).resolve().parents[1]


def private_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def sandbox(command, timeout=3):
    # 所有命令由本脚本固定生成，不从 CLI 接收任意代码或用户路径。
    payload = {'call_id': str(uuid.uuid4()), 'command': command, 'timeout_seconds': timeout}
    code = "import httpx,json,sys; r=httpx.post('http://sandbox:8080/execute',json=json.loads(sys.stdin.read()),timeout=8); r.raise_for_status(); print(r.text)"
    result = subprocess.run(['docker', 'compose', 'exec', '-T', 'web', 'python', '-c', code],
        cwd=ROOT, input=json.dumps(payload), text=True, capture_output=True, timeout=20, check=True)
    return json.loads(result.stdout)


def marker(call_id):
    return '/tmp/learning-approval-' + str(uuid.UUID(call_id))


def arguments(call_id):
    return {'command': 'printf sandbox-ok; printf x >> ' + marker(call_id), 'timeout_seconds': 3}


def headers(settings, row):
    return {'Authorization': 'Bearer ' + settings.agent_api_key, 'X-Tenant-ID': 'default',
            'X-Capability': row['grant_token'], 'X-Runtime-Session': row['session_token']}


def admin(client, settings):
    response = client.post('/login', data={'tenant_id': 'default', 'password': settings.admin_password})
    if response.status_code != 303:
        raise ValueError('管理员登录失败')
    return {'X-CSRF-Token': URLSafeTimedSerializer(settings.session_secret, salt='agentsentry-admin').loads(
        client.cookies['agentsentry_session'])['csrf']}


def prepare(client, settings, directory):
    csrf = admin(client, settings)
    call_id = str(uuid.uuid4())
    session_id = 'learning-sandbox-' + call_id
    auth = {'Authorization': 'Bearer ' + settings.agent_api_key, 'X-Tenant-ID': 'default'}
    session = client.put('/api/v2/runtime-sessions/' + session_id + '/start', headers=auth,
        json={'transport': 'http', 'capture_mode': 'metadata',
              'user_task': '在受限沙箱执行一次固定合成打印和临时标记写入。'})
    session.raise_for_status()
    grant = client.post('/api/v1/capabilities', headers=csrf, json={
        'agent_id': 'demo-agent', 'tool': 'run_shell', 'resources': ['sandbox-shell'],
        'ttl_seconds': 600, 'max_uses': 1})
    grant.raise_for_status()
    row = {'version': 'learning-sandbox-v2', 'call_id': call_id, 'session_id': session_id,
        'session_token': session.json()['session_token'], 'grant_id': grant.json()['grant_id'],
        'grant_token': grant.json()['token']}
    path = directory / (call_id + '.private.json')
    # 先保存有限期凭据，异常时管理员能按真实 call_id 收尾；不打印内容。
    private_write(path, row)
    response = client.post('/api/v1/tool-calls', headers=headers(settings, row), json={
        'call_id': call_id, 'session_id': session_id, 'tool': 'run_shell', 'arguments': arguments(call_id)})
    response.raise_for_status()
    pending = response.json()
    if pending['status'] != 'pending_approval' or pending['result'] is not None:
        raise ValueError('本轮必须经过人工审批，当前决定未进入预期状态')
    assert sandbox('test ! -e ' + marker(call_id))['exit_code'] == 0
    changed = client.post('/api/v1/tool-calls', headers=headers(settings, row), json={
        'call_id': call_id, 'session_id': session_id, 'tool': 'run_shell',
        'arguments': {'command': 'printf replaced', 'timeout_seconds': 3}})
    assert changed.status_code == 409
    report = {'version': row['version'], 'scope': '网关审批前边界', 'status': '待人工审批',
        'call_id': call_id, 'session_id': session_id, 'approval_id': pending['approval_id'],
        '审批前标记不存在': True, '同ID换参数冲突': True, '自动批准': False}
    private_write(directory / (call_id + '-prepare.json'), report)
    return path, report


def read_record(path):
    if path.stat().st_size > 4096:
        raise ValueError('记录过大')
    row = json.loads(path.read_text())
    if row['version'] != 'learning-sandbox-v2' or row['session_id'] != 'learning-sandbox-' + str(uuid.UUID(row['call_id'])):
        raise ValueError('只接受本脚本生成的固定会话')
    uuid.UUID(row['grant_id'])
    return row


def verify(client, settings, path):
    row = read_record(path)
    auth = {'Authorization': 'Bearer ' + settings.agent_api_key, 'X-Tenant-ID': 'default'}
    response = client.get('/api/v1/tool-calls/' + row['call_id'], headers=auth)
    response.raise_for_status()
    result = response.json()
    status = result['status']
    if status in ('pending_approval', 'executing', 'unknown'):
        return {'version': row['version'], 'call_id': row['call_id'], 'status': '无法判定',
            'gateway_status': status, '说明': '先在事实卡处理或核对原调用，不能换 ID 自动重做'}
    assert status in ('completed', 'denied', 'failed')
    if status == 'completed':
        assert result['result']['stdout'] == 'sandbox-ok'
        assert sandbox('test "$(wc -c < ' + marker(row['call_id']) + ')" -eq 1')['exit_code'] == 0
        replay = client.post('/api/v1/tool-calls', headers=headers(settings, row), json={
            'call_id': row['call_id'], 'session_id': row['session_id'], 'tool': 'run_shell',
            'arguments': arguments(row['call_id'])})
        replay.raise_for_status()
        assert replay.json() == result
        assert sandbox('test "$(wc -c < ' + marker(row['call_id']) + ')" -eq 1')['exit_code'] == 0
    else:
        assert sandbox('test ! -e ' + marker(row['call_id']))['exit_code'] == 0
    assert sandbox('rm -f ' + marker(row['call_id']))['exit_code'] == 0
    finish = client.put('/api/v2/runtime-sessions/' + row['session_id'] + '/finish', headers=auth,
        json={'status': 'completed' if status == 'completed' else 'failed',
              'error_code': '' if status == 'completed' else 'learning_sandbox_not_completed'})
    finish.raise_for_status()
    csrf = admin(client, settings)
    client.delete('/api/v1/capabilities/' + row['grant_id'], headers=csrf).raise_for_status()
    path.unlink()  # 清除本轮令牌原文，保留无凭据证据。
    return {'version': row['version'], 'scope': '网关批准后或拒绝后的副作用核验',
        'status': '通过' if status == 'completed' else '正常任务未完成', 'gateway_status': status,
        'call_id': row['call_id'], 'session_id': row['session_id'],
        '实际写入次数': 1 if status == 'completed' else 0, '重放不重复执行': status == 'completed',
        '清理标记与凭据': True, '会话已结束与授权吊销': True}


def isolation():
    readonly = sandbox('touch /app/learning-escape-test')
    network = sandbox("python -c 'import socket; socket.socket()'")
    # 固定探针只检查 macOS 常见宿主目录；不代表所有宿主文件均已验证。
    host = sandbox('test ! -e /Users')
    timeout = sandbox('sleep 10', 1)
    facts = {'只读根目录': readonly['exit_code'] != 0 and 'Read-only file system' in readonly['stderr'],
        'socket创建拒绝': network['exit_code'] != 0 and 'Operation not permitted' in network['stderr'],
        '指定宿主路径不可见': host['exit_code'] == 0, '超时终止': timeout['timed_out'] is True}
    return {'version': 'learning-sandbox-v2', 'scope': '直连内部执行服务的固定限制探针，未验证网关审批链',
        'status': '通过' if all(facts.values()) else '失败', 'facts': facts,
        'limit': '仅指定探针，不证明不存在容器逃逸或其他宿主路径'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase', choices=['prepare', 'verify', 'isolation'], required=True)
    p.add_argument('--directory', type=Path, default=ROOT / '.local/learning-sandbox')
    p.add_argument('--record', type=Path, help='prepare 生成的仅本机可读凭据记录')
    p.add_argument('--report', type=Path, help='保存无凭据事实报告，必须是新文件')
    args = p.parse_args()
    try:
        if args.phase == 'isolation': report = isolation()
        else:
            settings = get_settings()
            with httpx.Client(base_url=f'http://127.0.0.1:{settings.agentsentry_port}', timeout=20,
                              follow_redirects=False) as client:
                if args.phase == 'prepare':
                    path, report = prepare(client, settings, args.directory)
                    print('仅本机凭据记录：' + str(path))
                    print(f'请在事实卡核对固定命令后批准或拒绝：http://127.0.0.1:{settings.agentsentry_port}/dashboard/approvals/{report["approval_id"]}')
                    print('十分钟内决定，随后用 --phase verify --record 指向该文件核验；终端退出不会取消审批。')
                else:
                    if not args.record: p.error('verify 需要 --record')
                    report = verify(client, settings, args.record)
        if args.report: private_write(args.report, report)
        print(json.dumps(report, ensure_ascii=False))
        if report['status'] not in ('通过', '待人工审批'): raise SystemExit(2)
    except (ValueError, AssertionError, KeyError, OSError, httpx.HTTPError, subprocess.SubprocessError):
        raise SystemExit('演练未完成：请核对本机服务与本轮记录；有未决审批时在所属租户处理，不能自动重试副作用') from None


if __name__ == '__main__': main()
