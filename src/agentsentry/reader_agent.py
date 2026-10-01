"""固定只读协作 Agent；只能通过网关委托协议读取，不直接连接工具。"""
import argparse
import os
import uuid
from urllib.parse import urlparse
import httpx


def gateway_url(value):
    parsed = urlparse(value)
    if parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'} or parsed.username or parsed.password:
        raise ValueError('首版协作 Agent 只连接本机网关')
    return value.rstrip('/')


def execute_job(client, delegation_id):
    prefix = '/api/v3/delegations/' + str(uuid.UUID(delegation_id))
    response = client.post(prefix + '/claim')
    response.raise_for_status()
    job = response.json()
    envelope = job['envelope']
    common = {'envelope': envelope, 'envelope_hmac': job['envelope_hmac']}
    calls, contents = [], []
    for resource in job['resources']:
        call_id = str(uuid.uuid4())
        field = 'document_id' if job['tool'] == 'read_document' else 'card_id'
        response = client.post(prefix + '/tool-calls', headers={'X-Runtime-Session': job['session_token']},
            json={**common, 'call': {'call_id': call_id, 'session_id': job['worker_session_id'],
                                    'tool': job['tool'], 'arguments': {field: resource}}})
        response.raise_for_status()
        value = response.json()
        if value['status'] != 'completed':
            raise ValueError('协作读取未完成；不会重试或提交虚假结果')
        calls.append(call_id)
        contents.append(str(value['result'].get('content', ''))[:120])
    # 固定摘要演示：材料作为数据复制片段，展示前仍必须检查。此版本不声称模型语义安全。
    summary = '已读取公开材料：' + '；'.join(contents)
    response = client.post(prefix + '/complete', json={**common, 'text': summary[:500], 'source_call_ids': calls})
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description='通过网关执行单跳只读委托')
    parser.add_argument('delegation_id')
    parser.add_argument('--gateway', default=os.environ.get('GATEWAY_URL', 'http://127.0.0.1:8000'))
    args = parser.parse_args()
    key = os.environ.get('AGENTSENTRY_READER_API_KEY', '')
    if not key:
        parser.error('请在进程环境设置 AGENTSENTRY_READER_API_KEY，勿作为命令参数传递')
    with httpx.Client(base_url=gateway_url(args.gateway), timeout=30, headers={
        'Authorization': 'Bearer ' + key, 'X-Agent-ID': 'reader-agent',
        'X-Tenant-ID': os.environ.get('AGENT_TENANT_ID', 'default')}) as client:
        try:
            result = execute_job(client, args.delegation_id)
        except (httpx.HTTPError, ValueError):
            raise SystemExit('协作失败，未绕过网关；请查委托及调用证据')
        print('委托状态：' + result['status'])


if __name__ == '__main__':
    main()
