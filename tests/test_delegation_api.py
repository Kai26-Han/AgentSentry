import uuid
import pytest
from fastapi.testclient import TestClient
from agentsentry import main
from agentsentry.config import get_settings
from agentsentry.database import get_engine,get_session_factory,_sqlite_tenant_engine
from agentsentry.evaluation import MemoryRedis
from agentsentry.reader_agent import execute_job

@pytest.fixture
def web(tmp_path,monkeypatch):
    old_settings,old_serializer=main.settings,main.serializer
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/api.db')
    get_settings.cache_clear();get_engine.cache_clear();get_session_factory.cache_clear();_sqlite_tenant_engine.cache_clear()
    main.settings=get_settings();main.serializer=main.URLSafeTimedSerializer(main.settings.session_secret,salt='agentsentry-admin')
    store=MemoryRedis();monkeypatch.setattr(main,'get_redis',lambda:store)
    try:
        with TestClient(main.app) as client:
            client.post('/login',data={'password':main.settings.admin_password})
            csrf=main.serializer.loads(client.cookies['agentsentry_session'])['csrf']
            yield client,{'X-CSRF-Token':csrf},store
    finally:
        _sqlite_tenant_engine.cache_clear();get_session_factory.cache_clear();get_engine().dispose();get_engine.cache_clear();get_settings.cache_clear()
        main.settings,main.serializer=old_settings,old_serializer


def headers(key,role='demo-agent',tenant='default'):
    return {'Authorization':'Bearer '+key,'X-Agent-ID':role,'X-Tenant-ID':tenant}


def test_independent_identity_and_complete_gateway_path(web):
    client,admin,store=web
    path='/api/v3/delegation-workers/reader-agent/credential'
    assert client.post(path).status_code==403
    key=client.post(path,headers=admin).json()['agent_api_key']
    child=headers(key,'reader-agent');parent=headers(main.settings.agent_api_key)
    assert client.get('/api/v3/delegations/inbox',headers=child).status_code==200
    assert client.get('/api/v3/delegations/inbox',headers=headers(main.settings.agent_api_key,'reader-agent')).status_code==401
    assert client.get('/api/v3/delegations/inbox',headers=headers(key)).status_code==401
    assert client.post('/api/v3/delegations',headers=child,json={'request_id':str(uuid.uuid4()),
        'parent_session_id':'whatever','tool':'read_document','resources':['public-guide'],'max_uses':1,'ttl_seconds':300}).status_code==403
    for path in ['/api/v1/tool-calls','/api/v2/runtime-sessions/other/memory/write',
                 '/api/v2/runtime-sessions/other/model-egress/check','/api/v2/runtime-sessions/other/output-check']:
        assert client.post(path,headers=child,json={}).status_code==403,path
    assert client.put('/api/v2/runtime-sessions/other/start',headers=child,json={}).status_code==403
    other=client.post('/api/v2/tenants',headers=admin,json={'name':'Attack Lab 0123abcd'}).json()
    assert client.get('/api/v3/delegations/inbox',headers=headers(key,'reader-agent',other['tenant_id'])).status_code==401
    session='delegation-http-'+str(uuid.uuid4())
    body={'transport':'http','capture_mode':'metadata','user_task':'阅读公开资料并简要总结'}
    start=client.put(f'/api/v2/runtime-sessions/{session}/start',headers=parent,json=body).json()
    parent['X-Runtime-Session']=start['session_token']
    grant=client.post('/api/v1/capabilities',headers=admin,json={'agent_id':'demo-agent','tool':'read_document',
        'resources':['public-guide'],'max_uses':3,'ttl_seconds':600}).json()
    request={'request_id':str(uuid.uuid4()),'parent_session_id':session,'tool':'read_document',
             'resources':['public-guide'],'max_uses':1,'ttl_seconds':300}
    create=client.post('/api/v3/delegations',headers={**parent,'X-Capability':grant['token']},json=request)
    assert create.status_code==200,create.text
    job=create.json()
    assert 'token' not in str(job) and key not in str(job)
    claim=client.post(f'/api/v3/delegations/{job["id"]}/claim',headers=child).json()
    forged={**claim['envelope'],'resources':['private-finance']}
    call={'call_id':str(uuid.uuid4()),'session_id':claim['worker_session_id'],
          'tool':'read_document','arguments':{'document_id':'public-guide'}}
    payload={'call':call,'envelope':forged,'envelope_hmac':claim['envelope_hmac']}
    assert client.post(f'/api/v3/delegations/{job["id"]}/tool-calls',headers=child,json=payload).status_code==403
    payload['envelope']=claim['envelope'];payload['call']['tool']='create_task';payload['call']['arguments']={'title':'恶意写入'}
    assert client.post(f'/api/v3/delegations/{job["id"]}/tool-calls',headers=child,json=payload).status_code==403
    # 正式固定协作客户端只通过协议，独立身份。
    class Worker:
        def post(self,path,headers=None,json=None):
            return client.post(path,headers={**child,**(headers or {})},json=json)
    result=execute_job(Worker(),job['id'])
    assert result['status']=='completed',result
    result_url=f'/api/v3/delegations/{job["id"]}/result'
    assert client.get(result_url,headers=child).status_code==403
    accepted=client.get(result_url,headers=parent).json()
    assert accepted['trust']=='untrusted_data'
    assert len(accepted['source_call_ids'])==1
    checked=client.post(f'/api/v2/runtime-sessions/{session}/output-check',headers=parent,json={
        'check_id':str(uuid.uuid4()),'capture_mode':'metadata','output_kind':'final_answer',
        'user_task':body['user_task'],'draft':accepted['text'],
        'source_call_ids':accepted['source_call_ids']+[accepted['result_source_id']]})
    assert checked.status_code==200,checked.text
    page=client.get('/dashboard/delegations')
    assert page.status_code==200 and page.text.count('aria-current="page"')==1
    assert key not in page.text
    detail=client.get('/dashboard/delegations/'+job['id'])
    assert detail.status_code==200 and accepted['source_call_ids'][0] in detail.text
    assert accepted['text'] not in detail.text
    preview=client.get('/dashboard/delegations/'+job['id'],params={'show_result':'true'})
    assert preview.status_code==200 and accepted['text'] in preview.text
    assert client.get('/dashboard/runtime-sessions/calls/'+accepted['source_call_ids'][0]).status_code==200
    session_page=client.get('/dashboard/runtime-sessions/detail',params={'agent_id':'demo-agent','session_id':session})
    assert '/dashboard/delegations/'+job['id'] in session_page.text
    assert '/dashboard/calls/'+job['id'] not in session_page.text
    from agentsentry.database import tenant_db_session
    from agentsentry.models import Delegation
    with tenant_db_session('default') as db:
        db.get(Delegation,job['id']).result_text='<script>synthetic-tamper</script>'
        db.commit()
    tampered=client.get('/dashboard/delegations/'+job['id'],params={'show_result':'true'})
    assert '完整性异常' in tampered.text and 'synthetic-tamper' not in tampered.text
    assert client.post('/api/v3/delegations/'+job['id']+'/revoke').status_code==403
    assert client.post('/api/v3/delegations/'+job['id']+'/revoke',headers=admin).status_code==200
    assert client.get(result_url,headers=parent).status_code==403
    client.post('/api/v3/delegation-workers/reader-agent/credential',headers=admin)
    assert client.get('/api/v3/delegations/inbox',headers=child).status_code==401
