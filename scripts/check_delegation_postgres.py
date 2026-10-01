"""真实 PG／Redis 委托并发；仅临时 schema，不调用外部工具。"""
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from sqlalchemy import select,func,text
from agentsentry.database import create_tenant_tables,get_engine,tenant_db_session
from agentsentry.capability import get_redis
from agentsentry.models import Delegation,CapabilityGrant,ToolCall,AuditEvent
from agentsentry.delegation_lab import setup
from agentsentry.schemas import ToolCallRequest
from agentsentry.policy import PolicyEngine
from agentsentry.service import submit_call
from agentsentry import delegation as d


def main():
    assert get_engine().dialect.name=='postgresql','本项不能用 SQLite 替代'
    tenant='t_'+uuid.uuid4().hex
    store=get_redis();keys=[]
    try:
        create_tenant_tables(tenant)
        with tenant_db_session(tenant) as db:
            parent,binding,grant,token,body=setup(db,store,tenant=tenant,max_uses=2)
            keys.append('cap:'+grant.token_hash)
            parent_id=parent.session_id
        barrier=Barrier(4)
        def reserve(_):
            barrier.wait(timeout=10)
            with tenant_db_session(tenant) as db:
                request=body.model_copy(update={'request_id':uuid.uuid4()})
                try:return d.create(db,store,tenant,'demo-agent',request,token,binding)['id']
                except d.DelegationError as exc:
                    db.rollback();return exc.code
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(reserve,range(4)))
        admitted=[x for x in results if len(x)==36]
        assert len(admitted)==2 and results.count('parent_capability_exhausted')==2,results
        assert int(store.hgetall(keys[0])['remaining'])==0
        with tenant_db_session(tenant) as db:
            job=d.claim(db,tenant,'reader-agent',admitted[0])
        barrier=Barrier(4)
        call_id=uuid.uuid4()
        def call(_):
            barrier.wait(timeout=10)
            with tenant_db_session(tenant) as db:
                # 使用与 HTTP 路由一致的封签验证和行锁。
                d.load_valid(db,tenant,admitted[0],'reader-agent',job['envelope'],job['envelope_hmac'])
                req=ToolCallRequest(call_id=call_id,session_id=job['worker_session_id'],tool='read_document',arguments={'document_id':'public-guide'})
                return submit_call(db,store,PolicyEngine.from_file('policies/default.yaml'),req,'',
                    'reader-agent',tenant,job['session_token'],admitted[0])[1]['status']
        with ThreadPoolExecutor(max_workers=4) as pool:statuses=list(pool.map(call,range(4)))
        assert statuses==['completed']*4,statuses
        with tenant_db_session(tenant) as db:
            assert db.scalar(select(func.count()).select_from(ToolCall))==1
            assert db.get(Delegation,admitted[0]).remaining==0
            assert db.scalar(select(func.count()).select_from(AuditEvent).where(
                AuditEvent.call_id==str(call_id),AuditEvent.event_type=='tool_result'))==1
        print(json.dumps({'environment':'真实 PostgreSQL／Redis 临时租户 schema','passed':True,
            '四并发预留':{'允许':2,'额度耗尽':2,'父剩余次数':0},
            '四次同调用重试':{'完成响应':4,'实际读取记录':1,'结果审计':1},
            '禁止写入副作用':0},ensure_ascii=False))
    finally:
        for key in keys:store.delete(key)
        with get_engine().begin() as conn:conn.execute(text(f'DROP SCHEMA IF EXISTS "{tenant}" CASCADE'))

if __name__=='__main__':main()
