"""委托协议与管理员页面；身份凭据不进入消息正文。"""
import uuid
from fastapi import Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from redis.exceptions import RedisError
from . import delegation as d
from .database import tenant_db_session
from .models import Delegation, DelegationCall, DelegationLabRun, AuditEvent, WorkerPrincipal, ToolCall, ThreatMappingAssessment
from .schemas import DelegationRequest, DelegatedToolRequest, DelegationResultRequest


def register(app):
    from .main import (require_agent, require_csrf, admin_session, require_form_csrf, get_redis,
                       policy_for, research_tenant_for_read, research_tenant_choices, templates)
    from . import main as main_module
    get_redis = lambda: main_module.get_redis()
    from .service import submit_call

    def operation(tenant, fn, delegation_id=None):
        with tenant_db_session(tenant) as db:
            try:
                return fn(db)
            except d.DelegationError as exc:
                db.rollback()
                row = db.get(Delegation, delegation_id) if delegation_id else None
                d.event(db, row, "protocol", exc.code, "deny")
                db.commit()
                return JSONResponse({"detail": exc.code}, status_code=exc.status)
            except (RedisError, SQLAlchemyError):
                db.rollback()
                return JSONResponse({"detail": "委托存储不可用，未放行"}, status_code=503)
            except ValueError:
                db.rollback()
                return JSONResponse({"detail": "委托检查未通过"}, status_code=409)

    @app.post('/api/v3/delegation-workers/reader-agent/credential')
    def credential(session=Depends(require_csrf)):
        def run(db):
            key, generation = d.provision_worker(db)
            return {"agent_id": d.WORKER_ID, "agent_api_key": key, "generation": generation}
        return operation(session['tenant_id'], run)

    @app.post('/api/v3/delegation-workers/reader-agent/deactivate')
    def deactivate(session=Depends(require_csrf)):
        def run(db):
            row = db.get(WorkerPrincipal, d.WORKER_ID, with_for_update=True)
            if row:
                row.active = False
                d.event(db, None, 'identity', 'worker_deactivated', 'deny')
                db.commit()
            return {"active": False}
        return operation(session['tenant_id'], run)

    @app.post('/api/v3/delegations')
    def create(body: DelegationRequest, agent=Depends(require_agent),
               x_capability: str = Header(default=''), x_runtime_session: str = Header(default='')):
        return operation(agent[1], lambda db: d.create(db, get_redis(), agent[1], agent[0], body,
                                                      x_capability, x_runtime_session))

    @app.get('/api/v3/delegations/inbox')
    def inbox(request: Request, agent=Depends(require_agent)):
        if agent[0] != d.WORKER_ID:
            raise HTTPException(403, '协作身份才能读取委托收件箱')
        def run(db):
            principal = db.get(WorkerPrincipal, agent[0], with_for_update=True)
            if not principal or not principal.active or principal.key_hash != request.state.worker_key_hash:
                raise d.DelegationError('worker_identity_changed', 403)
            return {"delegations": [d.view(row) for row in db.scalars(
                select(Delegation).where(Delegation.worker_agent_id == agent[0],
                    Delegation.status.in_(['created', 'running'])).order_by(Delegation.created_at).limit(20))]}
        return operation(agent[1], run)


    @app.post('/api/v3/delegations/{delegation_id}/claim')
    def claim(delegation_id: uuid.UUID, request: Request, agent=Depends(require_agent)):
        if agent[0] != d.WORKER_ID:
            raise HTTPException(403, '协作身份才能领取委托')
        return operation(agent[1], lambda db: d.claim(db, agent[1], agent[0], str(delegation_id), request.state.worker_key_hash), str(delegation_id))

    @app.post('/api/v3/delegations/{delegation_id}/tool-calls')
    def call(delegation_id: uuid.UUID, body: DelegatedToolRequest, request: Request, agent=Depends(require_agent),
             x_runtime_session: str = Header(default='')):
        if agent[0] != d.WORKER_ID:
            raise HTTPException(403, '协作身份才能执行委托')
        def run(db):
            row = d.load_valid(db, agent[1], str(delegation_id), agent[0], body.envelope, body.envelope_hmac,
                               expected_worker_hash=request.state.worker_key_hash)
            if body.call.session_id != row.worker_session_id:
                raise d.DelegationError('worker_session_mismatch', 403)
            if body.call.tool != row.tool:
                raise d.DelegationError('delegated_scope_violation', 403)
            status, result = submit_call(db, get_redis(), policy_for(agent[1]), body.call, '',
                agent[0], agent[1], x_runtime_session, delegation_id=row.id)
            return JSONResponse(result, status_code=status)
        return operation(agent[1], run, str(delegation_id))

    @app.post('/api/v3/delegations/{delegation_id}/complete')
    def complete(delegation_id: uuid.UUID, body: DelegationResultRequest, request: Request, agent=Depends(require_agent)):
        if agent[0] != d.WORKER_ID:
            raise HTTPException(403, '协作身份才能提交结果')
        return operation(agent[1], lambda db: d.complete(db, agent[1], agent[0], str(delegation_id), body, request.state.worker_key_hash), str(delegation_id))

    @app.get('/api/v3/delegations/{delegation_id}/result')
    def result(delegation_id: uuid.UUID, agent=Depends(require_agent),
               x_runtime_session: str = Header(default='')):
        if agent[0] != 'demo-agent':
            raise HTTPException(403, '父身份才能接收结果')
        return operation(agent[1], lambda db: d.parent_result(db, agent[1], agent[0],
                                                            str(delegation_id), x_runtime_session), str(delegation_id))

    @app.post('/api/v3/delegations/{delegation_id}/revoke')
    def revoke(delegation_id: uuid.UUID, session=Depends(require_csrf)):
        def run(db):
            d.revoke_delegation(db, str(delegation_id))
            return {"revoked": True}
        return operation(session['tenant_id'], run)

    @app.get('/dashboard/delegations')
    def dashboard(request: Request, tenant: str | None = None, session=Depends(admin_session)):
        tenant_id = research_tenant_for_read(session, tenant)
        with tenant_db_session(tenant_id) as db:
            rows = db.scalars(select(Delegation).order_by(Delegation.created_at.desc()).limit(100)).all()
            worker = db.get(WorkerPrincipal, d.WORKER_ID)
            runs = db.scalars(select(DelegationLabRun).order_by(DelegationLabRun.created_at.desc()).limit(10)).all()
        choices = []
        for choice in research_tenant_choices(session):
            with tenant_db_session(choice["id"]) as db:
                count = db.scalar(select(func.count()).select_from(Delegation)) or 0
            if count:
                choices.append({**choice, "count": count})
        return templates.TemplateResponse(request, 'delegations.html', {
            'tenant_id': tenant_id, 'rows': rows, 'worker': worker, 'runs': runs,
            'observer': tenant_id != session['tenant_id'], 'csrf': session['csrf'],
            'research_tenants': choices, 'rules_version': d.VERSION})

    @app.get('/dashboard/delegations/{delegation_id}')
    def detail(request: Request, delegation_id: uuid.UUID, tenant: str | None = None,
               show_result: bool = False, session=Depends(admin_session)):
        tenant_id = research_tenant_for_read(session, tenant)
        with tenant_db_session(tenant_id) as db:
            row = db.get(Delegation, str(delegation_id))
            if not row:
                raise HTTPException(404, '委托不存在')
            calls = db.scalars(select(ToolCall).join(DelegationCall).where(
                DelegationCall.delegation_id == row.id)).all()
            events = [event for event in db.scalars(select(AuditEvent).where(
                AuditEvent.event_type == 'delegation_decision').order_by(AuditEvent.created_at))
                      if event.payload.get('delegation_id') == row.id]
            assessments = db.scalars(select(ThreatMappingAssessment).where(
                ThreatMappingAssessment.audit_event_id.in_([event.id for event in events]),
                ThreatMappingAssessment.status == 'matched')).all()
        from .runtime_redaction import redact_preview
        return templates.TemplateResponse(request, 'delegation_detail.html', {
            'row': row, 'calls': calls, 'events': events, 'assessments': assessments, 'tenant_id': tenant_id,
            'result_integrity': d.valid_reply(row),
            'result_preview': redact_preview(row.result_text)[0] if show_result and row.result_text and d.valid_reply(row) else None,
            'observer': tenant_id != session['tenant_id'], 'csrf': session['csrf']})

    @app.post('/dashboard/delegations/worker/credential')
    async def web_credential(request: Request, session=Depends(admin_session)):
        await require_form_csrf(request, session)
        result = credential(session)
        if isinstance(result, JSONResponse):
            return result
        return templates.TemplateResponse(request, 'delegation_credential.html', result)

    @app.post('/dashboard/delegations/worker/deactivate')
    async def web_deactivate(request: Request, session=Depends(admin_session)):
        await require_form_csrf(request, session)
        result = deactivate(session)
        if isinstance(result, JSONResponse):
            return result
        return RedirectResponse('/dashboard/delegations', status_code=303)

    @app.post('/dashboard/delegations/{delegation_id}/revoke')
    async def web_revoke(request: Request, delegation_id: uuid.UUID, session=Depends(admin_session)):
        await require_form_csrf(request, session)
        result = revoke(delegation_id, session)
        if isinstance(result, JSONResponse):
            return result
        return RedirectResponse('/dashboard/delegations/' + str(delegation_id), status_code=303)
