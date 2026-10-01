import secrets
import json
import uuid
import shutil
import re
from datetime import timedelta
from urllib.parse import quote, urlencode
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from redis.exceptions import RedisError

from .capability import get_redis, issue, revoke
from .config import get_settings
from .judge.adapters import JUDGE_PROVIDER_IDS, configured_judge_providers
from .judge.runtime import backfill_unfinished_routes, change_runtime_provider, runtime_config
from .database import Base, TenantBase, create_tenant_tables, db_session, ensure_runtime_task_column, get_engine, tenant_db_session, tenant_schema
from .models import ActionChainState, Alert, AlertGroup, Approval, AttackCaseResult, AttackRun, AuditEvent, CalibrationCaseResult, CalibrationRun, CapabilityGrant, DataFlowDecision, DataFlowIncident, ExternalMessage, GoalAssessment, GoalLabCase, GoalLabRun, JudgeResult, JudgeRuntimeChange, JudgeRoute, JudgeSample, JudgeSampleRun, McpProfileChange, McpProfileVersion, McpSupplyIncident, MemoryEntry, MemoryLabCase, MemoryLabRun, MemorySecurityCase, MemorySecurityRun, Outbox, RuntimeControl, RuntimeControlChange, RuntimeDecision, RuntimeIncident, RuntimeSession, Task, ThreatMappingAssessment, ToolCall, WebhookDelivery, utcnow
from .policy import PolicyManager
from .samples import create_sample, run_sample, sample_metrics, seed_samples
from .schemas import ApprovalDecision, AttackCaseSubmission, AttackRunFinish, AttackRunRequest, CalibrationCaseSubmission, CalibrationRunRequest, CapabilityRequest, GoalLabCaseSubmission, GoalLabRunFinish, GoalLabRunRequest, JudgeRuntimeUpdate, JudgeSampleRequest, JudgeSampleRunRequest, MemoryDecisionRequest, MemoryFailureRequest, MemoryLabCaseRequest, MemoryLabRunRequest, MemoryReadRequest, MemorySourceTrustRequest, MemoryWriteRequest, ModelEgressCheckRequest, OutputCheckRequest, PolicyUpdate, RuntimeControlRequest, RuntimeSessionFinish, RuntimeSessionReview, RuntimeSessionStart, TenantRequest, ToolCallRequest
from .attack_results import create_run, finish_run, install_fixtures, run_view, submit_result
from .calibration_results import (compare_views as compare_calibration_views,
    create_run as create_calibration_run, finish_run as finish_calibration_run,
    install_fixtures as install_calibration_fixtures, run_view as calibration_run_view,
    submit_case as submit_calibration_case)
from .runtime_analysis import finish_session, list_sessions, review_session, session_view, start_session
from .action_chain import session_view as action_chain_view
from .dashboard_navigation import navigation as dashboard_navigation
from .runtime_guard import RULES_VERSION as RUNTIME_RULES_VERSION, rule_catalog, set_control
from .runtime_binding import session_token
from .data_flow import (RULES_VERSION as DATA_FLOW_RULES_VERSION, check_model,
                        rule_catalog as data_flow_rule_catalog, scrub_operational_payloads)
from .output_safety import check_output
from .memory import decide_memory, enabled as memory_enabled, list_memories, list_trusted_sources, read_memories, reconcile_active_memories, record_failure, review_legacy_memory, revoke_source, trust_source, write_candidates
from .memory_integrity import list_incidents, migrate_unsealed
from .memory_lab import create_run as create_memory_run, expire_fixture_memory, finish_run as finish_memory_run, install_fixtures as install_memory_fixtures, run_view as memory_run_view, scrub_old_answer_text, submit_case as submit_memory_case
from .memory_security_lab import run_view as memory_security_run_view
from .service import call_view, decide_approval, recover_unknown_calls, submit_call
from .service import canonical_hash
from .goal_analysis import assessment_view
from .goal_lab import (create_run as create_goal_run, finish_run as finish_goal_run,
    install_fixtures as install_goal_fixtures, record_case as record_goal_case,
    run_view as goal_run_view)
from .tenants import Tenant, create_tenant, get_tenant, hash_agent_key, list_tenant_ids, seed_default_tenant, verify_password
from .tools import seed_documents
from .runtime_redaction import redact_preview
from .threat_mapping import load_catalog as load_threat_catalog, projection_health
from .mcp_remote import probe_remote_mcp, registry as remote_mcp_registry
from .mcp_supply import decide_candidate as decide_mcp_candidate, review_summary as mcp_review_summary, rollback_profile as rollback_mcp_profile, scrub_observations as scrub_mcp_observations, seed_baseline as seed_mcp_baseline


settings = get_settings()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def masked_payload(value):
    if isinstance(value, dict):
        return {key: ("[已遮盖]" if key in {"content", "title", "text", "command", "stdout", "stderr",
                                           "draft", "body", "user_task", "final_answer", "raw_text"}
                      and isinstance(item, str) else masked_payload(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [masked_payload(item) for item in value]
    if isinstance(value, str):
        return redact_preview(value)[0]
    return value


templates.env.filters["masked_payload"] = masked_payload
templates.env.globals["judge_threshold"] = lambda: settings.judge_score_threshold
serializer = URLSafeTimedSerializer(settings.session_secret or "testing-only", salt="agentsentry-admin")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_runtime()
    policy_path = Path(settings.policy_path)
    if not policy_path.exists():
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(policy_path.parent.parent / "policies/default.yaml", policy_path)
    app.state.policies = {"default": PolicyManager(settings.policy_path)}
    from . import models  # noqa: F401 - register mappings
    TenantBase.metadata.create_all(get_engine())
    Base.metadata.create_all(get_engine())
    ensure_runtime_task_column("default")
    seed_default_tenant()
    with db_session() as session:
        if "default" in remote_mcp_registry():
            seed_mcp_baseline(session, remote_mcp_registry()["default"])
            session.commit()
        backfill_unfinished_routes(session, settings)
        seed_documents(session)
        seed_samples(session)
        recover_unknown_calls(session)
        scrub_old_answer_text(session)
        migrate_unsealed(session)
        reconcile_active_memories(session)
        scrub_operational_payloads(session)
        scrub_mcp_observations(session)
    for tenant_id in list_tenant_ids():
        if tenant_id != "default":
            create_tenant_tables(tenant_id)
            with tenant_db_session(tenant_id) as session:
                if tenant_id in remote_mcp_registry():
                    seed_mcp_baseline(session, remote_mcp_registry()[tenant_id])
                    session.commit()
                backfill_unfinished_routes(session, settings)
                recover_unknown_calls(session)
                migrate_unsealed(session)
                reconcile_active_memories(session)
                scrub_operational_payloads(session)
                scrub_mcp_observations(session)
    yield


app = FastAPI(title="AgentSentry", version="0.3.0", lifespan=lifespan)

from .i18n import install as install_i18n
install_i18n(templates, app)


@app.exception_handler(SQLAlchemyError)
@app.exception_handler(RedisError)
async def dependency_unavailable(request: Request, exc):
    # 不向客户端泄露数据库地址、请求参数或依赖错误原文。
    return JSONResponse({"detail": "Safety dependency unavailable; query the original request ID if already submitted",
                         "status": "unavailable"}, status_code=503)


def policy_for(tenant_id: str) -> PolicyManager:
    tenant_schema(tenant_id)
    if tenant_id not in app.state.policies:
        path = Path(settings.policy_path).with_name(tenant_id + ".yaml")
        app.state.policies[tenant_id] = PolicyManager(str(path))
    return app.state.policies[tenant_id]


def policy_path_for(tenant_id: str) -> Path:
    tenant_schema(tenant_id)
    return Path(settings.policy_path) if tenant_id == "default" else Path(settings.policy_path).with_name(tenant_id + ".yaml")


@app.exception_handler(HTTPException)
async def browser_auth_redirect(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/dashboard") and request.method == "GET":
        return RedirectResponse("/login", status_code=303)
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/v3/delegations") or request.url.path.endswith(("/output-check", "/memory/write", "/memory/read", "/memory/failure", "/model-egress/check", "/complete")):
        return JSONResponse({"detail": "Invalid content request"}, status_code=422)
    return await request_validation_exception_handler(request, exc)


def admin_session(request: Request) -> dict:
    cookie = request.cookies.get("agentsentry_session", "")
    try:
        data = serializer.loads(cookie, max_age=8 * 3600)
        if data.get("role") == "admin" and isinstance(data.get("csrf"), str):
            tenant_id = data.get("tenant_id", "default")
            tenant = get_tenant(tenant_id)
            if tenant and tenant.active:
                data["tenant_id"] = tenant_id
                return data
    except (BadSignature, SignatureExpired):
        pass
    raise HTTPException(401, "Administrator login required")


def dashboard_shell(request: Request) -> dict:
    """Shared navigation context; never use a displayed research tenant as auth scope."""
    if not request.url.path.startswith("/dashboard"):
        return {}
    session = admin_session(request)
    path = request.url.path
    if path.startswith("/dashboard/calibration-runs"):
        active = "calibration-runs"
    elif path.startswith("/dashboard/goal-runs"):
        active = "goal-runs"
    elif path.startswith("/dashboard/attack-runs"):
        active = "attack-runs"
    elif path.startswith("/dashboard/memory-security-runs"):
        active = "memory-security-runs"
    elif path.startswith("/dashboard/memory-runs"):
        active = "memory-runs"
    elif path.startswith("/dashboard/memories") or path.startswith("/dashboard/memory-sources"):
        active = "memories"
    elif path.startswith("/dashboard/runtime-sessions"):
        active = "runtime-sessions"
    elif path.startswith("/dashboard/threat-map"):
        active = "threat-map"
    elif path.startswith("/dashboard/data-flow"):
        active = "data-flow"
    elif path.startswith("/dashboard/calls") or path.startswith("/dashboard/activity"):
        active = "activity"
    else:
        active = path.removeprefix("/dashboard/") if path != "/dashboard" else "overview"
        active = active.split("/", 1)[0]
    with tenant_db_session(session["tenant_id"]) as db:
        open_alerts = (db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0)
        open_alerts += db.scalar(select(func.count()).select_from(RuntimeIncident).where(RuntimeIncident.status == "open")) or 0
        open_alerts += db.scalar(select(func.count()).select_from(DataFlowIncident).where(DataFlowIncident.status == "open")) or 0
        pending_approvals = db.scalar(select(func.count()).select_from(Approval).where(Approval.status == "pending")) or 0
    return {"shell_tenant_id": session["tenant_id"], "shell_csrf": session["csrf"],
            "shell_active": active, "shell_open_alerts": open_alerts,
            "shell_pending_approvals": pending_approvals,
            **dashboard_navigation(active, path, request.query_params, session["tenant_id"])}


templates.context_processors.append(dashboard_shell)


def require_csrf(request: Request, session=Depends(admin_session)):
    if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
        raise HTTPException(403, "CSRF token required")
    return session


def research_tenant_for_read(session: dict, requested: str | None) -> str:
    """Allow the platform administrator to inspect only dedicated lab results."""
    current = session["tenant_id"]
    if not requested or requested == current:
        return current
    if current != "default":
        raise HTTPException(403, "Research tenant access denied")
    try:
        tenant = get_tenant(requested)
    except ValueError:
        tenant = None
    if not tenant or not tenant.active or not re.fullmatch(r"Attack Lab [0-9a-f]{8}", tenant.name):
        raise HTTPException(404, "Research tenant not found")
    return tenant.id


def research_tenant_choices(session: dict) -> list[dict]:
    if session["tenant_id"] != "default":
        return []
    with db_session() as db:
        return [{"id": row.id, "name": row.name} for row in db.scalars(select(Tenant).where(Tenant.active.is_(True)))
                if re.fullmatch(r"Attack Lab [0-9a-f]{8}", row.name)]


def goal_research_tenant_choices(session: dict) -> list[dict]:
    """Show only research tenants containing goal experiments, newest first."""
    choices = []
    for tenant in research_tenant_choices(session):
        with tenant_db_session(tenant["id"]) as db:
            latest = db.scalar(select(GoalLabRun).order_by(GoalLabRun.created_at.desc()).limit(1))
        if latest is not None:
            choices.append({**tenant, "latest_at": latest.created_at,
                            "mode": latest.mode, "status": latest.status})
    return sorted(choices, key=lambda item: item["latest_at"], reverse=True)


async def require_form_csrf(request: Request, session: dict):
    form = await request.form()
    if not secrets.compare_digest(str(form.get("csrf", "")), session["csrf"]):
        raise HTTPException(403, "Invalid CSRF token")
    return form


def require_agent(request: Request, authorization: str = Header(default=""),
                  x_tenant_id: str = Header(default="default"),
                  x_agent_id: str = Header(default="demo-agent")) -> tuple[str, str]:
    scheme, _, token = authorization.partition(" ")
    try:
        tenant = get_tenant(x_tenant_id)
    except ValueError:
        tenant = None
    if scheme.lower() != "bearer" or not token or not tenant or not tenant.active:
        raise HTTPException(401, "Agent authentication failed")
    if x_agent_id == "demo-agent":
        valid = secrets.compare_digest(hash_agent_key(token), tenant.agent_hash)
    elif x_agent_id == "reader-agent":
        from .models import WorkerPrincipal
        with tenant_db_session(x_tenant_id) as db:
            worker = db.get(WorkerPrincipal, x_agent_id)
            valid = bool(worker and worker.active and secrets.compare_digest(hash_agent_key(token), worker.key_hash))
    else:
        valid = False
    if not valid:
        raise HTTPException(401, "Agent authentication failed")
    if x_agent_id == "reader-agent":
        request.state.worker_key_hash = hash_agent_key(token)
    if x_agent_id == "reader-agent" and not request.url.path.startswith("/api/v3/delegations"):
        raise HTTPException(403, "协作身份仅允许委托协议")
    return x_agent_id, x_tenant_id


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    from sqlalchemy import text
    try:
        with db_session() as db:
            db.execute(text("SELECT 1"))
        get_redis().ping()
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    # Judge/通知故障不影响同步授权就绪；详细状态在管理员页面。
    return {"status": "ready"}


@app.get("/")
def home():
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login(request: Request, password: str = Form(), tenant_id: str = Form(default="default")):
    try:
        tenant = get_tenant(tenant_id)
    except ValueError:
        tenant = None
    if not tenant or not tenant.active or not verify_password(password, tenant.admin_hash):
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid password"}, status_code=401)
    cookie = serializer.dumps({"role": "admin", "tenant_id": tenant_id, "csrf": secrets.token_urlsafe(24)})
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie("agentsentry_session", cookie, httponly=True, samesite="strict", max_age=8 * 3600)
    return response


@app.post("/logout")
async def logout(request: Request, session=Depends(admin_session)):
    await require_form_csrf(request, session)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("agentsentry_session")
    return response


@app.get("/api/v2/tenants")
def list_tenants(_: dict = Depends(admin_session)):
    if _["tenant_id"] != "default":
        raise HTTPException(403, "Only the default administrator manages tenants")
    with db_session() as db:
        return {"tenants": [{"id": row.id, "name": row.name, "active": row.active}
                            for row in db.scalars(select(Tenant).order_by(Tenant.name))]}


@app.post("/api/v2/tenants")
def add_tenant(body: TenantRequest, _: dict = Depends(require_csrf)):
    if _["tenant_id"] != "default":
        raise HTTPException(403, "Only the default administrator manages tenants")
    try:
        tenant, admin_password, agent_key = create_tenant(
            body.name, policy_path_for("default").read_text(encoding="utf-8"), settings.policy_path,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"tenant_id": tenant.id, "name": tenant.name,
            "admin_password": admin_password, "agent_api_key": agent_key}


@app.post("/dashboard/tenants")
async def dashboard_add_tenant(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    result = add_tenant(TenantRequest(name=str(form["name"])), session)
    return templates.TemplateResponse(request, "tenant_issued.html", result)


@app.post("/api/v1/capabilities")
def issue_capability(request: CapabilityRequest, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        try:
            grant, token = issue(db, get_redis(), request, tenant_id=_["tenant_id"])
        except Exception:
            raise HTTPException(503, "Capability store or audit database unavailable")
        return {"grant_id": grant.id, "token": token, "expires_at": grant.expires_at.isoformat()}


@app.delete("/api/v1/capabilities/{grant_id}")
def revoke_capability(grant_id: str, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        grant = db.get(CapabilityGrant, grant_id)
        if not grant:
            raise HTTPException(404, "Grant not found")
        try:
            revoke(db, get_redis(), grant)
        except Exception:
            raise HTTPException(503, "Capability store unavailable")
    return {"revoked": True}


@app.get("/api/v1/policy")
def get_policy(_: dict = Depends(admin_session)):
    policy = policy_for(_["tenant_id"])
    return {
        "revision": policy.revision,
        "rules": len(policy.policy.rules),
        "yaml": policy_path_for(_["tenant_id"]).read_text(encoding="utf-8"),
    }


@app.post("/api/v1/policy/reload")
def reload_policy(_: dict = Depends(require_csrf)):
    policy = policy_for(_["tenant_id"])
    try:
        revision = policy.reload()
    except Exception as exc:
        raise HTTPException(422, f"Policy validation failed: {exc}")
    with tenant_db_session(_["tenant_id"]) as db:
        db.add(AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="policy_reload",
                          payload={"revision": revision}))
        db.commit()
    return {"revision": revision, "rules": len(policy.policy.rules)}


@app.put("/api/v1/policy")
def update_policy(body: PolicyUpdate, _: dict = Depends(require_csrf)):
    policy = policy_for(_["tenant_id"])
    try:
        revision = policy.replace(body.yaml)
    except Exception as exc:
        raise HTTPException(422, f"Policy validation failed: {exc}")
    with tenant_db_session(_["tenant_id"]) as db:
        db.add(AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="policy_reload",
                          payload={"revision": revision, "source": "admin_update"}))
        db.commit()
    return {"revision": revision, "rules": len(policy.policy.rules)}


@app.post("/dashboard/policy/reload")
async def dashboard_reload_policy(request: Request, session=Depends(admin_session)):
    await require_form_csrf(request, session)
    try:
        reload_policy(session)
        destination = "/dashboard/policy?policy_reload=ok"
    except HTTPException:
        destination = "/dashboard/policy?policy_reload=failed"
    return RedirectResponse(destination, status_code=303)


@app.post("/dashboard/policy/update")
async def dashboard_update_policy(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        update_policy(PolicyUpdate(yaml=str(form["yaml"])), session)
        destination = "/dashboard/policy?policy_reload=ok"
    except Exception:
        destination = "/dashboard/policy?policy_reload=failed"
    return RedirectResponse(destination, status_code=303)


def current_runtime_provider(tenant_id: str) -> str:
    with tenant_db_session(tenant_id) as db:
        config = runtime_config(db, settings)
        db.commit()
        return config.provider


def event_judge_evidence(db, events) -> dict[str, dict[str, str]]:
    ids = [event.id for event in events]
    if not ids:
        return {}
    rows = db.execute(select(AuditEvent.id, Outbox, JudgeRoute, JudgeResult)
                      .outerjoin(Outbox, Outbox.audit_event_id == AuditEvent.id)
                      .outerjoin(JudgeRoute, JudgeRoute.outbox_id == Outbox.id)
                      .outerjoin(JudgeResult, JudgeResult.outbox_id == Outbox.id)
                      .where(AuditEvent.id.in_(ids))).all()
    audit_only_types = {"judge_config_changed", "policy_reload", "tenant_initialized",
                        "capability_issued", "capability_revoked"}
    states = {"pending": "等待投递", "queued": "已入队", "processing": "评判中",
              "failed": "评判失败", "completed": "结果缺失（需检查）"}
    evidence = {}
    event_types = {event.id: event.event_type for event in events}
    for event_id, outbox, route, result in rows:
        if route:
            designated = f"{route.provider} / {route.model_name}"
        elif result:
            designated = "旧事件未记录指定 Judge"
        elif outbox:
            designated = "路由缺失（需检查）"
        else:
            designated = "不适用"
        if result:
            status = f"已评判：{result.provider} / {result.model_version}"
        elif outbox:
            status = states.get(outbox.status, "状态未知（需检查）")
        elif event_types[event_id] in audit_only_types:
            status = "仅保存审计，不进入 Judge"
        else:
            status = "无投递记录（需检查）"
        evidence[event_id] = {"designated": designated, "status": status}
    return evidence


def sample_run_provider(requested: str | None, tenant_id: str) -> str:
    provider = requested or current_runtime_provider(tenant_id)
    if provider not in {choice["id"] for choice in configured_judge_providers(settings)}:
        raise HTTPException(422, "Judge provider is not configured")
    return provider


@app.get("/api/v1/judge-runtime")
def get_judge_runtime(_: dict = Depends(admin_session)):
    with tenant_db_session(_["tenant_id"]) as db:
        config = runtime_config(db, settings)
        db.commit()
        return {"provider": config.provider, "revision": config.revision,
                "updated_at": config.updated_at,
                "choices": configured_judge_providers(settings)}


@app.put("/api/v1/judge-runtime")
def update_judge_runtime(body: JudgeRuntimeUpdate, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        try:
            config = change_runtime_provider(db, body.provider, body.expected_revision,
                                             "admin:" + _["tenant_id"], settings)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        return {"provider": config.provider, "revision": config.revision}


@app.get("/dashboard/judge-runtime", response_class=HTMLResponse)
def dashboard_judge_runtime(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        config = runtime_config(db, settings)
        changes = db.scalars(select(JudgeRuntimeChange).order_by(
            JudgeRuntimeChange.changed_at.desc()).limit(20)).all()
        last_result = db.scalar(select(JudgeResult).outerjoin(
            JudgeSampleRun, JudgeSampleRun.outbox_id == JudgeResult.outbox_id
        ).where(JudgeSampleRun.id.is_(None)).order_by(JudgeResult.created_at.desc()).limit(1))
        outbox_counts = dict(db.execute(select(Outbox.status, func.count()).group_by(Outbox.status)).all())
        latest_failure = db.scalar(select(Outbox).where(Outbox.status == "failed")
                                   .order_by(Outbox.updated_at.desc()).limit(1))
        db.commit()
    choices = configured_judge_providers(settings)
    selected = next((choice for choice in choices if choice["id"] == config.provider), None)
    known_errors = {
        "指定的 Judge 在 Worker 中未配置": "Worker 未配置该 Judge",
        "Judge 数据目的地配置已改变；原事件不会改投新地址": "数据目的地已变化，原事件不会改投新地址",
        "Judge route missing; event was not safely assigned a provider": "事件缺少 Judge 路由",
        "Judge 返回的提供方与事件指定值不一致": "Judge 返回的提供方不一致",
    }
    failure_summary = known_errors.get(latest_failure.error, "Judge 请求或结果校验失败") if latest_failure else None
    return templates.TemplateResponse(request, "judge_runtime.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "config": config, "changes": changes, "choices": choices, "selected": selected,
        "last_result": last_result, "outbox_counts": outbox_counts,
        "latest_failure": latest_failure, "failure_summary": failure_summary,
        "update_status": request.query_params.get("status"),
    })


@app.post("/dashboard/judge-runtime")
async def dashboard_update_judge_runtime(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = JudgeRuntimeUpdate(provider=str(form["provider"]),
                                  expected_revision=int(str(form["expected_revision"])))
        update_judge_runtime(body, session)
        status = "updated"
    except (ValueError, KeyError, RuntimeError, HTTPException):
        status = "rejected"
    return RedirectResponse(f"/dashboard/judge-runtime?status={status}", status_code=303)


@app.get("/api/v1/judge-samples")
def list_judge_samples(provider: str | None = None, _: dict = Depends(admin_session)):
    selected = provider or current_runtime_provider(_["tenant_id"])
    if selected not in JUDGE_PROVIDER_IDS:
        raise HTTPException(422, "Unknown Judge provider")
    with tenant_db_session(_["tenant_id"]) as db:
        samples = db.scalars(select(JudgeSample).order_by(JudgeSample.created_at)).all()
        metrics, _latest = sample_metrics(db, selected, settings.judge_score_threshold)
        return {"provider": selected, "runtime_provider": current_runtime_provider(_["tenant_id"]),
                "metrics": metrics, "samples": [
            {"id": sample.id, "name": sample.name, "event_type": sample.event_type,
             "payload": sample.payload, "expected_labels": sample.expected_labels}
            for sample in samples
        ]}


@app.post("/api/v1/judge-samples")
def add_judge_sample(body: JudgeSampleRequest, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        sample = create_sample(db, body)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Sample name already exists")
        return {"id": sample.id}


@app.delete("/api/v1/judge-samples/{sample_id}")
def delete_judge_sample(sample_id: uuid.UUID, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        sample = db.get(JudgeSample, str(sample_id))
        if not sample:
            raise HTTPException(404, "Sample not found")
        db.delete(sample)
        db.commit()
    return {"deleted": True}


@app.post("/api/v1/judge-samples/{sample_id}/run")
def evaluate_judge_sample(sample_id: uuid.UUID, body: JudgeSampleRunRequest | None = None,
                          _: dict = Depends(require_csrf)):
    provider = sample_run_provider(body.provider if body else None, _["tenant_id"])
    with tenant_db_session(_["tenant_id"]) as db:
        sample = db.get(JudgeSample, str(sample_id))
        if not sample:
            raise HTTPException(404, "Sample not found")
        outbox_id = run_sample(db, sample, provider)
    return JSONResponse({"outbox_id": outbox_id, "status": "pending", "provider": provider}, status_code=202)


@app.post("/dashboard/samples")
async def dashboard_add_sample(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    provider = str(form.get("provider", current_runtime_provider(session["tenant_id"])))
    if provider not in JUDGE_PROVIDER_IDS:
        raise HTTPException(422, "Unknown Judge provider")
    try:
        body = JudgeSampleRequest(
            name=str(form["name"]), event_type=str(form["event_type"]),
            payload=json.loads(str(form["payload"])),
            expected_labels=[part.strip() for part in str(form["expected_labels"]).split(",")],
        )
        add_judge_sample(body, session)
        destination = f"/dashboard/judge-samples?provider={provider}&sample_status=added"
    except Exception:
        destination = f"/dashboard/judge-samples?provider={provider}&sample_status=invalid"
    return RedirectResponse(destination, status_code=303)


@app.post("/dashboard/samples/{sample_id}/run")
async def dashboard_run_sample(sample_id: uuid.UUID, request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    provider = sample_run_provider(str(form.get("provider", "")), session["tenant_id"])
    evaluate_judge_sample(sample_id, JudgeSampleRunRequest(provider=provider), session)
    return RedirectResponse(f"/dashboard/judge-samples?provider={provider}&sample_status=queued", status_code=303)


@app.post("/dashboard/samples/{sample_id}/delete")
async def dashboard_delete_sample(sample_id: uuid.UUID, request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    provider = str(form.get("provider", current_runtime_provider(session["tenant_id"])))
    if provider not in JUDGE_PROVIDER_IDS:
        raise HTTPException(422, "Unknown Judge provider")
    delete_judge_sample(sample_id, session)
    return RedirectResponse(f"/dashboard/judge-samples?provider={provider}&sample_status=deleted", status_code=303)


@app.post("/api/v2/attack-lab/fixtures/install")
def install_attack_fixtures(_: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        try:
            installed = install_fixtures(db)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
    return {"installed": installed}


@app.post("/api/v2/attack-runs")
def start_attack_run(body: AttackRunRequest, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        try:
            run = create_run(db, body, policy_for(_["tenant_id"]).revision)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"id": run.id, "status": run.status, "expected_cases": run.expected_cases}


def _calibration_write_tenant(session: dict) -> str:
    tenant = get_tenant(session["tenant_id"])
    if not tenant or not re.fullmatch(r"Attack Lab [0-9a-f]{8}", tenant.name):
        raise HTTPException(403, "校准实验只能写入专用研究租户")
    return tenant.id


@app.post("/api/v2/calibration/fixtures/install")
def install_calibration_lab_fixtures(session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        try:
            return {"installed": install_calibration_fixtures(db)}
        except ValueError as exc:
            raise HTTPException(409, str(exc))


@app.post("/api/v2/calibration-runs")
def start_calibration_run(body: CalibrationRunRequest, session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        try:
            run = create_calibration_run(db, body, policy_for(tenant_id).revision)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"id": run.id, "status": run.status, "expected_cases": run.expected_cases}


@app.post("/api/v2/calibration-runs/{run_id}/cases")
def add_calibration_case(run_id: uuid.UUID, body: CalibrationCaseSubmission,
                         session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        run = db.get(CalibrationRun, str(run_id))
        if run is None:
            raise HTTPException(404, "校准运行不存在")
        try:
            row = submit_calibration_case(db, run, body)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"case_id": row.case_id, "repetition": row.repetition, "outcome": row.outcome}


@app.post("/api/v2/calibration-runs/{run_id}/finish")
def end_calibration_run(run_id: uuid.UUID, body: AttackRunFinish,
                        session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        run = db.get(CalibrationRun, str(run_id))
        if run is None:
            raise HTTPException(404, "校准运行不存在")
        try:
            finish_calibration_run(db, run, body.failed, body.error)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"id": run.id, "status": run.status}


@app.get("/api/v2/calibration-runs")
def calibration_runs_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        runs = db.scalars(select(CalibrationRun).order_by(
            CalibrationRun.started_at.desc()).limit(50)).all()
        return {"runs": [calibration_run_view(db, row) for row in runs]}


@app.get("/api/v2/calibration-runs/{run_id}")
def calibration_run_api(run_id: uuid.UUID, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        run = db.get(CalibrationRun, str(run_id))
        if run is None:
            raise HTTPException(404, "校准运行不存在")
        return calibration_run_view(db, run, include_cases=True)


def _daily_rule_summary(db) -> list[dict]:
    from collections import Counter
    from datetime import timedelta
    from .models import utcnow
    cutoff = utcnow() - timedelta(days=30)
    reviewed = {(row.agent_id, row.session_id) for row in db.scalars(select(RuntimeSession).where(
        RuntimeSession.review_status == "false_positive", RuntimeSession.started_at >= cutoff)).all()}
    counts = Counter()
    feedback = Counter()
    runtime_rows = db.scalars(select(RuntimeDecision).where(RuntimeDecision.created_at >= cutoff)).all()
    flow_rows = db.scalars(select(DataFlowDecision).where(DataFlowDecision.created_at >= cutoff)).all()
    for row in [*runtime_rows, *flow_rows]:
        for rule_id in row.findings:
            counts[rule_id] += 1
            feedback[rule_id] += (row.agent_id, row.session_id) in reviewed
    return [{"rule_id": key, "hits": counts[key], "related_false_positive_reviews": feedback[key]}
            for key in sorted(counts)]


@app.get("/dashboard/calibration-runs", response_class=HTMLResponse)
def dashboard_calibration_runs(request: Request, tenant: str | None = None,
                               session=Depends(admin_session)):
    choices = research_tenant_choices(session)
    selected = research_tenant_for_read(session, tenant) if tenant else None
    scopes = ([selected] if selected else
              [item["id"] for item in choices] if session["tenant_id"] == "default" else
              [session["tenant_id"]])
    runs = []
    for data_tenant in scopes:
        with tenant_db_session(data_tenant) as db:
            rows = db.scalars(select(CalibrationRun).order_by(
                CalibrationRun.started_at.desc()).limit(50)).all()
            for row in rows:
                view = calibration_run_view(db, row)
                view["data_tenant"] = data_tenant
                runs.append(view)
    runs.sort(key=lambda item: item["started_at"], reverse=True)
    runs = runs[:50]
    with tenant_db_session(session["tenant_id"]) as db:
        daily = _daily_rule_summary(db)
    return templates.TemplateResponse(request, "calibration_runs.html", {
        "runs": runs, "tenant_id": session["tenant_id"], "selected_tenant": selected,
        "research_tenants": choices, "daily": daily,
        "observer": bool(selected and selected != session["tenant_id"])})


@app.get("/dashboard/calibration-runs/{run_id}", response_class=HTMLResponse)
def dashboard_calibration_detail(run_id: uuid.UUID, request: Request, tenant: str | None = None,
                                 baseline: uuid.UUID | None = None,
                                 baseline_tenant: str | None = None,
                                 session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    baseline_id = research_tenant_for_read(session, baseline_tenant or tenant_id) if baseline else tenant_id
    with tenant_db_session(tenant_id) as db:
        run = db.get(CalibrationRun, str(run_id))
        if run is None:
            raise HTTPException(404, "校准运行不存在")
        view = calibration_run_view(db, run, include_cases=True)
    comparison = None
    if baseline:
        with tenant_db_session(baseline_id) as db:
            earlier = db.get(CalibrationRun, str(baseline))
            if earlier is None:
                raise HTTPException(404, "基线运行不存在")
            try:
                comparison = compare_calibration_views(
                    calibration_run_view(db, earlier, include_cases=True), view)
            except ValueError as exc:
                raise HTTPException(422, str(exc))
    return templates.TemplateResponse(request, "calibration_run_detail.html", {
        "run": view, "comparison": comparison, "tenant_id": tenant_id,
        "baseline_tenant": baseline_id,
        "observer": tenant_id != session["tenant_id"]})


@app.get("/dashboard/calibration-runs/{run_id}/calls/{call_id}", response_class=HTMLResponse)
def dashboard_calibration_call(run_id: uuid.UUID, call_id: uuid.UUID, request: Request,
                               tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        linked = db.scalar(select(CalibrationCaseResult).where(
            CalibrationCaseResult.run_id == str(run_id)))
        rows = db.scalars(select(CalibrationCaseResult).where(
            CalibrationCaseResult.run_id == str(run_id))).all() if linked else []
        if not any(str(call_id) in row.call_ids for row in rows):
            raise HTTPException(404, "调用不属于此实验")
        call = db.get(ToolCall, str(call_id))
        if call is None:
            raise HTTPException(404, "调用不存在")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call.call_id)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call.call_id)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence, "tenant_id": tenant_id,
        "observer": tenant_id != session["tenant_id"],
        "back_url": f"/dashboard/calibration-runs/{run_id}?tenant={tenant_id}"})


@app.post("/api/v2/attack-runs/{run_id}/cases")
def add_attack_case(run_id: uuid.UUID, body: AttackCaseSubmission, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        run = db.get(AttackRun, str(run_id))
        if not run:
            raise HTTPException(404, "Experiment not found")
        try:
            row = submit_result(db, run, body)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"case_id": row.case_id, "outcome": row.outcome}


@app.post("/api/v2/attack-runs/{run_id}/finish")
def end_attack_run(run_id: uuid.UUID, body: AttackRunFinish, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        run = db.get(AttackRun, str(run_id))
        if not run:
            raise HTTPException(404, "Experiment not found")
        try:
            finish_run(db, run, body.failed, body.error)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"id": run.id, "status": run.status}


@app.get("/api/v2/attack-runs")
def list_attack_runs(_: dict = Depends(admin_session)):
    with tenant_db_session(_["tenant_id"]) as db:
        runs = db.scalars(select(AttackRun).order_by(AttackRun.started_at.desc()).limit(50)).all()
        return {"runs": [run_view(db, run, settings.judge_score_threshold) for run in runs]}


@app.get("/api/v2/attack-runs/{run_id}")
def get_attack_run(run_id: uuid.UUID, _: dict = Depends(admin_session)):
    with tenant_db_session(_["tenant_id"]) as db:
        run = db.get(AttackRun, str(run_id))
        if not run:
            raise HTTPException(404, "Experiment not found")
        return run_view(db, run, settings.judge_score_threshold, include_cases=True)


@app.get("/dashboard/attack-runs", response_class=HTMLResponse)
def dashboard_attack_runs(request: Request, tenant: str | None = None, session=Depends(admin_session)):
    choices = research_tenant_choices(session)
    selected = tenant or (choices[0]["id"] if choices else session["tenant_id"])
    tenant_id = research_tenant_for_read(session, selected)
    with tenant_db_session(tenant_id) as db:
        runs = db.scalars(select(AttackRun).order_by(AttackRun.started_at.desc()).limit(50)).all()
        views = [run_view(db, run, settings.judge_score_threshold) for run in runs]
    return templates.TemplateResponse(request, "attack_runs.html", {"runs": views, "tenant_id": tenant_id,
                                      "research_tenants": choices, "observer": tenant_id != session["tenant_id"]})


@app.get("/dashboard/attack-runs/{run_id}", response_class=HTMLResponse)
def dashboard_attack_run_detail(run_id: uuid.UUID, request: Request, tenant: str | None = None,
                                session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(AttackRun, str(run_id))
        if not run:
            raise HTTPException(404, "Experiment not found")
        view = run_view(db, run, settings.judge_score_threshold, include_cases=True)
    return templates.TemplateResponse(request, "attack_run_detail.html", {"run": view, "tenant_id": tenant_id,
                                      "observer": tenant_id != session["tenant_id"]})


@app.get("/dashboard/attack-runs/{run_id}/calls/{call_id}", response_class=HTMLResponse)
def research_call_detail(run_id: uuid.UUID, call_id: uuid.UUID, request: Request,
                         tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        case_rows = db.scalars(select(AttackCaseResult).where(AttackCaseResult.run_id == str(run_id))).all()
        if not any(str(call_id) in row.call_ids for row in case_rows):
            raise HTTPException(404, "Experiment call not found")
        call = db.get(ToolCall, str(call_id))
        if not call:
            raise HTTPException(404, "Call not found")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call.call_id)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call.call_id)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence,
        "tenant_id": tenant_id, "observer": tenant_id != session["tenant_id"],
        "back_url": f"/dashboard/attack-runs/{run_id}?tenant={tenant_id}" if tenant else f"/dashboard/attack-runs/{run_id}",
    })


@app.post("/api/v1/tool-calls")
def tool_call(
    request: ToolCallRequest,
    x_capability: str = Header(default=""),
    x_runtime_session: str = Header(default=""),
    identity: tuple[str, str] = Depends(require_agent),
):
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        status, result = submit_call(db, get_redis(), policy_for(tenant_id), request,
                                     x_capability, agent_id, tenant_id, x_runtime_session)
        return JSONResponse(result, status_code=status)


@app.get("/api/v1/tool-calls/{call_id}")
def get_call(call_id: uuid.UUID, identity: tuple[str, str] = Depends(require_agent)):
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        call = db.get(ToolCall, str(call_id))
        if not call or call.agent_id != agent_id:
            raise HTTPException(404, "Call not found")
        approval = db.scalar(select(Approval).where(Approval.call_id == call.call_id))
        return call_view(call, approval.id if approval else None)


@app.put("/api/v2/runtime-sessions/{session_id}/start")
def report_runtime_start(session_id: str, body: RuntimeSessionStart,
                         identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            row = start_session(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"session_id": row.session_id, "status": row.status,
                "session_token": session_token(tenant_id, agent_id, row)}


@app.put("/api/v2/runtime-sessions/{session_id}/finish")
def report_runtime_finish(session_id: str, body: RuntimeSessionFinish,
                          identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            row = finish_session(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"session_id": row.session_id, "status": row.status}


@app.post("/api/v2/runtime-sessions/{session_id}/output-check")
def report_output_check(session_id: str, body: OutputCheckRequest,
                        identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            return check_output(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409 if "检查 ID 已用于" in str(exc) else 422, str(exc))


@app.post("/api/v2/runtime-sessions/{session_id}/model-egress/check")
def report_model_egress_check(session_id: str, body: ModelEgressCheckRequest,
                              x_runtime_session: str = Header(default=""),
                              identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            return check_model(db, tenant_id, agent_id, session_id, x_runtime_session, body)
        except ValueError as exc:
            raise HTTPException(409 if "请求 ID 已用于" in str(exc) else 422, str(exc))


@app.post("/api/v2/runtime-sessions/{session_id}/memory/read")
def report_memory_read(session_id: str, body: MemoryReadRequest,
                       identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            return read_memories(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409 if "ID 已用于" in str(exc) else 422, str(exc))


@app.post("/api/v2/runtime-sessions/{session_id}/memory/write")
def report_memory_write(session_id: str, body: MemoryWriteRequest,
                        identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            return write_candidates(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409 if "ID 已用于" in str(exc) else 422, str(exc))


@app.post("/api/v2/runtime-sessions/{session_id}/memory/failure")
def report_memory_failure(session_id: str, body: MemoryFailureRequest,
                          identity: tuple[str, str] = Depends(require_agent)):
    if not 1 <= len(session_id) <= 100:
        raise HTTPException(422, "Invalid session_id")
    agent_id, tenant_id = identity
    with tenant_db_session(tenant_id) as db:
        try:
            return record_failure(db, agent_id, session_id, body)
        except ValueError as exc:
            raise HTTPException(409 if "ID 已用于" in str(exc) else 422, str(exc))


@app.get("/api/v2/memories")
def memories_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        return {"enabled": memory_enabled(), "items": list_memories(db)}


@app.get("/api/v2/memory-sources")
def memory_sources_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        return {"items": list_trusted_sources(db)}


@app.get("/api/v2/memory-incidents")
def memory_incidents_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        return {"items": list_incidents(db)}


@app.post("/api/v2/memory-sources")
def trust_memory_source_api(body: MemorySourceTrustRequest, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return trust_source(db, str(body.call_id))
        except ValueError as exc:
            raise HTTPException(422, str(exc))


@app.delete("/api/v2/memory-sources/{source_id}")
def revoke_memory_source_api(source_id: uuid.UUID, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return revoke_source(db, str(source_id))
        except ValueError as exc:
            raise HTTPException(404 if "不存在" in str(exc) else 409, str(exc))


@app.post("/api/v2/memories/{memory_id}/decision")
def memory_decision_api(memory_id: uuid.UUID, body: MemoryDecisionRequest,
                        session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return decide_memory(db, str(memory_id), body.action)
        except ValueError as exc:
            raise HTTPException(404 if "不存在" in str(exc) else 409, str(exc))


@app.post("/api/v2/memories/{memory_id}/review-legacy")
def review_legacy_memory_api(memory_id: uuid.UUID, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return review_legacy_memory(db, str(memory_id))
        except ValueError as exc:
            raise HTTPException(409, str(exc))


@app.get("/dashboard/memories", response_class=HTMLResponse)
def dashboard_memories(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        rows = list_memories(db)
        sources = list_trusted_sources(db)
        incidents = list_incidents(db)
    return templates.TemplateResponse(request, "memories.html", {
        "items": rows, "trusted_sources": sources, "incidents": incidents,
        "enabled": memory_enabled(), "tenant_id": session["tenant_id"],
        "csrf": session["csrf"],
    })


@app.post("/dashboard/memory-sources/trust")
async def dashboard_trust_memory_source(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = MemorySourceTrustRequest(call_id=str(form["call_id"]))
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    trust_memory_source_api(body, session)
    return RedirectResponse("/dashboard/memories", status_code=303)


@app.post("/dashboard/memory-sources/{source_id}/revoke")
async def dashboard_revoke_memory_source(source_id: uuid.UUID, request: Request,
                                         session=Depends(admin_session)):
    await require_form_csrf(request, session)
    revoke_memory_source_api(source_id, session)
    return RedirectResponse("/dashboard/memories", status_code=303)


@app.post("/dashboard/memories/{memory_id}/decision")
async def dashboard_memory_decision(memory_id: uuid.UUID, request: Request,
                                    session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = MemoryDecisionRequest(action=str(form["action"]))
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    memory_decision_api(memory_id, body, session)
    return RedirectResponse("/dashboard/memories", status_code=303)


@app.post("/dashboard/memories/{memory_id}/review-legacy")
async def dashboard_review_legacy_memory(memory_id: uuid.UUID, request: Request,
                                         session=Depends(admin_session)):
    await require_form_csrf(request, session)
    review_legacy_memory_api(memory_id, session)
    return RedirectResponse("/dashboard/memories", status_code=303)


@app.post("/api/v2/memory-lab/fixtures/install")
def install_memory_lab_fixtures(session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return {"installed": install_memory_fixtures(db)}
        except ValueError as exc:
            raise HTTPException(409, str(exc))


@app.post("/api/v2/memory-lab/fixtures/{memory_id}/expire")
def expire_memory_lab_fixture(memory_id: uuid.UUID, session=Depends(require_csrf)):
    tenant = get_tenant(session["tenant_id"])
    if not tenant or not re.fullmatch(r"Attack Lab [0-9a-f]{8}", tenant.name):
        raise HTTPException(403, "仅供专用研究租户使用")
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            expire_fixture_memory(db, str(memory_id))
        except ValueError as exc:
            raise HTTPException(404, str(exc))
    return {"memory_id": str(memory_id), "expired_for_lab": True}


@app.post("/api/v2/memory-lab/runs")
def start_memory_lab_run(body: MemoryLabRunRequest, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            run = create_memory_run(db, body, policy_for(session["tenant_id"]).revision)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"id": run.id, "expected_cases": run.expected_cases, "status": run.status}


@app.post("/api/v2/memory-lab/runs/{run_id}/cases")
def add_memory_lab_case(run_id: uuid.UUID, body: MemoryLabCaseRequest,
                        session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        run = db.get(MemoryLabRun, str(run_id))
        if not run:
            raise HTTPException(404, "实验不存在")
        try:
            row = submit_memory_case(db, run, body)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"case_id": row.case_id}


@app.post("/api/v2/memory-lab/runs/{run_id}/finish")
def end_memory_lab_run(run_id: uuid.UUID, body: AttackRunFinish,
                       session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        run = db.get(MemoryLabRun, str(run_id))
        if not run:
            raise HTTPException(404, "实验不存在")
        try:
            finish_memory_run(db, run, body.failed, body.error)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"id": run.id, "status": run.status}


@app.get("/api/v2/memory-lab/runs")
def memory_lab_runs_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        runs = db.scalars(select(MemoryLabRun).order_by(MemoryLabRun.started_at.desc()).limit(50)).all()
        return {"runs": [memory_run_view(db, row) for row in runs]}


@app.get("/api/v2/memory-lab/runs/{run_id}")
def memory_lab_run_api(run_id: uuid.UUID, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        run = db.get(MemoryLabRun, str(run_id))
        if not run:
            raise HTTPException(404, "实验不存在")
        return memory_run_view(db, run, include_cases=True)


@app.get("/dashboard/memory-runs", response_class=HTMLResponse)
def dashboard_memory_runs(request: Request, tenant: str | None = None,
                          session=Depends(admin_session)):
    choices = research_tenant_choices(session)
    selected = tenant or (choices[0]["id"] if choices else session["tenant_id"])
    tenant_id = research_tenant_for_read(session, selected)
    with tenant_db_session(tenant_id) as db:
        runs = db.scalars(select(MemoryLabRun).order_by(MemoryLabRun.started_at.desc()).limit(50)).all()
        views = [memory_run_view(db, row) for row in runs]
    return templates.TemplateResponse(request, "memory_runs.html", {
        "runs": views, "tenant_id": tenant_id, "research_tenants": choices,
        "observer": tenant_id != session["tenant_id"],
    })


@app.get("/api/v2/memory-security-runs")
def memory_security_runs_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        rows = db.scalars(select(MemorySecurityRun).order_by(
            MemorySecurityRun.started_at.desc()).limit(50)).all()
        return {"runs": [memory_security_run_view(db, row) for row in rows]}


@app.get("/api/v2/memory-security-runs/{run_id}")
def memory_security_run_api(run_id: uuid.UUID, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        run = db.get(MemorySecurityRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        return memory_security_run_view(db, run, details=True)


@app.get("/dashboard/memory-security-runs", response_class=HTMLResponse)
def dashboard_memory_security_runs(request: Request, tenant: str | None = None,
                                   session=Depends(admin_session)):
    choices = research_tenant_choices(session)
    selected = tenant or (choices[0]["id"] if choices else session["tenant_id"])
    tenant_id = research_tenant_for_read(session, selected)
    with tenant_db_session(tenant_id) as db:
        rows = db.scalars(select(MemorySecurityRun).order_by(
            MemorySecurityRun.started_at.desc()).limit(50)).all()
        views = [memory_security_run_view(db, row, details=True) for row in rows]
    return templates.TemplateResponse(request, "memory_security_runs.html", {
        "runs": views, "tenant_id": tenant_id, "research_tenants": choices,
        "observer": tenant_id != session["tenant_id"],
    })


@app.get("/dashboard/memory-security-runs/{run_id}/sources/{call_id}", response_class=HTMLResponse)
def dashboard_memory_security_source(run_id: uuid.UUID, call_id: uuid.UUID, request: Request,
                                     tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(MemorySecurityRun, str(run_id))
        case = db.scalar(select(MemorySecurityCase).where(
            MemorySecurityCase.run_id == str(run_id),
            MemorySecurityCase.source_call_id == str(call_id)))
        call = db.get(ToolCall, str(call_id)) if case else None
        if run is None or case is None or call is None:
            raise HTTPException(404, "实验来源不存在")
        if call.session_id != f"v26-{run_id}-{case.case_id}-write":
            raise HTTPException(404, "实验来源与样本不匹配")
    return templates.TemplateResponse(request, "memory_security_source.html", {
        "run_id": str(run_id), "tenant_id": tenant_id, "case_id": case.case_id,
        "call": call, "observer": tenant_id != session["tenant_id"],
    })


@app.get("/dashboard/memory-runs/{run_id}", response_class=HTMLResponse)
def dashboard_memory_run_detail(run_id: uuid.UUID, request: Request, tenant: str | None = None,
                                session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(MemoryLabRun, str(run_id))
        if not run:
            raise HTTPException(404, "实验不存在")
        view = memory_run_view(db, run, include_cases=True)
    return templates.TemplateResponse(request, "memory_run_detail.html", {
        "run": view, "tenant_id": tenant_id,
        "observer": tenant_id != session["tenant_id"],
    })


@app.get("/dashboard/memory-runs/{run_id}/cases/{case_id}/sessions/{phase}", response_class=HTMLResponse)
def dashboard_memory_run_session(run_id: uuid.UUID, case_id: str, phase: str,
                                 request: Request, tenant: str | None = None,
                                 session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    if phase not in {"write", "read"}:
        raise HTTPException(404, "实验轮次不存在")
    with tenant_db_session(tenant_id) as db:
        run = db.get(MemoryLabRun, str(run_id))
        case = db.get(MemoryLabCase, (str(run_id), case_id)) if run else None
        if case is None:
            raise HTTPException(404, "实验样本不存在")
        session_id = case.write_session_id if phase == "write" else case.read_session_id
        view = session_view(db, "demo-agent", session_id)
        if view is None:
            raise HTTPException(404, "该轮尚无会话证据")
    return templates.TemplateResponse(request, "runtime_session_detail.html", {
        "item": view, "tenant_id": tenant_id, "csrf": session["csrf"],
        "observer": tenant_id != session["tenant_id"],
        "research_run_id": str(run_id),
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
        "back_url": f"/dashboard/memory-runs/{run_id}?tenant={tenant_id}",
    })


@app.get("/dashboard/memory-runs/{run_id}/calls/{call_id}", response_class=HTMLResponse)
def dashboard_memory_run_call(run_id: uuid.UUID, call_id: uuid.UUID, request: Request,
                              tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(MemoryLabRun, str(run_id))
        cases = db.scalars(select(MemoryLabCase).where(MemoryLabCase.run_id == str(run_id))).all() if run else []
        call = db.get(ToolCall, str(call_id)) if cases else None
        case = next((row for row in cases if call and call.session_id in {
            row.write_session_id, row.read_session_id}), None)
        if call is None or case is None or call.agent_id != "demo-agent":
            raise HTTPException(404, "实验调用不存在")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call.call_id)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call.call_id)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence,
        "tenant_id": tenant_id, "observer": tenant_id != session["tenant_id"],
        "back_url": f"/dashboard/memory-runs/{run_id}?tenant={tenant_id}",
    })


@app.get("/api/v2/runtime-sessions")
def runtime_sessions_api(limit: int = Query(default=50, ge=1, le=200), risk_only: bool = False,
                         include_research: bool = False,
                         status: str = Query(default="all", pattern=r"^(all|completed|failed|running|interrupted|unreported)$"),
                         days: int = Query(default=0, ge=0, le=3650),
                         session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        return {"sessions": list_sessions(db, limit, risk_only, include_research, status, days)}


@app.get("/api/v2/runtime-sessions/detail")
def runtime_session_detail_api(agent_id: str, session_id: str, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        view = session_view(db, agent_id, session_id)
        if view is None:
            raise HTTPException(404, "Session not found")
        return view


@app.post("/api/v2/runtime-sessions/review")
def runtime_session_review_api(body: RuntimeSessionReview, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            return review_session(db, body)
        except ValueError as exc:
            raise HTTPException(404, str(exc))


@app.post("/api/v2/runtime-controls")
def runtime_control_api(body: RuntimeControlRequest, session=Depends(require_csrf)):
    if body.agent_id != "demo-agent":
        raise HTTPException(422, "Unknown Agent")
    with tenant_db_session(session["tenant_id"]) as db:
        control = set_control(db, body.agent_id, body.session_id, body.paused,
                              body.reason, "tenant_admin")
        return {"key": control.key, "paused": control.paused,
                "updated_at": control.updated_at.isoformat()}


@app.get("/api/v2/runtime-incidents")
def runtime_incidents_api(limit: int = Query(default=50, ge=1, le=200),
                          session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        rows = db.scalars(select(RuntimeIncident).order_by(
            RuntimeIncident.updated_at.desc()).limit(limit)).all()
        return {"items": [{"id": row.id, "call_id": row.call_id,
            "agent_id": row.agent_id, "session_id": row.session_id,
            "rule_id": row.rule_id, "severity": row.severity, "title": row.title,
            "status": row.status, "occurrences": row.occurrences} for row in rows]}


@app.get("/api/v2/runtime-decisions/{call_id}")
def runtime_decisions_api(call_id: uuid.UUID, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        call = db.get(ToolCall, str(call_id))
        if not call:
            raise HTTPException(404, "Call not found")
        rows = db.scalars(select(RuntimeDecision).where(
            RuntimeDecision.call_id == str(call_id)).order_by(RuntimeDecision.created_at)).all()
        return {"call_id": str(call_id), "items": [{"id": row.id,
            "phase": row.phase, "effect": row.effect, "rules_version": row.rules_version,
            "findings": row.findings, "evidence": row.evidence} for row in rows]}


@app.post("/api/v2/runtime-incidents/{incident_id}/ack")
def runtime_incident_ack_api(incident_id: uuid.UUID, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        row = db.get(RuntimeIncident, str(incident_id))
        if not row:
            raise HTTPException(404, "Runtime incident not found")
        row.status = "acknowledged"
        db.commit()
        return {"id": row.id, "status": row.status}


@app.post("/api/v2/data-flow-incidents/{incident_id}/ack")
def data_flow_incident_ack_api(incident_id: uuid.UUID, session=Depends(require_csrf)):
    with tenant_db_session(session["tenant_id"]) as db:
        row = db.get(DataFlowIncident, str(incident_id))
        if not row:
            raise HTTPException(404, "Data flow incident not found")
        row.status = "acknowledged"
        db.commit()
        return {"id": row.id, "status": row.status}


@app.get("/dashboard/runtime-sessions", response_class=HTMLResponse)
def dashboard_runtime_sessions(request: Request, risk_only: bool = False,
                               include_research: bool = False,
                               tenant: str | None = None,
                               status: str = Query(default="all", pattern=r"^(all|completed|failed|running|interrupted|unreported)$"),
                               days: int = Query(default=0, ge=0, le=3650),
                               session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    observer = tenant_id != session["tenant_id"]
    with tenant_db_session(tenant_id) as db:
        rows = list_sessions(db, 50, risk_only, include_research or observer, status, days)
    return templates.TemplateResponse(request, "runtime_sessions.html", {
        "sessions": rows, "tenant_id": tenant_id, "observer": observer,
        "research_tenants": research_tenant_choices(session),
        "risk_only": risk_only, "include_research": include_research, "status": status, "days": days,
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
        "runtime_rules_version": RUNTIME_RULES_VERSION,
    })


@app.get("/api/v3/action-chains")
def list_action_chains_api(session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        states = db.scalars(select(ActionChainState).order_by(
            ActionChainState.created_at.desc()).limit(50)).all()
        return {"items": [{"agent_id": row.agent_id, "session_id": row.session_id,
            "created_at": row.created_at.isoformat(),
            "chain": action_chain_view(db, row.agent_id, row.session_id)} for row in states]}


@app.get("/dashboard/action-chains", response_class=HTMLResponse)
def dashboard_action_chains(request: Request, tenant: str | None = None,
                            session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        states = db.scalars(select(ActionChainState).order_by(
            ActionChainState.created_at.desc()).limit(50)).all()
        items = [{"agent_id": row.agent_id, "session_id": row.session_id,
                  "created_at": row.created_at.isoformat(),
                  "chain": action_chain_view(db, row.agent_id, row.session_id)} for row in states]
    return templates.TemplateResponse(request, "action_chains.html", {
        "items": items, "tenant_id": tenant_id,
        "observer": tenant_id != session["tenant_id"],
        "research_tenants": research_tenant_choices(session),
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
    })


@app.get("/dashboard/action-chains/detail", response_class=HTMLResponse)
def dashboard_action_chain_detail(agent_id: str, session_id: str, request: Request,
                                  tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        view = session_view(db, agent_id, session_id)
        if view is None or not view["action_chain"]["enrolled"]:
            raise HTTPException(404, "行动链会话不存在")
    return templates.TemplateResponse(request, "runtime_session_detail.html", {
        "item": view, "tenant_id": tenant_id, "csrf": session["csrf"],
        "observer": tenant_id != session["tenant_id"],
        "action_chain_research": tenant_id != session["tenant_id"],
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
        "back_url": "/dashboard/action-chains" + ("?tenant=" + tenant_id if tenant else ""),
        "back_label": "返回行动链列表",
    })


@app.get("/dashboard/runtime-sessions/calls/{call_id}", response_class=HTMLResponse)
@app.get("/dashboard/action-chains/calls/{call_id}", response_class=HTMLResponse)
def dashboard_action_chain_call(call_id: uuid.UUID, request: Request,
                                tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        call = db.get(ToolCall, str(call_id))
        chain_only = request.url.path.startswith("/dashboard/action-chains")
        if call is None or (chain_only and db.get(ActionChainState, (call.agent_id, call.session_id)) is None):
            raise HTTPException(404, "调用证据不存在")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call.call_id)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call.call_id)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence, "tenant_id": tenant_id,
        "observer": tenant_id != session["tenant_id"],
        "back_url": ("/dashboard/action-chains/detail?" if chain_only else
                     "/dashboard/runtime-sessions/detail?") + urlencode({
            "agent_id": call.agent_id, "session_id": call.session_id, "tenant": tenant_id}),
    })


@app.get("/dashboard/runtime-sessions/detail", response_class=HTMLResponse)
def dashboard_runtime_session_detail(agent_id: str, session_id: str, request: Request,
                                     tenant: str | None = None,
                                     session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        view = session_view(db, agent_id, session_id)
        if view is None:
            raise HTTPException(404, "Session not found")
        threat_rows = db.scalars(select(ThreatMappingAssessment).where(
            ThreatMappingAssessment.agent_id == agent_id,
            ThreatMappingAssessment.session_id == session_id,
            ThreatMappingAssessment.status == "matched")
            .order_by(ThreatMappingAssessment.observed_at.desc()).limit(30)).all()
    return templates.TemplateResponse(request, "runtime_session_detail.html", {
        "item": view, "tenant_id": tenant_id, "csrf": session["csrf"],
        "observer": tenant_id != session["tenant_id"],
        "session_research": tenant_id != session["tenant_id"],
        "back_url": "/dashboard/runtime-sessions?" + urlencode({"tenant": tenant_id}),
        "back_label": "返回会话调查",
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
        "threat_rows": threat_rows,
    })


@app.post("/dashboard/runtime-sessions/review")
async def dashboard_runtime_review(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = RuntimeSessionReview(agent_id=str(form["agent_id"]), session_id=str(form["session_id"]),
                                    status=str(form["status"]), note=str(form.get("note", "")))
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    runtime_session_review_api(body, session)
    from urllib.parse import urlencode
    return RedirectResponse("/dashboard/runtime-sessions/detail?" + urlencode({
        "agent_id": body.agent_id, "session_id": body.session_id,
    }), status_code=303)


@app.post("/dashboard/runtime-controls")
async def dashboard_runtime_control(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = RuntimeControlRequest(agent_id=str(form["agent_id"]),
            session_id=str(form["session_id"]) if form.get("scope") == "session" else None,
            scope=str(form["scope"]), paused=str(form["paused"]) == "true",
            reason=str(form.get("reason", "")))
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    runtime_control_api(body, session)
    from urllib.parse import urlencode
    return RedirectResponse("/dashboard/runtime-sessions/detail?" + urlencode({
        "agent_id": body.agent_id, "session_id": str(form.get("session_id", "")),
    }), status_code=303)


@app.post("/api/v1/approvals/{approval_id}/decision")
def approval_decision(approval_id: uuid.UUID, body: ApprovalDecision, _: dict = Depends(require_csrf)):
    with tenant_db_session(_["tenant_id"]) as db:
        approval = db.get(Approval, str(approval_id))
        call = db.get(ToolCall, approval.call_id) if approval else None
        if body.decision == "approve" and call and call.tool == "github_mcp_create_test_issue":
            return JSONResponse({"detail": "请在审批事实卡核对目标仓库和原始参数后批准"}, status_code=409)
        status, result = decide_approval(db, str(approval_id), body.decision, _["tenant_id"],
                                         policy_for(_["tenant_id"]))
        return JSONResponse(result, status_code=status)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        judge_alerts = db.scalars(select(Alert).where(Alert.status == "open")
                                  .order_by(Alert.created_at.desc()).limit(5)).all()
        runtime_alerts = db.scalars(select(RuntimeIncident).where(RuntimeIncident.status == "open")
                                    .order_by(RuntimeIncident.updated_at.desc()).limit(5)).all()
        flow_alerts = db.scalars(select(DataFlowIncident).where(DataFlowIncident.status == "open")
                                 .order_by(DataFlowIncident.created_at.desc()).limit(5)).all()
        alerts = sorted([*judge_alerts, *runtime_alerts, *flow_alerts],
                        key=lambda row: row.updated_at if isinstance(row, RuntimeIncident)
                        else row.created_at, reverse=True)[:5]
        sessions = list_sessions(db, 5, True, False, "all", 0)
        outbox_counts = dict(db.execute(select(Outbox.status, func.count()).group_by(Outbox.status)).all())
        webhook_counts = dict(db.execute(select(WebhookDelivery.status, func.count()).group_by(WebhookDelivery.status)).all())
    return templates.TemplateResponse(request, "dashboard.html", {
        "tenant_id": session["tenant_id"], "alerts": alerts, "sessions": sessions,
        "outbox_counts": outbox_counts, "webhook_counts": webhook_counts,
        "judge_provider": current_runtime_provider(session["tenant_id"]),
    })


@app.get("/dashboard/activity", response_class=HTMLResponse)
def dashboard_activity(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        calls = db.scalars(select(ToolCall).order_by(ToolCall.created_at.desc()).limit(50)).all()
    return templates.TemplateResponse(request, "activity.html", {
        "tenant_id": session["tenant_id"], "calls": calls,
    })


@app.get("/dashboard/data-flow", response_class=HTMLResponse)
def dashboard_data_flow(request: Request, session_id: str = Query(default="", max_length=100),
                        tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    choices = research_tenant_choices(session)
    research_summaries = []
    for choice in choices:
        with tenant_db_session(choice["id"]) as db:
            count = db.scalar(select(func.count()).select_from(DataFlowDecision)) or 0
        research_summaries.append({**choice, "count": count})
    research_summaries.sort(key=lambda item: item["count"], reverse=True)
    with tenant_db_session(tenant_id) as db:
        query = select(DataFlowDecision)
        if session_id:
            query = query.where(DataFlowDecision.session_id == session_id)
        decisions = db.scalars(query.order_by(DataFlowDecision.created_at.desc()).limit(100)).all()
        source_ids = {source_id for row in decisions for source_id in row.source_ids}
        from .models import Delegation
        delegation_ids = set(db.scalars(select(Delegation.id).where(Delegation.id.in_(source_ids)))) if source_ids else set()
        source_call_ids = set(db.scalars(select(ToolCall.call_id).where(
            ToolCall.call_id.in_(source_ids))).all()) if source_ids else set()
    return templates.TemplateResponse(request, "data_flow.html", {
        "tenant_id": tenant_id, "decisions": decisions, "selected_session": session_id,
        "research_tenants": research_summaries, "source_call_ids": source_call_ids, "delegation_ids": delegation_ids,
        "observer": tenant_id != session["tenant_id"],
    })


@app.get("/dashboard/data-flow/calls/{call_id}", response_class=HTMLResponse)
def dashboard_data_flow_call(call_id: uuid.UUID, request: Request, tenant: str | None = None,
                             session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        call_id_text = str(call_id)
        direct = db.scalar(select(DataFlowDecision.id).where(
            DataFlowDecision.call_id == call_id_text).limit(1))
        referenced = direct is not None or any(
            call_id_text in (ids or []) for ids in
            db.scalars(select(DataFlowDecision.source_ids)).all())
        if not referenced:
            raise HTTPException(404, "Data flow call not found")
        call = db.get(ToolCall, call_id_text)
        if not call:
            raise HTTPException(404, "Call not found")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call_id_text)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call_id_text)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence,
        "tenant_id": tenant_id, "observer": tenant_id != session["tenant_id"],
        "back_url": f"/dashboard/data-flow?tenant={tenant_id}",
    })


@app.get("/dashboard/audit", response_class=HTMLResponse)
def dashboard_audit(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(50)).all()
        judges = db.scalars(select(JudgeResult).order_by(JudgeResult.created_at.desc()).limit(30)).all()
        event_evidence = event_judge_evidence(db, events)
        judge_routes = {result.outbox_id: db.get(JudgeRoute, result.outbox_id) for result in judges}
    return templates.TemplateResponse(request, "audit.html", {
        "tenant_id": session["tenant_id"], "events": events, "judges": judges,
        "event_evidence": event_evidence, "judge_routes": judge_routes,
    })


def _threat_catalog() -> dict:
    try:
        return load_threat_catalog()
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "威胁映射目录不可用，请检查本地映射文件") from exc


def _threat_view(row: ThreatMappingAssessment) -> dict:
    return {"id": row.id, "audit_event_id": row.audit_event_id,
            "mapping_version": row.mapping_version, "event_type": row.event_type,
            "source_record_id": row.source_record_id, "call_id": row.call_id,
            "agent_id": row.agent_id, "session_id": row.session_id,
            "origin": row.origin, "status": row.status, "matches": row.matches,
            "observed_at": row.observed_at.isoformat(), "mapped_at": row.mapped_at.isoformat()}


def _threat_rows(db, days: int, threat_id: str = "") -> list[ThreatMappingAssessment]:
    rows = db.scalars(select(ThreatMappingAssessment).where(
        ThreatMappingAssessment.observed_at >= utcnow() - timedelta(days=days))
        .order_by(ThreatMappingAssessment.observed_at.desc(),
                  ThreatMappingAssessment.id.desc())).all()
    return [row for row in rows if row.status == "matched" and
            (not threat_id or any(item["threat_id"] == threat_id for item in row.matches))]


@app.get("/api/v3/threat-mappings")
def threat_mappings_api(threat_id: str = "", days: int = Query(default=30, ge=1, le=3650),
                        limit: int = Query(default=100, ge=1, le=200),
                        session=Depends(admin_session)):
    catalog = _threat_catalog()
    if threat_id and threat_id not in {item["id"] for item in catalog["threats"]}:
        raise HTTPException(422, "未知威胁编号")
    with tenant_db_session(session["tenant_id"]) as db:
        rows = _threat_rows(db, days, threat_id)
        health = projection_health(db, catalog=catalog)
    return {"tenant_id": session["tenant_id"], "health": health,
            "total_matched_events": len(rows), "items": [_threat_view(row) for row in rows[:limit]]}


@app.get("/api/v3/threat-mappings/{assessment_id}")
def threat_mapping_detail_api(assessment_id: uuid.UUID, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        row = db.get(ThreatMappingAssessment, str(assessment_id))
        if row is None:
            raise HTTPException(404, "映射记录不存在")
        return _threat_view(row)


@app.get("/dashboard/threat-map", response_class=HTMLResponse)
def dashboard_threat_map(request: Request, threat_id: str = "",
                         days: int = Query(default=30, ge=1, le=3650),
                         session=Depends(admin_session)):
    catalog = _threat_catalog()
    if threat_id and threat_id not in {item["id"] for item in catalog["threats"]}:
        raise HTTPException(422, "未知威胁编号")
    with tenant_db_session(session["tenant_id"]) as db:
        all_rows = _threat_rows(db, days)
        health = projection_health(db, catalog=catalog)
        latest_by_event = {}
        for assessment in db.scalars(select(ThreatMappingAssessment).where(
                ThreatMappingAssessment.observed_at >= utcnow() - timedelta(days=days))
                .order_by(ThreatMappingAssessment.mapped_at,
                          ThreatMappingAssessment.id)).all():
            latest_by_event[assessment.audit_event_id] = assessment
        unmapped_count = sum(row.status == "unmapped" for row in latest_by_event.values())
    counts = {item["id"]: 0 for item in catalog["threats"]}
    for row in all_rows:
        for linked_id in {item["threat_id"] for item in row.matches}:
            counts[linked_id] += 1
    rows = [row for row in all_rows if not threat_id or
            any(item["threat_id"] == threat_id for item in row.matches)]
    return templates.TemplateResponse(request, "threat_map.html", {
        "tenant_id": session["tenant_id"], "catalog": catalog,
        "rows": rows[:100], "total_rows": len(rows), "counts": counts,
        "health": health, "unmapped_count": unmapped_count,
        "selected_threat": threat_id, "days": days,
    })


@app.get("/dashboard/threat-map/threats/{threat_id}", response_class=HTMLResponse)
def dashboard_threat_scenario(threat_id: str, request: Request,
                              days: int = Query(default=30, ge=1, le=3650),
                              session=Depends(admin_session)):
    catalog = _threat_catalog()
    threat = next((item for item in catalog["threats"] if item["id"] == threat_id), None)
    if threat is None:
        raise HTTPException(404, "项目威胁不存在")
    categories = [item for item in catalog["categories"] if item["id"] in threat["owasp"]]
    techniques = [item for item in catalog["atlas_techniques"] if item["id"] in threat["atlas"]]
    signals = [item for item in catalog["runtime_signals"]
               if threat_id in item["threat_ids"]]
    with tenant_db_session(session["tenant_id"]) as db:
        rows = _threat_rows(db, days, threat_id)
    return templates.TemplateResponse(request, "threat_scenario.html", {
        "tenant_id": session["tenant_id"], "threat": threat,
        "categories": categories, "techniques": techniques,
        "signals": signals, "rows": rows[:100], "total_rows": len(rows),
        "days": days, "catalog": catalog,
    })


@app.get("/dashboard/threat-map/{assessment_id}", response_class=HTMLResponse)
def dashboard_threat_map_detail(assessment_id: uuid.UUID, request: Request,
                                session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        row = db.get(ThreatMappingAssessment, str(assessment_id))
        if row is None:
            raise HTTPException(404, "映射记录不存在")
        event = db.get(AuditEvent, row.audit_event_id)
        if event is None:
            raise HTTPException(404, "原始审计事件不存在")
        call_exists = bool(row.call_id and db.get(ToolCall, row.call_id))
        session_exists = bool(row.agent_id and row.session_id and
                              db.get(RuntimeSession, (row.agent_id, row.session_id)))
    return templates.TemplateResponse(request, "threat_map_detail.html", {
        "tenant_id": session["tenant_id"], "row": row,
        "call_exists": call_exists, "session_exists": session_exists,
    })


@app.get("/dashboard/alerts", response_class=HTMLResponse)
def dashboard_alerts(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        judge_alerts = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(50)).all()
        runtime_alerts = db.scalars(select(RuntimeIncident).order_by(
            RuntimeIncident.updated_at.desc()).limit(50)).all()
        flow_alerts = db.scalars(select(DataFlowIncident).order_by(
            DataFlowIncident.created_at.desc()).limit(50)).all()
        alerts = ([{"id": row.id, "source": "Judge", "created_at": row.created_at,
                    "severity": row.severity, "call_id": row.call_id,
                    "title": row.title, "status": row.status, "occurrences": 1}
                   for row in judge_alerts] +
                  [{"id": row.id, "source": "运行时安全规则", "created_at": row.updated_at,
                    "severity": row.severity, "call_id": row.call_id,
                    "title": row.title, "status": row.status,
                    "occurrences": row.occurrences} for row in runtime_alerts] +
                  [{"id": row.id, "source": "数据泄露防护", "created_at": row.created_at,
                    "severity": row.severity, "call_id": row.call_id,
                    "title": row.title + "（" + row.finding + "）", "status": row.status,
                    "occurrences": 1} for row in flow_alerts])
        alerts.sort(key=lambda item: item["created_at"], reverse=True)
        alerts = alerts[:50]
        alert_record_ids = {row.decision_id for row in [*runtime_alerts, *flow_alerts]}
        alert_event_ids = set()
        for row in judge_alerts:
            result = db.get(JudgeResult, row.judge_result_id)
            outbox = db.get(Outbox, result.outbox_id) if result else None
            if outbox:
                alert_event_ids.add(outbox.audit_event_id)
        selectors = []
        if alert_record_ids:
            selectors.append(ThreatMappingAssessment.source_record_id.in_(alert_record_ids))
        if alert_event_ids:
            selectors.append(ThreatMappingAssessment.audit_event_id.in_(alert_event_ids))
        assessments = db.scalars(select(ThreatMappingAssessment).where(
            or_(*selectors)).order_by(ThreatMappingAssessment.mapped_at,
                                      ThreatMappingAssessment.id)).all() if selectors else []
        by_record = {row.source_record_id: row for row in assessments if row.source_record_id}
        by_event = {row.audit_event_id: row for row in assessments}
        alert_sources = {row.id: ("record", row.decision_id) for row in
                         [*runtime_alerts, *flow_alerts]}
        for row in judge_alerts:
            result = db.get(JudgeResult, row.judge_result_id)
            outbox = db.get(Outbox, result.outbox_id) if result else None
            if outbox:
                alert_sources[row.id] = ("event", outbox.audit_event_id)
        for alert in alerts:
            kind, source_id = alert_sources.get(alert["id"], ("", ""))
            mapped = (by_record.get(source_id) if kind == "record" else
                      by_event.get(source_id) if kind == "event" else None)
            alert["threat_links"] = list(dict.fromkeys(
                item["threat_id"] for item in mapped.matches)) if mapped else []
            alert["threat_assessment_id"] = mapped.id if mapped and mapped.status == "matched" else None
            alert["mapping_status"] = mapped.status if mapped else "pending"
        alert_groups = db.scalars(select(AlertGroup).order_by(AlertGroup.last_seen_at.desc()).limit(20)).all()
    return templates.TemplateResponse(request, "alerts.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "alerts": alerts, "alert_groups": alert_groups,
    })


@app.get("/dashboard/approvals", response_class=HTMLResponse)
def dashboard_approvals(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        approvals = db.scalars(select(Approval).where(Approval.status == "pending").limit(50)).all()
        approval_calls = {approval.id: db.get(ToolCall, approval.call_id) for approval in approvals}
        runtime_reasons = {approval.id: db.scalar(select(RuntimeDecision).where(
            RuntimeDecision.call_id == approval.call_id, RuntimeDecision.phase == "submit"))
            for approval in approvals}
    return templates.TemplateResponse(request, "approvals.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "approvals": approvals, "approval_calls": approval_calls,
        "runtime_reasons": runtime_reasons,
    })


def approval_facts(db, approval_id: str) -> dict:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(404, "Approval not found")
    call = db.get(ToolCall, approval.call_id)
    if call is None:
        raise HTTPException(404, "Call not found")
    grant = db.get(CapabilityGrant, call.grant_id) if call.grant_id else None
    runtime = db.scalars(select(RuntimeDecision).where(RuntimeDecision.call_id == call.call_id)
                         .order_by(RuntimeDecision.created_at, RuntimeDecision.id)).all()
    flows = db.scalars(select(DataFlowDecision).where(DataFlowDecision.call_id == call.call_id)
                       .order_by(DataFlowDecision.created_at, DataFlowDecision.id)).all()
    goals = db.scalars(select(GoalAssessment).where(GoalAssessment.call_id == call.call_id)
                       .order_by(GoalAssessment.created_at, GoalAssessment.id)).all()
    source_ids = list(dict.fromkeys(
        [str(item) for goal in goals for item in goal.evidence_ids] +
        [str(item.get("id")) for decision in runtime for item in decision.evidence
         if item.get("kind") == "call" and item.get("id")] +
        [str(item) for flow in flows for item in flow.source_ids]))[:20]
    sources = []
    for source_id in source_ids:
        source_call = db.get(ToolCall, source_id)
        memory = db.get(MemoryEntry, source_id) if not source_call else None
        if source_call:
            sources.append({"id": source_id, "kind": "call", "tool": source_call.tool,
                            "status": source_call.status, "content_hash": canonical_hash(
                                {"result": source_call.result})})
        elif memory:
            sources.append({"id": source_id, "kind": "memory", "tool": "memory",
                            "status": memory.status, "content_hash": canonical_hash(
                                {"text": memory.text})})
        else:
            sources.append({"id": source_id, "kind": "missing", "tool": "unknown",
                            "status": "missing", "content_hash": ""})
    facts = {"approval_id": approval.id, "approval_status": approval.status,
             "call_id": call.call_id, "call_status": call.status, "agent_id": call.agent_id,
             "session_id": call.session_id, "tool": call.tool, "arguments_hash": approval.arguments_hash,
             "current_arguments_hash": canonical_hash(call.arguments), "policy_rule": call.policy_rule,
             "grant_id": call.grant_id, "grant_revoked": grant.revoked if grant else None,
             "grant_expires_at": grant.expires_at.isoformat() if grant else None,
             "grant_resources": grant.resources if grant else [],
             "approval_expires_at": call.approval_expires_at.isoformat() if call.approval_expires_at else None,
             "runtime": [{"id": row.id, "effect": row.effect, "findings": row.findings,
                          "evidence": row.evidence} for row in runtime],
             "data_flow": [{"id": row.id, "effect": row.effect, "findings": row.findings,
                             "source_ids": row.source_ids} for row in flows],
             "goals": [assessment_view(row) for row in goals],
             "sources": sources}
    return {"approval": approval, "call": call, "grant": grant, "facts": facts,
            "runtime": runtime, "flows": flows, "goals": goals,
            "sources": sources}


def approval_review_token(facts: dict, session: dict) -> str:
    signer = URLSafeTimedSerializer(settings.session_secret or "testing-only",
                                    salt="agentsentry-approval-review")
    return signer.dumps({"tenant": session["tenant_id"], "admin_csrf": session["csrf"],
                         "approval": facts["approval_id"], "facts_hash": canonical_hash(facts)})


def verify_approval_review(token: str, facts: dict, session: dict) -> None:
    signer = URLSafeTimedSerializer(settings.session_secret or "testing-only",
                                    salt="agentsentry-approval-review")
    try:
        payload = signer.loads(token, max_age=300)
    except (BadSignature, SignatureExpired):
        raise HTTPException(409, "审批确认已过期，请重新查看事实卡")
    expected = {"tenant": session["tenant_id"], "admin_csrf": session["csrf"],
                "approval": facts["approval_id"], "facts_hash": canonical_hash(facts)}
    if payload != expected or facts["approval_status"] != "pending" or facts["call_status"] != "pending_approval":
        raise HTTPException(409, "审批事实或状态已变化，请重新查看")


@app.get("/dashboard/approvals/{approval_id}", response_class=HTMLResponse)
def dashboard_approval_detail(approval_id: uuid.UUID, request: Request,
                              session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        card = approval_facts(db, str(approval_id))
        token = approval_review_token(card["facts"], session) if card["approval"].status == "pending" else ""
    return templates.TemplateResponse(request, "approval_detail.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "review_token": token, **card,
    })


@app.get("/api/v3/goal-assessments")
def goal_assessments_api(session_id: str | None = None, agent_id: str | None = None,
                         tenant: str | None = None,
                         session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        query = select(GoalAssessment)
        if session_id:
            query = query.where(GoalAssessment.session_id == session_id)
        if agent_id:
            query = query.where(GoalAssessment.agent_id == agent_id)
        rows = db.scalars(query.order_by(GoalAssessment.created_at.desc()).limit(100)).all()
        return {"tenant_id": tenant_id, "items": [assessment_view(row) for row in rows]}


@app.get("/dashboard/goal-assessments", response_class=HTMLResponse)
def dashboard_goal_assessments(request: Request, tenant: str | None = None,
                               session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    observer = tenant_id != session["tenant_id"]
    with tenant_db_session(tenant_id) as db:
        rows = db.scalars(select(GoalAssessment).order_by(
            GoalAssessment.created_at.desc()).limit(100)).all()
        cases = db.scalars(select(GoalLabCase).where(
            GoalLabCase.session_id.in_({row.session_id for row in rows}))).all() if observer and rows else []
        case_by_session = {case.session_id: case for case in cases}
        items = []
        for row in rows:
            case = case_by_session.get(row.session_id)
            call_ids = set(case.evidence.get("call_ids", [])) if case and isinstance(case.evidence, dict) else set()
            if observer:
                session_url = (f"/dashboard/goal-runs/{case.run_id}/sessions/"
                               f"{quote(row.session_id, safe='')}?{urlencode({'tenant': tenant_id})}") if case else None
                call_url = (f"/dashboard/goal-runs/{case.run_id}/calls/{row.call_id}"
                            f"?{urlencode({'tenant': tenant_id})}") if row.call_id in call_ids else None
                source_urls = {source: (f"/dashboard/goal-runs/{case.run_id}/calls/{source}"
                                        f"?{urlencode({'tenant': tenant_id})}")
                               for source in row.evidence_ids if source in call_ids}
                if case is None:
                    query = urlencode({"tenant": tenant_id})
                    session_url = ("/dashboard/runtime-sessions/detail?" + urlencode({
                        "tenant": tenant_id, "agent_id": row.agent_id,
                        "session_id": row.session_id, "view": "goal"})) if db.get(
                            RuntimeSession, (row.agent_id, row.session_id)) else None
                    call_url = (f"/dashboard/runtime-sessions/calls/{row.call_id}?{query}"
                                if row.call_id and db.get(ToolCall, row.call_id) else None)
                    source_urls = {source: f"/dashboard/runtime-sessions/calls/{source}?{query}"
                                   for source in row.evidence_ids if db.get(ToolCall, source)}
            else:
                session_url = "/dashboard/runtime-sessions/detail?" + urlencode({
                    "agent_id": row.agent_id, "session_id": row.session_id})
                call_url = f"/dashboard/calls/{row.call_id}" if row.call_id else None
                source_urls = {source: f"/dashboard/calls/{source}" for source in row.evidence_ids
                               if db.get(ToolCall, source) is not None}
            items.append({**assessment_view(row), "session_url": session_url,
                          "call_url": call_url,
                          "sources": [{"id": source, "url": source_urls.get(source)}
                                      for source in row.evidence_ids]})
    return templates.TemplateResponse(request, "goal_assessments.html", {
        "tenant_id": tenant_id, "items": items, "observer": observer,
        "choices": research_tenant_choices(session),
    })


@app.get("/api/v3/goal-runs")
def goal_runs_api(tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        rows = db.scalars(select(GoalLabRun).order_by(GoalLabRun.created_at.desc()).limit(50)).all()
        return {"tenant_id": tenant_id, "items": [{"id": row.id, "mode": row.mode,
                "status": row.status, "corpus_version": row.corpus_version,
                "model_name": row.model_name} for row in rows]}


@app.post("/api/v3/goal-lab/fixtures/install")
def install_goal_lab_fixtures(session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        try:
            return {"installed": install_goal_fixtures(db)}
        except ValueError as exc:
            raise HTTPException(409, str(exc))


@app.post("/api/v3/goal-runs")
def start_goal_run(body: GoalLabRunRequest, session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        try:
            row = create_goal_run(db, body.mode, policy_for(tenant_id).revision,
                                  body.model_name or None)
            return {"id": row.id, "status": row.status, "expected_cases": row.expected_cases}
        except ValueError as exc:
            raise HTTPException(422, str(exc))


@app.post("/api/v3/goal-runs/{run_id}/cases")
def submit_goal_case(run_id: uuid.UUID, body: GoalLabCaseSubmission,
                     session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        try:
            row = record_goal_case(db, run, body.case_id, body.repetition,
                body.session_id, body.trace, body.final_answer, body.display_text,
                body.finished, body.error)
            return {"case_id": row.case_id, "outcome": row.outcome}
        except ValueError as exc:
            raise HTTPException(422, str(exc))


@app.post("/api/v3/goal-runs/{run_id}/finish")
def complete_goal_run(run_id: uuid.UUID, body: GoalLabRunFinish,
                      session=Depends(require_csrf)):
    tenant_id = _calibration_write_tenant(session)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        if run.status != "running":
            raise HTTPException(409, "实验已结束")
        finish_goal_run(db, run, body.failed)
        return {"id": run.id, "status": run.status}


@app.get("/api/v3/goal-runs/{run_id}")
def goal_run_api(run_id: uuid.UUID, tenant: str | None = None,
                 session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        return goal_run_view(db, run)


@app.get("/dashboard/goal-runs", response_class=HTMLResponse)
def dashboard_goal_runs(request: Request, tenant: str | None = None,
                        session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        rows = db.scalars(select(GoalLabRun).order_by(GoalLabRun.created_at.desc()).limit(50)).all()
    return templates.TemplateResponse(request, "goal_runs.html", {
        "tenant_id": tenant_id, "runs": rows, "choices": research_tenant_choices(session),
    })


@app.get("/dashboard/goal-runs/{run_id}", response_class=HTMLResponse)
def dashboard_goal_run_detail(run_id: uuid.UUID, request: Request,
                              tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        view = goal_run_view(db, run)
    return templates.TemplateResponse(request, "goal_run_detail.html", {
        "tenant_id": tenant_id, "run": view,
    })


@app.get("/dashboard/goal-runs/{run_id}/calls/{call_id}", response_class=HTMLResponse)
def dashboard_goal_run_call(run_id: uuid.UUID, call_id: uuid.UUID, request: Request,
                            tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None:
            raise HTTPException(404, "实验不存在")
        view = goal_run_view(db, run)
        if not any(str(call_id) in item["evidence"]["call_ids"] for item in view["cases"]):
            raise HTTPException(404, "调用不属于此实验")
        call = db.get(ToolCall, str(call_id))
        if call is None:
            raise HTTPException(404, "调用不存在")
        events = db.scalars(select(AuditEvent).where(AuditEvent.call_id == call.call_id)
                            .order_by(AuditEvent.created_at)).all()
        judges = db.scalars(select(JudgeResult).where(JudgeResult.call_id == call.call_id)
                            .order_by(JudgeResult.created_at)).all()
        event_evidence = event_judge_evidence(db, events)
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence, "tenant_id": tenant_id,
        "observer": tenant_id != session["tenant_id"],
        "back_url": f"/dashboard/goal-runs/{run_id}?tenant={tenant_id}"})


@app.get("/dashboard/goal-runs/{run_id}/sessions/{session_id}", response_class=HTMLResponse)
def dashboard_goal_run_session(run_id: uuid.UUID, session_id: str, request: Request,
                               tenant: str | None = None, session=Depends(admin_session)):
    tenant_id = research_tenant_for_read(session, tenant)
    with tenant_db_session(tenant_id) as db:
        run = db.get(GoalLabRun, str(run_id))
        if run is None or not any(item["session_id"] == session_id for item in
                goal_run_view(db, run)["cases"]):
            raise HTTPException(404, "会话不属于此实验")
        view = session_view(db, "demo-agent", session_id)
        if view is None:
            raise HTTPException(404, "会话不存在")
    return templates.TemplateResponse(request, "runtime_session_detail.html", {
        "item": view, "tenant_id": tenant_id, "csrf": session["csrf"],
        "observer": tenant_id != session["tenant_id"],
        "research_run_id": str(run_id), "research_kind": "goal-runs",
        "back_url": f"/dashboard/goal-runs/{run_id}?tenant={tenant_id}",
        "runtime_binding_required": settings.agentsentry_runtime_binding_required})


@app.get("/dashboard/judge-samples", response_class=HTMLResponse)
def dashboard_judge_samples(request: Request, provider: str | None = None,
                            session=Depends(admin_session)):
    runtime_provider = current_runtime_provider(session["tenant_id"])
    selected = provider or runtime_provider
    if selected not in JUDGE_PROVIDER_IDS:
        raise HTTPException(422, "Unknown Judge provider")
    choices = configured_judge_providers(settings)
    selected_choice = next((choice for choice in choices if choice["id"] == selected), None)
    if selected_choice is None:
        choices.append({"id": selected, "label": selected + "（仅查看历史结果）",
                        "model": "未配置", "destination": "未配置"})
    with tenant_db_session(session["tenant_id"]) as db:
        samples = db.scalars(select(JudgeSample).order_by(JudgeSample.created_at.desc()).limit(50)).all()
        sample_stats, latest_samples = sample_metrics(db, selected, settings.judge_score_threshold)
    return templates.TemplateResponse(request, "judge_samples.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "samples": samples, "sample_stats": sample_stats, "latest_samples": latest_samples,
        "sample_status": request.query_params.get("sample_status"),
        "selected_provider": selected, "provider_choices": choices,
        "selected_choice": selected_choice, "runtime_provider": runtime_provider,
    })


@app.get("/dashboard/grants", response_class=HTMLResponse)
def dashboard_grants(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        grants = db.scalars(select(CapabilityGrant).order_by(CapabilityGrant.created_at.desc()).limit(20)).all()
    return templates.TemplateResponse(request, "grants.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"], "grants": grants,
    })


@app.get("/dashboard/policy", response_class=HTMLResponse)
def dashboard_policy(request: Request, session=Depends(admin_session)):
    return templates.TemplateResponse(request, "policy.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"],
        "policy_rules": policy_for(session["tenant_id"]).policy.rules,
        "policy_revision": policy_for(session["tenant_id"]).revision,
        "policy_source": policy_path_for(session["tenant_id"]).read_text(encoding="utf-8"),
        "policy_reload": request.query_params.get("policy_reload"),
    })


@app.get("/dashboard/runtime-rules", response_class=HTMLResponse)
def dashboard_runtime_rules(request: Request, session=Depends(admin_session)):
    return templates.TemplateResponse(request, "runtime_rules.html", {
        "tenant_id": session["tenant_id"],
        "rules": rule_catalog(), "data_flow_rules": data_flow_rule_catalog(),
        "rules_version": RUNTIME_RULES_VERSION + " / " + DATA_FLOW_RULES_VERSION,
        "runtime_binding_required": settings.agentsentry_runtime_binding_required,
    })


@app.get("/dashboard/remote-mcp", response_class=HTMLResponse)
def dashboard_remote_mcp(request: Request, session=Depends(admin_session)):
    with tenant_db_session(session["tenant_id"]) as db:
        recent = db.scalars(select(ToolCall).where(ToolCall.tool.in_([
            "remote_mcp_lookup_card", "remote_mcp_record_note", "github_mcp_read_license",
            "github_mcp_read_issue", "github_mcp_create_test_issue"])).order_by(
            ToolCall.created_at.desc()).limit(20)).all()
        profiles = db.scalars(select(McpProfileVersion).order_by(
            McpProfileVersion.revision.desc()).limit(15)).all()
        changes = db.scalars(select(McpProfileChange).order_by(
            McpProfileChange.created_at.desc()).limit(20)).all()
        incidents = db.scalars(select(McpSupplyIncident).order_by(
            McpSupplyIncident.created_at.desc()).limit(20)).all()
        health = probe_remote_mcp(session["tenant_id"], db)
        current_profile = next((item for item in profiles if item.active), None)
        change_summaries = {item.id: mcp_review_summary(current_profile, item) for item in changes}
    from .mcp_github import (ENDPOINT as github_endpoint, TOOL_SCHEMA_SHA256 as github_schema_sha256,
                             ISSUE_ENDPOINT as github_issue_endpoint,
                             ISSUE_TOOL_SCHEMA_SHA256 as github_issue_schema_sha256)
    return templates.TemplateResponse(request, "remote_mcp.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"], "health": health,
        "recent": recent, "profiles": profiles, "changes": changes, "incidents": incidents,
        "active_profile": current_profile, "change_summaries": change_summaries,
        "mcp_notice": request.query_params.get("notice", ""),
        "github_readonly": {"enabled": settings.agentsentry_github_mcp_enabled and session["tenant_id"] == "default"
                            and bool(settings.github_mcp_pat),
                            "endpoint": github_endpoint, "schema_sha256": github_schema_sha256,
                            "issue_endpoint": github_issue_endpoint,
                            "issue_schema_sha256": github_issue_schema_sha256},
        "github_write": {"enabled": settings.agentsentry_github_mcp_write_enabled and
                         session["tenant_id"] == "default" and bool(settings.github_mcp_write_pat),
                         "repository": settings.github_mcp_test_repo,
                         "schema_sha256": settings.github_mcp_create_issue_schema_sha256},
    })


@app.post("/dashboard/remote-mcp/scan")
async def dashboard_scan_remote_mcp(request: Request, session=Depends(admin_session)):
    await require_form_csrf(request, session)
    from starlette.concurrency import run_in_threadpool
    def scan():
        with tenant_db_session(session["tenant_id"]) as db:
            return probe_remote_mcp(session["tenant_id"], db, record=True)
    result = await run_in_threadpool(scan)
    return RedirectResponse("/dashboard/remote-mcp?notice=" + quote(result["status"]), status_code=303)


@app.post("/dashboard/remote-mcp/changes/{change_id}/decision")
async def dashboard_decide_remote_mcp(change_id: uuid.UUID, request: Request,
                                      session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        entry = remote_mcp_registry()[session["tenant_id"]]
        with tenant_db_session(session["tenant_id"]) as db:
            decide_mcp_candidate(db, entry, str(change_id), str(form.get("decision", "")))
    except (KeyError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse("/dashboard/remote-mcp?notice=reviewed", status_code=303)


@app.post("/dashboard/remote-mcp/versions/{revision}/rollback")
async def dashboard_rollback_remote_mcp(revision: int, request: Request,
                                        session=Depends(admin_session)):
    await require_form_csrf(request, session)
    try:
        entry = remote_mcp_registry()[session["tenant_id"]]
        with tenant_db_session(session["tenant_id"]) as db:
            rollback_mcp_profile(db, entry, revision)
    except (KeyError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse("/dashboard/remote-mcp?notice=rolled_back", status_code=303)


@app.get("/dashboard/tenants", response_class=HTMLResponse)
def dashboard_tenants(request: Request, session=Depends(admin_session)):
    if session["tenant_id"] != "default":
        raise HTTPException(403, "Only the default administrator manages tenants")
    with db_session() as db:
        tenants = db.scalars(select(Tenant).order_by(Tenant.name)).all()
    return templates.TemplateResponse(request, "tenants.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"], "tenant_rows": tenants,
    })


@app.get("/dashboard/system", response_class=HTMLResponse)
def dashboard_system(request: Request, session=Depends(admin_session)):
    provider = current_runtime_provider(session["tenant_id"])
    choice = next((item for item in configured_judge_providers(settings)
                   if item["id"] == provider), None)
    with tenant_db_session(session["tenant_id"]) as db:
        outbox_counts = dict(db.execute(select(Outbox.status, func.count()).group_by(Outbox.status)).all())
        webhook_counts = dict(db.execute(select(WebhookDelivery.status, func.count()).group_by(WebhookDelivery.status)).all())
        tasks = db.scalars(select(Task).limit(30)).all()
        inbox = db.scalars(select(ExternalMessage).limit(30)).all()
    return templates.TemplateResponse(request, "system.html", {
        "tenant_id": session["tenant_id"], "outbox_counts": outbox_counts,
        "webhook_counts": webhook_counts, "tasks": tasks, "inbox": inbox,
        "judge_provider": provider,
        "judge_destination": choice["destination"] if choice else "未配置",
    })


@app.get("/dashboard/resilience", response_class=HTMLResponse)
def dashboard_resilience(request: Request, session=Depends(admin_session)):
    from .resilience import health_view
    with tenant_db_session(session["tenant_id"]) as db:
        view = health_view(db)
    return templates.TemplateResponse(request, "resilience.html", {
        "tenant_id": session["tenant_id"], "csrf": session["csrf"], **view})


@app.post("/dashboard/resilience/{kind}/{record_id}/retry")
async def dashboard_retry_signal(kind: str, record_id: uuid.UUID, request: Request,
                                 session=Depends(admin_session)):
    from .resilience import retry_failed
    if kind not in {"judge", "webhook"}:
        raise HTTPException(404, "Unknown queue")
    form = await request.form()
    if not secrets.compare_digest(str(form.get("csrf", "")), session["csrf"]):
        raise HTTPException(403, "CSRF token required")
    with tenant_db_session(session["tenant_id"]) as db:
        result = retry_failed(db, kind, str(record_id))
        if result != "ok":
            raise HTTPException(404 if result == "not_found" else 409, "Failed signal not found or already retried")
        db.commit()
    return RedirectResponse("/dashboard/resilience", status_code=303)


@app.get("/dashboard/calls/{call_id}", response_class=HTMLResponse)
def call_detail(call_id: uuid.UUID, request: Request, _: dict = Depends(admin_session)):
    with tenant_db_session(_["tenant_id"]) as db:
        call = db.get(ToolCall, str(call_id))
        if not call:
            raise HTTPException(404, "Call not found")
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.call_id == call.call_id).order_by(AuditEvent.created_at)
        ).all()
        judges = db.scalars(
            select(JudgeResult).where(JudgeResult.call_id == call.call_id).order_by(JudgeResult.created_at)
        ).all()
        event_evidence = event_judge_evidence(db, events)
        threat_rows = db.scalars(select(ThreatMappingAssessment).where(
            ThreatMappingAssessment.call_id == call.call_id,
            ThreatMappingAssessment.status == "matched")
            .order_by(ThreatMappingAssessment.observed_at.desc()).limit(30)).all()
    return templates.TemplateResponse(request, "call_detail.html", {
        "call": call, "events": events, "judges": judges,
        "event_evidence": event_evidence,
        "threat_rows": threat_rows,
    })


@app.post("/dashboard/alerts/{alert_id}/ack")
async def acknowledge_alert(alert_id: uuid.UUID, request: Request, session=Depends(admin_session)):
    await require_form_csrf(request, session)
    with tenant_db_session(session["tenant_id"]) as db:
        alert = db.get(Alert, str(alert_id))
        if not alert:
            raise HTTPException(404, "Alert not found")
        alert.status = "acknowledged"
        db.commit()
    return RedirectResponse("/dashboard/alerts", status_code=303)


@app.post("/dashboard/runtime-incidents/{incident_id}/ack")
async def acknowledge_runtime_incident(incident_id: uuid.UUID, request: Request,
                                       session=Depends(admin_session)):
    await require_form_csrf(request, session)
    with tenant_db_session(session["tenant_id"]) as db:
        incident = db.get(RuntimeIncident, str(incident_id))
        if not incident:
            raise HTTPException(404, "Runtime incident not found")
        incident.status = "acknowledged"
        db.commit()
    return RedirectResponse("/dashboard/alerts", status_code=303)


@app.post("/dashboard/data-flow-incidents/{incident_id}/ack")
async def acknowledge_data_flow_incident(incident_id: uuid.UUID, request: Request,
                                         session=Depends(admin_session)):
    await require_form_csrf(request, session)
    with tenant_db_session(session["tenant_id"]) as db:
        incident = db.get(DataFlowIncident, str(incident_id))
        if not incident:
            raise HTTPException(404, "Data flow incident not found")
        incident.status = "acknowledged"
        db.commit()
    return RedirectResponse("/dashboard/alerts", status_code=303)


@app.post("/dashboard/grants")
async def dashboard_issue_grant(request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    try:
        body = CapabilityRequest(
            agent_id="demo-agent", tool=str(form["tool"]),
            resources=[item.strip() for item in str(form["resources"]).split(",") if item.strip()],
            ttl_seconds=int(form["ttl_seconds"]), max_uses=int(form["max_uses"]),
        )
    except Exception as exc:
        raise HTTPException(422, str(exc))
    with tenant_db_session(session["tenant_id"]) as db:
        try:
            grant, token = issue(db, get_redis(), body, tenant_id=session["tenant_id"])
        except Exception:
            raise HTTPException(503, "Capability store or audit database unavailable")
    return templates.TemplateResponse(request, "issued.html", {
        "grant": grant, "token": token, "tenant_id": session["tenant_id"],
    })


@app.post("/dashboard/grants/{grant_id}/revoke")
async def dashboard_revoke(grant_id: uuid.UUID, request: Request, session=Depends(admin_session)):
    await require_form_csrf(request, session)
    with tenant_db_session(session["tenant_id"]) as db:
        grant = db.get(CapabilityGrant, str(grant_id))
        if not grant:
            raise HTTPException(404, "Grant not found")
        revoke(db, get_redis(), grant)
    return RedirectResponse("/dashboard/grants", status_code=303)


@app.post("/dashboard/approvals/{approval_id}")
async def dashboard_approve(approval_id: uuid.UUID, request: Request, session=Depends(admin_session)):
    form = await require_form_csrf(request, session)
    decision = str(form.get("decision", ""))
    if decision not in {"approve", "reject"}:
        raise HTTPException(422, "Invalid decision")
    with tenant_db_session(session["tenant_id"]) as db:
        if decision == "approve":
            if str(form.get("reviewed", "")) != "yes":
                raise HTTPException(422, "请在审批详情页确认原始动作")
            card = approval_facts(db, str(approval_id))
            verify_approval_review(str(form.get("review_token", "")), card["facts"], session)
        status, result = decide_approval(db, str(approval_id), decision, session["tenant_id"],
                                         policy_for(session["tenant_id"]))
    if status != 200:
        raise HTTPException(status, result.get("detail", "Approval failed"))
    return RedirectResponse("/dashboard/approvals", status_code=303)


from .delegation_routes import register as register_delegation_routes
register_delegation_routes(app)
