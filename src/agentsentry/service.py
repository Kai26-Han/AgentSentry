import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from .capability import consume
from .models import ActionChainDecision, Approval, AuditEvent, CapabilityGrant, Outbox, RuntimeDecision, RuntimeSession, ToolCall, utcnow
from .policy import Decision, PolicyEngine
from .schemas import TOOL_SCHEMAS, ToolCallRequest, resource_for
from .tools import execute
from .judge.runtime import assign_route
from .runtime_guard import GuardResult, evaluate as runtime_evaluate, record as record_runtime
from .runtime_binding import valid_session_token
from .runtime_binding import session_token
from .goal_analysis import assess_tool as assess_goal_tool
from .data_flow import BOUND_SINKS, check_tool
from .action_chain import evaluate_tool as evaluate_action_chain, record as record_action_chain
from .models import DataFlowDecision
from .config import get_settings


def canonical_hash(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def audit(session: Session, call_id: str | None, event_type: str, payload: dict, judge: bool = True) -> None:
    payload = dict(payload)
    # Operational rows retain fixed arguments/results temporarily. Audit and Outbox do not.
    for key in ("arguments", "result"):
        if key in payload:
            raw = payload.pop(key)
            serialized = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str)
            payload[key + "_hash"] = hmac.new(get_settings().session_secret.encode(),
                                                  serialized.encode(), hashlib.sha256).hexdigest()
            payload[key + "_length"] = len(serialized)
            if key == "result" and isinstance(raw, dict):
                payload["sensitivity"] = raw.get("sensitivity")
            payload["has_instruction_marker"] = payload.get("has_instruction_marker", False) or (
                "ignore the user" in serialized.lower() or "忽略用户" in serialized)
            payload["has_secret_marker"] = payload.get("has_secret_marker", False) or (
                "secret" in serialized.lower() or "password" in serialized.lower())
    event = AuditEvent(id=str(uuid.uuid4()), call_id=call_id, event_type=event_type, payload=payload)
    session.add(event)
    if judge:
        outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
        session.add(outbox)
        assign_route(session, outbox)


def call_view(call: ToolCall, approval_id: str | None = None) -> dict:
    db = object_session(call)
    runtime = db.scalar(select(RuntimeDecision).where(
        RuntimeDecision.call_id == call.call_id).order_by(RuntimeDecision.created_at.desc())) if db else None
    return {
        "call_id": call.call_id,
        "status": call.status,
        "decision": call.decision,
        "policy_rule": call.policy_rule,
        "reason": call.reason,
        "approval_id": approval_id,
        "result": call.result,
        "runtime_effect": runtime.effect if runtime else None,
        "runtime_findings": runtime.findings if runtime else [],
        "remote_endpoint_id": ("github" if call.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"} else
                               "remote-demo" if call.tool.startswith("remote_mcp_") else None),
    }


def _execute_recorded(session: Session, call: ToolCall, tenant_id: str = "default") -> dict:
    from .resilience import finish_gate, take_gate, tool_dependency
    dependency = tool_dependency(call.tool)
    attempt_id = None
    dispatched = False
    try:
        if dependency:
            attempt_id, blocked = take_gate(session, dependency, call.call_id)
            session.commit()  # 租约持久化失败时不能调用依赖。
        else:
            blocked = None
        if blocked:
            result = {"error": blocked, "dependency": dependency}
        else:
            dispatched = True
            result = execute(session, call.tool, call.arguments, call.call_id, tenant_id)
        if attempt_id:
            error = result.get("error")
            # 资源不存在是已得到正常结构的业务结果，不触发依赖熔断。
            finish_gate(session, attempt_id, not error or error in {
                "card_not_found", "document_not_found", "task_not_found"})
        from .models import DelegationCall
        if session.get(DelegationCall, call.call_id) and "error" not in result:
            from .delegation import public_resource
            from .data_flow import contains_secret
            if (not public_resource(session, call.tool, resource_for(call.tool, call.arguments))
                    or contains_secret(str(result)) or
                    (call.tool == "read_document" and result.get("sensitivity") != "public")):
                result = {"error": "delegated_result_not_public"}
        call.result = result
        call.status = "completed" if "error" not in result else "failed"
        audit(session, call.call_id, "tool_result", {
            "tool": call.tool, "arguments": call.arguments, "result": result, "status": call.status,
            **({"remote_endpoint_id": ("github" if call.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"} else "remote-demo"),
                "remote_protocol": "streamable-http",
                "remote_manifest_sha256": (result.get("_remote", {}).get("manifest_sha256") or
                                           result.get("manifest_sha256")),
                "reason": result.get("error", "")}
               if call.tool.startswith("remote_mcp_") or call.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"} else {}),
        })
        session.commit()
    except Exception:
        session.rollback()
        with Session(session.get_bind()) as recovery:
            recovery.info["tenant_id"] = tenant_id
            current = recovery.get(ToolCall, call.call_id)
            if current and current.status == "executing":
                current.status = "unknown" if dispatched else "failed"
                current.reason = ("Execution outcome could not be committed" if dispatched else
                                  "Dependency admission unavailable; tool was not dispatched")
                if attempt_id:
                    finish_gate(recovery, attempt_id, False, "execution_outcome_unknown" if dispatched
                                else "admission_failed")
                audit(recovery, current.call_id, "tool_unknown" if dispatched else "tool_result", {
                    "tool": current.tool, "status": current.status,
                    **({"remote_endpoint_id": ("github" if current.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"} else "remote-demo"),
                        "remote_protocol": "streamable-http"}
                       if current.tool.startswith("remote_mcp_") or current.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"} else {}),
                })
                recovery.commit()
            view = call_view(current) if current else {"call_id": call.call_id, "status": "unknown"}
        session.expire_all()
        return view
    return call_view(call)


def submit_call(
    session: Session,
    redis_client,
    policy: PolicyEngine,
    request: ToolCallRequest,
    capability_token: str,
    agent_id: str = "demo-agent",
    tenant_id: str = "default",
    runtime_token: str = "",
    delegation_id: str | None = None,
) -> tuple[int, dict]:
    if agent_id != "demo-agent" and not delegation_id:
        return 403, {"detail": "Worker requires a scoped delegation"}
    call_id = str(request.call_id)
    try:
        arguments = TOOL_SCHEMAS[request.tool].model_validate(request.arguments).model_dump(mode="json")
    except ValidationError as exc:
        return 422, {"detail": exc.errors(include_url=False, include_context=False)}
    fingerprint = canonical_hash({
        "session_id": request.session_id, "agent_id": agent_id,
        "tool": request.tool, "arguments": arguments,
    })
    existing = session.get(ToolCall, call_id)
    if existing:
        from .models import DelegationCall
        linked = session.get(DelegationCall, call_id)
        if (linked.delegation_id if linked else None) != delegation_id:
            return 409, {"detail": "call_id belongs to a different delegation"}
        if existing.agent_id != agent_id or existing.request_hash != fingerprint:
            return 409, {"detail": "call_id already used for a different request"}
        approval = session.scalar(select(Approval).where(Approval.call_id == call_id))
        return (200 if existing.status in {"completed", "denied", "failed"} else 202), call_view(
            existing, approval.id if approval else None,
        )

    decision = policy.decide(request.tool, arguments)
    if tenant_id != "default" and request.tool == "run_shell":
        decision = Decision("deny", "tenant_sandbox_unavailable", decision.revision)
    status = "denied" if decision.effect == "deny" else "checking"
    call = ToolCall(
        call_id=call_id, session_id=request.session_id, agent_id=agent_id,
        tool=request.tool, arguments=arguments, request_hash=fingerprint,
        status=status, decision=decision.effect, policy_rule=decision.rule_id,
    )
    session.add(call)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        current = session.get(ToolCall, call_id)
        if current and current.agent_id == agent_id and current.request_hash == fingerprint:
            return 202, call_view(current)
        return 409, {"detail": "call_id already used"}

    if delegation_id:
        from .models import DelegationCall
        session.add(DelegationCall(call_id=call_id, delegation_id=delegation_id))
        session.flush()

    if (delegation_id or get_settings().agentsentry_runtime_binding_required or runtime_token or
            request.tool.startswith("remote_mcp_") or request.tool in {"github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"}) and not valid_session_token(
            session, tenant_id, agent_id, request.session_id, runtime_token):
        reported_session = session.get(RuntimeSession, (agent_id, request.session_id))
        finding = ("session_closed" if reported_session and reported_session.reported
                   and reported_session.status != "running" else "session_binding_invalid")
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Runtime session closed" if finding == "session_closed" else "Runtime session binding missing or invalid"
        record_runtime(session, call, "submit", GuardResult(
            "deny", (finding,), ({"kind": "session", "id": request.session_id},)))
        session.commit()
        return 200, call_view(call)

    assess_goal_tool(session, call, "submit")

    if decision.effect == "deny":
        call.reason = "Denied by policy"
        audit(session, call_id, "policy_decision", {
            "tool": call.tool, "arguments": arguments, "decision": "deny", "rule": decision.rule_id,
            "policy_revision": decision.revision,
        })
        session.commit()
        return 200, call_view(call)

    try:
        if delegation_id:
            from .delegation import consume_delegated
            cap_status, grant_id = consume_delegated(session, redis_client, tenant_id, call, delegation_id)
        else:
            cap_status, grant_id = consume(
                redis_client, capability_token, agent_id, request.tool, resource_for(request.tool, arguments),
                tenant_id=tenant_id,
            )
    except Exception:
        session.rollback()
        return 503, {"detail": "Capability store unavailable; call denied"}
    if cap_status != "ok":
        call.status = "denied"
        call.decision = "deny"
        call.reason = f"Capability {cap_status}"
        if runtime_token:
            chain = evaluate_action_chain(session, tenant_id, call)
            if chain is not None:
                record_action_chain(session, agent_id, request.session_id, call_id,
                                    "submit", chain, call_id)
        audit(session, call_id, "capability_denied", {
            "tool": call.tool, "arguments": arguments, "reason": call.reason,
        })
        session.commit()
        return 200, call_view(call)

    # 与吊销写事务串行化，锁持有到安全决定提交；刷新此前加载的权限缓存。
    grant = session.get(CapabilityGrant, grant_id, with_for_update=True, populate_existing=True)
    if not grant or grant.revoked or grant.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Capability revoked or expired"
        if runtime_token:
            chain = evaluate_action_chain(session, tenant_id, call)
            if chain is not None:
                record_action_chain(session, agent_id, request.session_id, call_id,
                                    "submit", chain, call_id)
        audit(session, call_id, "capability_denied", {"tool": call.tool, "reason": call.reason})
        session.commit()
        return 200, call_view(call)
    call.grant_id = grant_id
    runtime_result = runtime_evaluate(session, call, tenant_id)
    record_runtime(session, call, "submit", runtime_result)
    flow_effect, flow_findings = check_tool(session, tenant_id, call, runtime_token, "submit")
    # Bound callers receive a second, cross-call decision before any side effect.
    # Legacy unbound clients remain outside this protection until binding is required.
    chain = (evaluate_action_chain(session, tenant_id, call)
             if runtime_token and valid_session_token(
                 session, tenant_id, agent_id, request.session_id, runtime_token) else None)
    if chain is not None:
        record_action_chain(session, agent_id, request.session_id, call_id,
                            "submit", chain, call_id)
    audit(session, call_id, "policy_decision", {
        "tool": call.tool, "arguments": arguments, "decision": decision.effect,
        "rule": decision.rule_id, "grant_id": grant_id, "policy_revision": decision.revision,
    })
    if runtime_result.effect == "deny" or flow_effect == "deny" or (
            chain is not None and chain.effect == "deny"):
        call.status = "denied"
        call.decision = "deny"
        call.reason = ("Denied by action chain: " + ",".join(chain.findings)
                       if chain is not None and chain.effect == "deny" else
                       "Denied by data flow rule: " + ",".join(flow_findings)
                       if flow_effect == "deny" else
                       "Denied by runtime rule: " + ",".join(runtime_result.findings))
        session.commit()
        return 200, call_view(call)
    if grant.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Grant expired during security checks"
        audit(session, call_id, "capability_denied", {"reason": "expired_before_decision", "tool": call.tool})
        session.commit()
        return 200, call_view(call)
    final_effect = ("require_approval" if decision.effect == "require_approval"
                    or runtime_result.effect == "require_approval"
                    or flow_effect == "require_approval" else "allow")
    call.decision = final_effect
    if final_effect == "require_approval":
        call.status = "pending_approval"
        call.approval_expires_at = min(utcnow() + timedelta(minutes=10), grant.expires_at.replace(tzinfo=timezone.utc))
        approval = Approval(
            id=str(uuid.uuid4()), call_id=call_id, arguments_hash=canonical_hash(arguments),
            status="pending",
        )
        session.add(approval)
        session.commit()
        return 202, call_view(call, approval.id)

    call.status = "executing"
    try:
        session.commit()
    except Exception:
        session.rollback()
        return 503, {"detail": "Audit commit failed; tool was not executed"}
    return 200, _execute_recorded(session, call, tenant_id)


def decide_approval(session: Session, approval_id: str, decision: str, tenant_id: str = "default",
                    policy: PolicyEngine | None = None) -> tuple[int, dict]:
    # 路由可能已读取审批事实；等锁后必须刷新身份映射中的旧状态。
    approval = session.scalar(select(Approval).where(Approval.id == approval_id)
                              .with_for_update().execution_options(populate_existing=True))
    if not approval:
        return 404, {"detail": "Approval not found"}
    call = session.get(ToolCall, approval.call_id, with_for_update=True, populate_existing=True)
    if approval.status != "pending" or call.status != "pending_approval":
        return 409, {"detail": "Approval already resolved"}
    grant = session.get(CapabilityGrant, call.grant_id, with_for_update=True, populate_existing=True)
    expired = (
        call.approval_expires_at.replace(tzinfo=timezone.utc) <= utcnow()
        or not grant or grant.revoked
        or grant.expires_at.replace(tzinfo=timezone.utc) <= utcnow()
    )
    if approval.arguments_hash != canonical_hash(call.arguments):
        session.rollback()
        return 409, {"detail": "Approval arguments changed"}
    assess_goal_tool(session, call, "approval")
    approval.decided_at = utcnow()
    if decision == "reject" or expired:
        approval.status = "expired" if expired else "rejected"
        call.status = "denied"
        call.reason = "Approval expired or grant revoked" if expired else "Rejected by administrator"
        audit(session, call.call_id, "approval_decision", {
            "decision": approval.status, "tool": call.tool, "arguments": call.arguments,
        })
        session.commit()
        return 200, call_view(call, approval.id)

    if policy is not None and policy.decide(call.tool, call.arguments).effect == "deny":
        approval.status = "rejected"
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Policy changed before approval"
        audit(session, call.call_id, "approval_decision", {
            "decision": "rejected", "reason": "policy_changed", "tool": call.tool,
        })
        session.commit()
        return 200, call_view(call, approval.id)

    if call.tool == "github_mcp_create_test_issue" and (
            call.arguments.get("repository") != get_settings().github_mcp_test_repo or
            grant.resources != [call.arguments.get("repository")] or
            not get_settings().agentsentry_github_mcp_write_enabled):
        approval.status = "rejected"
        call.status = "denied"
        call.decision = "deny"
        call.reason = "GitHub test repository or write configuration changed"
        audit(session, call.call_id, "approval_decision", {
            "decision": "rejected", "reason": "write_target_changed", "tool": call.tool})
        session.commit()
        return 200, call_view(call, approval.id)

    if call.tool in BOUND_SINKS and session.scalar(select(DataFlowDecision).where(
            DataFlowDecision.call_id == call.call_id,
            DataFlowDecision.sink == "tool:submit")) is None:
        approval.status = "rejected"
        approval.decided_at = utcnow()
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Missing data flow check; submit a new call"
        audit(session, call.call_id, "approval_decision", {
            "decision": "rejected", "reason": "missing_data_flow_check", "tool": call.tool})
        session.commit()
        return 200, call_view(call, approval.id)

    original_guard = session.scalar(select(RuntimeDecision).where(
        RuntimeDecision.call_id == call.call_id, RuntimeDecision.phase == "submit"))
    original_chain = session.scalar(select(ActionChainDecision).where(
        ActionChainDecision.reference_id == call.call_id,
        ActionChainDecision.phase == "submit"))
    current_guard = runtime_evaluate(session, call, tenant_id)
    record_runtime(session, call, "approval", current_guard)
    reported = session.get(RuntimeSession, (call.agent_id, call.session_id))
    binding = session_token(tenant_id, call.agent_id, reported) if reported else ""
    flow_effect, flow_findings = check_tool(session, tenant_id, call, binding, "approval")
    chain = evaluate_action_chain(session, tenant_id, call) if original_chain else None
    if chain is not None:
        record_action_chain(session, call.agent_id, call.session_id, call.call_id,
                            "approval", chain, call.call_id)
    step_up_rules = {"instruction_source_before_write", "repeated_denials_before_write"}
    previous_rules = set(original_guard.findings) if original_guard else set()
    new_step_up = bool(step_up_rules.intersection(current_guard.findings) - previous_rules)
    if current_guard.effect == "deny" or flow_effect == "deny" or new_step_up or (
            chain is not None and chain.effect == "deny"):
        approval.status = "rejected"
        call.status = "denied"
        call.decision = "deny"
        call.reason = ("Denied by action chain: " + ",".join(chain.findings)
                       if chain is not None and chain.effect == "deny" else
                       "Runtime context changed; submit a new call" if new_step_up else
                       "Denied by data flow rule: " + ",".join(flow_findings) if flow_effect == "deny" else
                       "Denied by runtime rule: " + ",".join(current_guard.findings))
        audit(session, call.call_id, "approval_decision", {
            "decision": "rejected", "reason": "runtime_guard", "tool": call.tool,
        })
        session.commit()
        return 200, call_view(call, approval.id)

    # 锁能阻止并发吊销，不能冻结时间；慢检查或等锁后重新核对有效期。
    if min(call.approval_expires_at.replace(tzinfo=timezone.utc),
           grant.expires_at.replace(tzinfo=timezone.utc)) <= utcnow():
        approval.status = "expired"
        call.status = "denied"
        call.decision = "deny"
        call.reason = "Approval or grant expired during security checks"
        audit(session, call.call_id, "approval_decision", {
            "decision": "expired", "reason": "expired_during_review", "tool": call.tool})
        session.commit()
        return 200, call_view(call, approval.id)
    approval.status = "approved"
    call.status = "executing"
    audit(session, call.call_id, "approval_decision", {
        "decision": "approved", "tool": call.tool, "arguments": call.arguments,
    })
    try:
        session.commit()
    except Exception:
        session.rollback()
        return 503, {"detail": "Audit commit failed; tool was not executed"}
    view = _execute_recorded(session, call, tenant_id)
    view["approval_id"] = approval.id
    return 200, view


def recover_unknown_calls(session: Session) -> int:
    cutoff = utcnow() - timedelta(minutes=2)
    calls = session.scalars(select(ToolCall).where(
        ToolCall.status == "executing", ToolCall.updated_at < cutoff).with_for_update(skip_locked=True)).all()
    count = 0
    for call in calls:
        if call.updated_at.replace(tzinfo=timezone.utc) < cutoff:
            call.status = "unknown"
            call.reason = "Process interrupted before a recorded result"
            audit(session, call.call_id, "tool_unknown", {"tool": call.tool, "status": "unknown"})
            count += 1
    session.commit()
    return count
