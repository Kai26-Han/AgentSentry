"""按租户和会话关联已有网关证据，不修改安全判定。"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, Approval, AuditEvent, GoalAssessment, JudgeResult, MemoryEntry, MemoryFailure, MemoryRead, MemoryWrite, Outbox, RuntimeAdapterAttempt, RuntimeControl, RuntimeControlChange, RuntimeDecision, RuntimeIncident, RuntimeSession, ToolCall, utcnow
from .runtime_redaction import redact_preview
from .runtime_binding import task_fingerprint
from .goal_analysis import RULES_VERSION as GOAL_RULES_VERSION, assessment_view, profile_for
from .action_chain import enroll as enroll_action_chain, session_view as action_chain_view
from .output_safety import output_view
from .schemas import RuntimeSessionFinish, RuntimeSessionReview, RuntimeSessionStart


SENSITIVE_TOOLS = {"create_task", "delete_task", "send_external", "run_shell", "mcp_record_note", "remote_mcp_record_note", "github_mcp_create_test_issue"}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _text(value: datetime | None) -> str | None:
    return _aware(value).isoformat() if value else None


def _preview(value: str, mode: str) -> tuple[str | None, bool]:
    return (None, False) if mode == "metadata" else redact_preview(value)


def start_session(db: Session, agent_id: str, session_id: str, body: RuntimeSessionStart) -> RuntimeSession:
    preview, truncated = _preview(body.user_task, body.capture_mode)
    fingerprint = task_fingerprint(body.user_task) if body.user_task else None
    truncated = truncated or (body.user_task_truncated and body.capture_mode == "preview")
    model_name = redact_preview(body.model_name)[0][:120]
    row = db.get(RuntimeSession, (agent_id, session_id))
    if row and row.reported:
        if (row.transport, row.model_name or "", row.capture_mode, row.task_preview,
                row.task_truncated, row.task_fingerprint) != (
            body.transport, model_name, body.capture_mode, preview, truncated, fingerprint
        ):
            raise ValueError("session_id already used with different start data")
        return row
    if row is None:
        row = RuntimeSession(agent_id=agent_id, session_id=session_id)
        db.add(row)
    row.reported = True
    row.transport = body.transport
    row.model_name = model_name or None
    row.capture_mode = body.capture_mode
    row.task_preview = preview
    row.task_fingerprint = fingerprint
    row.goal_profile = profile_for(body.user_task) if body.user_task else {"kind": "unknown", "actions": [], "resources": []}
    row.goal_profile_version = GOAL_RULES_VERSION
    enroll_action_chain(db, agent_id, session_id)
    row.task_truncated = truncated
    row.status = "running"
    db.commit()
    return row


def finish_session(db: Session, agent_id: str, session_id: str, body: RuntimeSessionFinish) -> RuntimeSession:
    row = db.get(RuntimeSession, (agent_id, session_id))
    if row is None:
        row = RuntimeSession(agent_id=agent_id, session_id=session_id, reported=True,
                             capture_mode="metadata", task_preview=None)
        db.add(row)
    preview, truncated = _preview(body.final_answer, row.capture_mode)
    truncated = truncated or (body.final_answer_truncated and row.capture_mode == "preview")
    safe_attempts = [{"tool": redact_preview(item["tool"])[0][:100],
                      "error_code": item["error_code"]} for item in body.adapter_attempts]
    saved_attempts = db.scalars(select(RuntimeAdapterAttempt).where(
        RuntimeAdapterAttempt.agent_id == agent_id,
        RuntimeAdapterAttempt.session_id == session_id).order_by(RuntimeAdapterAttempt.sequence)).all()
    saved_view = [{"tool": item.tool, "error_code": item.error_code} for item in saved_attempts]
    if row.status in {"completed", "failed"}:
        if (row.status, row.answer_preview, row.answer_truncated, row.error_code or "", saved_view) != (
            body.status, preview, truncated, body.error_code, safe_attempts
        ):
            raise ValueError("session_id already finished with different data")
        return row
    row.reported = True
    row.answer_preview = preview
    row.answer_truncated = truncated
    row.status = body.status
    row.error_code = body.error_code or None
    for index, item in enumerate(safe_attempts):
        db.add(RuntimeAdapterAttempt(agent_id=agent_id, session_id=session_id,
                                     sequence=index, tool=item["tool"], error_code=item["error_code"]))
    row.finished_at = utcnow()
    db.commit()
    return row


def visible_status(row: RuntimeSession | None) -> str:
    if row is None or not row.reported:
        return "unreported"
    if row.status == "running" and _aware(row.started_at) < utcnow() - timedelta(minutes=20):
        return "interrupted"
    return row.status


def _context_states(row: RuntimeSession | None) -> tuple[str, str]:
    if row is None or not row.reported:
        return "unreported", "unreported"
    if row.capture_mode == "metadata":
        return "metadata_only", "metadata_only"
    task_state = "available" if row.task_preview else "empty_task"
    if row.answer_preview:
        answer_state = "available"
    elif row.status == "running":
        answer_state = "pending"
    elif row.status == "failed":
        answer_state = "failed_without_answer"
    else:
        answer_state = "no_text_answer"
    return task_state, answer_state


def session_view(db: Session, agent_id: str, session_id: str) -> dict | None:
    row = db.get(RuntimeSession, (agent_id, session_id))
    calls = db.scalars(select(ToolCall).where(ToolCall.agent_id == agent_id,
                                             ToolCall.session_id == session_id)
                       .order_by(ToolCall.created_at, ToolCall.call_id)).all()
    if row is None and not calls:
        return None
    goal_assessments = db.scalars(select(GoalAssessment).where(
        GoalAssessment.agent_id == agent_id, GoalAssessment.session_id == session_id)
        .order_by(GoalAssessment.created_at, GoalAssessment.id)).all()
    goal_source_ids = list(dict.fromkeys(identifier for assessment in goal_assessments
                                         for identifier in assessment.evidence_ids))[:40]
    goal_source_kinds = {identifier: ("call" if db.get(ToolCall, identifier) else
                         "memory" if db.get(MemoryEntry, identifier) else "missing")
                         for identifier in goal_source_ids}
    call_ids = [call.call_id for call in calls]
    approvals = db.scalars(select(Approval).where(Approval.call_id.in_(call_ids))).all() if call_ids else []
    approval_by_call = {item.call_id: item for item in approvals}
    events = db.scalars(select(AuditEvent).where(AuditEvent.call_id.in_(call_ids))
                        .order_by(AuditEvent.created_at)).all() if call_ids else []
    outboxes = db.scalars(select(Outbox).where(Outbox.audit_event_id.in_([event.id for event in events]))).all() if events else []
    outbox_by_event = {item.audit_event_id: item for item in outboxes}
    judges = db.scalars(select(JudgeResult).where(JudgeResult.outbox_id.in_([item.id for item in outboxes]))).all() if outboxes else []
    judge_by_outbox = {item.outbox_id: item for item in judges}
    alerts = db.scalars(select(Alert).where(Alert.call_id.in_(call_ids))).all() if call_ids else []
    runtime_decisions = db.scalars(select(RuntimeDecision).where(
        RuntimeDecision.call_id.in_(call_ids)).order_by(RuntimeDecision.created_at)).all() if call_ids else []
    decisions_by_call: dict[str, list] = {}
    for decision in runtime_decisions:
        decisions_by_call.setdefault(decision.call_id, []).append({
            "phase": decision.phase, "effect": decision.effect,
            "rules_version": decision.rules_version, "findings": decision.findings,
            "evidence": decision.evidence,
        })
    runtime_incidents = db.scalars(select(RuntimeIncident).where(
        RuntimeIncident.call_id.in_(call_ids))).all() if call_ids else []
    alerts_by_call: dict[str, list] = {}
    for alert in alerts:
        alerts_by_call.setdefault(alert.call_id, []).append({
            "severity": alert.severity, "title": alert.title, "status": alert.status,
        })
    for incident in runtime_incidents:
        alerts_by_call.setdefault(incident.call_id, []).append({
            "severity": incident.severity, "title": incident.title,
            "status": incident.status,
        })
    events_by_call: dict[str, list] = {}
    for event in events:
        outbox = outbox_by_event.get(event.id)
        verdict = judge_by_outbox.get(outbox.id) if outbox else None
        events_by_call.setdefault(event.call_id, []).append({
            "type": event.event_type, "at": _text(event.created_at),
            "judge_status": verdict.status if verdict else (
                "missing" if outbox and outbox.status == "completed" else outbox.status if outbox else "missing"),
            "judge_provider": verdict.provider if verdict else None,
            "judge_labels": verdict.labels if verdict else [],
            "judge_score": verdict.score if verdict else None,
        })
    signals: list[dict] = []
    timeline = []
    untrusted_read = False
    for call in calls:
        approval = approval_by_call.get(call.call_id)
        call_events = events_by_call.get(call.call_id, [])
        if not call_events or any(event["judge_status"] == "missing" for event in call_events):
            signals.append({"kind": "audit_gap", "label": "审计或 Judge 记录缺失，需核查", "call_id": call.call_id})
        if call.status == "denied":
            signals.append({"kind": "denied", "label": "权限或策略拒绝", "call_id": call.call_id})
        if call.status in {"unknown", "failed"}:
            signals.append({"kind": "execution_uncertain", "label": "工具执行失败或结果未知", "call_id": call.call_id})
        if approval and approval.status in {"pending", "rejected", "expired"}:
            signals.append({"kind": "approval", "label": "审批待处理或未通过", "call_id": call.call_id})
        for decision in decisions_by_call.get(call.call_id, []):
            if decision["effect"] in {"deny", "require_approval"} and decision["findings"]:
                signals.append({"kind": "runtime_guard", "label": "运行时安全规则已处置：" +
                                "、".join(decision["findings"]), "call_id": call.call_id})
        if untrusted_read and call.tool in SENSITIVE_TOOLS:
            signals.append({"kind": "read_then_sensitive", "label": "读取不可信内容后请求敏感工具，需复核", "call_id": call.call_id})
        if call.status == "completed" and call.tool in {"read_document", "mcp_lookup_card", "remote_mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"}:
            untrusted_read = True
        for event in call_events:
            if event["judge_status"] == "completed" and any(label != "none" for label in event["judge_labels"]):
                signals.append({"kind": "judge", "label": "Judge 风险信号", "call_id": call.call_id})
        timeline.append({
            "call_id": call.call_id, "at": _text(call.created_at), "tool": call.tool,
            "decision": call.decision, "status": call.status, "policy_rule": call.policy_rule,
            "approval_status": approval.status if approval else None,
            "runtime_decisions": decisions_by_call.get(call.call_id, []),
            "audit": call_events, "alerts": alerts_by_call.get(call.call_id, []),
        })
    unique_signals = list({(item["kind"], item["call_id"]): item for item in signals}.values())
    adapter_attempts = [{"tool": item.tool, "error_code": item.error_code} for item in db.scalars(
        select(RuntimeAdapterAttempt).where(RuntimeAdapterAttempt.agent_id == agent_id,
                                            RuntimeAdapterAttempt.session_id == session_id)
        .order_by(RuntimeAdapterAttempt.sequence)).all()] if row else []
    for attempt in adapter_attempts:
        unique_signals.append({"kind": "adapter_error", "label": "适配层工具请求失败：" + attempt["error_code"],
                               "call_id": None})
    first = min([_aware(call.created_at) for call in calls] + ([_aware(row.started_at)] if row else []))
    last = max([_aware(call.updated_at) for call in calls] +
               ([_aware(row.finished_at or row.started_at)] if row else []))
    task_state, answer_state = _context_states(row)
    output = output_view(db, agent_id, session_id)
    if output and output["outcome"] in {"block", "warn"}:
        unique_signals.append({"kind": "output_check", "label": (
            "最终输出已阻断" if output["outcome"] == "block" else "最终输出需复核"),
                               "call_id": None})
    memory_reads = db.scalars(select(MemoryRead).where(MemoryRead.agent_id == agent_id,
        MemoryRead.session_id == session_id).order_by(MemoryRead.created_at)).all()
    memory_writes = db.scalars(select(MemoryWrite).where(MemoryWrite.agent_id == agent_id,
        MemoryWrite.session_id == session_id).order_by(MemoryWrite.created_at)).all()
    memory_failures = db.scalars(select(MemoryFailure).where(MemoryFailure.agent_id == agent_id,
        MemoryFailure.session_id == session_id).order_by(MemoryFailure.created_at)).all()
    control_changes = db.scalars(select(RuntimeControlChange).where(
        RuntimeControlChange.agent_id == agent_id,
        (RuntimeControlChange.session_id == session_id) |
        RuntimeControlChange.session_id.is_(None),
    ).order_by(RuntimeControlChange.created_at.desc()).limit(10)).all()
    written_ids = [entry_id for write in memory_writes for entry_id in write.entry_ids]
    written = [db.get(MemoryEntry, entry_id) for entry_id in written_ids]
    if any(entry and entry.status == "quarantined" for entry in written):
        unique_signals.append({"kind": "memory_quarantine", "label": "本会话生成的记忆进入隔离",
                               "call_id": None})
    if memory_failures:
        unique_signals.append({"kind": "memory_failure", "label": "记忆读取、摘要或写入失败",
                               "call_id": None})
    from .models import Delegation
    from .delegation import view as delegation_view
    delegations = db.scalars(select(Delegation).where(
        ((Delegation.parent_agent_id == agent_id) & (Delegation.parent_session_id == session_id)) |
        ((Delegation.worker_agent_id == agent_id) & (Delegation.worker_session_id == session_id)))).all()
    return {
        "delegations": [delegation_view(item) for item in delegations],
        "agent_id": agent_id, "session_id": session_id, "status": visible_status(row),
        "action_chain": action_chain_view(db, agent_id, session_id),
        "goal_profile": row.goal_profile if row else None,
        "goal_profile_version": row.goal_profile_version if row else None,
        "goal_assessments": [assessment_view(item) for item in goal_assessments],
        "goal_source_kinds": goal_source_kinds,
        "transport": row.transport if row else None, "model_name": row.model_name if row else None,
        "capture_mode": row.capture_mode if row and row.reported else None,
        "task_preview": row.task_preview if row and row.reported else None,
        "answer_preview": row.answer_preview if row and row.reported else None,
        "task_state": task_state, "answer_state": answer_state,
        "task_truncated": bool(row.task_truncated) if row else False,
        "answer_truncated": bool(row.answer_truncated) if row else False,
        "error_code": row.error_code if row else None,
        "started_at": _text(first), "last_activity_at": _text(last),
        "finished_at": _text(row.finished_at) if row else None,
        "call_count": len(calls), "signals": unique_signals,
        "has_signal": bool(unique_signals), "timeline": timeline,
        "adapter_attempts": adapter_attempts,
        "output_check": output,
        "memory_reads": [{"id": item.id, "memory_ids": item.memory_ids} for item in memory_reads],
        "memory_writes": [{"id": item.id, "entries": [{"id": entry.id, "status": entry.status}
            for entry in written if entry and entry.write_id == item.id]} for item in memory_writes],
        "memory_failures": [{"stage": item.stage, "error_code": item.error_code,
            "at": _text(item.created_at)} for item in memory_failures],
        "review_status": row.review_status if row else "unreviewed",
        "review_note": row.review_note if row else "",
        "session_paused": bool((control := db.get(RuntimeControl, f"session:{agent_id}:{session_id}"))
                               and control.paused),
        "agent_paused": bool((control := db.get(RuntimeControl, f"agent:{agent_id}"))
                             and control.paused),
        "control_changes": [{"paused": item.paused, "reason": item.reason,
            "scope": "会话" if item.session_id else "Agent",
            "actor": item.actor, "at": _text(item.created_at)} for item in control_changes],
        "research": session_id.startswith("lab-"),
    }


def list_sessions(db: Session, limit: int = 50, risk_only: bool = False,
                  include_research: bool = False, status_filter: str = "all",
                  days: int = 0) -> list[dict]:
    keys = {(row.agent_id, row.session_id) for row in db.scalars(select(RuntimeSession))}
    keys.update(db.execute(select(ToolCall.agent_id, ToolCall.session_id).group_by(
        ToolCall.agent_id, ToolCall.session_id)).all())
    views = [session_view(db, agent_id, session_id) for agent_id, session_id in keys]
    cutoff = utcnow() - timedelta(days=days) if days else None
    views = [item for item in views if item and (include_research or not item["research"])
             and (not risk_only or item["has_signal"])
             and (status_filter == "all" or item["status"] == status_filter)
             and (cutoff is None or datetime.fromisoformat(item["last_activity_at"]) >= cutoff)]
    views.sort(key=lambda item: item["last_activity_at"], reverse=True)
    return views[:limit]


def review_session(db: Session, body: RuntimeSessionReview) -> dict:
    view = session_view(db, body.agent_id, body.session_id)
    if view is None:
        raise ValueError("Session not found")
    row = db.get(RuntimeSession, (body.agent_id, body.session_id))
    if row is None:
        row = RuntimeSession(agent_id=body.agent_id, session_id=body.session_id, reported=False,
                             capture_mode="metadata", status="unreported",
                             started_at=datetime.fromisoformat(view["started_at"]))
        db.add(row)
    row.review_status = body.status
    row.review_note = redact_preview(body.note)[0]
    row.reviewed_at = utcnow()
    db.commit()
    return {"status": row.review_status, "note": row.review_note}
