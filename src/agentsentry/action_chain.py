"""会话行动链的确定性预算；自然语言目标线索不参与强制授权。"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .judge.runtime import assign_route
from .models import (ActionChainDecision, ActionChainState, AuditEvent, Outbox,
                     RuntimeControl, RuntimeControlChange, ToolCall, utcnow)
from .runtime_guard import SIDE_EFFECT_TOOLS
from .schemas import resource_for


RULES_VERSION = "action-chain-v1"
TOOL_LIMIT = 20
TASK_MODEL_LIMIT = 8
SUMMARY_MODEL_LIMIT = 3
SESSION_WRITE_LIMIT = 3
AGENT_HOURLY_WRITE_LIMIT = 10
DENIED_RESOURCE_LIMIT = 4
DENIAL_WINDOW = timedelta(minutes=10)
AGENT_WINDOW = timedelta(hours=1)
RESERVED_STATUSES = {"checking", "pending_approval", "executing", "completed", "unknown"}


@dataclass(frozen=True)
class ChainResult:
    effect: str
    findings: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    counters: dict


def enroll(db: Session, agent_id: str, session_id: str) -> None:
    if db.get(ActionChainState, (agent_id, session_id)) is None:
        db.add(ActionChainState(agent_id=agent_id, session_id=session_id,
                                rules_version=RULES_VERSION))


def enrolled(db: Session, agent_id: str, session_id: str) -> bool:
    return db.get(ActionChainState, (agent_id, session_id)) is not None


def _lock(db: Session, tenant_id: str, agent_id: str) -> None:
    # Serialise every budget decision for this tenant and Agent, including separate sessions.
    if db.get_bind().dialect.name == "postgresql":
        raw = hashlib.sha256(f"chain\0{tenant_id}\0{agent_id}".encode()).digest()[:8]
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                   {"key": int.from_bytes(raw, "big", signed=True)})


def _control(db: Session, agent_id: str, session_id: str) -> RuntimeControl | None:
    return db.get(RuntimeControl, f"session:{agent_id}:{session_id}")


def _paused(db: Session, agent_id: str, session_id: str) -> bool:
    return any((row and row.paused) for row in (
        db.get(RuntimeControl, f"agent:{agent_id}"), _control(db, agent_id, session_id)))


def _count(db: Session, *conditions) -> int:
    return db.scalar(select(func.count()).select_from(ToolCall).where(*conditions)) or 0


def _write_conditions(agent_id: str):
    return (ToolCall.agent_id == agent_id, ToolCall.tool.in_(SIDE_EFFECT_TOOLS),
            ToolCall.status.in_(RESERVED_STATUSES))


def _pause_for_probe(db: Session, agent_id: str, session_id: str) -> None:
    key = f"session:{agent_id}:{session_id}"
    control = db.get(RuntimeControl, key, with_for_update=True)
    if control and control.paused:
        return
    if control is None:
        control = RuntimeControl(key=key, agent_id=agent_id, session_id=session_id)
        db.add(control)
    control.paused = True
    control.reason = "连续探测多个无权资源；待管理员复核"
    control.updated_at = utcnow()
    db.add(RuntimeControlChange(id=str(uuid.uuid4()), control_key=key,
        agent_id=agent_id, session_id=session_id, paused=True,
        reason=control.reason, actor="action_chain"))
    event = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="runtime_control",
        payload={"agent_id": agent_id, "session_id": session_id,
                 "paused": True, "control_key": key, "actor": "action_chain"})
    db.add(event)
    outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
    db.add(outbox)
    assign_route(db, outbox)


def evaluate_tool(db: Session, tenant_id: str, call: ToolCall) -> ChainResult | None:
    if not enrolled(db, call.agent_id, call.session_id):
        return None
    _lock(db, tenant_id, call.agent_id)
    now = utcnow()
    total = _count(db, ToolCall.agent_id == call.agent_id,
                   ToolCall.session_id == call.session_id)
    from .delegation import reserved_budget
    total += reserved_budget(db, call.agent_id, call.session_id)
    session_writes = _count(db, *_write_conditions(call.agent_id),
                            ToolCall.session_id == call.session_id)
    agent_writes = _count(db, *_write_conditions(call.agent_id),
                          ToolCall.created_at >= now - AGENT_WINDOW)
    findings: list[str] = []
    evidence: list[str] = []
    if _paused(db, call.agent_id, call.session_id):
        findings.append("action_chain_paused")
    if total > TOOL_LIMIT:
        findings.append("tool_budget_exceeded")
    if call.tool in SIDE_EFFECT_TOOLS:
        if session_writes > SESSION_WRITE_LIMIT:
            findings.append("session_write_budget_exceeded")
        if agent_writes > AGENT_HOURLY_WRITE_LIMIT:
            findings.append("agent_write_budget_exceeded")
    control = _control(db, call.agent_id, call.session_id)
    since = now - DENIAL_WINDOW
    if control and not control.paused and control.updated_at:
        resumed = control.updated_at if control.updated_at.tzinfo else control.updated_at.replace(tzinfo=timezone.utc)
        since = max(since, resumed)
    denied = db.scalars(select(ToolCall).where(
        ToolCall.agent_id == call.agent_id, ToolCall.session_id == call.session_id,
        ToolCall.status == "denied", ToolCall.created_at >= since,
        ToolCall.call_id != call.call_id,
    ).order_by(ToolCall.created_at.desc()).limit(20)).all()
    resources: dict[str, str] = {}
    for previous in denied:
        try:
            resource = resource_for(previous.tool, previous.arguments)
        except (KeyError, TypeError, ValueError):
            continue
        resources.setdefault(resource, previous.call_id)
    if call.status == "denied":
        try:
            resources.setdefault(resource_for(call.tool, call.arguments), call.call_id)
        except (KeyError, TypeError, ValueError):
            pass
    if len(resources) >= DENIED_RESOURCE_LIMIT:
        findings.append("denied_resource_probe")
        evidence.extend(list(resources.values())[:DENIED_RESOURCE_LIMIT])
        _pause_for_probe(db, call.agent_id, call.session_id)
    return ChainResult("deny" if findings else "allow", tuple(findings), tuple(evidence),
        {"tool_proposals": total, "session_writes_reserved": session_writes,
         "agent_hourly_writes_reserved": agent_writes,
         "denied_resources": len(resources)})


def evaluate_model(db: Session, tenant_id: str, agent_id: str, session_id: str,
                   purpose: str) -> ChainResult:
    if not enrolled(db, agent_id, session_id):
        raise ValueError("会话未加入行动链保护")
    _lock(db, tenant_id, agent_id)
    phase = "model:" + purpose
    count = (db.scalar(select(func.count()).select_from(ActionChainDecision).where(
        ActionChainDecision.agent_id == agent_id,
        ActionChainDecision.session_id == session_id,
        ActionChainDecision.phase == phase)) or 0) + 1
    limit = TASK_MODEL_LIMIT if purpose == "task" else SUMMARY_MODEL_LIMIT
    findings = []
    if _paused(db, agent_id, session_id):
        findings.append("action_chain_paused")
    if count > limit:
        findings.append("model_budget_exceeded")
    return ChainResult("deny" if findings else "allow", tuple(findings), (),
        {"model_requests": count, "model_limit": limit})


def record(db: Session, agent_id: str, session_id: str, reference_id: str,
           phase: str, result: ChainResult, call_id: str | None = None) -> ActionChainDecision:
    row = ActionChainDecision(id=str(uuid.uuid4()), agent_id=agent_id,
        session_id=session_id, reference_id=reference_id, phase=phase,
        effect=result.effect, findings=list(result.findings),
        evidence_ids=list(result.evidence_ids), counters=result.counters,
        rules_version=RULES_VERSION)
    db.add(row)
    event = AuditEvent(id=str(uuid.uuid4()), call_id=call_id,
        event_type="action_chain_decision", payload={
            "decision_id": row.id, "reference_id": reference_id,
            "agent_id": agent_id, "session_id": session_id,
            "phase": phase, "effect": result.effect,
            "findings": list(result.findings), "evidence_ids": list(result.evidence_ids),
            "counters": result.counters, "rules_version": RULES_VERSION,
        })
    db.add(event)
    outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
    db.add(outbox)
    assign_route(db, outbox)
    return row


def session_view(db: Session, agent_id: str, session_id: str) -> dict:
    state = db.get(ActionChainState, (agent_id, session_id))
    if not state:
        return {"enrolled": False, "rules_version": None, "decisions": [], "limits": {}}
    rows = db.scalars(select(ActionChainDecision).where(
        ActionChainDecision.agent_id == agent_id,
        ActionChainDecision.session_id == session_id,
    ).order_by(ActionChainDecision.created_at, ActionChainDecision.id).limit(100)).all()
    return {"enrolled": True, "rules_version": state.rules_version,
        "limits": {"tools": TOOL_LIMIT, "task_models": TASK_MODEL_LIMIT,
                   "session_writes": SESSION_WRITE_LIMIT,
                   "agent_hourly_writes": AGENT_HOURLY_WRITE_LIMIT},
        "decisions": [{"reference_id": row.reference_id, "phase": row.phase,
                       "effect": row.effect, "findings": row.findings,
                       "evidence_ids": row.evidence_ids, "counters": row.counters,
                       "at": row.created_at.isoformat()} for row in rows]}
