"""故障隔离：租户内依赖熔断、并发租约、队列代次及安全恢复。"""

import hashlib
import re
import uuid
from datetime import timedelta, timezone

from sqlalchemy import func, select, text

from .models import (AuditEvent, DependencyAttempt, DependencyState, FaultLabRun,
                     Outbox, QueueLease, ToolCall, WebhookDelivery, utcnow)

RULES_VERSION = "resilience-rules-v1"
FAILURE_THRESHOLD = 3
COOLDOWN_SECONDS = 30
DEPENDENCY_CONCURRENCY = 2
LEASE_SECONDS = 120
DISPATCH_BATCH = 20
MAX_ATTEMPTS = 3


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def serialize(session, key):
    if session.get_bind().dialect.name == "postgresql":
        tenant = session.info.get("tenant_id", "default")
        lock = int.from_bytes(hashlib.sha256(f"resilience:{tenant}:{key}".encode()).digest()[:8],
                              "big", signed=True)
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})


def fault_event(session, dependency, action, reason, reference_id=None):
    session.add(AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="dependency_fault",
                           payload={"dependency": dependency, "action": action, "status": action,
                                    "findings": (["dependency_circuit_open"] if action == "open" else
                                                 ["queue_attempts_exhausted"] if action == "attempts_exhausted" else []),
                                    "reason": reason, "reference_id": reference_id,
                                    "rules_version": RULES_VERSION}))


def take_gate(session, dependency, call_id=None, now=None):
    """返回租约或拒绝原因。调用者必须提交后才可发出网络请求。"""
    now = now or utcnow()
    serialize(session, "dependency:" + dependency)
    state = session.get(DependencyState, dependency, with_for_update=True, populate_existing=True)
    if state is None:
        state = DependencyState(dependency=dependency, failures=0)
        session.add(state)
        session.flush()
    active = session.scalars(select(DependencyAttempt).where(
        DependencyAttempt.dependency == dependency, DependencyAttempt.status == "executing"
    )).all()
    for attempt in active:
        if aware(attempt.expires_at) <= now:
            attempt.status = "abandoned"
            attempt.outcome = "lease_expired"
            state.failures += 1
            state.last_error = "lease_expired"
            if state.probe_id == attempt.id:
                state.probe_id = None
            fault_event(session, dependency, "abandoned", "lease_expired", attempt.call_id)
    active = [item for item in active if item.status == "executing"]
    if state.failures >= FAILURE_THRESHOLD and state.open_until is None:
        state.open_until = now + timedelta(seconds=COOLDOWN_SECONDS)
        fault_event(session, dependency, "open", state.last_error or "consecutive_failures")
    if state.open_until is not None:
        if aware(state.open_until) > now or state.probe_id is not None:
            return None, "dependency_circuit_open"
        # 冷却后只放行一次真实调用作为半开探测；不跳过现有安全检查。
    if len(active) >= DEPENDENCY_CONCURRENCY:
        return None, "dependency_busy"
    attempt = DependencyAttempt(id=str(uuid.uuid4()), dependency=dependency, call_id=call_id,
                                expires_at=now + timedelta(seconds=LEASE_SECONDS))
    session.add(attempt)
    if state.open_until is not None:
        state.probe_id = attempt.id
        fault_event(session, dependency, "half_open", "cooldown_elapsed", call_id)
    state.updated_at = now
    session.flush()
    return attempt.id, None


def finish_gate(session, attempt_id, success, reason="upstream_error", now=None):
    now = now or utcnow()
    attempt = session.get(DependencyAttempt, attempt_id)
    if not attempt:
        return
    serialize(session, "dependency:" + attempt.dependency)
    session.refresh(attempt)
    state = session.get(DependencyState, attempt.dependency, with_for_update=True,
                        populate_existing=True)
    if attempt.status != "executing":
        return  # 过期租约的迟到成功不能解除熔断。
    if aware(attempt.expires_at) <= now:
        success = False
        reason = "lease_expired"
    attempt.status = "completed" if success else "failed"
    attempt.outcome = "success" if success else reason
    probe = state.probe_id == attempt.id
    if success:
        if state.open_until is None or probe:
            if state.open_until is not None:
                fault_event(session, attempt.dependency, "closed", "probe_succeeded", attempt.call_id)
            state.failures = 0
            state.open_until = None
            state.last_error = None
    else:
        state.failures += 1
        state.last_error = reason
        fault_event(session, attempt.dependency, "failure", reason, attempt.call_id)
        if probe or state.failures >= FAILURE_THRESHOLD:
            state.open_until = now + timedelta(seconds=COOLDOWN_SECONDS)
            fault_event(session, attempt.dependency, "open", reason, attempt.call_id)
    if probe:
        state.probe_id = None
    state.updated_at = now


def tool_dependency(tool):
    if tool.startswith("remote_mcp_"):
        return "mcp:remote-demo"
    if tool.startswith("github_mcp_"):
        return "mcp:github"
    if tool in {"mcp_lookup_card", "mcp_record_note"}:
        return "mcp:local-demo"
    if tool == "run_shell":
        return "sandbox"
    return None


def queue_model(kind):
    return {"judge": Outbox, "webhook": WebhookDelivery}[kind]


def queue_ready(session, kind, row, now):
    lease = session.get(QueueLease, (kind, row.id))
    if lease:
        if aware(lease.due_at) > now:
            return False
        if row.status in {"queued", "processing"} and aware(lease.expires_at) > now:
            return False
    elif row.status in {"queued", "processing"} and aware(row.updated_at) > now - timedelta(seconds=LEASE_SECONDS):
        return False
    return row.status in {"pending", "queued", "processing"}


def new_queue_lease(session, kind, row, now):
    lease = session.get(QueueLease, (kind, row.id))
    if lease is None:
        lease = QueueLease(kind=kind, record_id=row.id, publish_failures=0)
        session.add(lease)
    lease.token = str(uuid.uuid4())
    lease.due_at = now
    lease.expires_at = now + timedelta(seconds=LEASE_SECONDS)
    row.updated_at = now
    return lease


def claim_job(session, kind, record_id, now=None):
    now = now or utcnow()
    serialize(session, f"queue:{kind}:{record_id}")
    row = session.get(queue_model(kind), record_id, with_for_update=True, populate_existing=True)
    if not row or row.status in {"completed", "delivered", "failed"}:
        return None, None
    lease = session.get(QueueLease, (kind, record_id), populate_existing=True)
    if lease and (aware(lease.due_at) > now or
                  row.status == "processing" and aware(lease.expires_at) > now):
        return None, None
    if not lease and row.status == "processing" and aware(row.updated_at) > now - timedelta(seconds=LEASE_SECONDS):
        return None, None
    if row.attempts >= MAX_ATTEMPTS:
        row.status = "failed"
        row.error = "processing_lease_exhausted"
        row.updated_at = now
        fault_event(session, "queue:" + kind, "attempts_exhausted", row.error, record_id)
        return None, None
    lease = new_queue_lease(session, kind, row, now)
    row.status = "processing"
    row.attempts += 1
    session.flush()
    return row, lease.token


def owned_job(session, kind, record_id, token):
    serialize(session, f"queue:{kind}:{record_id}")
    row = session.get(queue_model(kind), record_id, with_for_update=True, populate_existing=True)
    lease = session.get(QueueLease, (kind, record_id), populate_existing=True)
    return row if (row and row.status == "processing" and lease and lease.token == token
                   and aware(lease.expires_at) > utcnow()) else None


def postpone_job(session, kind, row, reason, seconds=None, attempted=True, now=None):
    now = now or utcnow()
    lease = session.get(QueueLease, (kind, row.id))
    if not attempted:
        row.attempts = max(0, row.attempts - 1)
    row.status = "failed" if attempted and row.attempts >= MAX_ATTEMPTS else "pending"
    row.error = reason
    row.updated_at = now
    lease.due_at = now + timedelta(seconds=seconds if seconds is not None else min(2 ** row.attempts, 60))
    lease.expires_at = now


def retry_failed(session, kind, record_id):
    serialize(session, f"queue:{kind}:{record_id}")
    row = session.get(queue_model(kind), record_id, with_for_update=True, populate_existing=True)
    if not row:
        return "not_found"
    if row.status != "failed":
        return "not_failed"
    # 只重试异步信号投递，既不重放工具，也不重新分配 Judge 提供方。
    row.attempts = 0
    row.error = None
    row.status = "pending"
    lease = new_queue_lease(session, kind, row, utcnow())
    lease.expires_at = utcnow()
    fault_event(session, "queue:" + kind, "manual_retry", "administrator_request", record_id)
    return "ok"


def health_view(session):
    now = utcnow()
    queues = []
    for kind in ("judge", "webhook"):
        model = queue_model(kind)
        counts = dict(session.execute(select(model.status, func.count()).group_by(model.status)).all())
        oldest = session.scalar(select(func.min(model.updated_at)).where(
            model.status.in_(["pending", "queued", "processing"])))
        failed = session.scalars(select(model).where(model.status == "failed")
                                  .order_by(model.updated_at.desc()).limit(20)).all()
        queues.append({"kind": kind, "counts": counts,
                       "oldest_wait_seconds": max(0, int((now - aware(oldest)).total_seconds())) if oldest else 0,
                       "failed": [{"id": row.id, "attempts": row.attempts,
                                   "error": row.error if row.error and re.fullmatch(
                                       r"[A-Za-z_][A-Za-z0-9_]{0,99}", row.error) else "旧错误原文已遮盖"}
                                  for row in failed]})
    states = session.scalars(select(DependencyState).order_by(DependencyState.dependency)).all()
    dependencies = [{"dependency": state.dependency, "failures": state.failures,
                     "state": ("半开探测中" if state.probe_id else
                               "熔断中" if state.open_until and aware(state.open_until) > now else
                               "等待半开探测" if state.open_until else "正常"),
                     "open_until": state.open_until, "last_error": state.last_error} for state in states]
    return {"rules_version": RULES_VERSION, "dependencies": dependencies, "queues": queues,
            "events": session.scalars(select(AuditEvent).where(AuditEvent.event_type == "dependency_fault")
                                      .order_by(AuditEvent.created_at.desc()).limit(50)).all(),
            "unknown_calls": session.scalars(select(ToolCall).where(ToolCall.status == "unknown")
                                              .order_by(ToolCall.updated_at.desc()).limit(30)).all(),
            "lab_runs": session.scalars(select(FaultLabRun).order_by(FaultLabRun.created_at.desc()).limit(10)).all()}
