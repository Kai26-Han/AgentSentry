import time
import logging
from datetime import timedelta, timezone

from sqlalchemy import select

from .database import db_session, tenant_db_session
from .models import Outbox, ThreatMappingState, WebhookDelivery, utcnow
from .judge.worker import judge_event, send_webhook
from .memory import expire_memories
from .data_flow import scrub_operational_payloads
from .mcp_supply import scrub_observations
from .tenants import list_tenant_ids
from .threat_mapping import project_once


def _dispatch(kind: str, tenant_id: str) -> int:
    from sqlalchemy import and_, or_
    from .models import QueueLease
    from .resilience import (DISPATCH_BATCH, LEASE_SECONDS, aware, fault_event,
                             new_queue_lease, queue_model)
    model = queue_model(kind)
    task = judge_event if kind == "judge" else send_webhook
    scope = db_session if tenant_id == "default" else lambda: tenant_db_session(tenant_id)
    now = utcnow()
    with scope() as session:
        rows = session.scalars(select(model).outerjoin(QueueLease, and_(
            QueueLease.kind == kind, QueueLease.record_id == model.id)).where(
            model.status.in_(["pending", "queued", "processing"]),
            or_(QueueLease.record_id.is_(None), QueueLease.due_at <= now),
            or_(model.status == "pending",
                and_(QueueLease.record_id.is_not(None), QueueLease.expires_at <= now),
                and_(QueueLease.record_id.is_(None),
                     model.updated_at < now - timedelta(seconds=LEASE_SECONDS)))
        ).order_by(model.updated_at, model.id).limit(DISPATCH_BATCH)
          .with_for_update(of=model, skip_locked=True)).all()
        ids = []
        for row in rows:
            lease = new_queue_lease(session, kind, row, now)
            row.status = "queued"
            if row.attempts >= 3:
                row.status = "failed"
                row.error = "processing_lease_exhausted"
                fault_event(session, "queue:" + kind, "attempts_exhausted", row.error, row.id)
                continue
            ids.append((row.id, lease.token))
        session.commit()
    count = 0
    for index, (record_id, token) in enumerate(ids):
        try:
            if tenant_id == "default":
                task.delay(record_id)
            else:
                task.delay(record_id, tenant_id)
            count += 1
        except Exception as exc:
            # Broker 故障后批内其余项统一退避，避免逐项连接放大故障。
            with scope() as session:
                for pending_id, pending_token in ids[index:]:
                    row = session.get(model, pending_id, with_for_update=True)
                    lease = session.get(QueueLease, (kind, pending_id))
                    if row and row.status == "queued" and lease.token == pending_token:
                        lease.publish_failures += 1
                        lease.due_at = utcnow() + timedelta(seconds=min(2 ** min(lease.publish_failures, 6), 60))
                        lease.expires_at = utcnow()
                        row.status = "pending"
                        row.error = type(exc).__name__[:100]
                        row.updated_at = utcnow()
                fault_event(session, "queue:" + kind, "publish_failed", type(exc).__name__[:100])
                session.commit()
            break
    return count


def dispatch_once(tenant_id: str = "default") -> int:
    return _dispatch("judge", tenant_id)


def dispatch_webhooks_once(tenant_id: str = "default") -> int:
    return _dispatch("webhook", tenant_id)


def dispatch_cycle(tenant_ids, cleanup_due=False):
    """每阶段、每租户独立失败；数据库/队列错误不跳过其他租户。"""
    from .service import recover_unknown_calls
    for tenant_id in tenant_ids:
        scope = db_session if tenant_id == "default" else lambda: tenant_db_session(tenant_id)
        phases = [lambda: dispatch_once(tenant_id), lambda: dispatch_webhooks_once(tenant_id)]
        def maintenance():
            with scope() as session:
                recover_unknown_calls(session)
                if cleanup_due:
                    expire_memories(session)
                    scrub_operational_payloads(session)
                    scrub_observations(session)
                    from .delegation import scrub as scrub_delegations
                    scrub_delegations(session)
        def mapping():
            try:
                with scope() as session:
                    project_once(session)
            except Exception as exc:
                with scope() as session:
                    state = session.get(ThreatMappingState, "active")
                    if state:
                        state.last_error = type(exc).__name__[:100]
                        session.commit()
                raise
        phases.extend([maintenance, mapping])
        for phase in phases:
            try:
                phase()
            except Exception:
                logging.error("异步阶段失败；继续其他阶段与租户：%s", tenant_id)


def main() -> None:
    next_memory_cleanup = 0.0
    while True:
        try:
            cleanup_due = time.monotonic() >= next_memory_cleanup
            dispatch_cycle(list_tenant_ids(), cleanup_due)
            if cleanup_due:
                next_memory_cleanup = time.monotonic() + 3600
        except Exception:
            logging.error("Outbox dispatch failed; retrying")
        time.sleep(2)


if __name__ == "__main__":
    main()
