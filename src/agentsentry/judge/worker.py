import uuid
import hashlib
import hmac
import json
from datetime import timedelta, timezone

import httpx
from celery import Celery
from sqlalchemy import select

from ..config import get_settings
from ..database import db_session, tenant_db_session
from ..models import Alert, AlertGroup, AuditEvent, JudgeResult, JudgeRoute, JudgeSampleRun, Outbox, WebhookDelivery, utcnow
from .adapters import build_judge
from .runtime import route_settings
from ..resilience import (COOLDOWN_SECONDS, claim_job, finish_gate, owned_job,
                          postpone_job, take_gate)


settings = get_settings()
settings.validate_runtime()
celery_app = Celery("agentsentry", broker=settings.redis_url)
celery_app.conf.update(
    task_acks_late=True, worker_prefetch_multiplier=1, task_publish_retry=False,
    broker_connection_timeout=2,
    broker_transport_options={"socket_connect_timeout": 2, "socket_timeout": 2,
                              "visibility_timeout": 180},
    task_soft_time_limit=60, task_time_limit=90,
    task_routes={"agentsentry.judge_event": {"queue": "judge"},
                 "agentsentry.send_webhook": {"queue": "webhook"}},
)


@celery_app.task(name="agentsentry.judge_event")
def judge_event(outbox_id: str, tenant_id: str = "default") -> None:
    scope = db_session if tenant_id == "default" else lambda: tenant_db_session(tenant_id)
    with scope() as session:
        outbox, token = claim_job(session, "judge", outbox_id)
        if outbox is None:
            session.commit()
            return
        event = session.get(AuditEvent, outbox.audit_event_id)
        sample_run = session.scalar(select(JudgeSampleRun.id).where(JudgeSampleRun.outbox_id == outbox_id))
        event_payload = dict(event.payload)
        if sample_run:
            event_payload.pop("_sample_judge_provider", None)  # legacy sample metadata
        route = session.get(JudgeRoute, outbox_id)
        event_data = {"type": event.event_type, "payload": event_payload}
        call_id = event.call_id
        attempt_id = None
        if route is not None:
            dependency = f"judge:{route.provider}:{route.endpoint_hash}"
            attempt_id, blocked = take_gate(session, dependency)
            if blocked:
                postpone_job(session, "judge", outbox, blocked, COOLDOWN_SECONDS, attempted=False)
                session.commit()
                return
        session.commit()
    try:
        if route is None:
            raise RuntimeError("Judge route missing; event was not safely assigned a provider")
        judge_settings = route_settings(route, settings)
        verdict = build_judge(judge_settings).evaluate(event_data, outbox_id)
        if verdict.provider != route.provider or verdict.status != "completed":
            raise RuntimeError("Judge 返回的提供方与事件指定值不一致")
    except Exception as exc:
        with scope() as session:
            outbox = owned_job(session, "judge", outbox_id, token)
            if outbox is None:
                return
            if attempt_id:
                finish_gate(session, attempt_id, False, type(exc).__name__[:100])
            postpone_job(session, "judge", outbox, type(exc).__name__[:100])
            session.commit()
        return
    with scope() as session:
        outbox = owned_job(session, "judge", outbox_id, token)
        if outbox is None:
            return
        if attempt_id:
            finish_gate(session, attempt_id, True)
        if session.scalar(select(JudgeResult).where(JudgeResult.outbox_id == outbox_id)):
            outbox.status = "completed"
            session.commit()
            return
        result = JudgeResult(
            id=str(uuid.uuid4()), outbox_id=outbox_id, call_id=call_id,
            labels=verdict.labels, score=verdict.score, provider=verdict.provider,
            model_version=verdict.model_version, status=verdict.status,
        )
        session.add(result)
        session.flush()
        is_sample = session.scalar(select(JudgeSampleRun.id).where(JudgeSampleRun.outbox_id == outbox_id)) is not None
        if not is_sample and verdict.score >= settings.judge_score_threshold and verdict.labels != ["none"]:
            arguments = event_data["payload"].get("arguments") or {}
            fingerprint = hashlib.sha256(json.dumps({
                "provider": verdict.provider, "labels": sorted(verdict.labels),
                "event_type": event_data["type"], "tool": event_data["payload"].get("tool"),
                "resource": next((arguments.get(key)
                                  for key in ("document_id", "destination_id", "task_id")
                                  if arguments.get(key)), None),
            }, sort_keys=True).encode()).hexdigest()
            group = session.get(AlertGroup, fingerprint, with_for_update=True)
            now = utcnow()
            notify = group is None
            if group is None:
                group = AlertGroup(
                    fingerprint=fingerprint, provider=verdict.provider, labels=verdict.labels,
                    event_type=event_data["type"], tool=event_data["payload"].get("tool"),
                    occurrences=1, latest_call_id=call_id, first_seen_at=now,
                    last_seen_at=now, last_alert_at=now,
                )
                session.add(group)
            else:
                group.occurrences += 1
                group.latest_call_id = call_id
                group.last_seen_at = now
                notify = (now - group.last_alert_at.replace(tzinfo=timezone.utc)).total_seconds() >= settings.alert_cooldown_seconds
                if notify:
                    group.last_alert_at = now
            if notify:
                alert = Alert(
                    id=str(uuid.uuid4()), judge_result_id=result.id, call_id=call_id,
                    severity="high" if verdict.score >= 0.9 else "medium",
                    title="Risk signal: " + ", ".join(verdict.labels),
                )
                session.add(alert)
                session.flush()
                if settings.webhook_url:
                    session.add(WebhookDelivery(
                        id=str(uuid.uuid4()), alert_id=alert.id,
                        payload={
                            "tenant_id": tenant_id, "alert_id": alert.id, "call_id": call_id, "severity": alert.severity,
                            "labels": verdict.labels, "score": verdict.score,
                            "provider": verdict.provider, "event_type": event_data["type"],
                            "tool": event_data["payload"].get("tool"),
                        },
                    ))
        outbox.status = "completed"
        outbox.error = None
        outbox.updated_at = utcnow()
        session.commit()


@celery_app.task(name="agentsentry.send_webhook")
def send_webhook(delivery_id: str, tenant_id: str = "default") -> None:
    scope = db_session if tenant_id == "default" else lambda: tenant_db_session(tenant_id)
    with scope() as session:
        delivery, token = claim_job(session, "webhook", delivery_id)
        if delivery is None:
            session.commit()
            return
        destination_hash = hashlib.sha256(settings.webhook_url.encode()).hexdigest()
        attempt_id, blocked = take_gate(session, "webhook:" + destination_hash)
        if blocked:
            postpone_job(session, "webhook", delivery, blocked, COOLDOWN_SECONDS, attempted=False)
            session.commit()
            return
        payload = delivery.payload
        session.commit()
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(settings.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    try:
        response = httpx.post(
            settings.webhook_url, content=body, timeout=5,
            headers={
                "Content-Type": "application/json",
                "X-AgentSentry-Signature": "sha256=" + signature,
                "Idempotency-Key": delivery_id,
            },
        )
        response.raise_for_status()
    except Exception as exc:
        with scope() as session:
            delivery = owned_job(session, "webhook", delivery_id, token)
            if delivery is None:
                return
            finish_gate(session, attempt_id, False, type(exc).__name__[:100])
            postpone_job(session, "webhook", delivery, type(exc).__name__[:100])
            session.commit()
        return
    with scope() as session:
        delivery = owned_job(session, "webhook", delivery_id, token)
        if delivery is None:
            return
        finish_gate(session, attempt_id, True)
        delivery.status = "delivered"
        delivery.error = None
        delivery.updated_at = utcnow()
        session.commit()
