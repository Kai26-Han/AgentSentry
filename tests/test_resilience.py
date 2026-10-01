import uuid
from contextlib import contextmanager
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from agentsentry.database import Base
from agentsentry.fault_lab import CASES, _one
from agentsentry.models import AuditEvent, DependencyAttempt, DependencyState, Outbox, QueueLease, utcnow
from agentsentry.resilience import claim_job, finish_gate, owned_job, take_gate


@pytest.mark.parametrize("case", CASES, ids=[item["id"] for item in CASES])
def test_fixed_fault_case(case, tmp_path):
    result = _one(case, tmp_path)
    assert result["passed"], result


def test_tenant_dependency_states_are_separate(tmp_path):
    engines = [create_engine(f"sqlite:///{tmp_path / (name + '.db')}") for name in ("a", "b")]
    try:
        for engine in engines:
            Base.metadata.create_all(engine)
        with Session(engines[0]) as db:
            for _ in range(3):
                attempt, _ = take_gate(db, "mcp:github")
                finish_gate(db, attempt, False)
                db.commit()
            assert take_gate(db, "mcp:github")[1] == "dependency_circuit_open"
        with Session(engines[1]) as db:
            assert take_gate(db, "mcp:github")[0]
    finally:
        for engine in engines:
            engine.dispose()


def test_late_success_cannot_close_new_circuit(lab):
    db, _, _ = lab
    now = utcnow()
    old, _ = take_gate(db, "sandbox", now=now)
    for _ in range(3):
        attempt, _ = take_gate(db, "sandbox", now=now)
        finish_gate(db, attempt, False, now=now)
    finish_gate(db, old, True, now=now)
    assert db.get(DependencyState, "sandbox").open_until is not None


def test_expired_queue_lease_cannot_write_and_stops_crash_loop(lab):
    db, _, _ = lab
    event = AuditEvent(id=str(uuid.uuid4()), event_type="test", payload={})
    row = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id)
    db.add_all([event, row])
    db.commit()
    tokens = []
    for _ in range(3):
        claimed, token = claim_job(db, "judge", row.id)
        assert claimed
        tokens.append(token)
        db.get(QueueLease, ("judge", row.id)).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
        assert owned_job(db, "judge", row.id, token) is None
    assert claim_job(db, "judge", row.id) == (None, None)
    assert row.status == "failed" and row.attempts == 3


def test_backoff_does_not_starve_later_ready_rows(tmp_path, monkeypatch):
    from agentsentry import dispatcher
    engine = create_engine(f"sqlite:///{tmp_path}/queue.db")
    Base.metadata.create_all(engine)
    ids = []
    with Session(engine) as db:
        for index in range(110):
            event = AuditEvent(id=str(uuid.uuid4()), event_type="test", payload={})
            row = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
            db.add_all([event, row])
            if index < 100:
                db.add(QueueLease(kind="judge", record_id=row.id, token=str(uuid.uuid4()),
                    due_at=utcnow() + timedelta(minutes=5), expires_at=utcnow()))
            else:
                ids.append(row.id)
        db.commit()
    @contextmanager
    def scope():
        with Session(engine, expire_on_commit=False) as db:
            yield db
    monkeypatch.setattr(dispatcher, "db_session", scope)
    sent = []
    monkeypatch.setattr(dispatcher.judge_event, "delay", sent.append)
    assert dispatcher.dispatch_once() == 10
    assert set(sent) == set(ids)
    engine.dispose()


def test_webhook_failure_does_not_duplicate_completion(tmp_path, monkeypatch):
    from agentsentry.judge import worker
    from agentsentry.models import Alert, JudgeResult, WebhookDelivery
    engine = create_engine(f"sqlite:///{tmp_path}/webhook.db")
    Base.metadata.create_all(engine)
    @contextmanager
    def scope():
        with Session(engine, expire_on_commit=False) as db:
            yield db
    with scope() as db:
        event = AuditEvent(id=str(uuid.uuid4()), event_type="test", payload={})
        outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id)
        result = JudgeResult(id=str(uuid.uuid4()), outbox_id=outbox.id, labels=["none"], score=0,
                             provider="mock", model_version="test", status="completed")
        alert = Alert(id=str(uuid.uuid4()), judge_result_id=result.id, severity="medium", title="合成告警")
        delivery = WebhookDelivery(id=str(uuid.uuid4()), alert_id=alert.id, payload={"synthetic": True})
        db.add_all([event, outbox, result, alert, delivery])
        db.commit()
        record_id = delivery.id
    monkeypatch.setattr(worker, "db_session", scope)
    monkeypatch.setattr(worker.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("secret-hidden")))
    worker.send_webhook.run(record_id)
    with scope() as db:
        assert db.get(WebhookDelivery, record_id).status == "pending"
        assert db.get(WebhookDelivery, record_id).error == "TimeoutError"
        db.get(QueueLease, ("webhook", record_id)).due_at = utcnow() - timedelta(seconds=1)
        db.commit()
    posts = []
    class Response:
        def raise_for_status(self):
            return None
    monkeypatch.setattr(worker.httpx, "post", lambda *a, **k: posts.append(k) or Response())
    worker.send_webhook.run(record_id)
    worker.send_webhook.run(record_id)
    assert len(posts) == 1
    assert posts[0]["headers"]["Idempotency-Key"] == record_id
    with scope() as db:
        assert db.get(WebhookDelivery, record_id).status == "delivered"
    engine.dispose()
