import uuid
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from agentsentry import dispatcher
from agentsentry.database import Base
from agentsentry.models import AuditEvent, Outbox, QueueLease, utcnow
from datetime import timedelta


def test_dispatcher_requeues_after_broker_error(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path}/dispatch.db")
    Base.metadata.create_all(engine)
    event_id, outbox_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session(engine) as db:
        db.add(AuditEvent(id=event_id, call_id=None, event_type="test", payload={}))
        db.add(Outbox(id=outbox_id, audit_event_id=event_id, status="pending"))
        db.commit()

    @contextmanager
    def local_session():
        with Session(engine, expire_on_commit=False) as db:
            yield db

    monkeypatch.setattr(dispatcher, "db_session", local_session)

    def fail(_):
        raise ConnectionError("broker unavailable")

    monkeypatch.setattr(dispatcher.judge_event, "delay", fail)
    assert dispatcher.dispatch_once() == 0
    with Session(engine) as db:
        assert db.get(Outbox, outbox_id).status == "pending"
    sent = []
    monkeypatch.setattr(dispatcher.judge_event, "delay", sent.append)
    assert dispatcher.dispatch_once() == 0  # 持久化退避不能被立即重试绕过。
    with Session(engine) as db:
        db.get(QueueLease, ("judge", outbox_id)).due_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert dispatcher.dispatch_once() == 1
    assert sent == [outbox_id]
    with Session(engine) as db:
        assert db.get(Outbox, outbox_id).status == "queued"
    engine.dispose()
