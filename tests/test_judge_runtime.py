"""运行时 Judge 切换不应改投已排队事件。"""

import uuid
from datetime import timedelta
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from agentsentry.config import Settings
from agentsentry.main import event_judge_evidence
from agentsentry.database import Base
from agentsentry.judge import worker
from agentsentry.judge.adapters import Verdict
from agentsentry.judge.adapters import configured_judge_providers
from agentsentry.judge.runtime import (
    assign_route, backfill_unfinished_routes, change_runtime_provider, route_settings,
)
from agentsentry.models import AuditEvent, JudgeResult, JudgeRoute, JudgeRuntimeChange, Outbox, QueueLease, utcnow


@pytest.fixture
def runtime_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path}/judge-runtime.db")
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)

    @contextmanager
    def session():
        with Session(engine, expire_on_commit=False) as db:
            yield db

    monkeypatch.setattr(worker, "db_session", session)
    yield session
    engine.dispose()


def add_event(db, settings):
    event_id, outbox_id = str(uuid.uuid4()), str(uuid.uuid4())
    db.add(AuditEvent(id=event_id, call_id=None, event_type="tool_result",
                      payload={"tool": "read_document", "result": {"sensitivity": "public", "content": "Safe."}}))
    outbox = Outbox(id=outbox_id, audit_event_id=event_id, status="pending")
    db.add(outbox)
    assign_route(db, outbox, settings=settings)
    db.commit()
    return outbox_id


def test_switch_keeps_queued_events_and_retry_on_original_provider(runtime_db, monkeypatch):
    settings = Settings(judge_provider="mock", jev_api_key="synthetic-key")
    monkeypatch.setattr(worker, "settings", settings)
    with runtime_db() as db:
        old_id = add_event(db, settings)
        config = change_runtime_provider(db, "jev", 1, "admin:default", settings)
        assert config.revision == 2
        new_id = add_event(db, settings)
        assert db.get(JudgeRoute, old_id).provider == "mock"
        assert db.get(JudgeRoute, new_id).provider == "jev"
        with pytest.raises(RuntimeError):
            change_runtime_provider(db, "mock", 1, "admin:default", settings)
        assert db.scalar(select(JudgeRuntimeChange).where(JudgeRuntimeChange.revision == 2))

    calls = []
    class FakeJudge:
        def __init__(self, provider):
            self.provider = provider
        def evaluate(self, event_data, event_id):
            calls.append((event_id, self.provider))
            if event_id == new_id and calls.count((new_id, "jev")) == 1:
                raise RuntimeError("temporary failure")
            return Verdict(["none"], 0.05, self.provider, "synthetic-model")

    monkeypatch.setattr(worker, "build_judge", lambda selected: FakeJudge(selected.judge_provider))
    worker.judge_event.run(old_id)
    worker.judge_event.run(new_id)
    with runtime_db() as db:
        assert db.get(Outbox, new_id).status == "pending"
        change_runtime_provider(db, "mock", 2, "admin:default", settings)
        after_rollback_id = add_event(db, settings)
        assert db.get(JudgeRoute, after_rollback_id).provider == "mock"
        db.get(QueueLease, ("judge", new_id)).due_at = utcnow() - timedelta(seconds=1)
        db.commit()
    worker.judge_event.run(new_id)
    assert calls == [(old_id, "mock"), (new_id, "jev"), (new_id, "jev")]
    with runtime_db() as db:
        assert db.scalar(select(JudgeResult).where(JudgeResult.outbox_id == old_id)).provider == "mock"
        assert db.scalar(select(JudgeResult).where(JudgeResult.outbox_id == new_id)).provider == "jev"


def test_legacy_backfill_and_destination_drift_fail_closed(runtime_db):
    settings = Settings(judge_provider="mock", jev_api_key="synthetic-key")
    with runtime_db() as db:
        event_id, outbox_id = str(uuid.uuid4()), str(uuid.uuid4())
        db.add(AuditEvent(id=event_id, call_id=None, event_type="tool_result",
                          payload={"_sample_judge_provider": "jev"}))
        db.add(Outbox(id=outbox_id, audit_event_id=event_id, status="pending"))
        db.commit()
        assert backfill_unfinished_routes(db, settings) == 1
        assert backfill_unfinished_routes(db, settings) == 0
        route = db.get(JudgeRoute, outbox_id)
        assert route.provider == "jev" and route.source == "sample"
        assert route_settings(route, settings).judge_provider == "jev"
        with pytest.raises(RuntimeError, match="数据目的地"):
            route_settings(route, settings.model_copy(update={"jev_base_url": "https://different.invalid"}))
        with pytest.raises(RuntimeError, match="未配置"):
            route_settings(route, settings.model_copy(update={"jev_api_key": ""}))


def test_destination_display_keeps_port_but_hides_credentials():
    settings = Settings(judge_openai_base_url="http://name:secret@127.0.0.1:11434/v1?token=hidden",
                        judge_openai_model="local-model")
    choice = next(row for row in configured_judge_providers(settings) if row["id"] == "openai_compat")
    assert choice["destination"] == "http://127.0.0.1:11434"


def test_audit_view_distinguishes_unjudged_from_legacy_judged_events(runtime_db):
    settings = Settings(judge_provider="mock")
    with runtime_db() as db:
        admin = AuditEvent(id=str(uuid.uuid4()), call_id=None,
                           event_type="judge_config_changed", payload={})
        old = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="tool_result", payload={})
        pending = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="tool_result", payload={})
        missing = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="tool_result", payload={})
        unexpected = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="tool_result", payload={})
        db.add_all([admin, old, pending, missing, unexpected])
        old_outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=old.id, status="completed")
        pending_outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=pending.id, status="pending")
        missing_outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=missing.id, status="pending")
        db.add_all([old_outbox, pending_outbox, missing_outbox])
        assign_route(db, pending_outbox, settings=settings)
        db.flush()
        db.add(JudgeResult(id=str(uuid.uuid4()), outbox_id=old_outbox.id, call_id=None,
                           labels=["none"], score=0.05, provider="deepseek",
                           model_version="legacy-model", status="completed"))
        db.commit()

        evidence = event_judge_evidence(db, [admin, old, pending, missing, unexpected])
        assert evidence[admin.id] == {"designated": "不适用", "status": "仅保存审计，不进入 Judge"}
        assert evidence[old.id] == {"designated": "旧事件未记录指定 Judge",
                                    "status": "已评判：deepseek / legacy-model"}
        assert evidence[pending.id] == {"designated": "mock / rules-v1", "status": "等待投递"}
        assert evidence[missing.id]["designated"] == "路由缺失（需检查）"
        assert evidence[unexpected.id]["status"] == "无投递记录（需检查）"
