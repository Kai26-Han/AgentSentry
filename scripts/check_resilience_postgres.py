"""在临时 PostgreSQL schema 验证并发隔离；不停止日常服务、不调用真实工具。"""
import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import func, select, text
from agentsentry.database import create_tenant_tables, get_engine, tenant_db_session
from agentsentry.models import AuditEvent, DependencyState, JudgeResult, Outbox, utcnow
from agentsentry.resilience import finish_gate, take_gate


def main():
    if get_engine().dialect.name != "postgresql":
        raise SystemExit("本项要求 PostgreSQL；SQLite 不能替代并发锁验证")
    tenant = "t_" + uuid.uuid4().hex
    results = {}
    try:
        create_tenant_tables(tenant)
        def race(dependency):
            barrier = Barrier(4)
            def one(_):
                barrier.wait(timeout=10)
                with tenant_db_session(tenant) as db:
                    attempt, blocked = take_gate(db, dependency)
                    db.commit()
                    return "admitted" if attempt else blocked
            with ThreadPoolExecutor(max_workers=4) as pool:
                return list(pool.map(one, range(4)))
        slots = race("sandbox")
        assert slots.count("admitted") == 2 and slots.count("dependency_busy") == 2
        results["四并发最多两个执行租约"] = slots
        with tenant_db_session(tenant) as db:
            for _ in range(3):
                attempt, _ = take_gate(db, "mcp:remote-demo")
                finish_gate(db, attempt, False)
                db.commit()
            db.get(DependencyState, "mcp:remote-demo").open_until = utcnow() - timedelta(seconds=1)
            db.commit()
        probes = race("mcp:remote-demo")
        assert probes.count("admitted") == 1 and probes.count("dependency_circuit_open") == 3
        results["四并发半开仅一个探测"] = probes

        from agentsentry.config import Settings
        from agentsentry.judge.runtime import assign_route
        from agentsentry.judge.worker import judge_event
        with tenant_db_session(tenant) as db:
            event = AuditEvent(id=str(uuid.uuid4()), event_type="test", payload={})
            row = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id)
            db.add_all([event, row])
            assign_route(db, row, settings=Settings(judge_provider="mock"))
            db.commit()
            outbox_id = row.id
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: judge_event.run(outbox_id, tenant), range(4)))
        with tenant_db_session(tenant) as db:
            assert db.scalar(select(func.count()).select_from(JudgeResult)) == 1
            assert db.get(Outbox, outbox_id).status == "completed"
        results["四并发重复分析仅一个结果"] = True
        print(json.dumps({"environment": "临时 PostgreSQL schema", "passed": True,
                          "results": results}, ensure_ascii=False))
    finally:
        with get_engine().begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{tenant}" CASCADE'))


if __name__ == "__main__":
    main()
