"""专属队列的真实 Broker 故障与 Worker 恢复；不停止日常服务。"""
import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from celery import Celery
from sqlalchemy import func, select, text

from agentsentry import dispatcher
from agentsentry.capability import get_redis
from agentsentry.config import Settings
from agentsentry.database import create_tenant_tables, get_engine, tenant_db_session
from agentsentry.judge.runtime import assign_route
from agentsentry.judge.worker import judge_event
from agentsentry.models import AuditEvent, JudgeResult, Outbox


def main():
    if get_engine().dialect.name != "postgresql":
        raise SystemExit("本项要求已运行的 PostgreSQL 和 Redis；请在 Compose Web 容器中执行")
    suffix = uuid.uuid4().hex
    tenant = "t_" + suffix
    queue = "agentsentry-fault-" + suffix
    process = None
    # 固定本机不可用端口，不读取或修改日常 Broker 配置。
    broken = Celery("fault-broker", broker="redis://127.0.0.1:1/0")
    broken.conf.update(task_publish_retry=False, broker_connection_timeout=1,
                       broker_transport_options={"socket_timeout": 1, "socket_connect_timeout": 1})
    class UnavailableTask:
        def delay(self, record_id, tenant_id):
            return broken.send_task("agentsentry.judge_event", args=[record_id, tenant_id],
                                    queue=queue, retry=False)
    class IsolatedTask:
        def delay(self, record_id, tenant_id):
            return judge_event.apply_async(args=[record_id, tenant_id], queue=queue, retry=False)
    try:
        create_tenant_tables(tenant)
        with tenant_db_session(tenant) as db:
            event = AuditEvent(id=str(uuid.uuid4()), event_type="fault_lab_queue", payload={})
            row = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id)
            db.add_all([event, row])
            assign_route(db, row, settings=Settings(judge_provider="mock"))
            db.commit()
            outbox_id = row.id
        start = time.monotonic()
        with patch.object(dispatcher, "judge_event", UnavailableTask()):
            assert dispatcher.dispatch_once(tenant) == 0
        failed_seconds = round(time.monotonic() - start, 2)
        with tenant_db_session(tenant) as db:
            assert db.get(Outbox, outbox_id).status == "pending"
            assert db.get(Outbox, outbox_id).attempts == 0
        with patch.object(dispatcher, "judge_event", IsolatedTask()):
            assert dispatcher.dispatch_once(tenant) == 0
            time.sleep(2.1)
            assert dispatcher.dispatch_once(tenant) == 1
        time.sleep(0.2)
        with tenant_db_session(tenant) as db:
            assert db.get(Outbox, outbox_id).status == "queued"
            assert db.scalar(select(func.count()).select_from(JudgeResult)) == 0
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen([
                sys.executable, "-m", "celery", "-A", "agentsentry.judge.worker:celery_app",
                "worker", "--pool=solo", "--concurrency=1", "--loglevel=warning",
                "-Q", queue, "-n", "fault-" + suffix + "@%h"], stdout=log, stderr=log)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                with tenant_db_session(tenant) as db:
                    if db.get(Outbox, outbox_id).status == "completed":
                        break
                if process.poll() is not None:
                    raise RuntimeError("Isolated Worker exited before processing")
                time.sleep(0.2)
            else:
                raise TimeoutError("Isolated Worker did not process its queue")
            judge_event.apply_async(args=[outbox_id, tenant], queue=queue, retry=False)
            time.sleep(0.5)
            with tenant_db_session(tenant) as db:
                assert db.get(Outbox, outbox_id).status == "completed"
                assert db.scalar(select(func.count()).select_from(JudgeResult)) == 1
                assert db.get(AuditEvent, event.id) is not None
            print(json.dumps({"environment": "真实 Redis＋专属队列＋临时 Worker＋临时 PostgreSQL schema",
                              "broker_failure_seconds": failed_seconds, "passed": True,
                              "failure_preserved_event": True, "before_worker_results": 0,
                              "after_worker_results": 1, "audit_missing": 0}, ensure_ascii=False))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        broken.close()
        # 只清除本次随机命名的专属队列，不清理共享 Broker 键。
        get_redis().delete(queue, "_kombu.binding." + queue)
        with get_engine().begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{tenant}" CASCADE'))


if __name__ == "__main__":
    main()
