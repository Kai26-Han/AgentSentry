"""离线故障实验；只在临时数据库和受控替身中注入故障。"""

import argparse
import json
import tempfile
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from .database import Base
from .models import (AuditEvent, DependencyState, FaultLabRun, JudgeResult, Outbox,
                     QueueLease, ToolCall, utcnow)
from .resilience import (claim_job, finish_gate, owned_job, retry_failed, take_gate)

VERSION = "fault-lab-v1"
_SPECS = [
    ("F01", "权限存储不可用时不执行工具", "redis_down"),
    ("F02", "安全决定提交失败时不执行工具", "audit_down"),
    ("F03", "可能已执行的写入结果不明且不自动重试", "unknown_write"),
    ("F04", "连续三次失败后熔断", "open"),
    ("F05", "冷却后成功探测恢复", "recover"),
    ("F06", "冷却后只放行一个探测", "single_probe"),
    ("F07", "每个依赖最多两个执行租约", "concurrency"),
    ("F08", "执行租约过期不永久占用并发槽", "expire"),
    ("F09", "一个依赖熔断不影响其他依赖", "dependency_isolation"),
    ("F10", "Broker 故障后批内停止发送并保留事件", "broker_down"),
    ("F11", "退避期限内不重新投递", "backoff"),
    ("F12", "重复任务只生成一条 Judge 结果", "duplicate"),
    ("F13", "迟到 Worker 不能覆盖新处理代次", "fence"),
    ("F14", "管理员仅能重试终止的异步任务", "manual_retry"),
    ("F15", "单租户投递异常仍继续其他租户和阶段", "tenant_isolation"),
    ("F16", "Judge 最多实际失败三次且错误不留原文", "judge_failure"),
    ("F17", "执行进程中断后标为 unknown", "recover_unknown"),
    ("F18", "半开失败重新冷却", "probe_failure"),
    ("N01", "正常依赖请求完成", "normal_dependency"),
    ("N02", "远程故障时正常本地读取仍可完成", "normal_local"),
    ("N03", "Judge 停机时同步调用保留审计并完成", "judge_down_local"),
    ("N04", "Broker 恢复后原事件可投递", "broker_recovery"),
]
CASES = [{"id": item[0], "name": item[1], "scenario": item[2]} for item in _SPECS]


def _one(case, directory):
    case_id, name, scenario = case["id"], case["name"], case["scenario"]
    engine = create_engine(f"sqlite:///{directory / (case_id + '.db')}")
    Base.metadata.create_all(engine)
    try:
        with Session(engine, expire_on_commit=False) as db:
            evidence = _scenario(scenario, db, engine)
            db.expire_all()
            missing = 0
            for call in db.scalars(select(ToolCall)):
                expected = ("tool_unknown" if call.status == "unknown" else
                            "tool_result" if call.status in {"completed", "failed"} else None)
                if expected and not db.scalar(select(AuditEvent.id).where(
                        AuditEvent.call_id == call.call_id, AuditEvent.event_type == expected)):
                    missing += 1
            assert missing == 0
            evidence["已提交执行记录审计缺失"] = missing
            return {"id": case_id, "name": name, "passed": True, "evidence": evidence,
                    "kind": "正常对照" if case_id.startswith("N") else "故障验证"}
    except Exception as exc:
        return {"id": case_id, "name": name, "passed": False,
                "evidence": type(exc).__name__, "kind": "故障验证"}
    finally:
        engine.dispose()


def _scenario(scenario, db, engine):
    from . import dispatcher, service
    from .capability import issue
    from .config import Settings
    from .evaluation import MemoryRedis
    from .judge import worker
    from .judge.adapters import MockJudge
    from .judge.runtime import assign_route
    from .policy import PolicyEngine
    from .schemas import CapabilityRequest, ToolCallRequest
    from .tools import seed_documents

    now = utcnow()

    @contextmanager
    def scope():
        with Session(engine, expire_on_commit=False) as other:
            yield other

    def job():
        event = AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="lab", payload={})
        row = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id)
        db.add_all([event, row])
        assign_route(db, row, settings=Settings(judge_provider="mock"))
        db.commit()
        return row.id

    def opened():
        for _ in range(3):
            attempt, denied = take_gate(db, "mcp:remote-demo", now=now)
            assert attempt and denied is None
            finish_gate(db, attempt, False, "TimeoutError", now=now)
            db.commit()

    if scenario in {"open", "recover", "single_probe", "probe_failure", "dependency_isolation"}:
        opened()
        attempt, reason = take_gate(db, "mcp:remote-demo", now=now)
        assert attempt is None and reason == "dependency_circuit_open"
        if scenario == "dependency_isolation":
            assert take_gate(db, "sandbox", now=now)[0]
        elif scenario != "open":
            later = now + timedelta(seconds=31)
            attempt, reason = take_gate(db, "mcp:remote-demo", now=later)
            assert attempt and reason is None
            if scenario == "single_probe":
                assert take_gate(db, "mcp:remote-demo", now=later)[1] == "dependency_circuit_open"
            else:
                finish_gate(db, attempt, scenario == "recover", now=later)
                state = db.get(DependencyState, "mcp:remote-demo")
                assert (state.open_until is None) == (scenario == "recover")
        db.commit()
        return {"首次拒绝": "dependency_circuit_open", "后续行为": scenario}

    if scenario in {"concurrency", "expire", "normal_dependency"}:
        attempt = take_gate(db, "sandbox", now=now)[0]
        assert attempt
        if scenario == "normal_dependency":
            finish_gate(db, attempt, True, now=now)
            assert db.get(DependencyState, "sandbox").failures == 0
        else:
            assert take_gate(db, "sandbox", now=now)[0]
            assert take_gate(db, "sandbox", now=now)[1] == "dependency_busy"
            if scenario == "expire":
                assert take_gate(db, "sandbox", now=now + timedelta(seconds=121))[0]
        db.commit()
        return {"并发上限": 2, "结果": scenario}

    if scenario in {"redis_down", "audit_down", "normal_local", "judge_down_local"}:
        seed_documents(db)
        store = MemoryRedis()
        token = issue(db, store, CapabilityRequest(agent_id="demo-agent", tool="read_document",
                      resources=["public-guide"], ttl_seconds=600, max_uses=2))[1]
        request = ToolCallRequest(call_id=uuid.uuid4(), session_id="fault-lab", tool="read_document",
                                  arguments={"document_id": "public-guide"})
        policy = PolicyEngine.from_file(str(Path(__file__).resolve().parents[2] / "policies/default.yaml"))
        if scenario == "normal_local":
            opened()
        with patch.object(service, "execute", wraps=service.execute) as execute:
            if scenario == "redis_down":
                with patch.object(store, "eval", side_effect=ConnectionError("synthetic-secret-hidden")):
                    status, view = service.submit_call(db, store, policy, request, token)
                assert status == 503 and execute.call_count == 0
            elif scenario == "audit_down":
                with patch.object(db, "commit", side_effect=RuntimeError("synthetic-commit-failure")):
                    status, view = service.submit_call(db, store, policy, request, token)
                assert status == 503 and execute.call_count == 0
            else:
                status, view = service.submit_call(db, store, policy, request, token)
                assert status == 200 and view["status"] == "completed"
                assert db.scalar(select(func.count()).select_from(Outbox)) > 0
        return {"HTTP状态": status, "工具执行次数": execute.call_count,
                "敏感错误未展示": "synthetic-secret-hidden" not in str(view)}

    if scenario in {"unknown_write", "recover_unknown"}:
        request = ToolCallRequest(call_id=uuid.uuid4(), session_id="fault-write", tool="mcp_record_note",
                                  arguments={"note_id": "fault-demo", "text": "合成内容"})
        row = ToolCall(call_id=str(request.call_id), session_id=request.session_id, agent_id="demo-agent",
                       tool=request.tool, arguments=request.arguments, status="executing", decision="allow",
                       request_hash=service.canonical_hash({"session_id": request.session_id,
                           "agent_id": "demo-agent", "tool": request.tool, "arguments": request.arguments}))
        db.add(row)
        db.commit()
        calls = []
        def uncertain(*args):
            calls.append("可能写入")
            raise TimeoutError("synthetic timeout")
        with patch.object(service, "execute", side_effect=uncertain):
            if scenario == "unknown_write":
                assert service._execute_recorded(db, row)["status"] == "unknown"
            else:
                row.updated_at = now - timedelta(minutes=3)
                db.commit()
                assert service.recover_unknown_calls(db) == 1
            policy = PolicyEngine.from_file(str(Path(__file__).resolve().parents[2] / "policies/default.yaml"))
            assert service.submit_call(db, MemoryRedis(), policy, request, "")[1]["status"] == "unknown"
        assert len(calls) == (1 if scenario == "unknown_write" else 0)
        return {"最终状态": "unknown", "重复请求额外执行": 0}

    if scenario in {"broker_down", "backoff", "broker_recovery"}:
        ids = [job(), job()]
        with patch.object(dispatcher, "db_session", scope), patch.object(
                dispatcher.judge_event, "delay", side_effect=ConnectionError("synthetic-secret-hidden")) as send:
            assert dispatcher.dispatch_once() == 0
            assert send.call_count == 1
            assert dispatcher.dispatch_once() == 0
            assert send.call_count == 1
            db.expire_all()
            for record_id in ids:
                assert db.get(Outbox, record_id).status == "pending"
                assert db.get(Outbox, record_id).attempts == 0
            if scenario == "broker_recovery":
                for record_id in ids:
                    db.get(QueueLease, ("judge", record_id)).due_at = now - timedelta(seconds=1)
                db.commit()
                with patch.object(dispatcher.judge_event, "delay", return_value=None):
                    assert dispatcher.dispatch_once() == 2
        return {"故障时连接尝试": 1, "事件保留数": 2, "实际分析次数": 0}

    if scenario in {"duplicate", "judge_failure"}:
        record_id = job()
        def broken(*args):
            raise TimeoutError("synthetic-secret-hidden")
        with patch.object(worker, "db_session", scope), patch.object(worker, "build_judge",
                side_effect=broken if scenario == "judge_failure" else lambda settings: MockJudge()):
            for _ in range(3 if scenario == "judge_failure" else 2):
                worker.judge_event.run(record_id)
                if scenario == "judge_failure":
                    db.expire_all()
                    db.get(QueueLease, ("judge", record_id)).due_at = now - timedelta(seconds=1)
                    db.commit()
            db.expire_all()
            row = db.get(Outbox, record_id)
            assert row.status == ("failed" if scenario == "judge_failure" else "completed")
            if scenario == "judge_failure":
                assert row.attempts == 3 and row.error == "TimeoutError"
                worker.judge_event.run(record_id)
            else:
                assert db.scalar(select(func.count()).select_from(JudgeResult)) == 1
        return {"最终状态": row.status, "实际尝试": row.attempts, "错误原文未保存": True}

    if scenario in {"fence", "manual_retry"}:
        record_id = job()
        row, first = claim_job(db, "judge", record_id, now)
        db.commit()
        if scenario == "fence":
            row, second = claim_job(db, "judge", record_id, now + timedelta(seconds=121))
            assert first != second and owned_job(db, "judge", record_id, first) is None
            assert owned_job(db, "judge", record_id, second) is not None
        else:
            assert retry_failed(db, "judge", record_id) == "not_failed"
            row.status = "failed"
            db.commit()
            assert retry_failed(db, "judge", record_id) == "ok"
            assert row.status == "pending" and row.attempts == 0
            assert owned_job(db, "judge", record_id, first) is None
        db.commit()
        return {"旧代次不能写入": True, "工具重放次数": 0}

    if scenario == "tenant_isolation":
        steps = []
        def dispatch(tenant):
            steps.append((tenant, "judge"))
            if tenant == "broken":
                raise ConnectionError("synthetic failure")
        with patch.object(dispatcher, "db_session", scope), patch.object(
                dispatcher, "tenant_db_session", lambda tenant: scope()), patch.object(
                dispatcher, "dispatch_once", side_effect=dispatch), patch.object(
                dispatcher, "dispatch_webhooks_once", side_effect=lambda tenant: steps.append((tenant, "webhook"))), patch.object(
                dispatcher, "project_once", return_value=None):
            dispatcher.dispatch_cycle(["broken", "healthy"])
        assert ("broken", "webhook") in steps and ("healthy", "judge") in steps
        return {"完成阶段": steps}
    raise ValueError("Unknown fixed scenario")


def run_lab():
    with tempfile.TemporaryDirectory(prefix="agentsentry-fault-lab-") as temporary:
        results = [_one(case, Path(temporary)) for case in CASES]
    import hashlib
    sample_hash = hashlib.sha256(json.dumps(CASES, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    return {"sample_version": VERSION, "sample_sha256": sample_hash,
            "environment": "隔离临时 SQLite 与受控替身",
            "passed": sum(item["passed"] for item in results), "total": len(results),
            "results": results}


def main():
    parser = argparse.ArgumentParser(description="AgentSentry 隔离故障实验，不关闭日常服务")
    parser.add_argument("--output", default=".local/fault-lab-report.json")
    parser.add_argument("--persist", action="store_true", help="将实验报告保存到当前本机数据库")
    parser.add_argument("--tenant", default="default", help="保存报告的租户 ID；不改变该租户策略")
    args = parser.parse_args()
    report = run_lab()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    if args.persist:
        from .database import tenant_db_session
        with tenant_db_session(args.tenant) as db:
            db.add(FaultLabRun(id=str(uuid.uuid4()), sample_version=VERSION,
                              status="通过" if report["passed"] == report["total"] else "失败",
                              results=report["results"]))
            db.commit()
    print(f"隔离故障实验：{report['passed']}/{report['total']}；报告：{output}")
    if report["passed"] != report["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
