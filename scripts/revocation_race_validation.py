"""真实 PostgreSQL 授权与吊销提交顺序；受控屏障只作用于本进程。"""

import argparse
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from unittest.mock import patch

from deep_validation import Lab, write_report
from agentsentry import service
from agentsentry.capability import get_redis, revoke
from agentsentry.database import tenant_db_session
from agentsentry.models import Approval, CapabilityGrant


def run():
    lab = Lab("revocation-race")
    sid = lab.start(task="发送合成公开通知")
    grant = lab.grant("send_external", ["demo-inbox"])
    pending = lab.call(sid, "send_external", {"destination_id": "demo-inbox", "content": "竞争合成通知"}, grant["token"])
    assert pending["status"] == "pending_approval"
    entered, release, revoker_entered = threading.Event(), threading.Event(), threading.Event()
    original = service.runtime_evaluate
    def gate(db, call, tenant):
        entered.set()
        if not release.wait(10):
            raise RuntimeError("验证屏障超时")
        return original(db, call, tenant)
    def approve():
        with tenant_db_session(lab.id) as db:
            return service.decide_approval(db, pending["approval_id"], "approve", lab.id, lab.policy)
    def revoking():
        with tenant_db_session(lab.id) as db:
            item = db.get(CapabilityGrant, grant["grant_id"])
            revoker_entered.set()
            revoke(db, get_redis(), item)
        with tenant_db_session(lab.id) as db:
            return db.get(Approval, pending["approval_id"]).status
    with patch("agentsentry.service.runtime_evaluate", gate), ThreadPoolExecutor(2) as pool:
        approving = pool.submit(approve)
        assert entered.wait(10)
        revoking_call = pool.submit(revoking)
        assert revoker_entered.wait(10)
        try:
            status_at_revocation = revoking_call.result(timeout=.5)
            revoked_before_release = True
        except TimeoutError:
            status_at_revocation = None
            revoked_before_release = False
        finally:
            release.set()
        _, result = approving.result(timeout=10)
        status_at_revocation = status_at_revocation or revoking_call.result(timeout=10)
    evidence = lab.evidence()
    # 吊销完成时若审批仍待处理，随后不可执行；已经原子提交的动作不能被追溯撤销。
    passed = (result["status"] == "denied" and evidence["messages"] == 0
              if status_at_revocation == "pending" else
              status_at_revocation == "approved" and result["status"] == "completed" and evidence["messages"] == 1)
    lab.close()
    return {"version": "revocation-race-v1", "passed": passed,
            "mode": "真实 PG/Redis 独立事务与服务层屏障注入",
            "revoked_before_release": revoked_before_release,
            "approval_status_when_revocation_committed": status_at_revocation,
            "call_status": result["status"], "evidence": evidence}


def expiry():
    lab = Lab("approval-expiry-during-check")
    sid = lab.start(task="发送合成公开通知")
    grant = lab.grant("send_external", ["demo-inbox"])
    pending = lab.call(sid, "send_external", {"destination_id": "demo-inbox", "content": "过期合成通知"}, grant["token"])
    assert pending["status"] == "pending_approval"
    with tenant_db_session(lab.id) as db:
        until = datetime.now(timezone.utc) + timedelta(seconds=2)
        db.get(CapabilityGrant, grant["grant_id"]).expires_at = until
        db.get(Approval, pending["approval_id"]).decided_at = None
        from agentsentry.models import ToolCall
        db.get(ToolCall, pending["call_id"]).approval_expires_at = until
        db.commit()
    original = service.runtime_evaluate
    def delay(db, call, tenant):
        result = original(db, call, tenant)
        time.sleep(2.2)  # 独立验证进程内的固定延迟，不修改在线服务或系统时间。
        return result
    with tenant_db_session(lab.id) as db, patch("agentsentry.service.runtime_evaluate", delay):
        _, result = service.decide_approval(db, pending["approval_id"], "approve", lab.id, lab.policy)
    evidence = lab.evidence()
    lab.close()
    return {"version": "approval-expiry-v1", "passed": result["status"] == "denied" and evidence["messages"] == 0,
            "call_status": result["status"], "evidence": evidence, "delay_seconds": 2.2}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--scenario", choices=["revocation", "expiry"], default="revocation")
    args = p.parse_args()
    report = run() if args.scenario == "revocation" else expiry()
    write_report(args.output, report)
    print(json.dumps({k: v for k, v in report.items() if k != "evidence"}, ensure_ascii=False))
