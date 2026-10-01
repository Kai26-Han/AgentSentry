import uuid

from agentsentry.memory_security_lab import CASES, VERSION, _case, corpus_hash, run_view
from agentsentry.models import MemorySecurityRun
from agentsentry.models import AuditEvent, MemoryEntry, MemoryWrite, Outbox, OutputCheck, RuntimeSession, utcnow
from agentsentry.memory_integrity import seal_memory
from agentsentry.service import audit
from datetime import timedelta
from sqlalchemy import select


def test_fixed_memory_security_corpus_repeats_without_forbidden_recall(lab):
    db, _, _ = lab
    # 研究租户可能同时有其他有效记忆；不能把它们计成本例攻击成功。
    db.add(RuntimeSession(agent_id="demo-agent", session_id="other-write",
        capture_mode="metadata", reported=True, status="running"))
    db.add(OutputCheck(id="other-check", agent_id="demo-agent", session_id="other-write",
        capture_mode="metadata", output_kind="final_answer", request_fingerprint="other",
        outcome="allow", rules_version="test", findings=[], sources=[], sentences=[], model_hint={}))
    db.add(MemoryWrite(id="other-write", agent_id="demo-agent", session_id="other-write",
        output_check_id="other-check", request_fingerprint="other", entry_ids=["other-memory"]))
    db.add(MemoryEntry(id="other-memory", write_id="other-write", agent_id="demo-agent",
        origin_session_id="other-write", kind="fact", text="外部正常记忆",
        text_hash="other", status="active", trust_level="untrusted", findings=[],
        source_call_ids=[], expires_at=utcnow() + timedelta(days=1)))
    db.commit()
    seal_memory(db, db.get(MemoryEntry, "other-memory"))
    audit(db, None, "memory_decision", {"memory_id": "other-memory", "action": "activate"})
    db.commit()
    assert len(CASES) == 18
    assert sum(case["kind"] == "attack" for case in CASES) == 12
    first = None
    for _ in range(2):
        run = MemorySecurityRun(id=str(uuid.uuid4()), status="running",
            corpus_version=VERSION, corpus_hash=corpus_hash(), expected_cases=len(CASES))
        db.add(run)
        db.commit()
        results = [_case(db, run.id, case) for case in CASES]
        summary = run_view(db, run)
        assert all(row.passed for row in results)
        assert summary["counts"]["blocked_attacks"] == 12
        assert summary["counts"]["normal_recalled"] == 6
        assert summary["counts"]["integrity_incidents"] >= 4
        assert summary["counts"]["audit_loss"] == 0
        snapshot = [(row.case_id, row.write_status, row.recalled, row.passed)
                    for row in results]
        if first is None:
            first = snapshot
            event = next(item for item in db.scalars(select(AuditEvent)).all()
                if item.event_type == "memory_write" and
                item.payload.get("memory_id") == results[0].memory_id)
            outbox = db.scalar(select(Outbox).where(Outbox.audit_event_id == event.id))
            db.delete(outbox)
            db.commit()
            assert run_view(db, run)["counts"]["audit_loss"] == 1
        else:
            assert snapshot == first
