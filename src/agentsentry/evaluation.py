"""Reproducible offline security cases; no model account or Docker required."""

import argparse
import json
import tempfile
import time
import uuid
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .capability import issue
from .database import Base
from .judge.adapters import MockJudge
from .models import AuditEvent, Outbox, Task
from .policy import PolicyEngine
from .schemas import CapabilityRequest, RuntimeSessionStart, ToolCallRequest
from .service import decide_approval, submit_call
from .runtime_analysis import start_session
from .runtime_binding import session_token
from .tools import seed_documents


class MemoryRedis:
    """Minimal stand-in used only by the offline evaluation harness."""

    def __init__(self):
        self.items = {}

    def hset(self, key, mapping):
        self.items[key] = {"value": dict(mapping), "expires": float("inf")}

    def expire(self, key, seconds):
        self.items[key]["expires"] = time.monotonic() + seconds

    def delete(self, key):
        self.items.pop(key, None)

    def ping(self):
        return True

    def hgetall(self, key):
        item = self.items.get(key)
        return dict(item["value"]) if item and item["expires"] > time.monotonic() else {}

    def eval(self, script, count, key, tenant, agent, tool, resource, uses=None):
        item = self.items.get(key)
        if not item or item["expires"] <= time.monotonic():
            return ["missing"]
        value = item["value"]
        resources = json.loads(resource) if uses is not None else [resource]
        if value.get("tenant", "default") != tenant or value["agent"] != agent or value["tool"] != tool or not set(resources).issubset(json.loads(value["resources"])):
            return ["scope"]
        amount = uses if uses is not None else 1
        if int(value["remaining"]) < amount:
            return ["exhausted"]
        value["remaining"] -= amount
        return ["ok", value["grant_id"]]


def run_cases(cases: list[dict], policy_path: str) -> dict:
    policy = PolicyEngine.from_file(policy_path)
    normal_total = normal_ok = attack_total = attack_success = 0
    judge_tp = judge_fp = judge_fn = 0
    audit_event_loss = 0
    results = []
    with tempfile.TemporaryDirectory() as folder:
        engine = create_engine(f"sqlite:///{folder}/eval.db")
        Base.metadata.create_all(engine)
        store = MemoryRedis()
        with Session(engine, expire_on_commit=False) as db:
            seed_documents(db)
            task_id = "11111111-1111-4111-8111-111111111111"
            db.add(Task(id=task_id, title="Example task", deleted=False))
            db.commit()
            for case in cases:
                runtime = start_session(db, "demo-agent", case["id"], RuntimeSessionStart(
                    transport="http", capture_mode="metadata"))
                binding = session_token("default", "demo-agent", runtime)
                prelude_call_id = None
                if case.get("prelude_document"):
                    _, read_token = issue(db, store, CapabilityRequest(
                        agent_id="demo-agent", tool="read_document",
                        resources=[case["prelude_document"]], ttl_seconds=600, max_uses=1,
                    ))
                    prelude = ToolCallRequest(
                        call_id=uuid.uuid4(), session_id=case["id"],
                        tool="read_document", arguments={"document_id": case["prelude_document"]},
                    )
                    _, read_result = submit_call(db, store, policy, prelude, read_token,
                                                 runtime_token=binding)
                    if read_result.get("status") != "completed":
                        raise RuntimeError(f"Prelude failed for {case['id']}")
                    prelude_call_id = str(prelude.call_id)
                arguments = json.loads(json.dumps(case["arguments"]).replace("$TASK_ID", task_id))
                token = ""
                if case.get("grant_resources"):
                    _, token = issue(db, store, CapabilityRequest(
                        agent_id="demo-agent", tool=case["tool"],
                        resources=case["grant_resources"], ttl_seconds=600, max_uses=1,
                    ))
                if case.get("revoke_before_call") and token:
                    from .capability import token_hash
                    store.delete("cap:" + token_hash(token))
                request = ToolCallRequest(
                    call_id=uuid.uuid4(), session_id=case["id"],
                    tool=case["tool"], arguments=arguments,
                )
                _, result = submit_call(db, store, policy, request, token,
                                        runtime_token=binding)
                if result.get("status") == "pending_approval" and case.get("approval"):
                    _, result = decide_approval(db, result["approval_id"], case["approval"])
                status = result.get("status")
                passed = status == case["expected_status"]
                if case["kind"] == "normal":
                    normal_total += 1
                    normal_ok += status == "completed"
                else:
                    attack_total += 1
                    attack_success += status == "completed"
                related_ids = [str(request.call_id)] + ([prelude_call_id] if prelude_call_id else [])
                events = db.scalars(select(AuditEvent).where(AuditEvent.call_id.in_(related_ids))).all()
                audit_event_loss += sum(not any(event.call_id == related_id for event in events) for related_id in related_ids)
                for event in events:
                    if not db.scalar(select(Outbox).where(Outbox.audit_event_id == event.id)):
                        audit_event_loss += 1
                risk_detected = any(
                    MockJudge().evaluate({"type": event.event_type, "payload": event.payload}, event.id).score >= 0.7
                    for event in events
                )
                expected_risk = case.get("judge_risk", False)
                judge_tp += bool(expected_risk and risk_detected)
                judge_fp += bool(not expected_risk and risk_detected)
                judge_fn += bool(expected_risk and not risk_detected)
                results.append({
                    "id": case["id"], "expected": case["expected_status"],
                    "actual": status, "pass": passed, "risk_detected": risk_detected,
                })
        engine.dispose()
    return {
        "cases": len(cases),
        "passed": sum(row["pass"] for row in results),
        "attack_success_rate": attack_success / attack_total if attack_total else 0,
        "normal_completion_rate": normal_ok / normal_total if normal_total else 0,
        "false_block_rate": (normal_total - normal_ok) / normal_total if normal_total else 0,
        "judge_false_positive_rate": judge_fp / (len(cases) - sum(c.get("judge_risk", False) for c in cases)) if cases else 0,
        "judge_false_negative_rate": judge_fn / sum(c.get("judge_risk", False) for c in cases) if any(c.get("judge_risk", False) for c in cases) else 0,
        "audit_event_loss": audit_event_loss,
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", default=str(Path(__file__).resolve().parents[2] / "evals/cases.jsonl"))
    parser.add_argument("--policy", default=str(Path(__file__).resolve().parents[2] / "policies/default.yaml"))
    parser.add_argument("--output", default="eval-report.json")
    args = parser.parse_args()
    cases = [json.loads(line) for line in Path(args.cases).read_text().splitlines() if line.strip()]
    report = run_cases(cases, args.policy)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    if report["passed"] != report["cases"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
