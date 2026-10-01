"""把已提交的租户审计元数据投影为可追溯的框架线索；不参与授权。"""

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
import os
import uuid

import yaml
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm import aliased

from .models import (AuditEvent, DataFlowDecision, GoalAssessment, MemoryEntry,
                     RuntimeDecision, ThreatMappingAssessment, ThreatMappingState,
                     ToolCall, utcnow)


BACKFILL_DAYS = 30


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    path = Path(os.environ.get("THREAT_MAPPING_PATH", "docs/threat-framework-map.yaml"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or not isinstance(data.get("mapping_version"), str)
            or not isinstance(data.get("runtime_signals"), list)
            or not isinstance(data.get("threats"), list)):
        raise ValueError("威胁映射目录无效")
    return data


def _context(db: Session, event: AuditEvent) -> tuple[str | None, str | None, str | None]:
    payload = event.payload if isinstance(event.payload, dict) else {}
    record_id = next((payload.get(key) for key in
                      ("decision_id", "assessment_id", "entity_id", "candidate_id", "incident_id")
                      if isinstance(payload.get(key), str)), None)
    row = None
    if record_id and event.event_type == "data_flow_decision":
        row = db.get(DataFlowDecision, record_id)
    elif record_id and event.event_type == "runtime_decision":
        row = db.get(RuntimeDecision, record_id)
    elif record_id and event.event_type == "goal_assessment":
        row = db.get(GoalAssessment, record_id)
    elif record_id and event.event_type == "memory_integrity":
        row = db.get(MemoryEntry, record_id)
    if row is not None:
        agent_id = getattr(row, "agent_id", None)
        session_id = (getattr(row, "session_id", None) or
                      getattr(row, "origin_session_id", None))
        return record_id, agent_id, session_id
    if event.call_id:
        call = db.get(ToolCall, event.call_id)
        if call:
            return record_id, call.agent_id, call.session_id
    agent_id = payload.get("agent_id")
    session_id = payload.get("session_id") or payload.get("origin_session_id")
    return (record_id, agent_id[:100] if isinstance(agent_id, str) else None,
            session_id[:100] if isinstance(session_id, str) else None)


def _source_tool_matches(db: Session, payload: dict, tool: str,
                         agent_id: str | None, session_id: str | None) -> bool:
    evidence = payload.get("evidence_ids")
    if not isinstance(evidence, list) or not agent_id or not session_id:
        return False
    from .delegation import linked_calls
    delegated_ids = {row.call_id for row in linked_calls(db, agent_id, session_id)}
    for source_id in evidence[:20]:
        if not isinstance(source_id, str):
            continue
        call = db.get(ToolCall, source_id)
        if (call and call.tool == tool and call.status == "completed"
                and ((call.agent_id == agent_id and call.session_id == session_id)
                     or call.call_id in delegated_ids)):
            return True
    return False


def _evidence_ids(payload: dict) -> list[str]:
    candidates = payload.get("source_ids") or payload.get("evidence_ids") or []
    if not isinstance(candidates, list):
        return []
    identifiers = []
    for value in candidates[:20]:
        if not isinstance(value, str):
            continue
        try:
            identifiers.append(str(uuid.UUID(value)))
        except ValueError:
            continue
    return identifiers


def _known_fixture_read(db: Session, event: AuditEvent, fixture_id: str) -> bool:
    """仅核实固定合成样本已实际返回；不保存样本文字。"""
    if not event.call_id:
        return False
    call = db.get(ToolCall, event.call_id)
    payload = event.payload if isinstance(event.payload, dict) else {}
    result = payload.get("result")
    if not (call and payload.get("tool") == "read_document"
            and call.tool == "read_document" and call.status == "completed"
            and call.decision == "allow" and isinstance(call.arguments, dict)
            and call.arguments.get("document_id") == fixture_id
            and isinstance(call.result, dict) and isinstance(result, dict)
            and call.result.get("document_id") == fixture_id
            and result.get("document_id") == fixture_id):
        return False
    from .tools import SEED_DOCUMENTS
    known = next((item for item in SEED_DOCUMENTS if item.id == fixture_id), None)
    return bool(known and call.result.get("content") == known.content
                and result.get("content") == known.content)


def classify(db: Session, event: AuditEvent, catalog: dict) -> tuple[list[dict],
                                                                       str | None, str | None, str | None]:
    """只读类型化事件字段；不把 Judge 标签或原文当成攻击事实。"""
    payload = event.payload if isinstance(event.payload, dict) else {}
    record_id, agent_id, session_id = _context(db, event)
    threats = {item["id"]: item for item in catalog["threats"]}
    atlas_urls = {item["id"]: item["url"] for item in catalog["atlas_techniques"]}
    matches = []
    for signal in catalog["runtime_signals"]:
        if event.event_type != signal["event_type"]:
            continue
        for key, expected in signal["when"].items():
            if key == "finding":
                findings = payload.get("findings")
                passed = isinstance(findings, list) and expected in findings
            elif key == "source_tool":
                passed = _source_tool_matches(db, payload, expected, agent_id, session_id)
            elif key == "fixture_document":
                passed = _known_fixture_read(db, event, expected)
            else:
                passed = payload.get(key) == expected
            if not passed:
                break
        else:
            evidence_ids = _evidence_ids(payload)
            effect = payload.get("effect")
            for threat_id in signal["threat_ids"]:
                threat = threats[threat_id]
                matches.append({"signal_id": signal["id"], "signal_title": signal["title"],
                    "threat_id": threat_id, "threat_title": threat["title"],
                    "owasp": list(threat["owasp"]), "atlas": list(threat["atlas"]),
                    "atlas_urls": {item: atlas_urls[item] for item in threat["atlas"]},
                    "effect": effect if isinstance(effect, str) and effect in {
                        "allow", "deny", "block", "quarantined", "rejected"} else None,
                    "evidence_ids": evidence_ids,
                    "interpretation": "已观察到线索；不证明攻击或副作用成功"})
    return matches, record_id, agent_id, session_id


def project_once(db: Session, limit: int = 100, *, catalog: dict | None = None,
                 now: datetime | None = None) -> int:
    """独立投影已提交事件；旧版记录不改写，新版本只处理启用后的事件。"""
    catalog = catalog or load_catalog()
    now = now or utcnow()
    version = catalog["mapping_version"]
    state = db.get(ThreatMappingState, "active", with_for_update=True)
    if state is None:
        state = ThreatMappingState(id="active", mapping_version=version,
            activated_at=now, backfill_since=now - timedelta(days=BACKFILL_DAYS))
        db.add(state)
        db.flush()
    elif state.mapping_version != version:
        state.mapping_version = version
        state.activated_at = now
        # 保留尚未投影的事件，同时不重新判定任何已有映射的历史事件。
        state.backfill_since = max(_aware(state.backfill_since),
                                   _aware(now) - timedelta(days=BACKFILL_DAYS))
        state.last_error = None
    current = aliased(ThreatMappingAssessment)
    prior_match = aliased(ThreatMappingAssessment)
    rows = db.scalars(select(AuditEvent)
        .outerjoin(current, and_(current.audit_event_id == AuditEvent.id,
                                 current.mapping_version == version))
        .outerjoin(prior_match, and_(prior_match.audit_event_id == AuditEvent.id,
                                     prior_match.status == "matched"))
        .where(AuditEvent.created_at >= state.backfill_since,
               current.id.is_(None), prior_match.id.is_(None))
        .order_by(AuditEvent.created_at, AuditEvent.id).limit(limit)).all()
    for event in rows:
        matches, record_id, agent_id, session_id = classify(db, event, catalog)
        db.add(ThreatMappingAssessment(id=str(uuid.uuid4()), audit_event_id=event.id,
            mapping_version=version, event_type=event.event_type,
            source_record_id=record_id, call_id=event.call_id,
            agent_id=agent_id, session_id=session_id,
            origin=("historical_backfill" if _aware(event.created_at) < _aware(state.activated_at)
                    else "live"),
            status="matched" if matches else "unmapped", matches=matches,
            observed_at=event.created_at))
    state.last_projected_at = now
    state.last_error = None
    db.commit()
    return len(rows)


def projection_health(db: Session, *, catalog: dict | None = None) -> dict:
    catalog = catalog or load_catalog()
    state = db.get(ThreatMappingState, "active")
    if state is None:
        return {"version": catalog["mapping_version"], "status": "not_started",
                "pending": None, "last_error": None}
    current = aliased(ThreatMappingAssessment)
    prior_match = aliased(ThreatMappingAssessment)
    pending = db.scalar(select(func.count()).select_from(AuditEvent)
        .outerjoin(current, and_(current.audit_event_id == AuditEvent.id,
                                 current.mapping_version == state.mapping_version))
        .outerjoin(prior_match, and_(prior_match.audit_event_id == AuditEvent.id,
                                     prior_match.status == "matched"))
        .where(AuditEvent.created_at >= state.backfill_since,
               current.id.is_(None), prior_match.id.is_(None))) or 0
    return {"version": state.mapping_version, "status": "failed" if state.last_error else
            "pending" if pending else "current", "pending": pending,
            "last_error": state.last_error,
            "last_projected_at": state.last_projected_at.isoformat() if state.last_projected_at else None}
