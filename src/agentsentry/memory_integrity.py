"""对租户记忆与来源审核状态做域隔离的完整性校验。"""

import hashlib
import hmac
import json
import uuid
from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import (MemoryEntry, MemoryIntegrityIncident, MemorySeal,
                     TrustedMemorySource, TrustedSourceSeal)
from .service import audit


SEAL_VERSION = "v1"


def _time(value) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(
        timezone.utc).isoformat()


def _tag(db: Session, kind: str, payload: dict) -> str:
    root = get_settings().session_secret.encode()
    key = hmac.new(root, b"AgentSentry.memory.integrity.v1", hashlib.sha256).digest()
    raw = json.dumps({"tenant_id": db.info.get("tenant_id", "default"), "kind": kind,
                      "version": SEAL_VERSION, "payload": payload},
                     ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def _memory_payload(row: MemoryEntry) -> dict:
    return {"id": row.id, "write_id": row.write_id, "agent_id": row.agent_id,
            "origin_session_id": row.origin_session_id, "kind": row.kind,
            "text": row.text, "text_hash": row.text_hash, "status": row.status,
            "trust_level": row.trust_level, "findings": row.findings,
            "source_call_ids": row.source_call_ids, "expires_at": _time(row.expires_at),
            "created_at": _time(row.created_at)}


def _source_payload(row: TrustedMemorySource) -> dict:
    return {"id": row.id, "tool": row.tool, "resource_id": row.resource_id,
            "content_hash": row.content_hash, "reviewed_call_id": row.reviewed_call_id,
            "revoked_at": _time(row.revoked_at), "created_at": _time(row.created_at)}


def seal_memory(db: Session, row: MemoryEntry) -> None:
    db.flush()
    seal = db.get(MemorySeal, row.id)
    if seal is None:
        seal = MemorySeal(memory_id=row.id, version=SEAL_VERSION, tag="")
        db.add(seal)
    seal.version = SEAL_VERSION
    seal.tag = _tag(db, "memory", _memory_payload(row))


def seal_source(db: Session, row: TrustedMemorySource) -> None:
    db.flush()
    seal = db.get(TrustedSourceSeal, row.id)
    if seal is None:
        seal = TrustedSourceSeal(source_id=row.id, version=SEAL_VERSION, tag="")
        db.add(seal)
    seal.version = SEAL_VERSION
    seal.tag = _tag(db, "source_review", _source_payload(row))


def _incident(db: Session, entity_type: str, entity_id: str, reason: str) -> None:
    previous = db.scalar(select(MemoryIntegrityIncident).where(
        MemoryIntegrityIncident.entity_type == entity_type,
        MemoryIntegrityIncident.entity_id == entity_id,
        MemoryIntegrityIncident.reason == reason))
    if previous:
        return
    db.add(MemoryIntegrityIncident(id=str(uuid.uuid4()), entity_type=entity_type,
                                   entity_id=entity_id, reason=reason))
    audit(db, None, "memory_integrity", {"entity_type": entity_type,
          "entity_id": entity_id, "reason": reason, "seal_version": SEAL_VERSION})


def verify_memory(db: Session, row: MemoryEntry) -> bool:
    seal = db.get(MemorySeal, row.id)
    if seal is None:
        _incident(db, "memory", row.id, "missing_seal")
        return False
    if seal.version != SEAL_VERSION or not hmac.compare_digest(
            seal.tag, _tag(db, "memory", _memory_payload(row))):
        _incident(db, "memory", row.id, "seal_mismatch")
        return False
    return True


def verify_source(db: Session, row: TrustedMemorySource) -> bool:
    seal = db.get(TrustedSourceSeal, row.id)
    if seal is None:
        _incident(db, "source_review", row.id, "missing_seal")
        return False
    if seal.version != SEAL_VERSION or not hmac.compare_digest(
            seal.tag, _tag(db, "source_review", _source_payload(row))):
        _incident(db, "source_review", row.id, "seal_mismatch")
        return False
    return True


def migrate_unsealed(db: Session) -> int:
    """历史数据只进入复核队列，绝不根据旧内容自动补签。"""
    changed = 0
    for row in db.scalars(select(MemoryEntry)).all():
        if db.get(MemorySeal, row.id) is None:
            if row.status == "active":
                row.status = "quarantined"
                row.findings = list(dict.fromkeys([*(row.findings or []), "legacy_unverified"]))
                changed += 1
            _incident(db, "memory", row.id, "legacy_unsealed")
    for row in db.scalars(select(TrustedMemorySource)).all():
        if db.get(TrustedSourceSeal, row.id) is None:
            if row.revoked_at is None:
                from .models import utcnow
                row.revoked_at = utcnow()
                changed += 1
            _incident(db, "source_review", row.id, "legacy_unsealed")
    db.commit()
    return changed


def list_incidents(db: Session) -> list[dict]:
    return [{"id": row.id, "entity_type": row.entity_type,
             "entity_id": row.entity_id, "reason": row.reason,
             "created_at": _time(row.created_at)} for row in db.scalars(
        select(MemoryIntegrityIncident).order_by(
            MemoryIntegrityIncident.created_at.desc()).limit(200)).all()]
