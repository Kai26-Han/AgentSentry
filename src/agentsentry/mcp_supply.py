"""租户隔离的 MCP 接入档案。只批准固定工具定义，不推断远端程序可信。"""

import hashlib
import json
import uuid
from datetime import timedelta
from pathlib import Path

from mcp.types import Tool
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import McpProfileChange, McpProfileVersion, McpSupplyIncident, utcnow


ENDPOINT_ID = "remote-demo"
MAX_MANIFEST_BYTES = 32768


def _lock_profile(db: Session) -> None:
    """Serialize competing approvals for this tenant and endpoint."""
    if db.get_bind().dialect.name == "postgresql":
        tenant = db.info.get("tenant_id", "default")
        digest = hashlib.sha256(f"{tenant}:{ENDPOINT_ID}".encode()).digest()
        key = int.from_bytes(digest[:8], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def config_facts(entry: dict) -> dict:
    """Only public endpoint identity, never OAuth client secrets or bearer tokens."""
    facts = {key: entry[key] for key in (
        "endpoint_id", "url", "token_url", "jwks_url", "issuer", "audience", "client_id")}
    if entry.get("ca_bundle"):
        facts["ca_sha256"] = hashlib.sha256(Path(entry["ca_bundle"]).read_bytes()).hexdigest()
    elif entry.get("ca_pem_b64"):
        import base64
        facts["ca_sha256"] = hashlib.sha256(base64.b64decode(entry["ca_pem_b64"])).hexdigest()
    else:
        facts["ca_sha256"] = "system-trust-store"
    return facts


def config_hash(entry: dict) -> str:
    return hashlib.sha256(json.dumps(config_facts(entry), sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def active_profile(db: Session, *, hold_for_call: bool = False) -> McpProfileVersion | None:
    query = select(McpProfileVersion).where(
        McpProfileVersion.endpoint_id == ENDPOINT_ID,
        McpProfileVersion.active.is_(True)).order_by(
            McpProfileVersion.revision.desc()).execution_options(populate_existing=True)
    if hold_for_call and db.get_bind().dialect.name == "postgresql":
        query = query.with_for_update(read=True)
    return db.scalar(query)


def seed_baseline(db: Session, entry: dict) -> McpProfileVersion:
    """Existing registry hash is the initial administrator-approved baseline only."""
    profile = active_profile(db)
    if profile:
        return profile
    _lock_profile(db)
    profile = active_profile(db)
    if profile:
        return profile
    profile = McpProfileVersion(
        id=str(uuid.uuid4()), endpoint_id=ENDPOINT_ID, revision=1,
        config_hash=config_hash(entry), config_facts=config_facts(entry),
        manifest_sha256=entry["manifest_sha256"], manifest=None, active=True,
        approved_by="initial_registry")
    db.add(profile)
    db.flush()
    return profile


def manifest_snapshot(tools: list) -> list[dict]:
    if len(tools) > 20:
        raise ValueError("Remote MCP manifest oversized")
    snapshot = [tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                for tool in sorted(tools, key=lambda item: item.name)]
    raw = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Remote MCP manifest oversized")
    return snapshot


def snapshot_hash(snapshot: list[dict]) -> str:
    raw = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Remote MCP manifest oversized")
    return hashlib.sha256(raw).hexdigest()


def record_candidate(db: Session, entry: dict, snapshot: list[dict]) -> McpProfileChange:
    digest = snapshot_hash(snapshot)
    identity = config_hash(entry)
    existing = db.scalar(select(McpProfileChange).where(
        McpProfileChange.endpoint_id == ENDPOINT_ID,
        McpProfileChange.config_hash == identity,
        McpProfileChange.manifest_sha256 == digest,
        McpProfileChange.status == "pending"))
    if existing:
        return existing
    row = McpProfileChange(id=str(uuid.uuid4()), endpoint_id=ENDPOINT_ID,
                           config_hash=identity, config_facts=config_facts(entry),
                           manifest_sha256=digest, manifest=snapshot, status="pending")
    db.add(row)
    from .service import audit
    current = active_profile(db)
    reason = ("remote_mcp_profile_drift" if current and current.config_hash != identity
              else "remote_mcp_manifest_drift")
    audit(db, None, "mcp_profile_observed", {
        "endpoint_id": ENDPOINT_ID, "candidate_id": row.id,
        "config_hash": identity, "manifest_sha256": digest,
        "reason": reason}, judge=False)
    db.flush()
    return row


def record_incident(db: Session, kind: str, *, call_id: str | None = None,
                    expected_sha256: str | None = None,
                    observed_sha256: str | None = None) -> McpSupplyIncident:
    row = McpSupplyIncident(id=str(uuid.uuid4()), endpoint_id=ENDPOINT_ID,
                            call_id=call_id, kind=kind,
                            expected_sha256=expected_sha256,
                            observed_sha256=observed_sha256)
    db.add(row)
    from .service import audit
    audit(db, call_id, "mcp_supply_incident", {
        "endpoint_id": ENDPOINT_ID, "incident_id": row.id, "kind": kind,
        "expected_sha256": expected_sha256, "observed_sha256": observed_sha256,
        "reason": "remote_mcp_behavior_drift" if kind == "behavior_canary" else kind}, judge=False)
    return row


def _fixed_tools(snapshot: list[dict]) -> bool:
    from .mcp_remote import UPSTREAM, _validate_tool
    required = {name: fields for name, _, fields in UPSTREAM.values()}
    if not isinstance(snapshot, list) or len(snapshot) != len(required):
        return False
    try:
        tools = [Tool.model_validate(item) for item in snapshot]
        if {tool.name for tool in tools} != set(required):
            return False
        for tool in tools:
            _validate_tool(tool, tool.name, required[tool.name])
    except (ValueError, TypeError, KeyError):
        return False
    return True


def review_summary(current: McpProfileVersion | None,
                   candidate: McpProfileChange) -> dict:
    old_facts = current.config_facts if current else {}
    changed_facts = sorted(key for key in set(old_facts) | set(candidate.config_facts)
                           if old_facts.get(key) != candidate.config_facts.get(key))
    old_tools = {item.get("name"): item for item in (current.manifest or [])} if current else {}
    new_tools = {item.get("name"): item for item in candidate.manifest}
    return {"changed_facts": changed_facts,
            "added_tools": sorted(set(new_tools) - set(old_tools)),
            "removed_tools": sorted(set(old_tools) - set(new_tools)),
            "changed_tools": sorted(name for name in set(old_tools) & set(new_tools)
                                    if old_tools[name] != new_tools[name]),
            "old_definition_available": bool(current and current.manifest),
            "approvable": _fixed_tools(candidate.manifest)}


def decide_candidate(db: Session, entry: dict, candidate_id: str, decision: str) -> McpProfileChange:
    if decision not in {"approve", "reject"}:
        raise ValueError("Invalid MCP change decision")
    _lock_profile(db)
    row = db.get(McpProfileChange, candidate_id, with_for_update=True)
    if not row or row.endpoint_id != ENDPOINT_ID or row.status != "pending":
        raise ValueError("MCP change is not pending")
    if row.created_at.replace(tzinfo=utcnow().tzinfo) < utcnow() - timedelta(minutes=10):
        raise ValueError("MCP observation expired; scan again")
    if row.config_hash != config_hash(entry) or row.manifest_sha256 != snapshot_hash(row.manifest):
        raise ValueError("MCP observation or registration changed; scan again")
    if decision == "approve" and not _fixed_tools(row.manifest):
        raise ValueError("New or changed tools require code registration and tests")
    if decision == "approve":
        current = active_profile(db)
        if current:
            current.active = False
        latest = db.scalar(select(McpProfileVersion).where(
            McpProfileVersion.endpoint_id == ENDPOINT_ID).order_by(
                McpProfileVersion.revision.desc()))
        db.add(McpProfileVersion(
            id=str(uuid.uuid4()), endpoint_id=ENDPOINT_ID,
            revision=(latest.revision + 1 if latest else 1),
            config_hash=row.config_hash, config_facts=row.config_facts,
            manifest_sha256=row.manifest_sha256, manifest=row.manifest,
            active=True, approved_by="administrator"))
    row.status = "approved" if decision == "approve" else "rejected"
    row.decided_at = utcnow()
    from .service import audit
    audit(db, None, "mcp_profile_decision", {
        "endpoint_id": ENDPOINT_ID, "candidate_id": row.id,
        "decision": row.status, "config_hash": row.config_hash,
        "manifest_sha256": row.manifest_sha256}, judge=False)
    db.commit()
    return row


def rollback_profile(db: Session, entry: dict, revision: int) -> McpProfileVersion:
    _lock_profile(db)
    current = active_profile(db)
    target = db.scalar(select(McpProfileVersion).where(
        McpProfileVersion.endpoint_id == ENDPOINT_ID,
        McpProfileVersion.revision == revision).with_for_update())
    if not current or not target or target.id == current.id:
        raise ValueError("Unknown or already active MCP profile revision")
    if target.config_hash != config_hash(entry):
        raise ValueError("Previous endpoint identity differs from current registration")
    current.active = False
    target.active = True
    from .service import audit
    audit(db, None, "mcp_profile_rollback", {
        "endpoint_id": ENDPOINT_ID, "from_revision": current.revision,
        "to_revision": target.revision, "manifest_sha256": target.manifest_sha256}, judge=False)
    db.commit()
    return target


def scrub_observations(db: Session) -> int:
    """Keep hashes and decisions while removing old upstream-controlled prose."""
    now = utcnow()
    expired = db.scalars(select(McpProfileChange).where(
        McpProfileChange.status == "pending",
        McpProfileChange.created_at < now - timedelta(minutes=10))).all()
    for row in expired:
        row.status = "expired"
        row.decided_at = now
    old_changes = db.scalars(select(McpProfileChange).where(
        McpProfileChange.created_at < now - timedelta(days=30))).all()
    old_versions = db.scalars(select(McpProfileVersion).where(
        McpProfileVersion.active.is_(False),
        McpProfileVersion.approved_at < now - timedelta(days=30))).all()
    count = len(expired)
    for row in old_changes:
        if row.manifest:
            row.manifest = []
            count += 1
    for row in old_versions:
        if row.manifest:
            row.manifest = None
            count += 1
    if count:
        db.commit()
    return count
