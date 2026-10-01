from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    sensitivity: Mapped[str] = mapped_column(String(20))


class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)


class ExternalMessage(Base):
    __tablename__ = "external_messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    destination_id: Mapped[str] = mapped_column(String(100))
    content: Mapped[str] = mapped_column(Text)


class CapabilityGrant(Base):
    __tablename__ = "capability_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[str] = mapped_column(String(100))
    tool: Mapped[str] = mapped_column(String(100))
    resources: Mapped[list] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_uses: Mapped[int] = mapped_column(Integer)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    call_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100))
    agent_id: Mapped[str] = mapped_column(String(100))
    tool: Mapped[str] = mapped_column(String(100))
    arguments: Mapped[dict] = mapped_column(JSON)
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(32))
    policy_rule: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(300), nullable=True)
    grant_id: Mapped[str | None] = mapped_column(ForeignKey("capability_grants.id"), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approval_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DataFlowDecision(Base):
    __tablename__ = "data_flow_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    related_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    sink: Mapped[str] = mapped_column(String(40), index=True)
    destination: Mapped[str] = mapped_column(String(200))
    source_ids: Mapped[list] = mapped_column(JSON)
    sensitivity: Mapped[str] = mapped_column(String(20))
    effect: Mapped[str] = mapped_column(String(32))
    findings: Mapped[list] = mapped_column(JSON)
    request_hash: Mapped[str] = mapped_column(String(64))
    rules_version: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DataFlowIncident(Base):
    __tablename__ = "data_flow_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    decision_id: Mapped[str] = mapped_column(ForeignKey("data_flow_decisions.id"), unique=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    finding: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeSession(Base):
    __tablename__ = "runtime_sessions"

    agent_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    reported: Mapped[bool] = mapped_column(Boolean, default=True)
    transport: Mapped[str | None] = mapped_column(String(20), nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    capture_mode: Mapped[str] = mapped_column(String(20), default="preview")
    task_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    task_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    goal_profile: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    goal_profile_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    answer_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    task_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    answer_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="running")
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    review_status: Mapped[str] = mapped_column(String(20), default="unreviewed")
    review_note: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RuntimeDecision(Base):
    __tablename__ = "runtime_decisions"
    __table_args__ = (UniqueConstraint("call_id", "phase"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    call_id: Mapped[str] = mapped_column(ForeignKey("tool_calls.call_id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    phase: Mapped[str] = mapped_column(String(20))
    effect: Mapped[str] = mapped_column(String(32))
    rules_version: Mapped[str] = mapped_column(String(30))
    findings: Mapped[list] = mapped_column(JSON)
    evidence: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoalAssessment(Base):
    __tablename__ = "goal_assessments"
    __table_args__ = (UniqueConstraint("call_id", "phase"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    output_check_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    phase: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(24))
    findings: Mapped[list] = mapped_column(JSON)
    evidence_ids: Mapped[list] = mapped_column(JSON)
    rules_version: Mapped[str] = mapped_column(String(40))
    model_status: Mapped[str] = mapped_column(String(20), default="disabled")
    model_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GoalLabRun(Base):
    __tablename__ = "goal_lab_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(20))
    corpus_version: Mapped[str] = mapped_column(String(40))
    corpus_hash: Mapped[str] = mapped_column(String(64))
    scoring_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    goal_rules_version: Mapped[str] = mapped_column(String(40))
    policy_revision: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    expected_cases: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GoalLabCase(Base):
    __tablename__ = "goal_lab_cases"

    run_id: Mapped[str] = mapped_column(ForeignKey("goal_lab_runs.id"), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    repetition: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(32))
    attempted: Mapped[bool] = mapped_column(Boolean, default=False)
    gateway_blocked: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    preapproval_effect: Mapped[bool] = mapped_column(Boolean, default=False)
    forbidden_effect: Mapped[bool] = mapped_column(Boolean, default=False)
    draft_contamination: Mapped[bool] = mapped_column(Boolean, default=False)
    displayed_contamination: Mapped[bool] = mapped_column(Boolean, default=False)
    normal_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    audit_missing: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeControl(Base):
    __tablename__ = "runtime_controls"

    key: Mapped[str] = mapped_column(String(210), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(300), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeControlChange(Base):
    __tablename__ = "runtime_control_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_key: Mapped[str] = mapped_column(String(210), index=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    paused: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(300))
    actor: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionChainState(Base):
    __tablename__ = "action_chain_states"

    agent_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    rules_version: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionChainDecision(Base):
    __tablename__ = "action_chain_decisions"
    __table_args__ = (UniqueConstraint("reference_id", "phase"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    reference_id: Mapped[str] = mapped_column(String(36), index=True)
    phase: Mapped[str] = mapped_column(String(32))
    effect: Mapped[str] = mapped_column(String(20))
    findings: Mapped[list] = mapped_column(JSON)
    evidence_ids: Mapped[list] = mapped_column(JSON)
    counters: Mapped[dict] = mapped_column(JSON)
    rules_version: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeIncident(Base):
    __tablename__ = "runtime_incidents"
    __table_args__ = (UniqueConstraint("decision_id", "rule_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    decision_id: Mapped[str] = mapped_column(ForeignKey("runtime_decisions.id"), index=True)
    call_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    rule_id: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeAdapterAttempt(Base):
    __tablename__ = "runtime_adapter_attempts"

    agent_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool: Mapped[str] = mapped_column(String(100))
    error_code: Mapped[str] = mapped_column(String(80))


class OutputCheck(Base):
    __tablename__ = "output_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    capture_mode: Mapped[str] = mapped_column(String(20))
    output_kind: Mapped[str] = mapped_column(String(20))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(20))
    rules_version: Mapped[str] = mapped_column(String(30))
    findings: Mapped[list] = mapped_column(JSON)
    sources: Mapped[list] = mapped_column(JSON)
    sentences: Mapped[list] = mapped_column(JSON)
    model_hint: Mapped[dict] = mapped_column(JSON, default=dict)
    draft_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemoryWrite(Base):
    __tablename__ = "memory_writes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    output_check_id: Mapped[str] = mapped_column(String(36))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    entry_ids: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrustedMemorySource(Base):
    __tablename__ = "trusted_memory_sources"
    __table_args__ = (UniqueConstraint("tool", "resource_id", "content_hash"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool: Mapped[str] = mapped_column(String(40))
    resource_id: Mapped[str] = mapped_column(String(100))
    content_hash: Mapped[str] = mapped_column(String(64))
    reviewed_call_id: Mapped[str] = mapped_column(String(36))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrustedSourceSeal(Base):
    __tablename__ = "trusted_source_seals"
    source_id: Mapped[str] = mapped_column(ForeignKey("trusted_memory_sources.id"), primary_key=True)
    version: Mapped[str] = mapped_column(String(20))
    tag: Mapped[str] = mapped_column(String(64))


class MemoryEntry(Base):
    __tablename__ = "memory_entries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    write_id: Mapped[str] = mapped_column(ForeignKey("memory_writes.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    origin_session_id: Mapped[str] = mapped_column(String(100), index=True)
    text: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), index=True)
    trust_level: Mapped[str] = mapped_column(String(20), default="untrusted")
    findings: Mapped[list] = mapped_column(JSON)
    source_call_ids: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MemorySeal(Base):
    __tablename__ = "memory_seals"
    memory_id: Mapped[str] = mapped_column(ForeignKey("memory_entries.id"), primary_key=True)
    version: Mapped[str] = mapped_column(String(20))
    tag: Mapped[str] = mapped_column(String(64))


class MemoryIntegrityIncident(Base):
    __tablename__ = "memory_integrity_incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(30))
    entity_id: Mapped[str] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemoryRead(Base):
    __tablename__ = "memory_reads"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    query_hash: Mapped[str] = mapped_column(String(64))
    memory_ids: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemoryFailure(Base):
    __tablename__ = "memory_failures"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    stage: Mapped[str] = mapped_column(String(20))
    error_code: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    call_id: Mapped[str] = mapped_column(ForeignKey("tool_calls.call_id"), unique=True)
    arguments_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(50))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class McpProfileVersion(Base):
    __tablename__ = "mcp_profile_versions"
    __table_args__ = (UniqueConstraint("endpoint_id", "revision"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(80), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    config_hash: Mapped[str] = mapped_column(String(64))
    config_facts: Mapped[dict] = mapped_column(JSON)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[list | None] = mapped_column(JSON, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_by: Mapped[str] = mapped_column(String(40))


class McpProfileChange(Base):
    __tablename__ = "mcp_profile_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(80), index=True)
    config_hash: Mapped[str] = mapped_column(String(64))
    config_facts: Mapped[dict] = mapped_column(JSON)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class McpSupplyIncident(Base):
    __tablename__ = "mcp_supply_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(80), index=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(40))
    expected_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ThreatMappingState(Base):
    __tablename__ = "threat_mapping_state"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="active")
    mapping_version: Mapped[str] = mapped_column(String(30))
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    backfill_since: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_projected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)


class ThreatMappingAssessment(Base):
    __tablename__ = "threat_mapping_assessments"
    __table_args__ = (UniqueConstraint("audit_event_id", "mapping_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_event_id: Mapped[str] = mapped_column(ForeignKey("audit_events.id"), index=True)
    mapping_version: Mapped[str] = mapped_column(String(30), index=True)
    event_type: Mapped[str] = mapped_column(String(50))
    source_record_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    origin: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(20))
    matches: Mapped[list] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    mapped_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkerPrincipal(Base):
    __tablename__ = "worker_principals"
    agent_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    generation: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Delegation(Base):
    __tablename__ = "delegations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    parent_agent_id: Mapped[str] = mapped_column(String(100))
    parent_session_id: Mapped[str] = mapped_column(String(100))
    parent_binding_hash: Mapped[str] = mapped_column(String(64))
    parent_grant_id: Mapped[str] = mapped_column(ForeignKey("capability_grants.id"))
    worker_agent_id: Mapped[str] = mapped_column(String(100))
    worker_generation: Mapped[int] = mapped_column(Integer)
    worker_session_id: Mapped[str] = mapped_column(String(100))
    tool: Mapped[str] = mapped_column(String(100))
    resources: Mapped[list] = mapped_column(JSON)
    max_uses: Mapped[int] = mapped_column(Integer)
    remaining: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    envelope_hmac: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="created", index=True)
    output_check_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_content_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_call_ids: Mapped[list] = mapped_column(JSON, default=list)
    transferred: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DelegationCall(Base):
    __tablename__ = "delegation_calls"
    call_id: Mapped[str] = mapped_column(ForeignKey("tool_calls.call_id"), primary_key=True)
    delegation_id: Mapped[str] = mapped_column(ForeignKey("delegations.id"), index=True)
    charged: Mapped[bool] = mapped_column(Boolean, default=False)


class DelegationLabRun(Base):
    __tablename__ = "delegation_lab_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(24))
    results: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DependencyState(Base):
    """每个租户 schema 的依赖隔离状态，不保存请求原文。"""
    __tablename__ = "dependency_states"
    dependency: Mapped[str] = mapped_column(String(160), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    open_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    probe_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DependencyAttempt(Base):
    __tablename__ = "dependency_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    dependency: Mapped[str] = mapped_column(String(160), index=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="executing", index=True)
    outcome: Mapped[str | None] = mapped_column(String(100), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class QueueLease(Base):
    """投递与处理的独立代次凭据；迟到 Worker 不能覆盖新代次。"""
    __tablename__ = "queue_leases"
    kind: Mapped[str] = mapped_column(String(20), primary_key=True)
    record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token: Mapped[str] = mapped_column(String(36))
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    publish_failures: Mapped[int] = mapped_column(Integer, default=0)


class FaultLabRun(Base):
    __tablename__ = "fault_lab_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    results: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    audit_event_id: Mapped[str] = mapped_column(ForeignKey("audit_events.id"), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class JudgeRuntimeConfig(Base):
    __tablename__ = "judge_runtime_config"
    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="active")
    provider: Mapped[str] = mapped_column(String(40))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JudgeRuntimeChange(Base):
    __tablename__ = "judge_runtime_changes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    previous_provider: Mapped[str | None] = mapped_column(String(40), nullable=True)
    provider: Mapped[str] = mapped_column(String(40))
    revision: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(100))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JudgeRoute(Base):
    __tablename__ = "judge_routes"
    outbox_id: Mapped[str] = mapped_column(ForeignKey("outbox.id"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(40))
    model_name: Mapped[str] = mapped_column(String(120))
    endpoint_hash: Mapped[str] = mapped_column(String(64))
    config_revision: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JudgeResult(Base):
    __tablename__ = "judge_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    outbox_id: Mapped[str] = mapped_column(ForeignKey("outbox.id"), unique=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    labels: Mapped[list] = mapped_column(JSON)
    score: Mapped[float] = mapped_column(Float)
    provider: Mapped[str] = mapped_column(String(40))
    model_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    judge_result_id: Mapped[str] = mapped_column(ForeignKey("judge_results.id"), unique=True)
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertGroup(Base):
    __tablename__ = "alert_groups"
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(40))
    labels: Mapped[list] = mapped_column(JSON)
    event_type: Mapped[str] = mapped_column(String(50))
    tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    latest_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_alert_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), unique=True)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class JudgeSample(Base):
    __tablename__ = "judge_samples"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    event_type: Mapped[str] = mapped_column(String(50))
    payload: Mapped[dict] = mapped_column(JSON)
    expected_labels: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JudgeSampleRun(Base):
    __tablename__ = "judge_sample_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("judge_samples.id", ondelete="SET NULL"), nullable=True, index=True)
    outbox_id: Mapped[str] = mapped_column(ForeignKey("outbox.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AttackRun(Base):
    __tablename__ = "attack_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="running")
    corpus_version: Mapped[str] = mapped_column(String(30))
    corpus_hash: Mapped[str] = mapped_column(String(64))
    policy_revision: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    model_host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    expected_cases: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AttackCaseResult(Base):
    __tablename__ = "attack_case_results"
    run_id: Mapped[str] = mapped_column(ForeignKey("attack_runs.id"), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    outcome: Mapped[str] = mapped_column(String(30))
    attempted: Mapped[bool] = mapped_column(Boolean, default=False)
    forbidden_execution: Mapped[bool] = mapped_column(Boolean, default=False)
    answer_contaminated: Mapped[bool] = mapped_column(Boolean, default=False)
    normal_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    call_ids: Mapped[list] = mapped_column(JSON)
    trace: Mapped[list] = mapped_column(JSON)
    final_answer: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CalibrationRun(Base):
    __tablename__ = "calibration_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="running")
    corpus_version: Mapped[str] = mapped_column(String(40))
    corpus_hash: Mapped[str] = mapped_column(String(64))
    policy_revision: Mapped[str] = mapped_column(String(64))
    runtime_rules_version: Mapped[str] = mapped_column(String(40))
    data_flow_rules_version: Mapped[str] = mapped_column(String(40))
    model_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    model_host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    expected_cases: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CalibrationCaseResult(Base):
    __tablename__ = "calibration_case_results"

    run_id: Mapped[str] = mapped_column(ForeignKey("calibration_runs.id"), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    repetition: Mapped[int] = mapped_column(Integer, primary_key=True)
    split: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(20))
    sink: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(String(32))
    attempted: Mapped[bool] = mapped_column(Boolean, default=False)
    gateway_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    forbidden_side_effect: Mapped[bool] = mapped_column(Boolean, default=False)
    draft_contaminated: Mapped[bool] = mapped_column(Boolean, default=False)
    displayed_contaminated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    normal_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    friction: Mapped[bool] = mapped_column(Boolean, default=False)
    audit_missing: Mapped[int] = mapped_column(Integer, default=0)
    session_id: Mapped[str] = mapped_column(String(100))
    call_ids: Mapped[list] = mapped_column(JSON)
    data_flow_ids: Mapped[list] = mapped_column(JSON)
    output_check_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    memory_ids: Mapped[list] = mapped_column(JSON)
    rule_ids: Mapped[list] = mapped_column(JSON)
    trace: Mapped[list] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemoryLabRun(Base):
    __tablename__ = "memory_lab_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="running")
    corpus_version: Mapped[str] = mapped_column(String(30))
    corpus_hash: Mapped[str] = mapped_column(String(64))
    policy_revision: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    expected_cases: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MemoryLabCase(Base):
    __tablename__ = "memory_lab_cases"
    run_id: Mapped[str] = mapped_column(ForeignKey("memory_lab_runs.id"), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    write_session_id: Mapped[str] = mapped_column(String(100))
    read_session_id: Mapped[str] = mapped_column(String(100))
    memory_ids: Mapped[list] = mapped_column(JSON)
    read_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    output_check_ids: Mapped[list] = mapped_column(JSON)
    call_ids: Mapped[list] = mapped_column(JSON)
    write_finished: Mapped[bool] = mapped_column(Boolean)
    read_finished: Mapped[bool] = mapped_column(Boolean)
    second_answer: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MemorySecurityRun(Base):
    __tablename__ = "memory_security_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    corpus_version: Mapped[str] = mapped_column(String(30))
    corpus_hash: Mapped[str] = mapped_column(String(64))
    expected_cases: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MemorySecurityCase(Base):
    __tablename__ = "memory_security_cases"
    run_id: Mapped[str] = mapped_column(ForeignKey("memory_security_runs.id"), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    memory_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    read_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    write_status: Mapped[str] = mapped_column(String(20))
    recalled: Mapped[bool] = mapped_column(Boolean)
    incident_count: Mapped[int] = mapped_column(Integer)
    passed: Mapped[bool] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
