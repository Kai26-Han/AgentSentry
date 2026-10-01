"""日常威胁映射只用可核实元数据，并与原安全决定隔离。"""

from copy import deepcopy
from datetime import timedelta, timezone
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from agentsentry import main
from agentsentry.config import get_settings
from agentsentry.database import (_sqlite_tenant_engine, get_engine, get_session_factory,
                                  tenant_db_session)
from agentsentry.evaluation import MemoryRedis
from agentsentry.models import (AuditEvent, DataFlowDecision, DataFlowIncident,
                               GoalAssessment, ThreatMappingAssessment,
                               ThreatMappingState, ToolCall, utcnow)
from agentsentry.threat_mapping import classify, load_catalog, project_once, projection_health
from agentsentry.tools import SEED_DOCUMENTS


def _event(event_type: str, payload: dict, call_id: str | None = None) -> AuditEvent:
    return AuditEvent(id=str(uuid.uuid4()), call_id=call_id,
                      event_type=event_type, payload=payload)


def test_projector_matches_typed_signals_and_leaves_unknown_unmapped(lab):
    db, _, _ = lab
    catalog = load_catalog()
    events = [
        _event("data_flow_decision", {"sink": "answer", "effect": "block",
            "findings": ["source_action_payload_in_answer"],
            "agent_id": "demo-agent", "session_id": "answer-1",
            "source_ids": ["SYNTHETIC_RAW_SECRET_42", str(uuid.uuid4())]}),
        _event("data_flow_decision", {"sink": "tool:submit", "destination": "send_external",
            "effect": "deny", "findings": ["external_after_private"],
            "agent_id": "demo-agent", "session_id": "external-1"}),
        _event("data_flow_decision", {"sink": "model", "effect": "deny",
            "findings": ["model_remote_sensitive"],
            "agent_id": "demo-agent", "session_id": "model-1"}),
        _event("data_flow_decision", {"sink": "memory", "effect": "quarantined",
            "findings": ["cross_session_command"],
            "agent_id": "demo-agent", "session_id": "memory-1"}),
        _event("memory_integrity", {"entity_type": "memory", "entity_id": "memory-1",
            "reason": "seal_mismatch"}),
        _event("goal_assessment", {"phase": "submit", "status": "suspected",
            "findings": ["source_authority_spoof"], "evidence_ids": [],
            "agent_id": "demo-agent", "session_id": "approval-1"}),
        _event("runtime_decision", {"effect": "deny",
            "findings": ["session_binding_invalid"],
            "agent_id": "demo-agent", "session_id": "identity-1"}),
        _event("action_chain_decision", {"phase": "submit", "effect": "deny",
            "findings": ["denied_resource_probe"],
            "agent_id": "demo-agent", "session_id": "chain-1"}),
        _event("policy_decision", {"findings": ["source_action_payload_in_answer"],
            "judge_labels": ["prompt_injection"], "content": "SYNTHETIC_RAW_SECRET_42"}),
        _event("data_flow_decision", {"sink": "answer", "effect": "allow",
            "findings": ["source_action_payload_in_answer"]}),
    ]
    db.add_all(events)
    db.commit()
    assert project_once(db, now=utcnow() + timedelta(seconds=1)) == len(events)
    rows = db.scalars(select(ThreatMappingAssessment)).all()
    by_event = {row.audit_event_id: row for row in rows}
    expected = ["TH-001", "TH-006", "TH-007", "TH-004", "TH-005", "TH-008", "TH-003", "TH-013"]
    assert [by_event[event.id].matches[0]["threat_id"] for event in events[:8]] == expected
    assert all(by_event[event.id].status == "unmapped" for event in events[8:])
    assert all(row.origin == "historical_backfill" for row in rows)
    assert len(by_event[events[0].id].matches[0]["evidence_ids"]) == 1
    assert project_once(db) == 0
    assert db.scalar(select(ThreatMappingState)).mapping_version == catalog["mapping_version"]
    assert projection_health(db)["pending"] == 0
    assert "SYNTHETIC_RAW_SECRET_42" not in str([row.matches for row in rows])


def test_mcp_mapping_requires_actual_same_session_source(lab):
    db, _, _ = lab
    source_id, target_id = str(uuid.uuid4()), str(uuid.uuid4())
    db.add_all([
        ToolCall(call_id=source_id, agent_id="demo-agent", session_id="mcp-1",
                 tool="mcp_lookup_card", arguments={"card_id": "lab-card"},
                 request_hash="read", status="completed", decision="allow", result={}),
        ToolCall(call_id=target_id, agent_id="demo-agent", session_id="mcp-1",
                 tool="mcp_record_note", arguments={"note_id": "n1", "text": "demo"},
                 request_hash="write", status="denied", decision="deny", result={}),
    ])
    assessment_id = str(uuid.uuid4())
    db.add(GoalAssessment(id=assessment_id, agent_id="demo-agent", session_id="mcp-1",
        call_id=target_id, phase="submit", status="suspected",
        findings=["source_action_match"], evidence_ids=[source_id],
        rules_version="goal-rules-v1"))
    db.commit()
    good = _event("goal_assessment", {"assessment_id": assessment_id, "phase": "submit",
        "status": "suspected", "findings": ["source_action_match"],
        "evidence_ids": [source_id]}, target_id)
    assert classify(db, good, load_catalog())[0][0]["threat_id"] == "TH-002"
    wrong_source = _event("goal_assessment", {**good.payload, "evidence_ids": [target_id]}, target_id)
    assert classify(db, wrong_source, load_catalog())[0] == []
    db.get(ToolCall, source_id).session_id = "another-session"
    db.flush()
    assert classify(db, good, load_catalog())[0] == []


def test_remote_manifest_drift_maps_only_explicit_failure(lab):
    db, _, _ = lab
    drift = _event("tool_result", {"tool": "remote_mcp_lookup_card", "status": "failed",
        "reason": "remote_mcp_manifest_drift", "remote_endpoint_id": "remote-demo"})
    assert classify(db, drift, load_catalog())[0][0]["threat_id"] == "TH-010"
    unavailable = _event("tool_result", {"tool": "remote_mcp_lookup_card", "status": "failed",
        "reason": "remote_mcp_unavailable", "remote_endpoint_id": "remote-demo"})
    assert classify(db, unavailable, load_catalog())[0] == []
    for reason in ("remote_mcp_profile_drift", "remote_mcp_behavior_drift"):
        event = _event("tool_result", {"tool": "remote_mcp_lookup_card", "status": "failed",
            "reason": reason, "remote_endpoint_id": "remote-demo"})
        assert classify(db, event, load_catalog())[0][0]["threat_id"] == "TH-010"
    observed = _event("mcp_profile_observed", {"reason": "remote_mcp_manifest_drift",
        "endpoint_id": "remote-demo", "candidate_id": str(uuid.uuid4())})
    assert classify(db, observed, load_catalog())[0][0]["threat_id"] == "TH-010"
    incident = _event("mcp_supply_incident", {"reason": "remote_mcp_behavior_drift",
        "endpoint_id": "remote-demo", "incident_id": str(uuid.uuid4())})
    assert classify(db, incident, load_catalog())[0][0]["threat_id"] == "TH-010"


def test_restricted_answer_block_maps_to_private_leak_threat(lab):
    db, _, _ = lab
    blocked = _event("data_flow_decision", {"sink": "answer", "effect": "block",
        "findings": ["restricted_source_answer"], "source_ids": ["synthetic-source-id"]})
    matched = classify(db, blocked, load_catalog())[0]
    assert len(matched) == 1 and matched[0]["threat_id"] == "TH-006"
    assert matched[0]["signal_id"] == "restricted_answer_blocked"
    assert classify(db, _event("data_flow_decision", {"sink": "answer", "effect": "allow",
        "findings": ["restricted_source_answer"]}), load_catalog())[0] == []


def _fixture_event(db, content: str) -> AuditEvent:
    call_id = str(uuid.uuid4())
    result = {"document_id": "injected-guide", "content": content,
              "sensitivity": "public"}
    db.add(ToolCall(call_id=call_id, agent_id="demo-agent", session_id="fixture-1",
        tool="read_document", arguments={"document_id": "injected-guide"},
        request_hash="fixture", status="completed", decision="allow", result=result))
    event = _event("tool_result", {"tool": "read_document", "status": "completed",
        "result": result}, call_id)
    db.add(event)
    db.commit()
    return event


def test_fixed_injection_document_is_mapped_only_when_actual_result_matches(lab):
    db, _, _ = lab
    content = next(item.content for item in SEED_DOCUMENTS if item.id == "injected-guide")
    actual = _fixture_event(db, content)
    altered = _fixture_event(db, "normal document")
    assert project_once(db) == 2
    rows = {row.audit_event_id: row for row in db.scalars(select(ThreatMappingAssessment)).all()}
    assert rows[actual.id].matches[0]["threat_id"] == "TH-012"
    assert rows[actual.id].matches[0]["effect"] is None
    assert rows[altered.id].status == "unmapped"
    assert content not in str(rows[actual.id].matches)


def test_new_version_can_map_previously_unmapped_fixture_without_changing_old_snapshot(lab):
    db, _, _ = lab
    content = next(item.content for item in SEED_DOCUMENTS if item.id == "injected-guide")
    event = _fixture_event(db, content)
    old_catalog = deepcopy(load_catalog())
    old_catalog["mapping_version"] = "1.2.0"
    old_catalog["runtime_signals"] = [item for item in old_catalog["runtime_signals"]
                                       if item["id"] != "injected_fixture_delivered"]
    assert project_once(db, catalog=old_catalog) == 1
    assert db.scalar(select(ThreatMappingAssessment)).status == "unmapped"
    assert project_once(db, catalog=load_catalog()) == 1
    rows = db.scalars(select(ThreatMappingAssessment).order_by(
        ThreatMappingAssessment.mapped_at)).all()
    assert [(row.mapping_version, row.status) for row in rows] == [
            ("1.2.0", "unmapped"), (load_catalog()["mapping_version"], "matched")]
    assert rows[1].matches[0]["threat_id"] == "TH-012"
    assert project_once(db) == 0


def test_new_mapping_version_does_not_reclassify_old_events(lab):
    db, _, _ = lab
    baseline = utcnow()
    old = _event("data_flow_decision", {"sink": "answer", "effect": "block",
        "findings": ["source_action_payload_in_answer"]})
    old.created_at = baseline
    db.add(old)
    db.commit()
    catalog = deepcopy(load_catalog())
    assert project_once(db, now=baseline + timedelta(seconds=1), catalog=catalog) == 1
    newer = deepcopy(catalog)
    newer["mapping_version"] = "1.2.1"
    assert project_once(db, now=baseline + timedelta(seconds=2), catalog=newer) == 0
    new = _event("data_flow_decision", {"sink": "answer", "effect": "block",
        "findings": ["source_action_payload_in_answer"]})
    new.created_at = baseline + timedelta(seconds=3)
    db.add(new)
    db.commit()
    assert project_once(db, now=baseline + timedelta(seconds=4), catalog=newer) == 1
    rows = db.scalars(select(ThreatMappingAssessment)).all()
    assert {(row.audit_event_id, row.mapping_version) for row in rows} == {
        (old.id, catalog["mapping_version"]), (new.id, "1.2.1")}
    assert db.get(ThreatMappingState, "active").backfill_since.replace(tzinfo=timezone.utc) == baseline + timedelta(seconds=2) - timedelta(days=30)


def test_version_switch_projects_backlog_without_reclassifying_history(lab):
    db, _, _ = lab
    baseline = utcnow()
    old = _event("data_flow_decision", {"sink": "answer", "effect": "block",
        "findings": ["source_action_payload_in_answer"]})
    old.created_at = baseline
    db.add(old)
    db.commit()
    first = deepcopy(load_catalog())
    assert project_once(db, limit=0, now=baseline + timedelta(seconds=1), catalog=first) == 0
    newer = deepcopy(first)
    newer["mapping_version"] = "1.2.1"
    assert project_once(db, now=baseline + timedelta(seconds=2), catalog=newer) == 1
    assert db.scalar(select(ThreatMappingAssessment)).mapping_version == "1.2.1"
    assert project_once(db, now=baseline + timedelta(seconds=3), catalog=newer) == 0


def test_tenant_admin_sees_only_own_mapping_and_no_raw_payload(tmp_path, monkeypatch):
    old_settings, old_serializer = main.settings, main.serializer
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/threats.db")
    get_settings.cache_clear(); get_engine.cache_clear(); get_session_factory.cache_clear()
    _sqlite_tenant_engine.cache_clear()
    main.settings = get_settings()
    main.serializer = main.URLSafeTimedSerializer(main.settings.session_secret,
                                                  salt="agentsentry-admin")
    monkeypatch.setattr(main, "get_redis", lambda: MemoryRedis())
    try:
        with TestClient(main.app) as client:
            client.post("/login", data={"tenant_id": "default",
                                        "password": main.settings.admin_password})
            csrf = main.serializer.loads(client.cookies["agentsentry_session"])["csrf"]
            a = client.post("/api/v2/tenants", headers={"X-CSRF-Token": csrf},
                            json={"name": "Map A"}).json()
            b = client.post("/api/v2/tenants", headers={"X-CSRF-Token": csrf},
                            json={"name": "Map B"}).json()
            with tenant_db_session(a["tenant_id"]) as db:
                decision_id = str(uuid.uuid4())
                db.add(DataFlowDecision(id=decision_id, agent_id="demo-agent",
                    session_id="synthetic-session", sink="answer", destination="user",
                    source_ids=[], sensitivity="public", effect="block",
                    findings=["source_action_payload_in_answer"], request_hash="synthetic",
                    rules_version="test-v1"))
                db.add(DataFlowIncident(id=str(uuid.uuid4()), decision_id=decision_id,
                    agent_id="demo-agent", session_id="synthetic-session",
                    finding="source_action_payload_in_answer", severity="high",
                    title="合成回答风险", status="open"))
                event = _event("data_flow_decision", {"sink": "answer", "effect": "block",
                    "findings": ["source_action_payload_in_answer"],
                    "decision_id": decision_id,
                    "agent_id": "demo-agent", "session_id": "synthetic-session",
                    "content": "SYNTHETIC_RAW_SECRET_42"})
                db.add(event)
                db.commit()
                project_once(db)
                assessment_id = db.scalar(select(ThreatMappingAssessment).where(
                    ThreatMappingAssessment.audit_event_id == event.id)).id
            client.post("/login", data={"tenant_id": a["tenant_id"],
                                        "password": a["admin_password"]})
            listing = client.get("/api/v3/threat-mappings")
            assert listing.status_code == 200
            assert listing.json()["items"][0]["matches"][0]["threat_id"] == "TH-001"
            assert "SYNTHETIC_RAW_SECRET_42" not in listing.text
            detail = client.get(f"/dashboard/threat-map/{assessment_id}")
            assert detail.status_code == 200 and "ASI01" in detail.text
            assert "SYNTHETIC_RAW_SECRET_42" not in detail.text
            assert "（会话详情不可用）" in detail.text
            overview = client.get("/dashboard/threat-map")
            assert overview.status_code == 200
            assert "/dashboard/threat-map/threats/TH-001?days=30" in overview.text
            for threat in load_catalog()["threats"]:
                scenario = client.get(f"/dashboard/threat-map/threats/{threat['id']}")
                assert scenario.status_code == 200, threat["id"]
                assert threat["title"] in scenario.text
                assert "项目控制措施" in scenario.text
                assert "测试与报告证据" in scenario.text
            scenario = client.get("/dashboard/threat-map/threats/TH-001")
            assert f"/dashboard/threat-map/{assessment_id}" in scenario.text
            assert client.get("/dashboard/threat-map/threats/TH-999").status_code == 404
            alerts = client.get("/dashboard/alerts")
            assert alerts.status_code == 200
            assert f"/dashboard/threat-map/{assessment_id}" in alerts.text
            assert "TH-001" in alerts.text
            assert client.get("/api/v3/threat-mappings?threat_id=TH-999").status_code == 422
            client.post("/login", data={"tenant_id": b["tenant_id"],
                                        "password": b["admin_password"]})
            assert client.get("/api/v3/threat-mappings").json()["items"] == []
            assert client.get(f"/api/v3/threat-mappings/{assessment_id}").status_code == 404
            assert client.get(f"/dashboard/threat-map/{assessment_id}").status_code == 404
            other_scenario = client.get("/dashboard/threat-map/threats/TH-001")
            assert other_scenario.status_code == 200
            assert f"/dashboard/threat-map/{assessment_id}" not in other_scenario.text
    finally:
        _sqlite_tenant_engine.cache_clear(); get_session_factory.cache_clear()
        get_engine().dispose(); get_engine.cache_clear(); get_settings.cache_clear()
        main.settings, main.serializer = old_settings, old_serializer
