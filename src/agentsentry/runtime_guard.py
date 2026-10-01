"""执行前的确定性运行时安全规则；只使用当前租户已提交的服务端证据。"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import (AuditEvent, Outbox, RuntimeControl, RuntimeControlChange, RuntimeDecision,
                     RuntimeIncident, RuntimeSession, ToolCall, utcnow)
from .judge.runtime import assign_route
from .runtime_redaction import redact_preview


RULES_VERSION = "runtime-rules-v1"
SIDE_EFFECT_TOOLS = {"create_task", "delete_task", "send_external", "run_shell", "mcp_record_note", "remote_mcp_record_note", "github_mcp_create_test_issue"}
READ_TOOLS = {"read_document", "mcp_lookup_card", "remote_mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"}
DENIAL_WINDOW = timedelta(minutes=10)
DENIAL_THRESHOLD = 3
REPEAT_WINDOW = timedelta(days=1)
REPEAT_HISTORY_LIMIT = 100
READ_HISTORY_LIMIT = 10
INSTRUCTION_SCAN_CHARS = 8192
INSTRUCTION_PATTERN = re.compile(
    r"(?i)(?:ignore\s+(?:(?:all\s+)?previous\s+instructions?|(?:the\s+)?user(?:\s+(?:request|task))?|system\s+instructions?)"
    r"|忽略(?:之前|以上|用户|系统).{0,12}(?:指令|任务|要求)"
    r"|(?:system|developer)\s+(?:message|instruction|prompt)\s*[:：])"
)


def rule_catalog() -> list[dict[str, str]]:
    """管理员只读目录；阈值引用执行路径使用的常量。"""
    return [
        {"id": "read_then_write_review", "title": "读取后请求写入", "category": "行为线索", "severity": "info",
         "scope": "写入类工具", "effect": "仅记录线索",
         "trigger": f"同一会话最近 {READ_HISTORY_LIMIT} 次已完成读取中至少有一次文档或 MCP 卡片读取。",
         "evidence": "读取调用 ID", "limit": "正常任务也常先读后写；这条线索不证明攻击。"},
        {"id": "instruction_source_before_write", "title": "可疑来源后请求写入", "category": "行为线索", "severity": "medium",
         "scope": "写入类工具", "effect": "基础策略原本放行时升级为审批",
         "trigger": f"同一会话最近 {READ_HISTORY_LIMIT} 次已完成读取中，结果正文的前 {INSTRUCTION_SCAN_CHARS} 字符命中下方指令模式。",
         "evidence": "命中来源的调用 ID", "limit": "只做字面匹配，可能误判引用或漏掉改写；读取发生不证明模型采纳了指令。",
         "pattern": INSTRUCTION_PATTERN.pattern},
        {"id": "repeated_denials_before_write", "title": "连续拒绝后请求写入", "category": "行为线索", "severity": "medium",
         "scope": "写入类工具", "effect": "基础策略原本放行时升级为审批",
         "trigger": f"同一 Agent 最近 {int(DENIAL_WINDOW.total_seconds() // 60)} 分钟至少 {DENIAL_THRESHOLD} 次调用被拒绝。",
         "evidence": "最近的拒绝调用 ID", "limit": "Agent 级窗口和阈值尚未由真实流量校准；配置错误也可能触发。"},
        {"id": "uncertain_action_repeat", "title": "结果未知的相同动作重试", "category": "执行边界", "severity": "high",
         "scope": "写入类工具", "effect": "拒绝新的调用 ID",
         "trigger": f"同一 Agent 在 {int(REPEAT_WINDOW.total_seconds() // 3600)} 小时内，最近 {REPEAT_HISTORY_LIMIT} 个执行中或结果未知的同工具调用里，有规范化参数相同的动作。",
         "evidence": "先前调用 ID 和状态", "limit": "相同参数不一定代表同一业务动作；原调用 ID 的重试走幂等查询。"},
        {"id": "administrator_paused", "title": "管理员暂停后仍请求工具", "category": "执行边界", "severity": "high",
         "scope": "全部已进入运行时检查的工具", "effect": "拒绝",
         "trigger": "管理员已暂停本会话或此 Agent。",
         "evidence": "暂停控制记录 ID", "limit": "只阻止后续网关调用，不能撤销已开始的副作用。"},
        {"id": "session_closed", "title": "已结束会话仍请求工具", "category": "执行边界", "severity": "high",
         "scope": "全部工具", "effect": "拒绝",
         "trigger": "已上报的会话状态不再是运行中。",
         "evidence": "会话 ID", "limit": "依赖可信适配层上报会话结束；未上报会话不能据此判定。"},
        {"id": "session_binding_invalid", "title": "会话绑定缺失或无效", "category": "执行边界", "severity": "high",
         "scope": "全部工具", "effect": "拒绝",
         "trigger": "强制绑定模式下缺少有效凭据，或任何模式下主动提交了无效凭据。",
         "evidence": "会话 ID", "limit": "当前是否强制绑定由服务配置决定；Agent 身份密钥失陷仍可新建会话。"},
        {"id": "session_unreported", "title": "会话未上报", "category": "行为线索", "severity": "info",
         "scope": "兼容模式下通过前置校验的工具", "effect": "仅记录线索",
         "trigger": "网关找不到已上报的当前会话。",
         "evidence": "会话 ID", "limit": "兼容模式允许旧客户端继续调用；强制绑定模式会在前置校验拒绝。"},
    ]


RULE_META = {item["id"]: item for item in rule_catalog()}


@dataclass(frozen=True)
class GuardResult:
    effect: str
    findings: tuple[str, ...]
    evidence: tuple[dict, ...]


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _same_action(left: ToolCall, right: ToolCall) -> bool:
    return left.tool == right.tool and json.dumps(left.arguments, sort_keys=True, ensure_ascii=False) == json.dumps(
        right.arguments, sort_keys=True, ensure_ascii=False)


def _control_key(agent_id: str, session_id: str | None) -> str:
    return f"session:{agent_id}:{session_id}" if session_id else f"agent:{agent_id}"


def _lock(db: Session, tenant_id: str, agent_id: str, session_id: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        raw = hashlib.sha256(f"{tenant_id}\0{agent_id}\0{session_id}".encode()).digest()[:8]
        lock_key = int.from_bytes(raw, "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})


def evaluate(db: Session, call: ToolCall, tenant_id: str = "default") -> GuardResult:
    """查询有界历史；未上报会话只标记缺口，不猜测 Agent 的任务意图。"""
    _lock(db, tenant_id, call.agent_id, call.session_id)
    findings: list[str] = []
    evidence: list[dict] = []
    effect = "allow"
    for key in (_control_key(call.agent_id, None), _control_key(call.agent_id, call.session_id)):
        control = db.get(RuntimeControl, key)
        if control and control.paused:
            findings.append("administrator_paused")
            evidence.append({"kind": "control", "id": key})
            effect = "deny"
            break

    reported = db.get(RuntimeSession, (call.agent_id, call.session_id))
    if reported is None or not reported.reported:
        findings.append("session_unreported")
    elif reported.status != "running":
        findings.append("session_closed")
        evidence.append({"kind": "session", "id": call.session_id})
        effect = "deny"

    if call.tool in SIDE_EFFECT_TOOLS:
        previous = db.scalars(select(ToolCall).where(
            ToolCall.agent_id == call.agent_id, ToolCall.tool == call.tool,
            ToolCall.status.in_(["unknown", "executing"]),
            ToolCall.created_at >= utcnow() - REPEAT_WINDOW,
            ToolCall.call_id != call.call_id,
        ).order_by(ToolCall.created_at.desc()).limit(REPEAT_HISTORY_LIMIT)).all()
        repeat = next((item for item in previous if _same_action(item, call)), None)
        if repeat:
            findings.append("uncertain_action_repeat")
            evidence.append({"kind": "call", "id": repeat.call_id, "status": repeat.status})
            effect = "deny"

        denied = db.scalars(select(ToolCall.call_id).where(
            ToolCall.agent_id == call.agent_id, ToolCall.status == "denied",
            ToolCall.created_at >= utcnow() - DENIAL_WINDOW,
            ToolCall.call_id != call.call_id,
        ).order_by(ToolCall.created_at.desc()).limit(DENIAL_THRESHOLD)).all()
        if len(denied) >= DENIAL_THRESHOLD:
            findings.append("repeated_denials_before_write")
            evidence.extend({"kind": "call", "id": item} for item in denied)
            if effect == "allow":
                effect = "require_approval"

        reads = db.scalars(select(ToolCall).where(
            ToolCall.agent_id == call.agent_id, ToolCall.session_id == call.session_id,
            ToolCall.tool.in_(READ_TOOLS), ToolCall.status == "completed",
            ToolCall.call_id != call.call_id,
        ).order_by(ToolCall.created_at.desc()).limit(READ_HISTORY_LIMIT)).all()
        from .delegation import linked_calls
        reads = list({read.call_id: read for read in [*reads, *linked_calls(db, call.agent_id, call.session_id)]}.values())
        if reads:
            findings.append("read_then_write_review")
            evidence.append({"kind": "call", "id": reads[0].call_id})
        suspicious = next((read for read in reads
                           if INSTRUCTION_PATTERN.search(str((read.result or {}).get("content", ""))[:INSTRUCTION_SCAN_CHARS])), None)
        if suspicious:
            findings.append("instruction_source_before_write")
            evidence.append({"kind": "call", "id": suspicious.call_id})
            if effect == "allow":
                effect = "require_approval"
    return GuardResult(effect, tuple(dict.fromkeys(findings)), tuple(evidence[:20]))


def record(db: Session, call: ToolCall, phase: str, result: GuardResult) -> RuntimeDecision:
    decision = RuntimeDecision(id=str(uuid.uuid4()), call_id=call.call_id,
        agent_id=call.agent_id, session_id=call.session_id, phase=phase,
        effect=result.effect, rules_version=RULES_VERSION,
        findings=list(result.findings), evidence=list(result.evidence))
    db.add(decision)
    db.flush()
    for rule_id in result.findings:
        if rule_id not in RULE_META:
            continue
        severity, title = RULE_META[rule_id]["severity"], RULE_META[rule_id]["title"]
        # 信息线索留在逐次决定中；可处置的命中才进入告警列表。
        if severity == "info":
            continue
        incident = db.scalar(select(RuntimeIncident).where(
            RuntimeIncident.agent_id == call.agent_id,
            RuntimeIncident.rule_id == rule_id,
            RuntimeIncident.status == "open",
            RuntimeIncident.updated_at >= utcnow() - timedelta(minutes=10),
        ).order_by(RuntimeIncident.updated_at.desc()).limit(1))
        if incident:
            incident.call_id = call.call_id
            incident.decision_id = decision.id
            incident.session_id = call.session_id
            incident.occurrences += 1
            incident.updated_at = utcnow()
        else:
            db.add(RuntimeIncident(id=str(uuid.uuid4()), decision_id=decision.id,
                call_id=call.call_id, agent_id=call.agent_id, session_id=call.session_id,
                rule_id=rule_id, severity=severity, title=title))
    event = AuditEvent(id=str(uuid.uuid4()), call_id=call.call_id,
        event_type="runtime_decision", payload={"decision_id": decision.id, "phase": phase,
        "effect": result.effect, "rules_version": RULES_VERSION,
        "findings": list(result.findings), "evidence": list(result.evidence)})
    db.add(event)
    outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
    db.add(outbox)
    assign_route(db, outbox)
    return decision


def set_control(db: Session, agent_id: str, session_id: str | None,
                paused: bool, reason: str, actor: str = "tenant_admin") -> RuntimeControl:
    key = _control_key(agent_id, session_id)
    control = db.get(RuntimeControl, key, with_for_update=True)
    if control is None:
        control = RuntimeControl(key=key, agent_id=agent_id, session_id=session_id)
        db.add(control)
    control.paused = paused
    control.reason = redact_preview(reason)[0][:300]
    control.updated_at = utcnow()
    db.add(RuntimeControlChange(id=str(uuid.uuid4()), control_key=key,
        agent_id=agent_id, session_id=session_id, paused=paused,
        reason=control.reason, actor=actor))
    event = AuditEvent(id=str(uuid.uuid4()), call_id=None,
        event_type="runtime_control", payload={"agent_id": agent_id,
        "session_id": session_id, "paused": paused, "control_key": key,
        "actor": actor})
    db.add(event)
    outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
    db.add(outbox)
    assign_route(db, outbox)
    db.commit()
    return control
