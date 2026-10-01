"""V2.8: server-derived sensitivity labels and synchronous sink decisions."""

import base64
import hashlib
import hmac
import json
import re
import uuid
from urllib.parse import unquote

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .judge.runtime import assign_route
from .models import (AuditEvent, DataFlowDecision, DataFlowIncident, Document, MemoryEntry, MemoryRead,
                     Outbox, ToolCall)
from .runtime_binding import valid_session_token


RULES_VERSION = "data-flow-rules-v4"
READ_TOOLS = {"read_document", "mcp_lookup_card", "remote_mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue", "run_shell", "create_task"}
WRITE_FIELDS = {"create_task": "title", "mcp_record_note": "text", "remote_mcp_record_note": "text",
                "send_external": "content", "run_shell": "command",
                "github_mcp_create_test_issue": "body"}
BOUND_SINKS = {"create_task", "mcp_record_note", "remote_mcp_record_note", "send_external", "run_shell",
               "github_mcp_create_test_issue"}
_SECRET = re.compile(
    r"(?i)(?:\bBearer\s+[^\s,;，；。]{4,}|\b(?:api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|password|passwd|secret)\s*[:=]\s*[^\s,;，；。]{4,}|"
    r"\bsk(?:-ant|-proj)?-[A-Za-z0-9_-]{16,})"
)
_PERSONAL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?<!\d)1[3-9]\d{9}(?!\d)|(?<!\d)\d{17}[\dXx](?!\d)")
_B64 = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_LEVEL = {"public": 0, "private": 1, "secret": 2}


def rule_catalog() -> list[dict[str, str]]:
    return [
        {"id": "model_remote_sensitive", "title": "远程模型敏感上下文", "category": "模型外发",
         "scope": "已登记的远程模型", "trigger": "会话含私有／未知来源，或请求含凭据、个人信息。",
         "effect": "拒绝发送", "severity": "high", "evidence": "来源 ID、目的地和摘要",
         "limit": "仅覆盖示例 Agent 的显式模型发送函数。"},
        {"id": "model_local_secret", "title": "本地模型凭据输入", "category": "模型外发",
         "scope": "本地模型", "trigger": "请求消息含明确凭据。", "effect": "拒绝发送",
         "severity": "high", "evidence": "请求摘要", "limit": "规则匹配不能识别所有秘密形式。"},
        {"id": "external_after_private", "title": "敏感读取后尝试外发", "category": "工具写入",
         "scope": "send_external", "trigger": "本会话读过私有、未知或秘密来源。",
         "effect": "拒绝", "severity": "high", "evidence": "来源调用 ID",
         "limit": "即使本次内容无关也会拒绝，以防分段或改写外发。"},
        {"id": "github_write_after_private", "title": "敏感来源后创建 GitHub Issue", "category": "工具写入",
         "scope": "固定测试仓库的 GitHub Issue 写入", "trigger": "同一会话读过私有、未知或秘密来源。",
         "effect": "拒绝", "severity": "high", "evidence": "来源调用 ID、请求摘要",
         "limit": "会话级保守限制；无法证明与本次 Issue 正文无关。"},
        {"id": "github_write_personal", "title": "GitHub Issue 含个人信息", "category": "工具写入",
         "scope": "固定测试仓库的 GitHub Issue 写入", "trigger": "标题或正文命中个人信息模式。",
         "effect": "拒绝", "severity": "high", "evidence": "请求摘要",
         "limit": "仅覆盖固定格式，不能识别所有个人信息。"},
        {"id": "write_sensitive_content", "title": "写入参数含敏感内容", "category": "工具写入",
         "scope": "本地写入工具", "trigger": "参数命中凭据或私有来源片段。",
         "effect": "凭据拒绝；私有片段升级审批", "severity": "high",
         "evidence": "来源调用 ID、参数摘要", "limit": "隐晦的语义改写无法可靠字面识别。"},
        {"id": "sensitive_sink_binding", "title": "敏感出口缺少会话绑定", "category": "执行边界",
         "scope": "任务写入、模拟外发、MCP 写入与沙箱命令", "trigger": "没有有效会话绑定凭据。",
         "effect": "拒绝", "severity": "high", "evidence": "会话 ID",
         "limit": "旧客户端须先完成会话上报。"},
        {"id": "private_source_leak", "title": "回答含私有来源片段", "category": "回答展示",
         "scope": "最终回答与工具结果展示", "trigger": "草稿含私有来源原文、长数字或可还原编码片段。",
         "effect": "阻断展示", "severity": "high", "evidence": "输出检查 ID 与来源 ID",
         "limit": "不能可靠识别所有语义改写。"},
        {"id": "restricted_source_answer", "title": "受限来源后的自由文本回答", "category": "回答展示",
         "scope": "实际读取过私有、未知或秘密来源的会话",
         "trigger": "最终回答拟展示自由文本；来源级别由网关核定。",
         "effect": "阻断展示", "severity": "high", "evidence": "输出检查 ID 与来源 ID",
         "limit": "可能阻断与私有资料无关的正常回答；本版尚无人工放行或安全模板流程。"},
        {"id": "source_action_payload_in_answer", "title": "来源动作载荷进入回答", "category": "回答展示",
         "scope": "最终回答与工具结果展示", "trigger": "已读取的低信任材料包含发送命令，草稿复述命令中的不透明载荷。",
         "effect": "阻断展示", "severity": "high", "evidence": "输出检查 ID 与实际来源调用 ID",
         "limit": "只覆盖可抽取的明确动作与可还原编码；可信用户明确要求带来源引用时例外。"},
        {"id": "personal_data_review", "title": "回答含个人信息", "category": "回答展示",
         "scope": "最终回答与工具结果展示", "trigger": "草稿命中邮箱、手机号或身份证号模式。",
         "effect": "脱敏后提示", "severity": "medium", "evidence": "输出检查 ID",
         "limit": "仅覆盖列出的固定格式；可还原编码时直接阻断。"},
        {"id": "private_source_context", "title": "私有来源生成长期记忆", "category": "记忆写入",
         "scope": "长期记忆候选", "trigger": "本轮实际提供过私有或未知来源。",
         "effect": "隔离待审", "severity": "medium", "evidence": "记忆 ID 与来源 ID",
         "limit": "激活后仍不能发送给远程模型。"},
    ]


def _hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(get_settings().session_secret.encode(), raw, hashlib.sha256).hexdigest()


def contains_secret(text: str) -> bool:
    return bool(_SECRET.search(text))


def contains_personal(text: str) -> bool:
    return bool(_PERSONAL.search(text))


def redact_personal(text: str) -> str:
    return _PERSONAL.sub("[个人信息已脱敏]", text)


def _variants(text: str) -> list[str]:
    values = [text, unquote(text)]
    for token in _B64.findall(text)[:20]:
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode()
        except (ValueError, UnicodeError):
            continue
        values.append(decoded[:8192])
    return values


def _normalized(text: str) -> str:
    return re.sub(r"\s+", "", text).casefold()


def private_match(text: str, sources: list[dict]) -> bool:
    for variant in _variants(text):
        candidate = _normalized(variant)
        for source in sources:
            if source.get("level", source.get("sensitivity", "private")) == "public" or not source.get("content"):
                continue
            content = _normalized(source["content"])
            if len(content) >= 12 and content in candidate:
                return True
            if any(len(part) >= 12 and part in candidate
                   for part in (_normalized(value) for value in
                                re.split(r"[。！？.!?;；\n]", source["content"]))):
                return True
            if any(number in candidate for number in re.findall(r"\b\d{4,}\b", source["content"])):
                return True
    return False


def _mcp_level(resource_id: str) -> str:
    # Classification comes from the gateway's fixed catalogue, never the MCP body.
    if resource_id in {"public-guide", "routing-guide"} or resource_id.startswith("lab-v26-"):
        return "public"
    from .attack_corpus import cards as attack_cards
    from .memory_lab import cards as memory_cards
    from .calibration_corpus import cards as calibration_cards
    from .goal_lab_corpus import cards as goal_cards
    if (resource_id in attack_cards() or resource_id in memory_cards()
            or resource_id in calibration_cards() or resource_id in goal_cards()):
        return "public"
    return "private"


def source_context(db: Session, agent_id: str, session_id: str) -> list[dict]:
    calls = db.scalars(select(ToolCall).where(
        ToolCall.agent_id == agent_id, ToolCall.session_id == session_id,
        ToolCall.tool.in_(READ_TOOLS), ToolCall.status == "completed").order_by(ToolCall.created_at)).all()
    from .delegation import linked_calls, reply_sources
    calls = list({call.call_id: call for call in [*calls, *linked_calls(db, agent_id, session_id)]}.values())
    sources = []
    for call in calls:
        result = call.result or {}
        content = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))
                   if call.tool == "run_shell" else
                   result.get("title") if call.tool == "create_task" else result.get("content"))
        if (call.tool in {"read_document", "mcp_lookup_card", "remote_mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"} and
                isinstance(content, str) and isinstance(result.get("title"), str)):
            content = result["title"] + "\n" + content
        resource_id = (result.get("document_id") if call.tool == "read_document" else
                       result.get("card_id") if call.tool in {"mcp_lookup_card", "remote_mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"} else
                       "sandbox-shell" if call.tool == "run_shell" else result.get("task_id"))
        if not isinstance(content, str) or not isinstance(resource_id, str):
            level = "private"
            content = ""
        elif call.tool in {"run_shell", "create_task"}:
            level = "private"
        elif call.tool == "read_document":
            document = db.get(Document, resource_id)
            current = (document.sensitivity if document and document.sensitivity in _LEVEL else
                       "public" if resource_id.startswith("lab-v26-") else "private")
            observed = result.get("sensitivity")
            level = max((current, observed if observed in _LEVEL else "private"),
                        key=lambda item: _LEVEL[item])
        elif call.tool == "remote_mcp_lookup_card":
            # The gateway's pinned catalogue is authoritative; upstream labels are ignored.
            level = "public" if resource_id == "remote-public-guide" else "private"
        elif call.tool in {"github_mcp_read_license", "github_mcp_read_issue"}:
            level = "private"
        else:
            level = _mcp_level(resource_id)
        if contains_secret(content):
            level = "secret"
        sources.append({"id": call.call_id, "kind": call.tool, "level": level, "content": content})
    sources.extend(reply_sources(db, agent_id, session_id, sources))
    reads = db.scalars(select(MemoryRead).where(
        MemoryRead.agent_id == agent_id, MemoryRead.session_id == session_id)).all()
    for memory_id in dict.fromkeys(item for read in reads for item in read.memory_ids):
        memory = db.get(MemoryEntry, memory_id)
        if not memory or memory.agent_id != agent_id:
            sources.append({"id": memory_id, "kind": "memory", "level": "private", "content": ""})
            continue
        inherited = [item["level"] for item in sources if item["id"] in memory.source_call_ids]
        if not inherited and memory.source_call_ids:
            origins = [db.get(ToolCall, item) for item in memory.source_call_ids]
            for row in origins:
                if row is None or not isinstance((row.result or {}).get("content"), str):
                    inherited.append("private")
                elif contains_secret(row.result["content"]):
                    inherited.append("secret")
                elif row.tool == "read_document":
                    document = db.get(Document, (row.result or {}).get("document_id"))
                    current = document.sensitivity if document and document.sensitivity in _LEVEL else "private"
                    observed = (row.result or {}).get("sensitivity")
                    inherited.append(max((current, observed if observed in _LEVEL else "private"),
                                         key=lambda item: _LEVEL[item]))
                elif row.tool == "mcp_lookup_card":
                    inherited.append(_mcp_level((row.result or {}).get("card_id", "")))
                elif row.tool == "remote_mcp_lookup_card":
                    inherited.append("public" if (row.result or {}).get("card_id") == "remote-public-guide" else "private")
                elif row.tool in {"github_mcp_read_license", "github_mcp_read_issue"}:
                    inherited.append("private")
                else:
                    inherited.append("private")
        level = max(inherited or ["public"], key=lambda item: _LEVEL[item])
        if "private_source_context" in (memory.findings or []) and level == "public":
            level = "private"
        content = memory.text or ""
        if contains_secret(content):
            level = "secret"
        sources.append({"id": memory.id, "kind": "memory", "level": level, "content": content})
    return sources


def _level(sources: list[dict]) -> str:
    return max((item["level"] for item in sources), key=lambda item: _LEVEL[item], default="public")


def record(db: Session, agent_id: str, session_id: str, sink: str, destination: str,
           sources: list[dict], effect: str, findings: list[str], request_hash: str,
           call_id: str | None = None, decision_id: str | None = None,
           related_id: str | None = None, detected_level: str = "public") -> DataFlowDecision:
    row = DataFlowDecision(id=decision_id or str(uuid.uuid4()), agent_id=agent_id,
        session_id=session_id, call_id=call_id, related_id=related_id,
        sink=sink, destination=destination,
        source_ids=[item["id"] for item in sources],
        sensitivity=max((_level(sources), detected_level), key=lambda item: _LEVEL[item]),
        effect=effect, findings=findings, request_hash=request_hash,
        rules_version=RULES_VERSION)
    db.add(row)
    if effect in {"deny", "block", "quarantined", "rejected"} and findings:
        db.add(DataFlowIncident(id=str(uuid.uuid4()), decision_id=row.id, call_id=call_id,
            agent_id=agent_id, session_id=session_id, finding=findings[0][:80],
            severity="high" if effect in {"deny", "block", "rejected"} else "medium",
            title="敏感数据流已" + {"deny": "拒绝", "block": "阻断",
                            "quarantined": "隔离", "rejected": "拒绝"}[effect]))
    event = AuditEvent(id=str(uuid.uuid4()), call_id=call_id, event_type="data_flow_decision",
        payload={"decision_id": row.id, "session_id": session_id, "sink": sink,
                 "destination": destination, "source_ids": row.source_ids,
                 "related_id": related_id,
                 "sensitivity": row.sensitivity, "effect": effect, "findings": findings,
                 "rules_version": RULES_VERSION})
    db.add(event)
    outbox = Outbox(id=str(uuid.uuid4()), audit_event_id=event.id, status="pending")
    db.add(outbox)
    assign_route(db, outbox)
    return row


def model_destinations() -> dict[str, str]:
    settings = get_settings()
    return {"local": settings.agentsentry_model_local_base_url,
            **json.loads(settings.agentsentry_model_remote_destinations)}


def check_model(db: Session, tenant_id: str, agent_id: str, session_id: str,
                session_token: str, body, destinations: dict[str, str] | None = None) -> dict:
    if not valid_session_token(db, tenant_id, agent_id, session_id, session_token):
        raise ValueError("模型请求缺少有效会话绑定")
    destinations = destinations if destinations is not None else model_destinations()
    base_url = destinations.get(body.destination_id)
    if not base_url:
        raise ValueError("模型目的地未登记")
    serialized = json.dumps(body.messages, ensure_ascii=False)
    if len(serialized.encode()) > 65536:
        raise ValueError("模型消息超过 64 KiB")
    if any(not isinstance(message, dict) or message.get("role") not in
           {"system", "developer", "user", "assistant", "tool"} for message in body.messages):
        raise ValueError("模型消息结构无效")
    sources = source_context(db, agent_id, session_id)
    requested_calls = [str(value) for value in body.source_call_ids]
    requested_memories = [str(value) for value in body.memory_ids]
    expected_calls = {item["id"] for item in sources if item["kind"] != "memory"}
    expected_memories = {item["id"] for item in sources if item["kind"] == "memory"}
    if (len(requested_calls) != len(set(requested_calls)) or
            len(requested_memories) != len(set(requested_memories)) or
            set(requested_calls) != expected_calls or
            set(requested_memories) != expected_memories):
        raise ValueError("模型请求来源与本会话已读取来源不一致")
    fingerprint = _hash(body.model_dump(mode="json"))
    existing = db.get(DataFlowDecision, str(body.request_id))
    if existing:
        if (existing.agent_id, existing.session_id, existing.sink, existing.request_hash) != (
                agent_id, session_id, "model", fingerprint):
            raise ValueError("请求 ID 已用于其他内容")
        if (set(existing.source_ids) != {item["id"] for item in sources}
                or _LEVEL[existing.sensitivity] < _LEVEL[_level(sources)]
                or existing.rules_version != RULES_VERSION):
            raise ValueError("模型请求的来源或规则已变化，请重新检查")
        return {"check_id": existing.id, "outcome": existing.effect,
                "findings": existing.findings, "base_url": base_url if existing.effect == "allow" else "",
                "approved_messages": body.messages if existing.effect == "allow" else []}
    from .action_chain import evaluate_model, record as record_action_chain
    chain = evaluate_model(db, tenant_id, agent_id, session_id, body.purpose)
    record_action_chain(db, agent_id, session_id, str(body.request_id),
                        "model:" + body.purpose, chain)
    findings = []
    findings.extend(chain.findings)
    if any(contains_secret(value) for value in _variants(serialized)):
        findings.append("model_local_secret")
    if body.destination_id != "local" and (
            _level(sources) != "public" or contains_personal(serialized)):
        findings.append("model_remote_sensitive")
    effect = "deny" if findings else "allow"
    record(db, agent_id, session_id, "model", body.destination_id, sources,
           effect, findings, fingerprint, decision_id=str(body.request_id),
           related_id=str(body.request_id),
           detected_level="secret" if "model_local_secret" in findings else
                          "private" if contains_personal(serialized) else "public")
    db.commit()
    return {"check_id": str(body.request_id), "outcome": effect, "findings": findings,
            "base_url": base_url if effect == "allow" else "",
            "approved_messages": body.messages if effect == "allow" else []}


def check_tool(db: Session, tenant_id: str, call: ToolCall, runtime_token: str,
               phase: str) -> tuple[str, list[str]]:
    if call.tool not in WRITE_FIELDS:
        return "allow", []
    sources = source_context(db, call.agent_id, call.session_id)
    content = str(call.arguments.get(WRITE_FIELDS[call.tool], ""))
    if call.tool == "github_mcp_create_test_issue":
        content = str(call.arguments.get("title", "")) + "\n" + content
    findings = []
    if call.tool in BOUND_SINKS and not valid_session_token(
            db, tenant_id, call.agent_id, call.session_id, runtime_token):
        findings.append("sensitive_sink_binding")
    if any(contains_secret(value) for value in _variants(content)):
        findings.append("write_sensitive_content")
    if call.tool == "send_external" and _level(sources) != "public":
        findings.append("external_after_private")
    elif call.tool == "github_mcp_create_test_issue" and _level(sources) != "public":
        findings.append("github_write_after_private")
    if call.tool == "github_mcp_create_test_issue" and contains_personal(content):
        findings.append("github_write_personal")
    elif call.tool in {"create_task", "mcp_record_note"} and private_match(content, sources):
        findings.append("private_local_write")
    elif call.tool == "remote_mcp_record_note" and _level(sources) != "public":
        findings.append("remote_after_private")
    elif call.tool == "remote_mcp_record_note" and private_match(content, sources):
        findings.append("remote_private_copy")
    effect = ("deny" if set(findings) & {"sensitive_sink_binding", "write_sensitive_content",
                                         "external_after_private", "remote_after_private", "remote_private_copy",
                                         "github_write_after_private", "github_write_personal"} else
              "require_approval" if findings else "allow")
    record(db, call.agent_id, call.session_id, "tool:" + phase, call.tool,
           sources, effect, findings, _hash({"tool": call.tool, "arguments": call.arguments}),
           call_id=call.call_id, related_id=call.call_id,
           detected_level="secret" if "write_sensitive_content" in findings else "public")
    return effect, findings


def scrub_operational_payloads(db: Session) -> int:
    """Remove new terminal call payloads after 30 days; keep legacy evidence intact."""
    from datetime import timedelta
    from .models import utcnow
    cutoff = utcnow() - timedelta(days=30)
    rows = db.scalars(select(ToolCall).where(
        ToolCall.status.in_(["completed", "denied", "failed"]),
        ToolCall.created_at < cutoff,
        ToolCall.call_id.in_(select(DataFlowDecision.call_id).where(
            DataFlowDecision.call_id.is_not(None))))).all()
    for row in rows:
        row.arguments = {"retained": False, "request_hash": row.request_hash}
        row.result = {"retained": False} if row.result is not None else None
    if rows:
        db.commit()
    return len(rows)
