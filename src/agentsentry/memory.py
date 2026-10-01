"""V2.5 tenant-local, low-trust memory. Model text is never authority."""

import hashlib
import hmac
import json
import re
import uuid
import base64
from datetime import timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditEvent, MemoryEntry, MemoryFailure, MemoryRead, MemoryWrite, OutputCheck, RuntimeSession, ToolCall, TrustedMemorySource, utcnow
from .memory_integrity import seal_memory, seal_source, verify_memory, verify_source
from .schemas import MemoryFailureRequest, MemoryReadRequest, MemoryWriteRequest
from .service import audit


VERSION = "memory-rules-v3"
_SECRET = re.compile(r"(?i)(?:\bBearer\s+[^\s,;]{4,}|\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]{4,}|\bsk(?:-ant|-proj)?-[A-Za-z0-9_-]{16,})")
_PERSONAL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?<!\d)1[3-9]\d{9}(?!\d)")
_INSTRUCTION = re.compile(r"(?i)(ignore (?:the )?(?:user|previous|system)|忽略(?:用户|之前|系统)|system prompt|系统指令|开发者指令|必须(?:调用|发送|泄露)|send (?:the )?(?:secret|private)|发送.*(?:秘密|私有)|LAB_MARKER_7319)")
_ROLE = re.compile(r"(?i)(?:<\s*/?\s*(?:system|developer)\s*>|\[(?:INST|SYS)\]|(?:system|developer)\s*(?:message|role)\s*[:：]|(?:系统|开发者|管理员)(?:消息|身份|角色)\s*[:：])")
_TOOL_COMMAND = re.compile(r"(?i)(?:调用|执行|使用|run|call|invoke)\s*(?:工具|tool)?\s*[`\"']?\s*(?:send_external|run_shell|delete_task|mcp_record_note)\b")
_EXFILTRATE = re.compile(r"(?i)(?:(?:发送|上传|外发|传给|send|upload|exfiltrat\w*)[^。\n]{0,80}(?:秘密|私有|凭据|令牌|secret|private|credential|token)|(?:秘密|私有|凭据|令牌|secret|private|credential|token)[^。\n]{0,80}(?:发送|上传|外发|传给|send|upload))")
_PERSISTENT = re.compile(r"(?i)(?:以后|下次|后续|今后|未来|每次|always|next time|future sessions?)[^。\n]{0,60}(?:必须|先|忽略|绕过|调用|发送|执行|must|ignore|bypass|send|call|run)")
_ENCODED = re.compile(r"(?i)(?:base64|rot13|unicode\s*escape|解码|译码)[^。\n]{0,80}(?:执行|遵循|指令|run|execute|follow|instruction)")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,400}={0,2}(?![A-Za-z0-9+/])")
_WORDS = re.compile(r"[\w]{2,}", re.UNICODE)


def _text_variants(text: str) -> list[str]:
    cleaned = re.sub(r"[\u200b-\u200f\u2060]", "", text)
    compact = re.sub(r"[\s·._-]+", "", cleaned)
    variants = list(dict.fromkeys([text, cleaned, compact]))
    for encoded in _BASE64.findall(text[:2000]):
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and len(decoded) <= 500:
            variants.append(decoded)
    return variants


def memory_risks(text: str) -> tuple[list[str], list[str]]:
    """硬拒绝与待隔离信号；输出只包含规则标签。"""
    hard = []
    review = []
    variants = _text_variants(text)
    for index, value in enumerate(variants):
        if _SECRET.search(value):
            hard.append("credential_exposure")
        if _EXFILTRATE.search(value):
            hard.append("exfiltration_instruction")
        for pattern, label in ((_INSTRUCTION, "instruction_review"),
                               (_ROLE, "role_spoofing"),
                               (_TOOL_COMMAND, "tool_command"),
                               (_PERSISTENT, "cross_session_command"),
                               (_ENCODED, "encoded_instruction"),
                               (_PERSONAL, "personal_data_review")):
            if pattern.search(value):
                review.append(label)
        if index > 0 and (hard or review):
            review.append("obfuscated_content")
    compact = re.sub(r"[\s·._-]+", "", re.sub(r"[\u200b-\u200f\u2060]", "", text))
    if re.search(r"(?i)(?:sendexternal|runshell|deletetask|mcprecordnote|ignoretheuser|忽略用户|发送私有)",
                 compact):
        review.append("obfuscated_content")
    return list(dict.fromkeys(hard)), list(dict.fromkeys(review))


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(get_settings().session_secret.encode(), raw, hashlib.sha256).hexdigest()


def enabled() -> bool:
    return get_settings().agentsentry_memory_enabled


def _session(db: Session, agent_id: str, session_id: str) -> RuntimeSession:
    row = db.get(RuntimeSession, (agent_id, session_id))
    if row is None or not row.reported or row.status != "running":
        raise ValueError("记忆操作需要正在运行的已上报会话")
    return row


def _expire(db: Session) -> int:
    now = utcnow()
    rows = db.scalars(select(MemoryEntry).where(MemoryEntry.status.in_(["active", "quarantined"]),
                                                 MemoryEntry.expires_at <= now)).all()
    changed = 0
    for row in rows:
        if not verify_memory(db, row):
            continue
        row.status = "expired"
        row.text = None
        seal_memory(db, row)
        audit(db, None, "memory_expired", {"memory_id": row.id, "text_hash": row.text_hash,
                                            "status": "expired", "rules_version": VERSION})
        changed += 1
    return changed


def expire_memories(db: Session) -> int:
    count = _expire(db)
    db.commit()
    return count


def _entry_view(row: MemoryEntry) -> dict:
    return {"id": row.id, "kind": row.kind, "text": row.text, "status": row.status,
            "trust_level": row.trust_level, "findings": row.findings,
            "origin_session_id": row.origin_session_id, "source_call_ids": row.source_call_ids,
            "text_hash": row.text_hash, "created_at": row.created_at.isoformat(),
            "expires_at": row.expires_at.isoformat()}


def _source_snapshot(call: ToolCall) -> tuple[str, str, str]:
    result = call.result or {}
    if call.status != "completed" or call.tool not in {"read_document", "mcp_lookup_card"}:
        raise ValueError("仅可审核已完成的读取来源")
    resource_id = result.get("document_id" if call.tool == "read_document" else "card_id")
    content = result.get("content")
    if not isinstance(resource_id, str) or not isinstance(content, str) or not content:
        raise ValueError("读取来源缺少内容")
    if result.get("sensitivity") == "private":
        raise ValueError("私有来源不能自动信任")
    return resource_id, content, _hash({"source_content": content})


def _trusted_snapshot(db: Session, call: ToolCall) -> tuple[bool, str]:
    try:
        resource_id, content, digest = _source_snapshot(call)
    except ValueError:
        return False, ""
    row = db.scalar(select(TrustedMemorySource).where(
        TrustedMemorySource.tool == call.tool,
        TrustedMemorySource.resource_id == resource_id,
        TrustedMemorySource.content_hash == digest,
        TrustedMemorySource.revoked_at.is_(None)))
    return bool(row and verify_source(db, row)), content


def _trusted_extract(db: Session, sources: list[ToolCall]) -> str:
    if not sources:
        return ""
    contents = []
    for call in sources:
        trusted, content = _trusted_snapshot(db, call)
        if not trusted:
            return ""
        contents.append(content)
    combined = "\n".join(contents)
    return combined if len(combined) <= 500 else ""


def _current_source_ids(db: Session, agent_id: str, session_id: str) -> tuple[set[str], set[str]]:
    tools = {call.call_id for call in db.scalars(select(ToolCall).where(
        ToolCall.agent_id == agent_id, ToolCall.session_id == session_id,
        ToolCall.tool.in_(["read_document", "mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"]),
        ToolCall.status == "completed")).all()}
    memories = {memory_id for read in db.scalars(select(MemoryRead).where(
        MemoryRead.agent_id == agent_id, MemoryRead.session_id == session_id)).all()
        for memory_id in read.memory_ids}
    return tools, memories


def trust_source(db: Session, call_id: str) -> dict:
    call = db.get(ToolCall, call_id)
    if call is None:
        raise ValueError("来源调用不存在")
    resource_id, _, digest = _source_snapshot(call)
    row = db.scalar(select(TrustedMemorySource).where(
        TrustedMemorySource.tool == call.tool,
        TrustedMemorySource.resource_id == resource_id,
        TrustedMemorySource.content_hash == digest))
    if row is None:
        row = TrustedMemorySource(id=str(uuid.uuid4()), tool=call.tool,
            resource_id=resource_id, content_hash=digest, reviewed_call_id=call.call_id)
        db.add(row)
    else:
        from .models import TrustedSourceSeal
        if db.get(TrustedSourceSeal, row.id) is not None and not verify_source(db, row):
            db.commit()
            raise ValueError("来源审核记录完整性异常")
        if db.get(TrustedSourceSeal, row.id) is None and row.revoked_at is None:
            raise ValueError("未签名来源尚未撤销，不能直接补签")
        row.revoked_at = None
        row.reviewed_call_id = call.call_id
    seal_source(db, row)
    audit(db, None, "memory_source_trust", {"source_id": row.id, "tool": row.tool,
        "resource_id": row.resource_id, "content_hash": row.content_hash,
        "reviewed_call_id": call.call_id, "status": "trusted"})
    db.commit()
    return _source_view(row)


def _source_view(row: TrustedMemorySource) -> dict:
    return {"id": row.id, "tool": row.tool, "resource_id": row.resource_id,
            "content_hash": row.content_hash, "reviewed_call_id": row.reviewed_call_id,
            "status": "revoked" if row.revoked_at else "trusted"}


def list_trusted_sources(db: Session) -> list[dict]:
    items = []
    for row in db.scalars(select(TrustedMemorySource)
                          .order_by(TrustedMemorySource.created_at.desc()).limit(200)).all():
        view = _source_view(row)
        view["integrity_status"] = "valid" if verify_source(db, row) else "failed"
        if view["integrity_status"] != "valid":
            view["status"] = "untrusted"
        items.append(view)
    db.commit()
    return items


def revoke_source(db: Session, source_id: str) -> dict:
    row = db.get(TrustedMemorySource, source_id, with_for_update=True)
    if row is None:
        raise ValueError("可信来源不存在")
    if not verify_source(db, row):
        db.commit()
        raise ValueError("来源审核记录完整性异常")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        seal_source(db, row)
        audit(db, None, "memory_source_trust", {"source_id": row.id, "tool": row.tool,
            "resource_id": row.resource_id, "content_hash": row.content_hash,
            "status": "revoked"})
        db.commit()
        reconcile_active_memories(db)
    return _source_view(row)


def _manually_activated(db: Session) -> set[str]:
    return {event.payload.get("memory_id") for event in db.scalars(select(AuditEvent)
        .where(AuditEvent.event_type == "memory_decision")).all()
        if event.payload.get("action") == "activate"}


def reconcile_active_memories(db: Session) -> int:
    """阻止旧版或已撤销来源的自动激活记忆继续被读取。"""
    manual = _manually_activated(db)
    changed = 0
    rows = db.scalars(select(MemoryEntry).where(MemoryEntry.status == "active")).all()
    for row in rows:
        if not verify_memory(db, row):
            continue
        write = db.get(MemoryWrite, row.write_id)
        output = db.get(OutputCheck, write.output_check_id) if write else None
        read_ids = {source["call_id"] for source in output.sources
            if source.get("tool") in {"read_document", "mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"}} if output else set()
        checked_memories = {source["call_id"] for source in output.sources
            if source.get("tool") == "memory"} if output else set()
        current_reads, current_memories = _current_source_ids(db, row.agent_id, row.origin_session_id)
        if (not read_ids and not row.source_call_ids and not checked_memories
                and not current_reads and not current_memories):
            safe = row.id in manual
        else:
            safe = False
            if (read_ids and read_ids == current_reads and checked_memories == current_memories
                    and not checked_memories and set(row.source_call_ids) == read_ids):
                calls = [db.get(ToolCall, value) for value in row.source_call_ids]
                content = _trusted_extract(db, calls) if all(calls) else ""
                safe = bool(content and (row.id in manual or (
                    "trusted_source_extract" in (row.findings or []) and row.text == content)))
        if not safe:
            row.status = "quarantined"
            row.findings = list(dict.fromkeys([*(row.findings or []), "source_review_required"]))
            seal_memory(db, row)
            audit(db, None, "memory_reclassified", {"memory_id": row.id,
                "text_hash": row.text_hash, "status": row.status,
                "reason": "source_review_required", "rules_version": VERSION})
            changed += 1
    if changed:
        db.commit()
    return changed


def _classify(db: Session, text: str, sources: list[ToolCall], output: OutputCheck) -> tuple[str, list[str], str]:
    hard, review = memory_risks(text)
    findings = [*hard, *review]
    from .data_flow import contains_secret, source_context
    if contains_secret(text):
        hard.append("secret_memory_text")
        findings.append("secret_memory_text")
    context_levels = [item["level"] for item in source_context(db, output.agent_id, output.session_id)]
    if any(level != "public" for level in context_levels):
        findings.append("private_source_context")
    for call in sources:
        result = call.result or {}
        content = result.get("content", "")
        if result.get("sensitivity") == "private" and isinstance(content, str) and (
                content in text or any(number in text for number in re.findall(r"\b\d{4,}\b", content))):
            hard.append("private_source_leak")
            findings.append("private_source_leak")
    if hard:
        return "rejected", list(dict.fromkeys(findings)), text
    stored_text = text
    if sources:
        content = _trusted_extract(db, sources)
        if not content:
            findings.append("source_review_required")
        else:
            source_hard, source_review = memory_risks(content)
            if source_hard:
                return "rejected", list(dict.fromkeys([*findings, *source_hard])), content
            if source_review:
                findings.extend(["source_content_review", *source_review])
            else:
                stored_text = content
                findings.append("trusted_source_extract")
    else:
        findings.append("source_review_required")
    if any(source.get("tool") == "memory" for source in output.sources):
        findings.append("memory_context_review")
    if output.outcome == "warn" and (not output.findings or
            set(output.findings) - {"unverified_sentence"}):
        findings.append("output_warning")
    blocking = set(findings) - {"trusted_source_extract"}
    return ("quarantined" if blocking else "active"), findings, stored_text


def write_candidates(db: Session, agent_id: str, session_id: str,
                     body: MemoryWriteRequest) -> dict:
    if not enabled():
        raise ValueError("长期记忆已关闭")
    reconcile_active_memories(db)
    fingerprint = _hash(body.model_dump(mode="json"))
    existing = db.get(MemoryWrite, str(body.write_id))
    if existing:
        if (existing.agent_id, existing.session_id, existing.request_fingerprint) != (
                agent_id, session_id, fingerprint):
            raise ValueError("写入 ID 已用于其他内容")
        rows = [db.get(MemoryEntry, item) for item in existing.entry_ids]
        if any(row and not verify_memory(db, row) for row in rows):
            db.commit()
            raise ValueError("记忆完整性异常")
        return {"write_id": existing.id, "items": [{"id": row.id, "status": row.status,
                "findings": row.findings} for row in rows if row]}
    _session(db, agent_id, session_id)
    output = db.get(OutputCheck, str(body.output_check_id))
    if (output is None or output.agent_id != agent_id or output.session_id != session_id
            or output.output_kind != "final_answer" or output.outcome == "block"):
        raise ValueError("记忆写入缺少本会话已放行的最终回答检查")
    required = {item["call_id"] for item in output.sources
                if item.get("tool") in {"read_document", "mcp_lookup_card", "github_mcp_read_license", "github_mcp_read_issue"}}
    current_reads, current_memories = _current_source_ids(db, agent_id, session_id)
    checked_memories = {item["call_id"] for item in output.sources
                        if item.get("tool") == "memory"}
    if required != current_reads or checked_memories != current_memories:
        raise ValueError("最终回答检查早于本会话的最新来源读取")
    _expire(db)
    verified_items = []
    for item in body.items:
        source_ids = [str(value) for value in item.source_call_ids]
        if len(source_ids) != len(set(source_ids)) or set(source_ids) != required:
            raise ValueError("记忆来源未经过本会话输出检查")
        sources = [db.get(ToolCall, value) for value in source_ids]
        if any(value is None or value.agent_id != agent_id or value.session_id != session_id
               for value in sources):
            raise ValueError("记忆来源不属于本会话")
        verified_items.append((item, source_ids, sources))
    active_count = db.scalar(select(func.count()).select_from(MemoryEntry).where(
        MemoryEntry.agent_id == agent_id, MemoryEntry.status == "active",
        MemoryEntry.expires_at > utcnow())) or 0
    write = MemoryWrite(id=str(body.write_id), agent_id=agent_id, session_id=session_id,
                        output_check_id=output.id, request_fingerprint=fingerprint, entry_ids=[])
    db.add(write)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        current = db.get(MemoryWrite, str(body.write_id))
        if current and (current.agent_id, current.session_id, current.request_fingerprint) == (
                agent_id, session_id, fingerprint):
            rows = [db.get(MemoryEntry, value) for value in current.entry_ids]
            if any(row and not verify_memory(db, row) for row in rows):
                db.commit()
                raise ValueError("记忆完整性异常")
            return {"write_id": current.id, "items": [{"id": row.id, "status": row.status,
                "findings": row.findings} for row in rows if row]}
        raise ValueError("写入 ID 已用于其他内容")
    views = []
    for item, source_ids, sources in verified_items:
        status, findings, stored_text = _classify(db, item.text, sources, output)
        if status == "active" and active_count >= 100:
            status, findings = "rejected", ["active_memory_limit"]
        if status == "active":
            active_count += 1
        entry = MemoryEntry(
            id=str(uuid.uuid4()), write_id=write.id, agent_id=agent_id,
            origin_session_id=session_id, kind=item.kind,
            text=stored_text if status != "rejected" else None,
            text_hash=_hash(stored_text), status=status, trust_level="untrusted",
            findings=findings, source_call_ids=source_ids,
            expires_at=utcnow() + timedelta(days=30),
        )
        db.add(entry)
        seal_memory(db, entry)
        views.append({"id": entry.id, "status": status, "findings": findings})
        audit(db, None, "memory_write", {"memory_id": entry.id, "write_id": write.id,
              "agent_id": agent_id, "origin_session_id": session_id, "text_hash": entry.text_hash,
              "status": status, "source_call_ids": source_ids, "rules_version": VERSION})
        from .data_flow import record as record_data_flow, source_context
        record_data_flow(db, agent_id, session_id, "memory", "tenant-memory",
            source_context(db, agent_id, session_id), status, findings, _hash(item.text),
            related_id=entry.id,
            detected_level="secret" if "secret_memory_text" in findings else "public")
    # SQLAlchemy JSON does not track in-place list mutation.
    write.entry_ids = [item["id"] for item in views]
    db.commit()
    return {"write_id": write.id, "items": views}


def _score(query: str, text: str) -> int:
    q = set(_WORDS.findall(query.lower()))
    t = set(_WORDS.findall(text.lower()))
    return len(q & t) * 10 + sum(1 for word in q if word in text.lower())


def _safe_active(db: Session, row: MemoryEntry) -> bool:
    if not verify_memory(db, row):
        return False
    if row.status != "active" or not row.text or _aware(row.expires_at) <= utcnow():
        return False
    hard, review = memory_risks(row.text)
    if hard or review:
        row.status = "quarantined"
        row.findings = list(dict.fromkeys([*(row.findings or []), *hard, *review,
                                           "read_time_review"]))
        seal_memory(db, row)
        audit(db, None, "memory_read_blocked", {"memory_id": row.id,
              "text_hash": row.text_hash, "reason": "content_risk",
              "rules_version": VERSION})
        return False
    return True


def read_memories(db: Session, agent_id: str, session_id: str,
                  body: MemoryReadRequest) -> dict:
    if not enabled():
        raise ValueError("长期记忆已关闭")
    _session(db, agent_id, session_id)
    reconcile_active_memories(db)
    fingerprint = _hash(body.query)
    existing = db.get(MemoryRead, str(body.read_id))
    if existing:
        if (existing.agent_id, existing.session_id, existing.query_hash) != (
                agent_id, session_id, fingerprint):
            raise ValueError("读取 ID 已用于其他查询")
        rows = [db.get(MemoryEntry, item) for item in existing.memory_ids]
        items = [_entry_view(row) for row in rows
                 if row and row.agent_id == agent_id and _safe_active(db, row)]
        db.commit()
        return {"read_id": existing.id, "items": items}
    _expire(db)
    rows = db.scalars(select(MemoryEntry).where(MemoryEntry.agent_id == agent_id,
                                                MemoryEntry.status == "active",
                                                MemoryEntry.expires_at > utcnow())).all()
    rows = [row for row in rows if _safe_active(db, row)]
    rows.sort(key=lambda row: (_score(body.query, row.text or ""), _aware(row.created_at)), reverse=True)
    selected = rows[:5]
    db.add(MemoryRead(id=str(body.read_id), agent_id=agent_id, session_id=session_id,
                      query_hash=fingerprint, memory_ids=[row.id for row in selected]))
    audit(db, None, "memory_read", {"read_id": str(body.read_id), "agent_id": agent_id,
          "session_id": session_id, "memory_ids": [row.id for row in selected],
          "query_hash": fingerprint})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        current = db.get(MemoryRead, str(body.read_id))
        if not current or (current.agent_id, current.session_id, current.query_hash) != (
                agent_id, session_id, fingerprint):
            raise ValueError("读取 ID 已用于其他查询")
        rows = [db.get(MemoryEntry, value) for value in current.memory_ids]
        items = [_entry_view(row) for row in rows
                 if row and row.agent_id == agent_id and _safe_active(db, row)]
        db.commit()
        return {"read_id": current.id, "items": items}
    return {"read_id": str(body.read_id), "items": [_entry_view(row) for row in selected]}


def list_memories(db: Session, agent_id: str = "demo-agent") -> list[dict]:
    _expire(db)
    reconcile_active_memories(db)
    items = []
    for row in db.scalars(select(MemoryEntry).where(
            MemoryEntry.agent_id == agent_id).order_by(MemoryEntry.created_at.desc()).limit(200)).all():
        valid = verify_memory(db, row)
        view = _entry_view(row)
        view["integrity_status"] = "valid" if valid else "failed"
        if not valid:
            from .models import MemorySeal
            legacy = (db.get(MemorySeal, row.id) is None and
                      "legacy_unverified" in (row.findings or []) and row.status == "quarantined")
            if not legacy:
                view["text"] = None
                view["status"] = "integrity_failed"
        items.append(view)
    db.commit()
    return items


def decide_memory(db: Session, memory_id: str, action: str) -> dict:
    row = db.get(MemoryEntry, memory_id, with_for_update=True)
    if row is None:
        raise ValueError("记忆不存在")
    _expire(db)
    if action != "purge" and not verify_memory(db, row):
        db.commit()
        raise ValueError("记忆完整性异常，请先复核或清除")
    if action == "activate":
        if row.status != "quarantined" or not row.text:
            raise ValueError("仅隔离中的记忆可激活")
        hard, review = memory_risks(row.text)
        if hard or review:
            raise ValueError("危险内容不能激活")
        if row.source_call_ids:
            calls = [db.get(ToolCall, value) for value in row.source_call_ids]
            if not all(calls) or not _trusted_extract(db, calls):
                raise ValueError("来源未经审核或已撤销")
        active_count = db.scalar(select(func.count()).select_from(MemoryEntry).where(
            MemoryEntry.agent_id == row.agent_id, MemoryEntry.status == "active",
            MemoryEntry.expires_at > utcnow())) or 0
        if active_count >= 100:
            raise ValueError("有效记忆数量已达上限")
        row.status = "active"
    elif action == "revoke":
        if row.status not in {"active", "quarantined"}:
            raise ValueError("记忆不可撤销")
        row.status = "revoked"
    elif action == "purge":
        row.status = "purged"
        row.text = None
    else:
        raise ValueError("未知记忆操作")
    seal_memory(db, row)
    audit(db, None, "memory_decision", {"memory_id": row.id, "text_hash": row.text_hash,
          "status": row.status, "action": action})
    db.commit()
    return _entry_view(row)


def review_legacy_memory(db: Session, memory_id: str) -> dict:
    from .models import MemorySeal
    row = db.get(MemoryEntry, memory_id, with_for_update=True)
    if row is None or row.status != "quarantined" or not row.text:
        raise ValueError("仅可复核仍有文字的历史隔离记忆")
    if db.get(MemorySeal, row.id) is not None:
        raise ValueError("这条记忆已经完成完整性登记")
    if not hmac.compare_digest(row.text_hash, _hash(row.text)):
        raise ValueError("历史记忆文字与原始摘要哈希不一致")
    hard, review = memory_risks(row.text)
    if hard or review:
        raise ValueError("危险内容不能登记为可信历史记忆")
    if row.source_call_ids:
        calls = [db.get(ToolCall, value) for value in row.source_call_ids]
        content = _trusted_extract(db, calls) if all(calls) else ""
        if not content or row.text != content:
            raise ValueError("历史记忆与已审核来源原文不一致")
    row.findings = [value for value in row.findings or [] if value != "legacy_unverified"]
    seal_memory(db, row)
    audit(db, None, "memory_legacy_review", {"memory_id": row.id,
          "text_hash": row.text_hash, "status": row.status, "rules_version": VERSION})
    db.commit()
    return _entry_view(row)


def record_failure(db: Session, agent_id: str, session_id: str,
                   body: MemoryFailureRequest) -> dict:
    _session(db, agent_id, session_id)
    existing = db.get(MemoryFailure, str(body.failure_id))
    if existing:
        if (existing.agent_id, existing.session_id, existing.stage, existing.error_code) != (
                agent_id, session_id, body.stage, body.error_code):
            raise ValueError("失败 ID 已用于其他事件")
        return {"failure_id": existing.id, "recorded": True}
    db.add(MemoryFailure(id=str(body.failure_id), agent_id=agent_id, session_id=session_id,
                         stage=body.stage, error_code=body.error_code))
    audit(db, None, "memory_failure", {"failure_id": str(body.failure_id),
          "agent_id": agent_id, "session_id": session_id,
          "stage": body.stage, "error_code": body.error_code})
    db.commit()
    return {"failure_id": str(body.failure_id), "recorded": True}
