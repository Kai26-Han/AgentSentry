"""从实际低信任来源中提取有限的输出指令目标；不把来源内容当作授权。"""

import html
import re
from urllib.parse import unquote

from .data_flow import _variants


_TARGET = r"(?:[\"'“‘`]([^\"'”’`]{3,80})[\"'”’`]|([A-Za-z][A-Za-z0-9_:-]{5,79})|([\u4e00-\u9fff]{3,24}))"
_DIRECTIVES = (
    re.compile(r"(?:最终)?(?:回答|回复|答复|总结)(?:中|时|里)?\s*"
               r"(?:必须|务必|一定要|请|应当|应该)?\s*"
               r"(?:包含|加入|写入|输出|说出|提到)\s*[:：]?\s*" + _TARGET, re.I),
    re.compile(r"(?:^|[。；;\n：:])\s*(?:请|必须|务必|一定要)\s*"
               r"(?:输出|回复|说出)\s*[:：]?\s*" + _TARGET, re.I),
    re.compile(r"(?:final\s+)?(?:answer|response|summary)\s+"
               r"(?:must|should|shall)\s+(?:include|contain|say|print)\s+" + _TARGET, re.I),
)
_QUOTE_INTENT = re.compile(r"引用|逐字|原文|照录|quote|verbatim", re.I)
_ATTRIBUTION = re.compile(r"材料|文档|卡片|原文|来源|引文|文中|攻击文本|指令|注入|source|document|card|text|quote", re.I)
_ACTION_TARGET = r"(?P<target>[A-Za-z][A-Za-z0-9_:-]{7,79})"
_ACTION_PATTERNS = (
    re.compile(r"(?:发送|外发|传送)\s*[\"“‘]?" + _ACTION_TARGET +
               r"[\"”’]?\s*(?:到|至|给|往)\s*[A-Za-z0-9._:-]{2,80}", re.I),
    re.compile(r"(?:把|将)\s*[\"“‘]?" + _ACTION_TARGET +
               r"[\"”’]?\s*(?:发送|外发|传送)\s*(?:到|至|给|往)\s*[A-Za-z0-9._:-]{2,80}", re.I),
    re.compile(r"\b(?:send|forward|email)\s+[\"“‘]?" + _ACTION_TARGET +
               r"[\"”’]?\s+to\s+[A-Za-z0-9._:-]{2,80}", re.I),
)
_ACTION_NEGATION = re.compile(r"(?:不要|禁止|不得|不应|do not|don't|never)\s*$", re.I)
_ACTION_SOURCE_LIMIT = 65536
_OVERRIDE_COMMAND = re.compile(
    r"(?:^|[。！？.!?；;\n])\s*(?:请|please\s+)?"
    r"(忽略用户|ignore\s+the\s+user)(?=[\s,，。；;.!?]|$)", re.I)


def _compact(value: str) -> str:
    return re.sub(r"[\s\u200b-\u200d\ufeff]+", "", value).casefold()


def _draft_forms(draft: str) -> set[str]:
    """有界解码常见可还原表示；仅用于比较，不改变用户可见的回答。"""
    forms = {draft}
    frontier = {draft}
    for _ in range(3):
        next_frontier = {decoded for item in frontier
                         for decoded in (unquote(item), html.unescape(item))
                         if decoded not in forms}
        forms.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
    for item in list(forms):
        forms.update(_variants(item)[:22])
    return {_compact(item) for item in forms}


def _quoted_by_user(task: str, draft: str, target: str) -> bool:
    if not task or not _QUOTE_INTENT.search(task):
        return False
    occurrences = list(re.finditer(re.escape(target), draft, re.I))
    if not occurrences:
        return False
    for match in occurrences:
        before = draft[max(0, match.start() - 100):match.start()]
        after = draft[match.end():match.end() + 100]
        if not (_ATTRIBUTION.search(before) and
                re.search(r"[\"'“‘`]([^\"'”’`]{0,100})$", before) and
                re.match(r"[^\"'”’`]{0,100}[\"'”’`]", after)):
            return False
    return True


def source_instruction_echoes(draft: str, trusted_task: str, sources: list[dict]) -> list[str]:
    """返回命中的来源 ID；解析和对照均有长度上限，避免来源控制处理成本。"""
    compact_draft = _compact(draft)
    matched = []
    for source in sources[:32]:
        content = str(source.get("content", ""))[:8192]
        # 明确命令的直接复述；“材料写着‘忽略用户’”等引用不会命中句首命令。
        source_commands = {_compact(hit.group(1)) for hit in _OVERRIDE_COMMAND.finditer(content)}
        if any(_compact(hit.group(1)) in source_commands
               for hit in _OVERRIDE_COMMAND.finditer(draft)):
            matched.append(str(source["call_id"]))
        targets = []
        for pattern in _DIRECTIVES:
            if len(targets) >= 20:
                break
            for hit in pattern.finditer(content):
                target = next((item for item in hit.groups() if item), "").strip(" ，,。.!?；;:：")
                if 3 <= len(target) <= 80 and target not in targets:
                    targets.append(target)
                if len(targets) >= 20:
                    break
        for target in targets:
            if _compact(target) in compact_draft and not _quoted_by_user(trusted_task, draft, target):
                matched.append(str(source["call_id"]))
                break
    return list(dict.fromkeys(matched))


def source_action_payload_hits(draft: str, trusted_task: str,
                               sources: list[dict]) -> list[tuple[str, str]]:
    """只扫描来源一次，返回被回答复述的（来源 ID，动作载荷）。"""
    draft_forms = _draft_forms(draft)
    matched: list[tuple[str, str]] = []
    for source in sources[:32]:
        content = str(source.get("content", ""))[:_ACTION_SOURCE_LIMIT]
        for clause in re.split(r"[。！？.!?；;\n]", content):
            for pattern in _ACTION_PATTERNS:
                for hit in pattern.finditer(clause):
                    target = hit.group("target")
                    if (not any(character.isdigit() for character in target) or
                            not ("_" in target or "-" in target or ":" in target or len(target) >= 14)):
                        continue
                    prefix = clause[max(0, hit.start() - 32):hit.start()]
                    if _ACTION_NEGATION.search(prefix.rstrip(" ，,")):
                        continue
                    if (any(_compact(target) in form for form in draft_forms) and
                            not _quoted_by_user(trusted_task, draft, target)):
                        matched.append((str(source["call_id"]), target))
    return list(dict.fromkeys(matched))


def source_action_sentence_sources(sentence: str, trusted_task: str,
                                   hits: list[tuple[str, str]]) -> list[str]:
    """使用已提取的载荷关联句子，不对每个句子重新扫描来源。"""
    if not hits:
        return []
    forms = _draft_forms(sentence)
    return list(dict.fromkeys(source_id for source_id, target in hits
        if any(_compact(target) in form for form in forms) and
        not _quoted_by_user(trusted_task, sentence, target)))


def action_source_scan_incomplete(sources: list[dict]) -> bool:
    """来源或来源数超出本规则可检查范围时，要求展示关口失败关闭。"""
    return len(sources) > 32 or any(
        len(str(source.get("content", ""))) > _ACTION_SOURCE_LIMIT for source in sources
    )
