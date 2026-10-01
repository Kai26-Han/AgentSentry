"""本地会话片段脱敏；输入中的指令文本本身仍保留作调查证据。"""

import re


PREVIEW_LIMIT = 1000
_BEARER = re.compile(r"(?i)(?<![A-Za-z0-9_])Bearer\s+[^\s,;，；。]+")
_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(api[ _-]?key|access[ _-]?token|refresh[ _-]?token|token|password|passwd|secret)"
    r"(\s*[:=]\s*)([^\s,;&#，；。]+)"
)
_STANDALONE_KEY = re.compile(r"(?<![\w-])(?:sk|sk-ant|sk-proj)-[A-Za-z0-9_-]{16,}")
_EMAIL = re.compile(r"(?<![A-Za-z0-9_.+-])[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_IDENTITY = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")


def redact_preview(value: str) -> tuple[str, bool]:
    text = _BEARER.sub("Bearer [已脱敏]", value)
    text = _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + "[已脱敏]", text)
    text = _STANDALONE_KEY.sub("[已脱敏]", text)
    text = _EMAIL.sub("[邮箱]", text)
    text = _PHONE.sub("[手机号]", text)
    text = _IDENTITY.sub("[身份证号]", text)
    return text[:PREVIEW_LIMIT], len(text) > PREVIEW_LIMIT
