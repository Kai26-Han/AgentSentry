"""深入验证场景索引；具体固定输入由 scripts/deep_validation.py 构造。

索引版本和运行器 SHA-256 一起标识实验，不把场景数量解释为风险覆盖率。
"""

VERSION = "deep-validation-v1"


def group(stage, ids):
    return [{"id": value, "stage": stage} for value in ids]


CASES = [
    *group("authorization", [f"AUTH-{i}-{kind}" for i in range(3) for kind in ("LAST", "REPLAY")]),
    *group("authorization", ["AUTH-APPROVAL-" + v for v in ("DOUBLE", "REVOKE", "PAUSE", "SOURCE", "TAMPER")]),
    *group("authorization", ["AUTH-FAULT-COMMIT", "AUTH-FAULT-UNKNOWN"]),
    *group("outputs", ["OUTPUT-" + v for v in ("COPY", "SPACE", "URL", "BASE64", "URL-BASE64", "WORDS-CN", "WORDS-EN",
        "ARITHMETIC", "UNRELATED", "INSTRUCTION", "MARKER", "QUOTE", "PUBLIC", "SECRET-ENCODED")]),
    *group("memories", ["MEMORY-" + v for v in ("SAFE", "UNREVIEWED", "INSTRUCTION", "FALSE-CANDIDATE", "REVOKE",
        "EXPIRED", "TAMPER", "RESUMMARY")]),
    *group("behavior", ["CHAIN-" + v for v in ("SESSION-CONCURRENT", "AGENT-MULTISESSION", "RESOURCE-PROBE", "NORMAL", "SEMANTIC-DRIFT")]),
    *group("mcp", ["MCP-" + v for v in ("SAFE", "SCHEMA-DRIFT", "WRONG-ID", "WRONG-TYPE", "OVERSIZED-UTF8",
        "CONTENT-POISON", "UNAVAILABLE", "COMMIT-THEN-ERROR", "COMMIT-THEN-TIMEOUT")]),
]
