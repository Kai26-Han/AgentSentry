import re
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .schemas import TOOL_SCHEMAS


class RegexCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(min_length=1, max_length=100)
    pattern: str = Field(min_length=1, max_length=200)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,99}$")
    effect: str
    tool: str
    argument_regex: RegexCondition | None = None

    @model_validator(mode="after")
    def validate_rule(self):
        if self.effect not in {"allow", "deny", "require_approval"}:
            raise ValueError("Invalid effect")
        if self.tool not in TOOL_SCHEMAS:
            raise ValueError("Unknown policy tool")
        if self.tool in {"delete_task", "send_external", "run_shell", "mcp_record_note", "remote_mcp_record_note", "github_mcp_create_test_issue"} and self.effect == "allow":
            raise ValueError("Sensitive tools require approval")
        if self.argument_regex:
            if self.effect != "deny":
                raise ValueError("Regex conditions may only deny")
            if self.argument_regex.field not in TOOL_SCHEMAS[self.tool].model_fields:
                raise ValueError("Unknown policy argument field")
            re.compile(self.argument_regex.pattern)
        return self


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    default: str
    rules: list[Rule]

    @model_validator(mode="after")
    def validate_file(self):
        if self.version != 1 or self.default != "deny":
            raise ValueError("V1 requires version 1 and default deny")
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate rule ID")
        return self


@dataclass(frozen=True)
class Decision:
    effect: str
    rule_id: str
    revision: str = ""


class PolicyEngine:
    def __init__(self, policy: PolicyFile, revision: str = ""):
        self.policy = policy
        self.revision = revision

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        return cls.from_content(Path(path).read_bytes())

    @classmethod
    def from_content(cls, content: bytes) -> "PolicyEngine":
        data = yaml.safe_load(content)
        return cls(PolicyFile.model_validate(data), hashlib.sha256(content).hexdigest()[:12])

    def decide(self, tool: str, arguments: dict) -> Decision:
        matches = []
        for rule in self.policy.rules:
            if rule.tool != tool:
                continue
            if rule.argument_regex:
                value = arguments.get(rule.argument_regex.field)
                if not isinstance(value, str) or not re.search(rule.argument_regex.pattern, value[:4000]):
                    continue
            matches.append(rule)
        for effect in ("deny", "require_approval", "allow"):
            for rule in matches:
                if rule.effect == effect:
                    return Decision(effect, rule.id, self.revision)
        return Decision("deny", "default_deny", self.revision)


class PolicyManager:
    """Validate a candidate completely before atomically swapping the active policy."""

    def __init__(self, path: str):
        self.path = path
        self._lock = RLock()
        self._engine = PolicyEngine.from_file(path)

    @property
    def policy(self) -> PolicyFile:
        with self._lock:
            return self._engine.policy

    @property
    def revision(self) -> str:
        with self._lock:
            return self._engine.revision

    def decide(self, tool: str, arguments: dict) -> Decision:
        with self._lock:
            engine = self._engine
        return engine.decide(tool, arguments)

    def reload(self) -> str:
        candidate = PolicyEngine.from_file(self.path)
        with self._lock:
            self._engine = candidate
            return candidate.revision

    def replace(self, content: str) -> str:
        encoded = content.encode("utf-8")
        if not 1 <= len(encoded) <= 65536:
            raise ValueError("Policy size must be 1–65536 bytes")
        candidate = PolicyEngine.from_content(encoded)
        path = Path(self.path)
        with self._lock:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
                    temporary = handle.name
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                if temporary and os.path.exists(temporary):
                    os.unlink(temporary)
            self._engine = candidate
            return candidate.revision
