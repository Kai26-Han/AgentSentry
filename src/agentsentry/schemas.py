from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict, model_validator

from .config import get_settings


class ReadDocumentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,100}$")


class CreateTaskArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    list_id: Literal["main"] = "main"


class DeleteTaskArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: UUID


class SendExternalArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    destination_id: Literal["demo-inbox"]
    content: str = Field(min_length=1, max_length=2000)


class RunShellArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(min_length=1, max_length=1000)
    timeout_seconds: int = Field(default=3, ge=1, le=5)


class MCPLookupCardArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    card_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class MCPRecordNoteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    text: str = Field(min_length=1, max_length=500)


class RemoteMCPLookupCardArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    card_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class RemoteMCPRecordNoteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    text: str = Field(min_length=1, max_length=500)


class GitHubMCPReadLicenseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GitHubMCPReadIssueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GitHubMCPCreateTestIssueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository: str = Field(min_length=3, max_length=140)
    title: str = Field(min_length=20, max_length=140,
                       pattern=r"^\[AgentSentry Test\] [^\r\n]{1,121}$")
    body: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def fixed_repository(self):
        if not get_settings().github_mcp_test_repo or self.repository != get_settings().github_mcp_test_repo:
            raise ValueError("GitHub test repository does not match trusted configuration")
        return self


TOOL_SCHEMAS = {
    "read_document": ReadDocumentArgs,
    "create_task": CreateTaskArgs,
    "delete_task": DeleteTaskArgs,
    "send_external": SendExternalArgs,
    "run_shell": RunShellArgs,
    "mcp_lookup_card": MCPLookupCardArgs,
    "mcp_record_note": MCPRecordNoteArgs,
    "remote_mcp_lookup_card": RemoteMCPLookupCardArgs,
    "remote_mcp_record_note": RemoteMCPRecordNoteArgs,
    "github_mcp_read_license": GitHubMCPReadLicenseArgs,
    "github_mcp_read_issue": GitHubMCPReadIssueArgs,
    "github_mcp_create_test_issue": GitHubMCPCreateTestIssueArgs,
}


def resource_for(tool: str, arguments: dict) -> str:
    return {
        "read_document": lambda: arguments["document_id"],
        "create_task": lambda: arguments["list_id"],
        "delete_task": lambda: str(arguments["task_id"]),
        "send_external": lambda: arguments["destination_id"],
        "run_shell": lambda: "sandbox-shell",
        "mcp_lookup_card": lambda: arguments["card_id"],
        "mcp_record_note": lambda: "demo-notes",
        "remote_mcp_lookup_card": lambda: arguments["card_id"],
        "remote_mcp_record_note": lambda: "remote-demo-notes",
        "github_mcp_read_license": lambda: "github/github-mcp-server:LICENSE",
        "github_mcp_read_issue": lambda: "modelcontextprotocol/modelcontextprotocol#3213",
        "github_mcp_create_test_issue": lambda: arguments["repository"],
    }[tool]()


class CapabilityRequest(BaseModel):
    agent_id: Literal["demo-agent"]
    tool: Literal["read_document", "create_task", "delete_task", "send_external", "run_shell", "mcp_lookup_card", "mcp_record_note", "remote_mcp_lookup_card", "remote_mcp_record_note", "github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"]
    resources: list[str] = Field(min_length=1, max_length=20)
    ttl_seconds: int = Field(ge=30, le=3600)
    max_uses: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def validate_resources(self):
        if any(not value or len(value) > 100 for value in self.resources):
            raise ValueError("Invalid resource")
        return self


class ToolCallRequest(BaseModel):
    call_id: UUID
    session_id: str = Field(min_length=1, max_length=100)
    tool: Literal["read_document", "create_task", "delete_task", "send_external", "run_shell", "mcp_lookup_card", "mcp_record_note", "remote_mcp_lookup_card", "remote_mcp_record_note", "github_mcp_read_license", "github_mcp_read_issue", "github_mcp_create_test_issue"]
    arguments: dict


class DelegationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    parent_session_id: str = Field(min_length=1, max_length=100)
    worker_agent_id: Literal["reader-agent"] = "reader-agent"
    tool: Literal["read_document", "mcp_lookup_card"]
    resources: list[str] = Field(min_length=1, max_length=3)
    max_uses: int = Field(ge=1, le=3)
    ttl_seconds: int = Field(ge=30, le=300)

    @model_validator(mode="after")
    def bounded_resources(self):
        import re
        if (len(set(self.resources)) != len(self.resources) or len(self.resources) > self.max_uses
                or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", value) for value in self.resources)):
            raise ValueError("Invalid delegated resource set")
        return self


class DelegatedToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call: ToolCallRequest
    envelope: dict
    envelope_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bounded_envelope(self):
        import json
        if len(json.dumps(self.envelope).encode()) > 4096:
            raise ValueError("Delegation envelope too large")
        return self


class DelegationResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: dict
    envelope_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    text: str = Field(min_length=1, max_length=500)
    source_call_ids: list[UUID] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def bounded_envelope(self):
        import json
        if len(json.dumps(self.envelope).encode()) > 4096:
            raise ValueError("Delegation envelope too large")
        return self


class RuntimeSessionStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: Literal["http", "mcp"]
    model_name: str = Field(default="", max_length=120)
    capture_mode: Literal["preview", "metadata"] = "preview"
    user_task: str = Field(default="", max_length=2000)
    user_task_truncated: bool = False


class RuntimeSessionFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["completed", "failed"]
    final_answer: str = Field(default="", max_length=2000)
    final_answer_truncated: bool = False
    error_code: str = Field(default="", pattern=r"^[a-zA-Z0-9_-]{0,80}$")
    adapter_attempts: list[dict[str, str]] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_adapter_attempts(self):
        for item in self.adapter_attempts:
            if set(item) != {"tool", "error_code"}:
                raise ValueError("Invalid adapter attempt fields")
            if not 1 <= len(item["tool"]) <= 100 or not 1 <= len(item["error_code"]) <= 80:
                raise ValueError("Invalid adapter attempt length")
            if not all(char.isalnum() or char in "_-" for char in item["error_code"]):
                raise ValueError("Invalid adapter error code")
        return self


class RuntimeSessionReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=100)
    session_id: str = Field(min_length=1, max_length=100)
    status: Literal["unreviewed", "investigating", "confirmed", "false_positive"]
    note: str = Field(default="", max_length=500)


class RuntimeControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=100)
    session_id: str | None = Field(default=None, min_length=1, max_length=100)
    scope: Literal["agent", "session"]
    paused: bool
    reason: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def validate_scope(self):
        if (self.scope == "session") != (self.session_id is not None):
            raise ValueError("Session scope requires exactly one session ID")
        if self.paused and not self.reason.strip():
            raise ValueError("Pausing tools requires a reason")
        return self


class OutputCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: UUID
    capture_mode: Literal["preview", "metadata"]
    output_kind: Literal["final_answer", "tool_result"]
    draft: str = Field(max_length=8192)
    user_task: str = Field(default="", max_length=2000)
    source_call_ids: list[UUID] = Field(default_factory=list, max_length=40)


class ModelEgressCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    destination_id: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=120)
    purpose: Literal["task", "memory_summary"]
    messages: list[dict] = Field(min_length=1, max_length=50)
    source_call_ids: list[UUID] = Field(default_factory=list, max_length=40)
    memory_ids: list[UUID] = Field(default_factory=list, max_length=5)


class MemoryCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["fact", "preference", "task_context"]
    text: str = Field(min_length=1, max_length=500)
    source_call_ids: list[UUID] = Field(default_factory=list, max_length=20)


class MemoryWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    write_id: UUID
    output_check_id: UUID
    items: list[MemoryCandidate] = Field(max_length=3)


class MemorySourceTrustRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call_id: UUID


class MemoryReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    read_id: UUID
    query: str = Field(min_length=1, max_length=2000)


class MemoryDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["activate", "revoke", "purge"]


class MemoryFailureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failure_id: UUID
    stage: Literal["read", "summary", "write"]
    error_code: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")


class ApprovalDecision(BaseModel):
    decision: Literal["approve", "reject"]


class GoalLabRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["scripted", "live"]
    model_name: str = Field(default="", max_length=120)


class GoalLabCaseSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[AN][0-9]{2}$")
    repetition: int = Field(ge=1, le=3)
    session_id: str = Field(min_length=1, max_length=100)
    trace: list[dict] = Field(default_factory=list, max_length=60)
    final_answer: str = Field(default="", max_length=8192)
    display_text: str = Field(default="", max_length=9000)
    finished: bool = False
    error: str = Field(default="", max_length=80)


class GoalLabRunFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failed: bool = False


class JudgeSampleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    event_type: Literal["tool_result", "policy_decision", "capability_denied"]
    payload: dict
    expected_labels: list[Literal["prompt_injection", "exfiltration", "tool_misuse", "none"]] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_sample(self):
        import json
        if len(json.dumps(self.payload, ensure_ascii=False)) > 4000:
            raise ValueError("Sample payload too large")
        if "none" in self.expected_labels and len(self.expected_labels) != 1:
            raise ValueError("none cannot be combined with risk labels")
        return self


class JudgeSampleRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["mock", "openai_compat", "jev", "deepseek"] | None = None


class JudgeRuntimeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["mock", "openai_compat", "jev", "deepseek"]
    expected_revision: int = Field(ge=1)


class PolicyUpdate(BaseModel):
    yaml: str = Field(min_length=1, max_length=65536)


class TenantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)


class AttackRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["scripted", "live"]
    model_name: str = Field(default="", max_length=120)
    model_host: str = Field(default="", max_length=200)


class AttackCaseSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[A-Z][0-9]{2}$")
    call_ids: list[UUID] = Field(default_factory=list, max_length=20)
    trace: list[dict] = Field(default_factory=list, max_length=40)
    final_answer: str = Field(default="", max_length=2000)
    error: str = Field(default="", max_length=300)


class AttackRunFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failed: bool = False
    error: str = Field(default="", max_length=300)


class CalibrationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["scripted", "live"]
    model_name: str = Field(default="", max_length=120)
    model_host: str = Field(default="", max_length=200)


class CalibrationCaseSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[AN][0-9]{2}$")
    repetition: int = Field(ge=1, le=3)
    call_ids: list[UUID] = Field(default_factory=list, max_length=20)
    trace: list[dict] = Field(default_factory=list, max_length=40)
    final_answer: str = Field(default="", max_length=2000)
    output_check_id: UUID | None = None
    memory_ids: list[UUID] = Field(default_factory=list, max_length=3)
    finished: bool = True
    error: str = Field(default="", max_length=300)


class MemoryLabRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["scripted", "live"]
    model_name: str = Field(default="", max_length=120)


class MemoryLabCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^(D|M|N)[0-9]{2}$")
    memory_ids: list[UUID] = Field(default_factory=list, max_length=3)
    read_id: UUID | None = None
    output_check_ids: list[UUID] = Field(default_factory=list, max_length=2)
    call_ids: list[UUID] = Field(default_factory=list, max_length=20)
    write_finished: bool = False
    read_finished: bool = False
    second_answer: str = Field(default="", max_length=2000)
    error: str = Field(default="", max_length=300)
