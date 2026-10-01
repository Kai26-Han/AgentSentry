from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
import json
import re

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./agentsentry.db"
    redis_url: str = "redis://localhost:6379/0"
    agentsentry_port: int = 8000
    admin_password: str = ""
    session_secret: str = ""
    agent_api_key: str = ""
    policy_path: str = str(Path(__file__).resolve().parents[2] / "policies/default.yaml")
    sandbox_url: str = "http://127.0.0.1:8080"
    mcp_demo_dir: str = ".local/mcp-data"
    judge_provider: str = "mock"
    judge_score_threshold: float = 0.7
    alert_cooldown_seconds: int = 600
    webhook_url: str = ""
    webhook_secret: str = ""
    judge_openai_base_url: str = ""
    judge_openai_api_key: str = ""
    judge_openai_model: str = ""
    jev_api_key: str = ""
    jev_base_url: str = "https://api.typesafe.ai"
    jev_model: str = "jev-latest"
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-flash"
    output_local_model_base_url: str = ""
    output_local_model_name: str = ""
    goal_local_model_base_url: str = ""
    goal_local_model_name: str = ""
    agentsentry_memory_enabled: bool = True
    agentsentry_runtime_binding_required: bool = False
    agentsentry_model_local_base_url: str = "http://127.0.0.1:11434/v1"
    agentsentry_model_remote_destinations: str = "{}"
    agentsentry_remote_mcp_registry: str = "{}"
    agentsentry_remote_mcp_allow_loopback_demo: bool = False
    agentsentry_github_mcp_enabled: bool = False
    github_mcp_pat: str = ""
    agentsentry_github_mcp_write_enabled: bool = False
    github_mcp_write_pat: str = ""
    github_mcp_test_repo: str = ""
    github_mcp_create_issue_schema_sha256: str = ""

    def validate_runtime(self) -> None:
        from .mcp_remote import registry as remote_mcp_registry
        remote_mcp_registry()
        if self.agentsentry_github_mcp_enabled and not self.github_mcp_pat:
            raise ValueError("GitHub MCP read-only test requires GITHUB_MCP_PAT")
        if self.github_mcp_test_repo and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}",
                self.github_mcp_test_repo):
            raise ValueError("GITHUB_MCP_TEST_REPO must be owner/repo")
        if self.agentsentry_github_mcp_write_enabled and (
                not self.github_mcp_write_pat or not self.github_mcp_test_repo or
                self.github_mcp_write_pat == self.github_mcp_pat or
                not re.fullmatch(r"[0-9a-f]{64}", self.github_mcp_create_issue_schema_sha256)):
            raise ValueError("GitHub MCP write requires a separate PAT, fixed test repo and approved tool hash")
        if not self.admin_password or self.admin_password == "CHANGE_ME":
            raise ValueError("Set a non-placeholder ADMIN_PASSWORD")
        if len(self.session_secret) < 32 or self.session_secret.startswith("CHANGE_ME"):
            raise ValueError("Set a random SESSION_SECRET of at least 32 characters")
        if len(self.agent_api_key) < 32 or self.agent_api_key.startswith("CHANGE_ME"):
            raise ValueError("Set a random AGENT_API_KEY of at least 32 characters")
        if self.judge_provider not in {"mock", "openai_compat", "jev", "deepseek"}:
            raise ValueError("Unsupported JUDGE_PROVIDER")
        if self.alert_cooldown_seconds < 0:
            raise ValueError("ALERT_COOLDOWN_SECONDS must be nonnegative")
        if self.webhook_url and (not self.webhook_url.startswith("https://") or len(self.webhook_secret) < 32):
            raise ValueError("WEBHOOK_URL requires HTTPS and WEBHOOK_SECRET of at least 32 characters")
        if self.output_local_model_base_url:
            host = urlparse(self.output_local_model_base_url).hostname
            if host not in {"127.0.0.1", "localhost", "::1", "host.docker.internal"} or not self.output_local_model_name:
                raise ValueError("OUTPUT_LOCAL_MODEL_BASE_URL requires a local host and OUTPUT_LOCAL_MODEL_NAME")
        if self.goal_local_model_base_url:
            parsed = urlparse(self.goal_local_model_base_url)
            if (parsed.scheme != "http" or parsed.hostname not in
                    {"127.0.0.1", "localhost", "::1", "host.docker.internal"} or
                    not self.goal_local_model_name or parsed.username or parsed.password):
                raise ValueError("GOAL_LOCAL_MODEL_BASE_URL requires local HTTP and GOAL_LOCAL_MODEL_NAME")
        local = urlparse(self.agentsentry_model_local_base_url)
        if (local.scheme != "http" or local.hostname not in
                {"127.0.0.1", "localhost", "::1", "host.docker.internal"}):
            raise ValueError("AGENTSENTRY_MODEL_LOCAL_BASE_URL must be local HTTP")
        try:
            destinations = json.loads(self.agentsentry_model_remote_destinations)
        except ValueError as exc:
            raise ValueError("Invalid AGENTSENTRY_MODEL_REMOTE_DESTINATIONS") from exc
        if not isinstance(destinations, dict):
            raise ValueError("Remote model destinations must be a JSON object")
        for key, value in destinations.items():
            parsed = urlparse(value) if isinstance(value, str) else None
            if (not isinstance(key, str) or not key or key == "local" or not parsed
                    or parsed.scheme != "https" or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment):
                raise ValueError("Remote model destinations require named HTTPS base URLs")


@lru_cache
def get_settings() -> Settings:
    return Settings()
