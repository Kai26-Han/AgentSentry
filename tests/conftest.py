import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

os.environ.setdefault("ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("SESSION_SECRET", "testing-session-secret-at-least-32-characters")
os.environ.setdefault("AGENT_API_KEY", "testing-agent-secret-at-least-32-characters")
os.environ.setdefault("JUDGE_PROVIDER", "mock")
os.environ.setdefault("POLICY_PATH", str(Path(__file__).resolve().parents[1] / "policies/default.yaml"))

from agentsentry.database import Base  # noqa: E402
from agentsentry.evaluation import MemoryRedis  # noqa: E402
from agentsentry.policy import PolicyEngine  # noqa: E402
from agentsentry.tools import seed_documents  # noqa: E402


@pytest.fixture
def lab(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        seed_documents(db)
        yield db, MemoryRedis(), PolicyEngine.from_file(os.environ["POLICY_PATH"])
    engine.dispose()
