"""现有租户的轻量 schema 补建。"""

from sqlalchemy import text

from agentsentry.config import get_settings
from agentsentry.database import (ensure_runtime_task_column, get_engine,
                                  get_session_factory)


def test_existing_runtime_sessions_adds_nullable_task_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/old.db")
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    try:
        with get_engine().begin() as conn:
            conn.execute(text("CREATE TABLE runtime_sessions (agent_id VARCHAR, session_id VARCHAR, "
                              "task_preview VARCHAR, PRIMARY KEY (agent_id, session_id))"))
            conn.execute(text("INSERT INTO runtime_sessions VALUES "
                              "('demo-agent', 'old-session', '旧会话')"))
            conn.execute(text("CREATE TABLE goal_lab_runs (id VARCHAR PRIMARY KEY)"))
            conn.execute(text("INSERT INTO goal_lab_runs VALUES ('old-run')"))
        ensure_runtime_task_column("default")
        ensure_runtime_task_column("default")
        with get_engine().connect() as conn:
            columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runtime_sessions)"))}
            old = conn.execute(text("SELECT task_preview, task_fingerprint, goal_profile, goal_profile_version "
                                    "FROM runtime_sessions WHERE session_id='old-session'")).one()
            scoring = conn.execute(text("SELECT scoring_version FROM goal_lab_runs "
                                        "WHERE id='old-run'")).scalar_one()
        assert "task_fingerprint" in columns
        assert "goal_profile" in columns and "goal_profile_version" in columns
        assert old == ("旧会话", None, None, None)
        assert scoring is None
    finally:
        get_engine().dispose()
        get_engine.cache_clear()
        get_session_factory.cache_clear()
        get_settings.cache_clear()
