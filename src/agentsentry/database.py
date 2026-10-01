from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
import re

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


class TenantBase(DeclarativeBase):
    """Registry tables stay in the legacy public database/schema."""


def tenant_schema(tenant_id: str) -> str:
    if tenant_id == "default":
        return "public"
    if not re.fullmatch(r"t_[0-9a-f]{32}", tenant_id):
        raise ValueError("Invalid tenant ID")
    return tenant_id


@lru_cache
def get_engine():
    url = get_settings().database_url
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    if not url.startswith("sqlite"):
        kwargs = {"pool_size": 5, "max_overflow": 5, "pool_timeout": 3,
                  "connect_args": {"connect_timeout": 3,
                                   "options": "-c statement_timeout=15000 -c lock_timeout=5000"}}
    return create_engine(url, pool_pre_ping=True, **kwargs)


@lru_cache
def get_session_factory():
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


@contextmanager
def db_session():
    session = get_session_factory()()
    session.info["tenant_id"] = "default"
    try:
        yield session
    finally:
        session.close()


@lru_cache
def _sqlite_tenant_engine(tenant_id: str):
    tenant_schema(tenant_id)
    url = get_settings().database_url
    if not url.startswith("sqlite:///") or url.endswith(":memory:"):
        raise RuntimeError("V2 tenant SQLite tests require a file database")
    base = Path(url.removeprefix("sqlite:///"))
    path = base.with_name(f"{base.stem}-{tenant_id}{base.suffix or '.db'}")
    return create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False}, pool_pre_ping=True)


@contextmanager
def tenant_db_session(tenant_id: str):
    schema = tenant_schema(tenant_id)
    if tenant_id == "default":
        with db_session() as session:
            yield session
        return
    if get_settings().database_url.startswith("sqlite"):
        with Session(_sqlite_tenant_engine(tenant_id), expire_on_commit=False) as session:
            session.info["tenant_id"] = tenant_id
            yield session
        return
    with get_engine().connect().execution_options(schema_translate_map={None: schema}) as conn:
        with Session(conn, expire_on_commit=False) as session:
            session.info["tenant_id"] = tenant_id
            yield session


def create_tenant_tables(tenant_id: str) -> None:
    schema = tenant_schema(tenant_id)
    if tenant_id == "default":
        Base.metadata.create_all(get_engine())
    elif get_settings().database_url.startswith("sqlite"):
        Base.metadata.create_all(_sqlite_tenant_engine(tenant_id))
    else:
        with get_engine().begin() as conn:
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
            Base.metadata.create_all(conn.execution_options(schema_translate_map={None: schema}))
    ensure_runtime_task_column(tenant_id)
    # 早期 V2.5 实验保存过脱敏回答片段；新语义只保留预定义标记。
    from .memory_lab import scrub_old_answer_text
    with tenant_db_session(tenant_id) as session:
        scrub_old_answer_text(session)


def ensure_runtime_task_column(tenant_id: str) -> None:
    """补建现有租户的会话任务指纹及目标轮廓列；旧记录不回填。"""
    schema = tenant_schema(tenant_id)
    engine = (get_engine() if tenant_id == "default" else
              _sqlite_tenant_engine(tenant_id) if get_settings().database_url.startswith("sqlite") else
              get_engine())
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            columns = {row[1] for row in conn.execute(text("PRAGMA table_info(runtime_sessions)"))}
            if "task_fingerprint" not in columns:
                conn.execute(text("ALTER TABLE runtime_sessions ADD COLUMN task_fingerprint VARCHAR(64)"))
            if "goal_profile" not in columns:
                conn.execute(text("ALTER TABLE runtime_sessions ADD COLUMN goal_profile JSON"))
            if "goal_profile_version" not in columns:
                conn.execute(text("ALTER TABLE runtime_sessions ADD COLUMN goal_profile_version VARCHAR(40)"))
            lab_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(goal_lab_runs)"))}
            if lab_columns and "scoring_version" not in lab_columns:
                conn.execute(text("ALTER TABLE goal_lab_runs ADD COLUMN scoring_version VARCHAR(40)"))
        else:
            conn.execute(text(f'ALTER TABLE "{schema}"."runtime_sessions" '
                              'ADD COLUMN IF NOT EXISTS task_fingerprint VARCHAR(64)'))
            conn.execute(text(f'ALTER TABLE "{schema}"."runtime_sessions" '
                              'ADD COLUMN IF NOT EXISTS goal_profile JSON'))
            conn.execute(text(f'ALTER TABLE "{schema}"."runtime_sessions" '
                              'ADD COLUMN IF NOT EXISTS goal_profile_version VARCHAR(40)'))
            conn.execute(text(f'ALTER TABLE "{schema}"."goal_lab_runs" '
                              'ADD COLUMN IF NOT EXISTS scoring_version VARCHAR(40)'))
