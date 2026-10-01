"""Tenant registry and credential verification for the local V2 lab."""

import hashlib
import hmac
import secrets
import uuid

import yaml
from sqlalchemy import Boolean, String, select
from sqlalchemy.orm import Mapped, mapped_column

from .config import get_settings
from .database import TenantBase, create_tenant_tables, db_session, tenant_db_session, tenant_schema
from .models import AuditEvent
from .samples import seed_samples
from .tools import seed_documents


class Tenant(TenantBase):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    admin_hash: Mapped[str] = mapped_column(String(160))
    agent_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1,
                                dklen=len(bytes.fromhex(digest_hex)))
        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


def hash_agent_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def seed_default_tenant() -> None:
    settings = get_settings()
    with db_session() as session:
        tenant = session.get(Tenant, "default")
        if tenant is None:
            tenant = Tenant(id="default", name="Default", active=True)
            session.add(tenant)
        # The existing private .env remains the default tenant's credential source.
        tenant.admin_hash = hash_password(settings.admin_password)
        tenant.agent_hash = hash_agent_key(settings.agent_api_key)
        session.commit()


def get_tenant(tenant_id: str) -> Tenant | None:
    tenant_schema(tenant_id)
    with db_session() as session:
        return session.get(Tenant, tenant_id)


def list_tenant_ids() -> list[str]:
    with db_session() as session:
        return list(session.scalars(select(Tenant.id).where(Tenant.active.is_(True))))


def policy_for_new_tenant(policy_source: str) -> str:
    from .policy import PolicyEngine
    policy_data = yaml.safe_load(policy_source)
    policy_data["rules"] = [rule for rule in policy_data["rules"] if rule["tool"] != "run_shell"]
    policy_data["rules"].append({"id": "tenant_sandbox_unavailable",
                                  "effect": "deny", "tool": "run_shell"})
    candidate = yaml.safe_dump(policy_data, sort_keys=False)
    PolicyEngine.from_content(candidate.encode())
    return candidate


def create_tenant(name: str, policy_source: str, policy_path: str) -> tuple[Tenant, str, str]:
    from pathlib import Path

    if not 1 <= len(name) <= 120:
        raise ValueError("Tenant name must be 1–120 characters")
    with db_session() as session:
        if session.scalar(select(Tenant.id).where(Tenant.name == name)):
            raise ValueError("Tenant name already exists")
    policy_source = policy_for_new_tenant(policy_source)
    tenant_id = "t_" + uuid.uuid4().hex
    admin_password = secrets.token_urlsafe(40)
    agent_key = secrets.token_urlsafe(40)
    path = Path(policy_path)
    tenant_path = path.with_name(tenant_id + ".yaml")
    tenant_path.write_text(policy_source, encoding="utf-8")
    try:
        create_tenant_tables(tenant_id)
        with tenant_db_session(tenant_id) as session:
            from .judge.runtime import runtime_config
            runtime_config(session)
            seed_documents(session)
            seed_samples(session)
            session.add(AuditEvent(id=str(uuid.uuid4()), call_id=None,
                                   event_type="tenant_initialized", payload={"tenant_id": tenant_id}))
            session.commit()
        with db_session() as session:
            tenant = Tenant(
                id=tenant_id, name=name, admin_hash=hash_password(admin_password),
                agent_hash=hash_agent_key(agent_key), active=True,
            )
            session.add(tenant)
            session.commit()
            return tenant, admin_password, agent_key
    except Exception:
        tenant_path.unlink(missing_ok=True)
        raise
