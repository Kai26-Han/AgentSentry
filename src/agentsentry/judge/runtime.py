"""Tenant-scoped runtime Judge selection and per-event routing snapshots."""

import hashlib
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..models import AuditEvent, JudgeRoute, JudgeRuntimeChange, JudgeRuntimeConfig, Outbox, utcnow
from .adapters import JUDGE_PROVIDER_IDS, configured_judge_providers


MODEL_FIELDS = {"jev": "jev_model", "deepseek": "deepseek_model", "openai_compat": "judge_openai_model"}
URL_FIELDS = {"jev": "jev_base_url", "deepseek": "deepseek_base_url", "openai_compat": "judge_openai_base_url"}


def route_values(provider: str, settings: Settings) -> tuple[str, str]:
    if provider not in JUDGE_PROVIDER_IDS:
        raise ValueError("Unknown Judge provider")
    model = "rules-v1" if provider == "mock" else getattr(settings, MODEL_FIELDS[provider])
    endpoint = "local" if provider == "mock" else getattr(settings, URL_FIELDS[provider])
    return model, hashlib.sha256(endpoint.rstrip("/").encode()).hexdigest()


def runtime_config(db: Session, settings: Settings | None = None, *, lock: bool = False) -> JudgeRuntimeConfig:
    settings = settings or get_settings()
    query = select(JudgeRuntimeConfig).where(JudgeRuntimeConfig.id == "active")
    if lock:
        query = query.with_for_update(read=True)
    config = db.scalar(query)
    if config is None:
        config = JudgeRuntimeConfig(id="active", provider=settings.judge_provider, revision=1)
        db.add(config)
        db.add(JudgeRuntimeChange(id=str(uuid.uuid4()), previous_provider=None,
                                  provider=config.provider, revision=1, actor="initial_configuration"))
        db.flush()
    return config


def assign_route(db: Session, outbox: Outbox, *, provider: str | None = None,
                 settings: Settings | None = None) -> JudgeRoute:
    settings = settings or get_settings()
    config = runtime_config(db, settings, lock=True)
    selected = provider or config.provider
    model, endpoint_hash = route_values(selected, settings)
    route = JudgeRoute(outbox_id=outbox.id, provider=selected, model_name=model,
                       endpoint_hash=endpoint_hash, config_revision=config.revision,
                       source="sample" if provider else "runtime")
    db.add(route)
    return route


def change_runtime_provider(db: Session, provider: str, expected_revision: int,
                            actor: str, settings: Settings | None = None) -> JudgeRuntimeConfig:
    settings = settings or get_settings()
    if provider not in {choice["id"] for choice in configured_judge_providers(settings)}:
        raise ValueError("Judge provider is not configured")
    config = db.scalar(select(JudgeRuntimeConfig).where(JudgeRuntimeConfig.id == "active").with_for_update())
    if config is None:
        config = runtime_config(db, settings)
    if config.revision != expected_revision:
        raise RuntimeError("Judge configuration changed; reload the page")
    if config.provider != provider:
        previous = config.provider
        config.provider = provider
        config.revision += 1
        config.updated_at = utcnow()
        db.add(JudgeRuntimeChange(id=str(uuid.uuid4()), previous_provider=previous,
                                  provider=provider, revision=config.revision, actor=actor))
        db.add(AuditEvent(id=str(uuid.uuid4()), call_id=None, event_type="judge_config_changed",
                          payload={"previous_provider": previous, "provider": provider,
                                   "revision": config.revision, "actor": actor}))
    db.commit()
    return config


def backfill_unfinished_routes(db: Session, settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    runtime_config(db, settings)
    rows = db.scalars(select(Outbox).outerjoin(JudgeRoute, JudgeRoute.outbox_id == Outbox.id)
                      .where(JudgeRoute.outbox_id.is_(None), Outbox.status != "completed")).all()
    for outbox in rows:
        event = db.get(AuditEvent, outbox.audit_event_id)
        payload = event.payload if event else {}
        sample_provider = payload.get("_sample_judge_provider")
        assign_route(db, outbox, provider=sample_provider if sample_provider in JUDGE_PROVIDER_IDS else None,
                     settings=settings)
    db.commit()
    return len(rows)


def route_settings(route: JudgeRoute, settings: Settings) -> Settings:
    if route.provider not in {choice["id"] for choice in configured_judge_providers(settings)}:
        raise RuntimeError("指定的 Judge 在 Worker 中未配置")
    _, endpoint_hash = route_values(route.provider, settings)
    if endpoint_hash != route.endpoint_hash:
        raise RuntimeError("Judge 数据目的地配置已改变；原事件不会改投新地址")
    update = {"judge_provider": route.provider}
    if route.provider in MODEL_FIELDS:
        update[MODEL_FIELDS[route.provider]] = route.model_name
    return settings.model_copy(update=update)
