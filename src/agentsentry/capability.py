import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import redis
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditEvent, CapabilityGrant
from .schemas import CapabilityRequest


CONSUME_SCRIPT = """
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then return {'missing'} end
local agent = redis.call('HGET', key, 'agent')
local tenant = redis.call('HGET', key, 'tenant')
if not tenant then tenant = 'default' end
local tool = redis.call('HGET', key, 'tool')
local resources = cjson.decode(redis.call('HGET', key, 'resources'))
if tenant ~= ARGV[1] or agent ~= ARGV[2] or tool ~= ARGV[3] then return {'scope'} end
local found = false
for _, resource in ipairs(resources) do
  if resource == ARGV[4] then found = true end
end
if not found then return {'scope'} end
local remaining = tonumber(redis.call('HGET', key, 'remaining'))
if remaining <= 0 then return {'exhausted'} end
redis.call('HINCRBY', key, 'remaining', -1)
return {'ok', redis.call('HGET', key, 'grant_id')}
"""

RESERVE_SCRIPT = """
-- delegation-reserve-v1
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then return {'missing'} end
if redis.call('HGET', key, 'tenant') ~= ARGV[1]
or redis.call('HGET', key, 'agent') ~= ARGV[2]
or redis.call('HGET', key, 'tool') ~= ARGV[3] then return {'scope'} end
local allowed = cjson.decode(redis.call('HGET', key, 'resources'))
for _, requested in ipairs(cjson.decode(ARGV[4])) do
  local found = false
  for _, resource in ipairs(allowed) do if resource == requested then found = true end end
  if not found then return {'scope'} end
end
local amount = tonumber(ARGV[5])
if tonumber(redis.call('HGET', key, 'remaining')) < amount then return {'exhausted'} end
redis.call('HINCRBY', key, 'remaining', -amount)
return {'ok', redis.call('HGET', key, 'grant_id')}
"""


def reserve(client, token, tenant_id, agent_id, tool, resources, uses):
    if not token:
        return "missing", None
    result = client.eval(RESERVE_SCRIPT, 1, f"cap:{token_hash(token)}", tenant_id, agent_id,
                         tool, json.dumps(resources), uses)
    return result[0], result[1] if len(result) > 1 else None


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_redis():
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True,
                                socket_connect_timeout=2, socket_timeout=2,
                                retry_on_timeout=False)


def issue(session: Session, client, request: CapabilityRequest, tenant_id: str = "default") -> tuple[CapabilityGrant, str]:
    token = secrets.token_urlsafe(32)
    grant = CapabilityGrant(
        id=str(uuid.uuid4()),
        token_hash=token_hash(token),
        agent_id=request.agent_id,
        tool=request.tool,
        resources=sorted(set(request.resources)),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=request.ttl_seconds),
        max_uses=request.max_uses,
    )
    key = f"cap:{grant.token_hash}"
    client.hset(key, mapping={
        "grant_id": grant.id,
        "tenant": tenant_id,
        "agent": grant.agent_id,
        "tool": grant.tool,
        "resources": json.dumps(grant.resources),
        "remaining": grant.max_uses,
    })
    client.expire(key, request.ttl_seconds)
    try:
        session.add(grant)
        session.add(AuditEvent(
            id=str(uuid.uuid4()), call_id=None, event_type="capability_issued",
            payload={"grant_id": grant.id, "tool": grant.tool, "resources": grant.resources},
        ))
        session.commit()
    except Exception:
        client.delete(key)
        session.rollback()
        raise
    return grant, token


def consume(client, token: str, agent_id: str, tool: str, resource: str,
            tenant_id: str = "default") -> tuple[str, str | None]:
    if not token:
        return "missing", None
    result = client.eval(CONSUME_SCRIPT, 1, f"cap:{token_hash(token)}", tenant_id, agent_id, tool, resource)
    return result[0], result[1] if len(result) > 1 else None


def revoke(session: Session, client, grant: CapabilityGrant) -> None:
    # 吊销与工具/审批决定共用权限行锁；先提交者定义生效顺序。
    grant = session.get(CapabilityGrant, grant.id, with_for_update=True, populate_existing=True)
    if grant is None:
        raise ValueError("授权不存在")
    grant.revoked = True
    session.add(AuditEvent(
        id=str(uuid.uuid4()), call_id=None, event_type="capability_revoked",
        payload={"grant_id": grant.id},
    ))
    session.commit()
    try:
        client.delete(f"cap:{grant.token_hash}")
    except Exception:
        # The committed DB revocation remains authoritative even if cache cleanup fails.
        pass
