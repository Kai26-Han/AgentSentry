"""把已上报会话绑定到可信适配层；令牌不进入模型消息。"""

import hashlib
import hmac
from datetime import timedelta, timezone

from sqlalchemy.orm import Session

from .config import get_settings
from .models import RuntimeSession, utcnow


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def task_fingerprint(task: str) -> str:
    message = ("runtime-user-task-v1\0" + task).encode()
    return hmac.new(get_settings().session_secret.encode(), message, hashlib.sha256).hexdigest()


def session_token(tenant_id: str, agent_id: str, row: RuntimeSession) -> str:
    message = ("runtime-session-v1\0" + tenant_id + "\0" + agent_id + "\0" +
               row.session_id + "\0" + _aware(row.started_at).isoformat()).encode()
    return hmac.new(get_settings().session_secret.encode(), message, hashlib.sha256).hexdigest()


def valid_session_token(db: Session, tenant_id: str, agent_id: str,
                        session_id: str, token: str) -> bool:
    if not token or len(token) != 64:
        return False
    row = db.get(RuntimeSession, (agent_id, session_id))
    if not row or not row.reported or row.status != "running":
        return False
    if _aware(row.started_at) < utcnow() - timedelta(hours=8):
        return False
    return hmac.compare_digest(token, session_token(tenant_id, agent_id, row))
