"""Exercise a stopped Judge worker against the running local Compose stack."""

import subprocess
import time
import uuid
from pathlib import Path

import httpx
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


ROOT = Path(__file__).resolve().parents[1]


def compose(*args: str) -> str:
    result = subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True,
        text=True, capture_output=True,
    )
    return result.stdout.strip()


def counts(call_id: str) -> tuple[int, int, int, int]:
    # call_id is generated locally as a UUID before it enters this query.
    sql = (
        "SELECT count(*), "
        "count(*) FILTER (WHERE o.status = 'completed'), "
        "count(j.id), count(al.id) "
        "FROM audit_events a "
        "JOIN outbox o ON o.audit_event_id = a.id "
        "LEFT JOIN judge_results j ON j.outbox_id = o.id "
        "LEFT JOIN alerts al ON al.judge_result_id = j.id "
        f"WHERE a.call_id = '{call_id}'"
    )
    output = compose("exec", "-T", "db", "psql", "-U", "agentsentry", "-d", "agentsentry", "-At", "-c", sql)
    return tuple(map(int, output.split("|")))


def main() -> None:
    settings = get_settings()
    call_id = str(uuid.uuid4())
    worker_stopped = False
    try:
        compose("stop", "worker")
        worker_stopped = True
        with httpx.Client(base_url=f"http://127.0.0.1:{settings.agentsentry_port}", timeout=15) as client:
            login = client.post("/login", data={"password": settings.admin_password}, follow_redirects=False)
            assert login.status_code == 303, login.text
            csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
                client.cookies["agentsentry_session"]
            )["csrf"]
            grant = client.post("/api/v1/capabilities", headers={"X-CSRF-Token": csrf}, json={
                "agent_id": "demo-agent", "tool": "read_document", "resources": ["injected-guide"],
                "ttl_seconds": 600, "max_uses": 1,
            })
            grant.raise_for_status()
            call = client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + settings.agent_api_key,
                "X-Capability": grant.json()["token"],
            }, json={
                "call_id": call_id, "session_id": "recovery-drill",
                "tool": "read_document", "arguments": {"document_id": "injected-guide"},
            })
            call.raise_for_status()
            assert call.json()["status"] == "completed", call.text

        queued = counts(call_id)
        assert queued[0] >= 2 and queued[1] == 0 and queued[2] == 0, queued
        compose("start", "worker")
        worker_stopped = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            recovered = counts(call_id)
            if recovered[1] == recovered[0] and recovered[2] == recovered[0] and recovered[3] >= 1:
                break
            time.sleep(1)
        else:
            raise AssertionError(f"Judge did not recover within 60 seconds: {recovered}")
        print(f"call_id={call_id} stopped={queued} recovered={recovered} audit_loss=0")
    finally:
        if worker_stopped:
            compose("start", "worker")


if __name__ == "__main__":
    main()
