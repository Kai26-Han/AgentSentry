"""Create a tenant and run the existing example Agent against its isolated data."""

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


ROOT = Path(__file__).resolve().parents[1]


def csrf_from(client: httpx.Client, secret: str) -> str:
    return URLSafeTimedSerializer(secret, salt="agentsentry-admin").loads(
        client.cookies["agentsentry_session"]
    )["csrf"]


def main() -> None:
    settings = get_settings()
    settings.validate_runtime()
    with httpx.Client(base_url=f"http://127.0.0.1:{settings.agentsentry_port}", timeout=20) as client:
        root = client.post("/login", data={"tenant_id": "default", "password": settings.admin_password},
                           follow_redirects=False)
        assert root.status_code == 303
        created = client.post("/api/v2/tenants", headers={"X-CSRF-Token": csrf_from(client, settings.session_secret)},
                              json={"name": "Demo " + uuid.uuid4().hex[:8]})
        created.raise_for_status()
        credentials = created.json()
        private_dir = ROOT / ".local"
        private_dir.mkdir(mode=0o700, exist_ok=True)
        private_path = private_dir / (credentials["tenant_id"] + ".json")
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(credentials, handle, indent=2)

        tenant_login = client.post("/login", data={
            "tenant_id": credentials["tenant_id"], "password": credentials["admin_password"],
        }, follow_redirects=False)
        assert tenant_login.status_code == 303
        grant = client.post("/api/v1/capabilities", headers={
            "X-CSRF-Token": csrf_from(client, settings.session_secret),
        }, json={
            "agent_id": "demo-agent", "tool": "read_document", "resources": ["public-guide"],
            "ttl_seconds": 600, "max_uses": 1,
        })
        grant.raise_for_status()
        environment = os.environ.copy()
        environment.update({
            "AGENT_API_KEY": credentials["agent_api_key"],
            "AGENT_TENANT_ID": credentials["tenant_id"],
            "AGENT_CAPABILITIES_JSON": json.dumps({"read_document": grant.json()["token"]}),
            "AGENTSENTRY_PORT": str(settings.agentsentry_port),
        })
        run = subprocess.run(
            [sys.executable, "-m", "agentsentry.demo_agent", "--scenario", "read-public"],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=True,
        )
        result = json.loads(run.stdout)
        assert result["status"] == "completed"
        assert result["result"]["document_id"] == "public-guide"
        assert result["call_id"] in client.get("/dashboard").text
        root_again = client.post("/login", data={
            "tenant_id": "default", "password": settings.admin_password,
        }, follow_redirects=False)
        assert root_again.status_code == 303
        assert result["call_id"] not in client.get("/dashboard").text
        print(f"tenant={credentials['tenant_id']} example_agent=completed isolation=passed credentials={private_path}")


if __name__ == "__main__":
    main()
