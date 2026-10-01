"""Issue one scoped grant and run the existing Agent through MCP stdio."""

import argparse
import json
import os
import subprocess
import sys

import httpx
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--write", action="store_true", help="Request a note write and wait for dashboard approval")
    args = parser.parse_args()
    settings = get_settings()
    password = settings.admin_password if args.tenant == "default" else os.environ.get("TENANT_ADMIN_PASSWORD", "")
    agent_key = settings.agent_api_key if args.tenant == "default" else os.environ.get("TENANT_AGENT_API_KEY", "")
    if not password or not agent_key:
        parser.error("Set TENANT_ADMIN_PASSWORD and TENANT_AGENT_API_KEY for a nondefault tenant")
    base_url = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}").rstrip("/")
    tool = "mcp_record_note" if args.write else "mcp_lookup_card"
    resources = ["demo-notes"] if args.write else ["public-guide"]
    with httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as client:
        login = client.post("/login", data={"tenant_id": args.tenant, "password": password})
        if login.status_code != 303:
            raise RuntimeError("Administrator login failed")
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"]
        )["csrf"]
        grant = client.post("/api/v1/capabilities", json={
            "agent_id": "demo-agent", "tool": tool,
            "resources": resources, "ttl_seconds": 600, "max_uses": 1,
        }, headers={"X-CSRF-Token": csrf})
        grant.raise_for_status()
    env = os.environ.copy()
    env.update({
        "SENTRY_URL": base_url,
        "AGENT_TENANT_ID": args.tenant,
        "AGENT_API_KEY": agent_key,
        "AGENT_CAPABILITIES_JSON": json.dumps({tool: grant.json()["token"]}),
    })
    command = [sys.executable, "-m", "agentsentry.demo_agent", "--transport", "mcp",
               "--scenario", "mcp-note" if args.write else "mcp-read"]
    if args.write:
        print(f"Open {base_url}/dashboard and approve the pending mcp_record_note call.", flush=True)
        subprocess.run(command, env=env, check=True, timeout=630)
        return
    completed = subprocess.run(
        command,
        env=env, capture_output=True, text=True, check=True, timeout=30,
    )
    result = json.loads(completed.stdout)
    if result.get("status") != "completed":
        raise RuntimeError(f"MCP demo did not complete: {result.get('status')}")
    print(json.dumps({"tenant_id": args.tenant, "call_id": result["call_id"],
                      "status": result["status"], "result": result["result"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
