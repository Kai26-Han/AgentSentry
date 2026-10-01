"""Explicitly add the V2.1 demo rules to one tenant's active policy."""

import argparse
import os

import httpx
import yaml
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


RULES = [
    {"id": "mcp_card_read", "effect": "allow", "tool": "mcp_lookup_card"},
    {"id": "mcp_note_needs_review", "effect": "require_approval", "tool": "mcp_record_note"},
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--apply", action="store_true", help="Save the proposed rules; otherwise show a dry run")
    args = parser.parse_args()
    settings = get_settings()
    password = settings.admin_password if args.tenant == "default" else os.environ.get("TENANT_ADMIN_PASSWORD", "")
    if not password:
        parser.error("Set TENANT_ADMIN_PASSWORD for a nondefault tenant")
    base_url = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}").rstrip("/")
    with httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as client:
        login = client.post("/login", data={"tenant_id": args.tenant, "password": password})
        if login.status_code != 303:
            raise RuntimeError("Administrator login failed")
        policy_response = client.get("/api/v1/policy")
        policy_response.raise_for_status()
        current = policy_response.json()
        policy = yaml.safe_load(current["yaml"])
        present = {rule["tool"]: rule for rule in policy["rules"] if rule["tool"] in {item["tool"] for item in RULES}}
        for rule in RULES:
            if rule["tool"] in present and present[rule["tool"]] != rule:
                raise RuntimeError(f"Existing {rule['tool']} rule differs; review the policy manually")
        missing = [rule for rule in RULES if rule["tool"] not in present]
        print(f"Tenant: {args.tenant}; current revision: {current['revision']}; rules to add: {[r['id'] for r in missing]}")
        if not args.apply or not missing:
            return
        policy["rules"].extend(missing)
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"]
        )["csrf"]
        response = client.put(
            "/api/v1/policy", json={"yaml": yaml.safe_dump(policy, sort_keys=False)},
            headers={"X-CSRF-Token": csrf},
        )
        response.raise_for_status()
        print(f"Active revision: {response.json()['revision']}")


if __name__ == "__main__":
    main()
