"""显式为已有租户增添远程 MCP 固定工具策略；默认仅预览。"""

import argparse
import os

import httpx
import yaml
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


RULES = [
    {"id": "remote_mcp_card_read", "effect": "allow", "tool": "remote_mcp_lookup_card"},
    {"id": "remote_mcp_note_needs_review", "effect": "require_approval", "tool": "remote_mcp_record_note"},
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--apply", action="store_true", help="明确同意写入策略；默认只预览")
    args = parser.parse_args()
    settings = get_settings()
    password = settings.admin_password if args.tenant == "default" else os.environ.get("TENANT_ADMIN_PASSWORD", "")
    if not password:
        parser.error("非默认租户需提供 TENANT_ADMIN_PASSWORD")
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    with httpx.Client(base_url=base, timeout=15, follow_redirects=False) as client:
        if client.post("/login", data={"tenant_id": args.tenant, "password": password}).status_code != 303:
            raise RuntimeError("管理员登录失败")
        response = client.get("/api/v1/policy")
        response.raise_for_status()
        current = response.json()
        policy = yaml.safe_load(current["yaml"])
        existing = {rule["tool"]: rule for rule in policy["rules"]
                    if rule["tool"] in {item["tool"] for item in RULES}}
        for rule in RULES:
            if rule["tool"] in existing and existing[rule["tool"]] != rule:
                raise RuntimeError(f"已有 {rule['tool']} 策略不同，请人工检查")
        missing = [rule for rule in RULES if rule["tool"] not in existing]
        print(f"租户：{args.tenant}；当前修订：{current['revision']}；待增规则：{[r['id'] for r in missing]}")
        if not args.apply or not missing:
            return
        policy["rules"].extend(missing)
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"])["csrf"]
        response = client.put("/api/v1/policy", json={"yaml": yaml.safe_dump(policy, sort_keys=False)},
                              headers={"X-CSRF-Token": csrf})
        response.raise_for_status()
        print(f"生效修订：{response.json()['revision']}")


if __name__ == "__main__":
    main()
