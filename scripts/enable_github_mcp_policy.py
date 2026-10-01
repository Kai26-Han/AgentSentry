"""为默认租户显式启用固定 GitHub MCP 只读工具；默认仅预览。"""

import argparse
import os

import httpx
import yaml
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


RULES = [
    {"id": "github_mcp_license_read", "effect": "allow", "tool": "github_mcp_read_license"},
    {"id": "github_mcp_public_issue_read", "effect": "allow", "tool": "github_mcp_read_issue"},
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="实际更新默认租户策略")
    args = parser.parse_args()
    settings = get_settings()
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    with httpx.Client(base_url=base, timeout=15, follow_redirects=False) as client:
        if client.post("/login", data={"password": settings.admin_password}).status_code != 303:
            raise RuntimeError("默认管理员登录失败")
        response = client.get("/api/v1/policy")
        response.raise_for_status()
        current = response.json()
        policy = yaml.safe_load(current["yaml"])
        missing = []
        for rule in RULES:
            existing = [item for item in policy["rules"] if item["tool"] == rule["tool"]]
            if existing and existing != [rule]:
                raise RuntimeError("已有不同的 GitHub MCP 策略，请人工检查")
            if not existing:
                missing.append(rule)
        print(f"当前策略修订：{current['revision']}；待增规则：{[item['id'] for item in missing]}")
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
