"""显式启用固定 GitHub 测试仓库 Issue 写入审批规则；默认仅预览。"""

import argparse
import os

import httpx
import yaml
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


RULE = {"id": "github_test_issue_needs_review", "effect": "require_approval",
        "tool": "github_mcp_create_test_issue"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="更新默认租户策略")
    args = parser.parse_args()
    settings = get_settings()
    if args.apply and not settings.agentsentry_github_mcp_write_enabled:
        raise RuntimeError("请先配置独立写入 PAT、固定测试仓库和工具定义摘要")
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    with httpx.Client(base_url=base, timeout=15, follow_redirects=False) as client:
        if client.post("/login", data={"password": settings.admin_password}).status_code != 303:
            raise RuntimeError("默认管理员登录失败")
        response = client.get("/api/v1/policy")
        response.raise_for_status()
        current = response.json()
        policy = yaml.safe_load(current["yaml"])
        existing = [item for item in policy["rules"] if item["tool"] == RULE["tool"]]
        if existing and existing != [RULE]:
            raise RuntimeError("已有不同的 GitHub MCP 写入策略，请人工检查")
        print(f"当前策略修订：{current['revision']}；待增规则：{[] if existing else [RULE['id']]}")
        if not args.apply or existing:
            return
        policy["rules"].append(RULE)
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"])["csrf"]
        response = client.put("/api/v1/policy", json={"yaml": yaml.safe_dump(policy, sort_keys=False)},
                              headers={"X-CSRF-Token": csrf})
        response.raise_for_status()
        print(f"生效修订：{response.json()['revision']}")


if __name__ == "__main__":
    main()
