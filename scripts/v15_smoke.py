"""Exercise live policy updates and the asynchronous Judge sample path."""

import time
import uuid

import httpx
import yaml
from itsdangerous import URLSafeTimedSerializer

from agentsentry.config import get_settings


def main() -> None:
    settings = get_settings()
    base = f"http://127.0.0.1:{settings.agentsentry_port}"
    with httpx.Client(base_url=base, timeout=20) as client:
        login = client.post("/login", data={"password": settings.admin_password}, follow_redirects=False)
        assert login.status_code == 303
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"]
        )["csrf"]
        headers = {"X-CSRF-Token": csrf}
        policy = client.get("/api/v1/policy")
        policy.raise_for_status()
        original = policy.json()["yaml"]
        invalid = client.put("/api/v1/policy", headers=headers, json={"yaml": "invalid policy"})
        assert invalid.status_code == 422
        candidate = yaml.safe_load(original)
        unsafe = dict(candidate)
        unsafe["rules"] = [{"id": "unsafe_shell", "effect": "allow", "tool": "run_shell"}]
        unsafe_response = client.put("/api/v1/policy", headers=headers, json={
            "yaml": yaml.safe_dump(unsafe, sort_keys=False),
        })
        assert unsafe_response.status_code == 422
        candidate["rules"].insert(0, {
            "id": "v15_smoke_deny", "effect": "deny", "tool": "create_task",
            "argument_regex": {"field": "title", "pattern": "V15_SMOKE_DENY"},
        })
        changed = False
        try:
            update = client.put("/api/v1/policy", headers=headers, json={
                "yaml": yaml.safe_dump(candidate, sort_keys=False),
            })
            update.raise_for_status()
            changed = True
            revision = update.json()["revision"]
            denied = client.post("/api/v1/tool-calls", headers={
                "Authorization": "Bearer " + settings.agent_api_key,
            }, json={
                "call_id": str(uuid.uuid4()), "session_id": "v15-policy-smoke",
                "tool": "create_task", "arguments": {"title": "V15_SMOKE_DENY"},
            })
            denied.raise_for_status()
            assert denied.json()["status"] == "denied"
            assert denied.json()["policy_rule"] == "v15_smoke_deny"
        finally:
            if changed:
                restore = client.put("/api/v1/policy", headers=headers, json={"yaml": original})
                restore.raise_for_status()
        samples = client.get("/api/v1/judge-samples")
        samples.raise_for_status()
        fixtures = samples.json()["samples"]
        assert len(fixtures) >= 4
        seed_names = {"normal-public-read", "document-injection", "normal-task", "blocked-exfiltration"}
        assert seed_names.issubset({sample["name"] for sample in fixtures})
        for sample in fixtures:
            if sample["name"] in seed_names:
                queued = client.post(f"/api/v1/judge-samples/{sample['id']}/run", headers=headers)
                assert queued.status_code == 202
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            metrics = client.get("/api/v1/judge-samples").json()["metrics"]
            if metrics["evaluated"] >= len(seed_names):
                break
            time.sleep(2)
        else:
            raise AssertionError("Judge samples did not complete within 90 seconds")
        assert metrics["false_positive_rate"] is not None
        assert metrics["false_negative_rate"] is not None
        print(f"policy_hot_update=passed revision={revision} restored=passed sample_provider={settings.judge_provider} evaluated={metrics['evaluated']} fp={metrics['fp']} fn={metrics['fn']}")


if __name__ == "__main__":
    main()
