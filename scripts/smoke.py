"""Local Compose end-to-end smoke check. Requires .env and running services."""

import uuid
import time

import httpx

from agentsentry.config import get_settings


def main():
    settings = get_settings()
    with httpx.Client(base_url=f"http://127.0.0.1:{settings.agentsentry_port}", timeout=15, follow_redirects=False) as client:
        health = client.get("/health")
        health.raise_for_status()
        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 303 and dashboard.headers["location"] == "/login"
        assert client.get("/login").status_code == 200
        login = client.post("/login", data={"password": settings.admin_password})
        assert login.status_code == 303, login.text
        from itsdangerous import URLSafeTimedSerializer
        csrf = URLSafeTimedSerializer(settings.session_secret, salt="agentsentry-admin").loads(
            client.cookies["agentsentry_session"]
        )["csrf"]
        admin_headers = {"X-CSRF-Token": csrf}
        agent_headers = {"Authorization": "Bearer " + settings.agent_api_key}

        def grant(tool, resource):
            response = client.post("/api/v1/capabilities", headers=admin_headers, json={
                "agent_id": "demo-agent", "tool": tool, "resources": [resource],
                "ttl_seconds": 600, "max_uses": 1,
            })
            response.raise_for_status()
            return response.json()["token"]

        def call(tool, arguments, token):
            response = client.post("/api/v1/tool-calls", headers={
                **agent_headers, "X-Capability": token,
            }, json={
                "call_id": str(uuid.uuid4()), "session_id": "smoke",
                "tool": tool, "arguments": arguments,
            })
            response.raise_for_status()
            return response.json()

        read = call("read_document", {"document_id": "public-guide"}, grant("read_document", "public-guide"))
        assert read["status"] == "completed" and read["result"]["document_id"] == "public-guide"
        injected = call("read_document", {"document_id": "injected-guide"}, grant("read_document", "injected-guide"))
        assert injected["status"] == "completed"
        pending = call("send_external", {
            "destination_id": "demo-inbox", "content": "Synthetic summary only",
        }, grant("send_external", "demo-inbox"))
        assert pending["status"] == "pending_approval"
        approval = client.post(
            "/api/v1/approvals/" + pending["approval_id"] + "/decision",
            headers=admin_headers, json={"decision": "approve"},
        )
        approval.raise_for_status()
        assert approval.json()["result"]["simulated"] is True
        assert client.get("/dashboard").status_code == 200
        assert client.get("/dashboard/calls/" + read["call_id"]).status_code == 200
        for _ in range(40):
            detail = client.get("/dashboard/calls/" + injected["call_id"])
            if detail.status_code == 200 and "prompt_injection" in detail.text:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Judge alert did not appear in dashboard within 20 seconds")
    print("Gateway, grant, policy, approval, simulated tools, outbox, Judge alert and dashboard: OK")


if __name__ == "__main__":
    main()
