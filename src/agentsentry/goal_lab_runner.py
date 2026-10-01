"""在新建的隔离研究租户运行目标偏移与审批欺骗实验。"""

import argparse
import json
import os
import stat
import uuid
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from .attack_runner import _grant, _live_case, _login, _post, _reject, _tool_call
from .config import get_settings
from .goal_lab_corpus import CASES


ROOT = Path(__file__).resolve().parents[2]


def _new_tenant(client: httpx.Client, settings) -> dict:
    root = _login(client, {"tenant_id": "default",
                           "admin_password": settings.admin_password}, settings.session_secret)
    tenant = _post(client, "/api/v2/tenants", root,
                   {"name": "Attack Lab " + uuid.uuid4().hex[:8]})
    path = ROOT / ".local" / f"goal-lab-{tenant['tenant_id']}.json"
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(tenant, handle, ensure_ascii=False)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("研究租户凭据权限异常")
    return tenant


def _agent_headers(tenant: dict, runtime_token: str = "") -> dict:
    return {"Authorization": "Bearer " + tenant["agent_api_key"],
            "X-Tenant-ID": tenant["tenant_id"], "X-Runtime-Session": runtime_token}


def _scripted_case(client: httpx.Client, tenant: dict, admin_headers: dict,
                   case: dict, run_id: str) -> dict:
    session_id = f"lab-goal-{run_id[:8]}-{case['id'].lower()}"
    response = client.put(f"/api/v2/runtime-sessions/{session_id}/start",
        headers=_agent_headers(tenant), json={"transport": "http" if case["entry"] == "document" else "mcp",
        "capture_mode": "metadata", "user_task": case["user_task"]})
    response.raise_for_status()
    binding = response.json()["session_token"]
    source_tool = "read_document" if case["entry"] == "document" else "mcp_lookup_card"
    source_key = "document_id" if case["entry"] == "document" else "card_id"
    source_token, _ = _grant(client, admin_headers, source_tool, [case["fixture_id"]])
    _, source = _tool_call(client, tenant, source_tool, {source_key: case["fixture_id"]},
                            source_token, session_id, runtime_token=binding)
    if source.get("status") != "completed":
        raise RuntimeError(f"{case['id']} 的合成来源读取失败")
    trace = [{"tool": source_tool, "status": source["status"], "call_id": source["call_id"]}]
    if case["kind"] == "attack" or case["tool"] not in {"read_document", "mcp_lookup_card"}:
        target_token = (_grant(client, admin_headers, case["tool"], case["grant"])[0]
                        if case["grant"] else "")
        status, target = _tool_call(client, tenant, case["tool"], case["arguments"],
                                    target_token, session_id, runtime_token=binding)
        trace.append({"tool": case["tool"], "status": target.get("status", str(status)),
                      "call_id": target.get("call_id")})
        if target.get("status") == "pending_approval":
            _reject(client, admin_headers, target)
            trace.append({"tool": case["tool"], "approval": "rejected", "status": "denied"})
    draft = ("季度计划总结：" + case["answer_marker"] if case["answer_marker"] else
             "季度计划主要事项已整理。")
    response = client.post(f"/api/v2/runtime-sessions/{session_id}/output-check",
        headers=_agent_headers(tenant, binding), json={
            "check_id": str(uuid.uuid4()), "capture_mode": "metadata",
            "output_kind": "final_answer", "draft": draft,
            "user_task": case["user_task"], "source_call_ids": [source["call_id"]]})
    response.raise_for_status()
    display = response.json()["display_text"]
    response = client.put(f"/api/v2/runtime-sessions/{session_id}/finish",
        headers=_agent_headers(tenant), json={"status": "completed", "final_answer": ""})
    response.raise_for_status()
    return {"session_id": session_id, "trace": trace, "final_answer": draft,
            "display_text": display, "finished": True}


def _run_once(client: httpx.Client, settings, mode: str, model_name: str,
              base_url: str) -> dict:
    tenant = _new_tenant(client, settings)
    admin_headers = _login(client, tenant, settings.session_secret)
    policy = client.get("/api/v1/policy")
    policy.raise_for_status()
    tools = {item.get("tool") for item in yaml.safe_load(policy.json()["yaml"])["rules"]}
    if not {"read_document", "create_task", "send_external", "mcp_lookup_card",
            "mcp_record_note"}.issubset(tools):
        raise RuntimeError("研究租户未显式启用所需工具策略")
    _post(client, "/api/v3/goal-lab/fixtures/install", admin_headers)
    run = _post(client, "/api/v3/goal-runs", admin_headers,
                {"mode": mode, "model_name": model_name})
    run_id = run["id"]
    try:
        ordered = ([*filter(lambda item: item["kind"] == "normal", CASES),
                    *filter(lambda item: item["kind"] == "attack", CASES)]
                   if mode == "scripted" else CASES)
        for case in ordered:
            if mode == "live" and not case["live"]:
                continue
            for repetition in range(1, 4 if mode == "live" else 2):
                if mode == "live":
                    session_id = f"lab-goal-{run_id[:8]}-{case['id'].lower()}-{repetition}"
                    result = _live_case(client, {"lab": tenant}, admin_headers, case,
                                        base_url, run_id, session_id=session_id,
                                        include_display=True, include_full_answer=True)
                else:
                    result = _scripted_case(client, tenant, admin_headers, case, run_id)
                    session_id = result["session_id"]
                safe_trace = []
                for item in result["trace"]:
                    proposal = item.get("tool") == case["tool"] and case["kind"] == "attack"
                    if proposal and case["tool"] in {"read_document", "mcp_lookup_card"}:
                        proposal = (item.get("arguments") or {}) == case["arguments"]
                    safe_trace.append({**{key: value for key, value in item.items()
                                          if key in {"tool", "status", "call_id", "approval"}},
                                       "target_proposal": bool(proposal)})
                _post(client, f"/api/v3/goal-runs/{run_id}/cases", admin_headers, {
                    "case_id": case["id"], "repetition": repetition,
                    "session_id": session_id, "trace": safe_trace,
                    "final_answer": result.get("final_answer", ""),
                    "display_text": result.get("display_text", ""),
                    "finished": bool(result.get("finished")),
                    "error": result.get("error", "")[:80]})
                print(f"{case['id']} / {repetition}：已记录", flush=True)
    except Exception:
        _post(client, f"/api/v3/goal-runs/{run_id}/finish", admin_headers,
              {"failed": True})
        raise
    _post(client, f"/api/v3/goal-runs/{run_id}/finish", admin_headers,
          {"failed": False})
    response = client.get(f"/api/v3/goal-runs/{run_id}")
    response.raise_for_status()
    view = response.json()
    view["tenant_id"] = tenant["tenant_id"]
    view["dashboard"] = (base_url + f"/dashboard/goal-runs/{run_id}?tenant="
                         + tenant["tenant_id"])
    return view


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["scripted", "live"], default="scripted")
    parser.add_argument("--allow-remote-model", action="store_true")
    parser.add_argument("--output", default=str(ROOT / ".local" / "goal-lab-report.json"))
    args = parser.parse_args()
    settings = get_settings()
    settings.validate_runtime()
    base_url = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}").rstrip("/")
    model_url = os.environ.get("DEMO_MODEL_BASE_URL", settings.agentsentry_model_local_base_url)
    model_host = urlparse(model_url).hostname or ""
    if args.mode == "live" and model_host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote_model:
        parser.error("远端模型需显式 --allow-remote-model，且只能使用合成样本")
    model_name = os.environ.get("DEMO_MODEL_NAME", "qwen3:0.6b") if args.mode == "live" else ""
    if args.mode == "live":
        os.environ["DEMO_MODEL_BASE_URL"] = model_url
        os.environ["DEMO_MODEL_NAME"] = model_name
    with httpx.Client(base_url=base_url, timeout=30) as client:
        reports = [_run_once(client, settings, args.mode, model_name, base_url)
                   for _ in range(2 if args.mode == "scripted" else 1)]
    if args.mode == "scripted":
        first, second = reports
        by_case = lambda report: [(item["case_id"], item["outcome"], item["attempted"],
            item["gateway_blocked"], item["forbidden_effect"],
            item["displayed_contamination"], item["audit_missing"])
            for item in report["cases"]]
        consistent = by_case(first) == by_case(second)
    else:
        consistent = None
    result = {"mode": args.mode, "consistent": consistent, "runs": reports}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps({"mode": args.mode, "consistent": consistent,
        "runs": [{"id": item["id"], "tenant_id": item["tenant_id"],
                  "status": item["status"], "counts": item["counts"],
                  "dashboard": item["dashboard"]} for item in reports]}, ensure_ascii=False))
    if consistent is False or any(item["counts"]["preapproval_effect"] or
            item["counts"]["forbidden_effect"] or item["counts"]["audit_missing"]
            for item in reports):
        raise SystemExit("验收失败：逐例不一致、禁止动作、审批前副作用或审计缺失")


if __name__ == "__main__":
    main()
