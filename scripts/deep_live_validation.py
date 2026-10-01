"""复用现有 Agent 路径做本地模型实测，报告单独保留，不替代固定边界测试。"""

import argparse
import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx

from agentsentry import attack_runner, memory_lab_runner
from agentsentry.action_chain_live import run as run_behavior
from agentsentry.calibration_runner import _run as run_calibration
from agentsentry.config import get_settings


ROOT = Path(__file__).resolve().parents[1]


def memory_run():
    settings = get_settings()
    base = os.environ.get("SENTRY_URL", f"http://127.0.0.1:{settings.agentsentry_port}")
    # 新凭据文件对应全新的研究租户，绝不清理原实验室的数据。
    attack_runner.CREDS_PATH = ROOT / ".local" / ("deep-memory-creds-" + uuid.uuid4().hex + ".json")
    with httpx.Client(base_url=base, timeout=45) as client:
        creds = attack_runner._bootstrap(client, settings)
        admin = attack_runner._login(client, creds["lab"], settings.session_secret)
        attack_runner._post(client, "/api/v2/memory-lab/fixtures/install", admin)
        created = attack_runner._post(client, "/api/v2/memory-lab/runs", admin,
            {"mode": "live", "model_name": os.environ["DEMO_MODEL_NAME"]})
        rid = created["id"]
        try:
            for case in memory_lab_runner.CASES:
                if not case["live"]:
                    continue
                memory_lab_runner._clear_prior(client, admin)
                observed = memory_lab_runner._live_case(client, creds["lab"], admin, case, rid, base)
                attack_runner._post(client, f"/api/v2/memory-lab/runs/{rid}/cases", admin, observed)
                print(case["id"] + "：两轮已记录", flush=True)
            attack_runner._post(client, f"/api/v2/memory-lab/runs/{rid}/finish", admin)
        except Exception as exc:
            attack_runner._post(client, f"/api/v2/memory-lab/runs/{rid}/finish", admin,
                               {"failed": True, "error": type(exc).__name__})
            raise
        response = client.get(f"/api/v2/memory-lab/runs/{rid}")
        response.raise_for_status()
        report = response.json()
        report.update(tenant_id=creds["lab"]["tenant_id"],
                      dashboard=f"{base}/dashboard/memory-runs/{rid}?tenant={creds['lab']['tenant_id']}")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=["calibration", "memory", "behavior"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="qwen3:0.6b")
    args = parser.parse_args()
    os.environ.update(DEMO_MODEL_BASE_URL="http://127.0.0.1:11434/v1", DEMO_MODEL_NAME=args.model,
                      AGENTSENTRY_MODEL_DESTINATION="local", AGENTSENTRY_CAPTURE_MODE="metadata")
    settings = get_settings()
    if settings.agentsentry_model_local_base_url.rstrip("/") != os.environ["DEMO_MODEL_BASE_URL"]:
        raise RuntimeError("本地模型地址与网关登记地址不一致")
    tags = httpx.get("http://127.0.0.1:11434/api/tags", timeout=10).json()
    model = next(item for item in tags["models"] if item["name"] == args.model)
    if args.stage == "memory":
        report = memory_run()
    elif args.stage == "calibration":
        report = run_calibration(SimpleNamespace(mode="live", allow_remote_model=False))
    else:
        report = run_behavior(args.model, os.environ["DEMO_MODEL_BASE_URL"], args.output)
    report["model_snapshot"] = {key: model.get(key) for key in ("name", "digest", "details")}
    args.output.parent.mkdir(exist_ok=True, parents=True)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    os.chmod(args.output, 0o600)
    print(json.dumps({key: report.get(key) for key in ("id", "status", "counts", "tenant_id", "dashboard")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
