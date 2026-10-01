"""威胁矩阵的离线一致性检查。"""

import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_threat_mapping.py"
DATA = ROOT / "docs" / "threat-framework-map.yaml"
OUTPUT = ROOT / "docs" / "threat-framework-mapping.md"


def run_check(data: Path = DATA, output: Path = OUTPUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--check", "--data", str(data), "--output", str(output)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_committed_mapping_is_current() -> None:
    result = run_check()
    assert result.returncode == 0, result.stderr


def test_invalid_sample_id_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    data["threats"][0]["evidence"][0]["cases"] = ["A999"]
    changed = tmp_path / "bad-case.yaml"
    changed.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    result = run_check(changed)
    assert result.returncode != 0
    assert "不存在的样本" in result.stderr


def test_missing_test_path_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    data["threats"][1]["evidence"][1]["path"] = "tests/does_not_exist.py"
    changed = tmp_path / "bad-path.yaml"
    changed.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    result = run_check(changed)
    assert result.returncode != 0
    assert "文件不存在" in result.stderr


def test_duplicate_threat_id_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    data["threats"][1]["id"] = data["threats"][0]["id"]
    changed = tmp_path / "duplicate.yaml"
    changed.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    result = run_check(changed)
    assert result.returncode != 0
    assert "重复" in result.stderr


def test_stale_generated_document_is_rejected(tmp_path: Path) -> None:
    changed = tmp_path / "stale.md"
    changed.write_text(OUTPUT.read_text(encoding="utf-8") + "\n额外内容\n", encoding="utf-8")
    result = run_check(output=changed)
    assert result.returncode != 0
    assert "文档与数据不一致" in result.stderr


def test_unknown_runtime_threat_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    data["runtime_signals"][0]["threat_ids"] = ["TH-999"]
    changed = tmp_path / "unknown-runtime-threat.yaml"
    changed.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    result = run_check(changed)
    assert result.returncode != 0
    assert "不存在的威胁" in result.stderr


def test_unknown_runtime_condition_is_rejected(tmp_path: Path) -> None:
    data = yaml.safe_load(DATA.read_text(encoding="utf-8"))
    data["runtime_signals"][0]["when"]["content"] = "attack"
    changed = tmp_path / "raw-content-condition.yaml"
    changed.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    result = run_check(changed)
    assert result.returncode != 0
    assert "类型化字段" in result.stderr
