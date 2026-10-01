"""离线校验威胁映射，并从唯一数据源生成中文阅读版。"""

import argparse
import importlib
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "docs" / "threat-framework-map.yaml"
DEFAULT_OUTPUT = ROOT / "docs" / "threat-framework-mapping.md"
sys.path.insert(0, str(ROOT / "src"))

OWASP = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
STATUSES = {"范围内已验证", "部分验证", "已确认缺口", "未验证", "当前不适用"}
APPLICABILITY = {"当前适用", "未来接入", "当前范围外", "尚待验证"}
KINDS = {"固定重放", "真实模型", "单元测试", "现场演练", "验收报告"}
RUNTIME_EVENT_TYPES = {"tool_result", "data_flow_decision", "goal_assessment", "runtime_decision",
                       "memory_integrity", "action_chain_decision", "mcp_profile_observed",
                       "mcp_supply_incident", "dependency_fault", "delegation_decision"}
RUNTIME_CONDITIONS = {"sink", "destination", "effect", "finding", "phase",
                      "status", "reason", "source_tool", "fixture_document"}
CORPORA = {
    "delegation-lab-v1": ("agentsentry.delegation_lab", "delegation-lab-v1"),
    "fault-lab-v1": ("agentsentry.fault_lab", "fault-lab-v1"),
    "deep-validation-v1": ("agentsentry.deep_validation_corpus", "deep-validation-v1"),
    "goal-lab-v1": ("agentsentry.goal_lab_corpus", "goal-lab-v1"),
    "attack/v2.2.0": ("agentsentry.attack_corpus", "v2.2.0"),
    "memory-security/v2.6.0": ("agentsentry.memory_security_lab", "v2.6.0"),
    "data-flow-cases-v1": ("agentsentry.data_flow_corpus_v1", "data-flow-cases-v1"),
    "data-flow-cases-v2": ("agentsentry.data_flow_lab", "data-flow-cases-v2"),
    "output-samples-v5": ("agentsentry.output_samples", "output-samples-v5"),
    "calibration-cases-v1": ("agentsentry.calibration_corpus", "calibration-cases-v1"),
    "runtime-cases-v1": ("agentsentry.runtime_lab", "runtime-cases-v1"),
    "action-chain-cases-v1": ("agentsentry.action_chain_lab", "action-chain-cases-v1"),
    "action-chain-live-v1": ("agentsentry.action_chain_live", "action-chain-live-v1"),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _local_path(value: str) -> Path:
    _require(isinstance(value, str) and value and not value.startswith(("/", "~")),
             f"无效的仓库内路径：{value!r}")
    candidate = (ROOT / value).resolve()
    _require(candidate.is_relative_to(ROOT) and candidate.is_file(), f"证据或控制文件不存在：{value}")
    return candidate


def validate(data: dict) -> None:
    _require(isinstance(data, dict) and data.get("schema_version") == 1, "映射数据版本必须为 1")
    _require(re.fullmatch(r"\d+\.\d+\.\d+", str(data.get("mapping_version", ""))) is not None,
             "映射内容版本无效")
    sources = data.get("frameworks", {})
    _require(sources.get("owasp", {}).get("edition") == "Agentic Top 10 2026", "OWASP 版本不匹配")
    _require(sources["owasp"].get("url") ==
             "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
             "OWASP 必须引用官方 2026 版本页面")
    atlas_source = sources.get("atlas", {})
    _require(atlas_source.get("release") == "2026.08" and
             re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(atlas_source.get("checked_on", ""))) is not None,
             "ATLAS 快照版本或核对日期无效")
    source_url = atlas_source.get("source_url", "")
    _require(source_url == "https://github.com/mitre-atlas/atlas-data/blob/v2026.08/dist/v6/ATLAS-2026.08.yaml",
             "ATLAS 必须引用固定的 MITRE 官方发布版本")

    techniques = data.get("atlas_techniques", [])
    _require(isinstance(techniques, list), "ATLAS 技术目录必须是列表")
    technique_ids = {}
    technique_urls = set()
    for item in techniques:
        identifier = item.get("id", "")
        _require(re.fullmatch(r"AML\.T\d{4}(?:\.\d{3})?", identifier) is not None,
                 f"ATLAS 技术编号无效：{identifier}")
        _require(identifier not in technique_ids and isinstance(item.get("name"), str) and item["name"],
                 f"ATLAS 技术重复或缺名称：{identifier}")
        url = item.get("url", "")
        _require(isinstance(url, str) and
                 re.fullmatch(re.escape(source_url) + r"#L\d+", url) is not None and
                 url not in technique_urls,
                 f"ATLAS 技术未链接到固定官方发布版本：{identifier}")
        technique_ids[identifier] = item
        technique_urls.add(url)

    threats = data.get("threats", [])
    _require(isinstance(threats, list) and threats, "至少需要一条项目威胁")
    threat_ids = set()
    corpus_cache = {}
    for threat in threats:
        identifier = threat.get("id", "")
        _require(re.fullmatch(r"TH-\d{3}", identifier) is not None and identifier not in threat_ids,
                 f"威胁编号无效或重复：{identifier}")
        threat_ids.add(identifier)
        for field in ("title", "entry", "asset", "scope", "limitation"):
            _require(isinstance(threat.get(field), str) and threat[field].strip(),
                     f"{identifier} 缺少 {field}")
        _require(threat.get("status") in STATUSES, f"{identifier} 结论状态无效")
        owasp = threat.get("owasp", [])
        _require(isinstance(owasp, list) and owasp and len(owasp) == len(set(owasp)) and
                 all(item in OWASP for item in owasp), f"{identifier} OWASP 编号无效")
        atlas = threat.get("atlas", [])
        _require(isinstance(atlas, list) and len(atlas) == len(set(atlas)) and
                 all(item in technique_ids for item in atlas), f"{identifier} ATLAS 编号无效")
        if not atlas:
            _require(isinstance(threat.get("atlas_note"), str) and threat["atlas_note"].strip(),
                     f"{identifier} 未映射 ATLAS 时必须解释原因")
        controls = threat.get("controls", [])
        evidence = threat.get("evidence", [])
        _require(isinstance(controls, list) and controls and isinstance(evidence, list) and evidence,
                 f"{identifier} 缺少控制或证据")
        for control in controls:
            _local_path(control.get("path"))
            _require(isinstance(control.get("summary"), str) and control["summary"].strip(),
                     f"{identifier} 控制说明为空")
        for item in evidence:
            _require(item.get("kind") in KINDS, f"{identifier} 证据类型无效")
            _local_path(item.get("path"))
            if item["kind"] == "单元测试":
                _require(item["path"].startswith("tests/") and item["path"].endswith(".py"),
                         f"{identifier} 单元测试证据必须指向 tests 下的 Python 文件")
            _require(isinstance(item.get("summary"), str) and item["summary"].strip(),
                     f"{identifier} 证据结论为空")
            corpus = item.get("corpus")
            cases = item.get("cases")
            _require((corpus is None and cases is None) or
                     (corpus in CORPORA and isinstance(cases, list) and cases and
                      len(cases) == len(set(cases))), f"{identifier} 样本库或样本 ID 无效")
            if corpus:
                if corpus not in corpus_cache:
                    module_name, expected_version = CORPORA[corpus]
                    module = importlib.import_module(module_name)
                    _require(module.VERSION == expected_version, f"样本库版本已变化：{corpus}")
                    corpus_cache[corpus] = {case["id"] for case in module.CASES}
                _require(all(case in corpus_cache[corpus] for case in cases),
                         f"{identifier} 引用了不存在的样本：{corpus}:{cases}")

    categories = data.get("categories", [])
    _require(isinstance(categories, list) and len(categories) == 10, "必须逐项说明 OWASP 十类风险")
    _require({item.get("id") for item in categories} == set(OWASP), "OWASP 类别缺失或重复")
    for category in categories:
        identifier = category["id"]
        _require(category.get("name") == OWASP[identifier], f"{identifier} 类别名称不符")
        _require(category.get("applicability") in APPLICABILITY and
                 isinstance(category.get("note"), str) and category["note"].strip(),
                 f"{identifier} 缺少适用性或说明")
        expected = {threat["id"] for threat in threats if identifier in threat["owasp"]}
        actual = category.get("threat_ids", [])
        _require(isinstance(actual, list) and len(actual) == len(set(actual)) and
                 set(actual) == expected, f"{identifier} 威胁关联与场景映射不一致")
    signals = data.get("runtime_signals", [])
    _require(isinstance(signals, list) and signals, "缺少日常事件映射规则")
    signal_ids = set()
    for signal in signals:
        identifier = signal.get("id", "")
        _require(re.fullmatch(r"[a-z][a-z0-9_]{2,79}", identifier) is not None
                 and identifier not in signal_ids, f"日常映射规则 ID 无效或重复：{identifier}")
        signal_ids.add(identifier)
        _require(isinstance(signal.get("title"), str) and signal["title"].strip(),
                 f"{identifier} 缺少中文名称")
        _require(signal.get("event_type") in RUNTIME_EVENT_TYPES,
                 f"{identifier} 审计事件类型未登记")
        conditions = signal.get("when")
        _require(isinstance(conditions, dict) and conditions and
                 set(conditions) <= RUNTIME_CONDITIONS and
                 all(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_:-]{0,79}", value)
                     for value in conditions.values()),
                 f"{identifier} 触发条件只能使用登记过的类型化字段")
        _require("finding" in conditions or "reason" in conditions or
                 "fixture_document" in conditions,
                 f"{identifier} 必须关联明确的规则命中、异常原因或固定样本")
        if "fixture_document" in conditions:
            _require(signal["event_type"] == "tool_result" and
                     conditions["fixture_document"] == "injected-guide" and
                     conditions.get("status") == "completed",
                     f"{identifier} 只允许核实已完成的固定合成注入文档读取")
        linked = signal.get("threat_ids")
        _require(isinstance(linked, list) and linked and len(linked) == len(set(linked)) and
                 set(linked) <= threat_ids, f"{identifier} 引用了不存在的威胁")


def render(data: dict) -> str:
    techniques = {item["id"]: item for item in data["atlas_techniques"]}
    atlas = data["frameworks"]["atlas"]
    owasp = data["frameworks"]["owasp"]

    def link(path: str, label: str) -> str:
        target = "../" + path if not path.startswith("docs/") else path.removeprefix("docs/")
        return f"[{label}]({target})"

    def cell(value: str) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        "# AgentSentry 安全威胁与框架映射",
        "",
        "[中文](#) · [English](en/threat-framework-mapping.md)",
        "",
        "> 本页由 `docs/threat-framework-map.yaml` 生成，请修改数据文件后运行 `python scripts/check_threat_mapping.py --write`。",
        "",
        f"映射版本：{data['mapping_version']}。",
        "",
        f"OWASP 来源：[Agentic Top 10 2026]({owasp['url']})。MITRE ATLAS 来源：[官方 {atlas['release']} 数据快照]({atlas['source_url']})；核对日期：{atlas['checked_on']}。",
        "",
        "**判读口径**：每行只评价注明的项目路径与样本；固定重放、真实模型和单元测试分开列示。框架编号是分类线索，不代表整类风险已解决。案例保留实验日期、规则版本与修复前后事实，已确认缺口不会被其他通过样本抵消。",
        "",
        "## OWASP 十类风险的项目适用性",
        "",
        "| 类别 | 项目适用性 | 对应威胁 | 说明 |",
        "| --- | --- | --- | --- |",
    ]
    for category in data["categories"]:
        refs = "、".join(f"[{item}](#{item.lower()})" for item in category["threat_ids"]) or "无"
        lines.append(f"| {category['id']} {cell(category['name'])} | {category['applicability']} | {refs} | {cell(category['note'])} |")
    lines += ["", "## 项目威胁概览", "", "| 场景 | OWASP | MITRE ATLAS | 当前结论 |",
              "| --- | --- | --- | --- |"]
    for threat in data["threats"]:
        atlas_refs = "、".join(f"[{item}]({techniques[item]['url']})" for item in threat["atlas"]) or "未强行映射"
        lines.append(f"| [{threat['id']}](#{threat['id'].lower()}) {cell(threat['title'])} | "
                     f"{'、'.join(threat['owasp'])} | {atlas_refs} | {threat['status']} |")
    for threat in data["threats"]:
        lines += ["", f"<a id=\"{threat['id'].lower()}\"></a>", "",
                  f"## {threat['id']} {threat['title']}", "",
                  f"- **入口与资产**：{threat['entry']}；{threat['asset']}。",
                  f"- **适用范围**：{threat['scope']}。",
                  f"- **当前结论**：{threat['status']}。",
                  f"- **OWASP**：{'、'.join(threat['owasp'])}。"]
        if threat["atlas"]:
            refs = "、".join(f"[{item} {techniques[item]['name']}]({techniques[item]['url']})"
                             for item in threat["atlas"])
            lines.append(f"- **MITRE ATLAS**：{refs}。")
        else:
            lines.append(f"- **MITRE ATLAS**：未映射；{threat['atlas_note'].rstrip('。')}。")
        lines.append("- **控制措施**：" + "；".join(
            link(item["path"], item["summary"]) for item in threat["controls"]) + "。")
        lines.append("- **证据**：")
        for item in threat["evidence"]:
            samples = "、".join(f"`{item['corpus']}:{case}`" for case in item["cases"]) + "；" if item.get("corpus") else ""
            lines.append(f"  - {item['kind']}：{samples}{link(item['path'], '查看证据')}；{item['summary']}。")
        lines.append(f"- **剩余边界**：{threat['limitation'].rstrip('。')}。")
    lines += ["", "## 日常事件映射规则", "",
              "这些规则只对已经提交的审计元数据作分类。命中表示观察到线索；阻断、待审批与实际副作用必须分别核对。未列出的事件保持未映射，Judge 标签不会单独触发威胁归类。", "",
              "| 规则 | 审计事件 | 必要条件 | 项目威胁 |", "| --- | --- | --- | --- |"]
    for signal in data["runtime_signals"]:
        conditions = "、".join(f"{key}={value}" for key, value in signal["when"].items())
        lines.append(f"| `{signal['id']}` {cell(signal['title'])} | `{signal['event_type']}` | "
                     f"{cell(conditions)} | {'、'.join(signal['threat_ids'])} |")
    lines += ["", "## 维护规则", "", "1. 新增或修改样本时，先更新映射数据中的样本库版本与 ID，再核对实际实验记录。",
              "2. 实测结果改变时新增或引用案例证据；修复前后的事实分别标注，不将旧结果描述为当前复测。",
              "3. 远程 MCP 接入、模型或策略改变后，重新评估相关场景；未运行新实验时标为“未验证”。",
              "4. 执行 `python scripts/check_threat_mapping.py --check`；CI 离线检查数据及此页是否一致。",
              ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="校验并生成中文安全威胁框架映射")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="校验数据和已生成文档")
    group.add_argument("--write", action="store_true", help="校验数据并更新生成文档")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        data = yaml.safe_load(args.data.read_text(encoding="utf-8"))
        validate(data)
        expected = render(data)
        if args.write:
            args.output.write_text(expected, encoding="utf-8")
            print(f"已生成 {args.output}")
        else:
            _require(args.output.is_file() and args.output.read_text(encoding="utf-8") == expected,
                     "中文映射文档与数据不一致，请运行 --write")
            print(f"映射校验通过：{len(data['threats'])} 条威胁，10 个 OWASP 类别")
        return 0
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"映射校验失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
