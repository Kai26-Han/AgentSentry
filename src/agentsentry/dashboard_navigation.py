"""共用工作区目录；页面合并只影响呈现，不改变授权范围。"""

from urllib.parse import urlencode


GROUPS = [
    ("运行分析", [
        ("sessions", "会话调查", "/dashboard/runtime-sessions", ["runtime-sessions", "goal-assessments", "action-chains"]),
        ("calls", "工具调用与审计", "/dashboard/activity", ["activity", "audit"]),
        ("delegations", "Agent 安全委托", "/dashboard/delegations", ["delegations"]),
        ("data-flow", "敏感数据流", "/dashboard/data-flow", ["data-flow"]),
        ("threat-map", "威胁关联", "/dashboard/threat-map", ["threat-map"]),
    ]),
    ("记忆安全", [
        ("memories", "长期记忆", "/dashboard/memories", ["memories"]),
        ("memory-labs", "记忆实验", "/dashboard/memory-runs", ["memory-runs", "memory-security-runs"]),
    ]),
    ("安全实验与评测", [
        ("attack-labs", "Agent 攻击实验", "/dashboard/attack-runs", ["attack-runs", "goal-runs"]),
        ("calibration-runs", "攻防验证与规则校准", "/dashboard/calibration-runs", ["calibration-runs"]),
        ("judge-samples", "Judge 评测", "/dashboard/judge-samples", ["judge-samples"]),
    ]),
    ("管理配置", [
        ("grants", "工具调用授权", "/dashboard/grants", ["grants"]),
        ("rules", "防护规则", "/dashboard/policy", ["policy", "runtime-rules"]),
        ("remote-mcp", "远程 MCP 接入", "/dashboard/remote-mcp", ["remote-mcp"]),
        ("judge-runtime", "Judge 运行设置", "/dashboard/judge-runtime", ["judge-runtime"]),
        ("tenants", "租户管理", "/dashboard/tenants", ["tenants"]),
        ("system", "系统与演示数据", "/dashboard/system", ["system", "resilience"]),
    ]),
]

TABS = {
    "system": [("system", "运行状态与演示数据", "/dashboard/system"),
               ("resilience", "故障隔离与恢复", "/dashboard/resilience")],
    "sessions": [("runtime-sessions", "概览", "/dashboard/runtime-sessions"),
                 ("goal-assessments", "目标偏移", "/dashboard/goal-assessments"),
                 ("action-chains", "行动链", "/dashboard/action-chains")],
    "calls": [("activity", "工具调用", "/dashboard/activity"),
              ("audit", "审计事件", "/dashboard/audit"),
              ("judge-results", "Judge 结果", "/dashboard/audit?view=judge")],
    "threat-map": [("events", "事件证据", "/dashboard/threat-map"),
                   ("framework", "框架映射", "/dashboard/threat-map?view=framework")],
    "memory-labs": [("memory-runs", "跨会话污染", "/dashboard/memory-runs"),
                    ("memory-security-runs", "存储安全", "/dashboard/memory-security-runs")],
    "attack-labs": [("attack-runs", "综合攻击", "/dashboard/attack-runs"),
                    ("goal-runs", "目标偏移", "/dashboard/goal-runs")],
    "rules": [("policy", "工具调用策略", "/dashboard/policy"),
              ("runtime-rules", "运行时安全规则", "/dashboard/runtime-rules")],
}


def navigation(active: str, path: str, query, tenant_id: str) -> dict:
    groups = []
    selected = None
    for label, definitions in GROUPS:
        entries = []
        for key, title, url, pages in definitions:
            if key == "tenants" and tenant_id != "default":
                continue
            is_active = active in pages
            entries.append({"key": key, "label": title, "url": url, "active": is_active})
            if is_active:
                selected = (key, title, label, url)
        groups.append({"label": label, "items": entries,
                       "active": any(item["active"] for item in entries)})
    tabs = []
    view = query.get("view", "")
    if selected:
        key = selected[0]
        # 详情仍归属同一目录；列表标签不能把当前证据误认为另一份会话。
        is_list = path.rstrip("/") in {url.split("?", 1)[0] for _, _, url in TABS.get(key, [])}
        if is_list:
            selected_tab = ("judge-results" if active == "audit" and view == "judge" else
                            "framework" if key == "threat-map" and view == "framework" else
                            "events" if key == "threat-map" else active)
            for tab_id, title, url in TABS.get(key, []):
                args = {}
                if "?" in url:
                    args["view"] = url.split("view=", 1)[1]
                if key in {"sessions", "memory-labs", "attack-labs"} and query.get("tenant"):
                    args["tenant"] = query["tenant"]
                if key == "threat-map":
                    for name in ("days", "threat_id"):
                        if query.get(name):
                            args[name] = query[name]
                href = url.split("?", 1)[0] + ("?" + urlencode(args) if args else "")
                tabs.append({"label": title, "url": href, "active": tab_id == selected_tab})
    return {"shell_groups": groups, "shell_workspace": selected[1] if selected else None,
            "shell_workspace_key": selected[0] if selected else None,
            "shell_group": selected[2] if selected else None,
            "shell_workspace_url": selected[3] if selected else None,
            "shell_tabs": tabs, "shell_view": view}
