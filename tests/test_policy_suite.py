from pathlib import Path

import pytest
import yaml

from agentsentry.policy import PolicyEngine
from agentsentry.policy_tests import PolicySuite, run_policy_suite
from agentsentry.tenants import policy_for_new_tenant


ROOT = Path(__file__).resolve().parents[1]


def test_policy_suite_covers_every_default_rule():
    suite = PolicySuite.model_validate(yaml.safe_load((ROOT / "policy-tests/cases.yaml").read_text()))
    policy = PolicyEngine.from_file(str(ROOT / "policies/default.yaml"))
    report = run_policy_suite(policy, suite)
    assert report["cases"] == report["passed"] == 13
    assert report["uncovered_rules"] == []


def test_policy_suite_catches_behavior_drift_and_untested_rules():
    suite = PolicySuite.model_validate(yaml.safe_load((ROOT / "policy-tests/cases.yaml").read_text()))
    policy = yaml.safe_load((ROOT / "policies/default.yaml").read_text())
    for rule in policy["rules"]:
        if rule["id"] == "create_task":
            rule["effect"] = "deny"
    report = run_policy_suite(PolicyEngine.from_content(yaml.safe_dump(policy).encode()), suite)
    assert report["passed"] < report["cases"]

    policy["rules"].append({"id": "new_rule_without_case", "effect": "deny", "tool": "read_document",
                            "argument_regex": {"field": "document_id", "pattern": "never-tested-resource"}})
    report = run_policy_suite(PolicyEngine.from_content(yaml.safe_dump(policy).encode()), suite)
    assert "new_rule_without_case" in report["uncovered_rules"]


def test_new_tenant_policy_suite():
    suite = PolicySuite.model_validate(yaml.safe_load((ROOT / "policy-tests/tenant-cases.yaml").read_text()))
    content = policy_for_new_tenant((ROOT / "policies/default.yaml").read_text())
    report = run_policy_suite(PolicyEngine.from_content(content.encode()), suite)
    assert report["cases"] == report["passed"] == 13
    assert report["uncovered_rules"] == []


def test_mcp_note_cannot_be_directly_allowed_by_policy():
    policy = yaml.safe_load((ROOT / "policies/default.yaml").read_text())
    for rule in policy["rules"]:
        if rule["tool"] == "mcp_record_note":
            rule["effect"] = "allow"
    with pytest.raises(ValueError, match="Sensitive tools require approval"):
        PolicyEngine.from_content(yaml.safe_dump(policy).encode())
