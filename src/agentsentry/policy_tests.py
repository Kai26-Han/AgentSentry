"""Typed, repeatable policy decision tests for CI and tenant policy review."""

import argparse
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .policy import PolicyEngine
from .schemas import TOOL_SCHEMAS


class PolicyCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    tool: str
    arguments: dict
    effect: str
    rule: str

    @model_validator(mode="after")
    def validate_case(self):
        if self.tool not in TOOL_SCHEMAS:
            raise ValueError("Unknown tool in policy test")
        TOOL_SCHEMAS[self.tool].model_validate(self.arguments)
        if self.effect not in {"allow", "deny", "require_approval"}:
            raise ValueError("Invalid expected effect")
        return self


class PolicySuite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    cases: list[PolicyCase] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_suite(self):
        if self.version != 1:
            raise ValueError("Unsupported policy test version")
        names = [case.name for case in self.cases]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate policy test name")
        return self


def run_policy_suite(policy: PolicyEngine, suite: PolicySuite) -> dict:
    results = []
    hit_rules = set()
    for case in suite.cases:
        arguments = TOOL_SCHEMAS[case.tool].model_validate(case.arguments).model_dump(mode="json")
        actual = policy.decide(case.tool, arguments)
        hit_rules.add(actual.rule_id)
        results.append({
            "name": case.name,
            "expected": {"effect": case.effect, "rule": case.rule},
            "actual": {"effect": actual.effect, "rule": actual.rule_id},
            "passed": actual.effect == case.effect and actual.rule_id == case.rule,
        })
    uncovered = sorted({rule.id for rule in policy.policy.rules} - hit_rules)
    return {
        "cases": len(results), "passed": sum(item["passed"] for item in results),
        "uncovered_rules": uncovered, "results": results,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=str(root / "policies/default.yaml"))
    parser.add_argument("--cases", default=str(root / "policy-tests/cases.yaml"))
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    policy = PolicyEngine.from_file(args.policy)
    suite = PolicySuite.model_validate(yaml.safe_load(Path(args.cases).read_text()))
    report = run_policy_suite(policy, suite)
    if args.output:
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, ensure_ascii=False))
    if report["passed"] != report["cases"] or report["uncovered_rules"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
