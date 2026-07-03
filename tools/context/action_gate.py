#!/usr/bin/env python3
"""Action gate for BlackBox Hunter runtime operations.

The gate evaluates potentially risky operations before execution. It is designed
for deterministic preflight checks and does not execute commands.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HIGH_IMPACT = {"critical", "high"}
INSTALL_ACTIONS = {"install_tool", "pull_image", "package_manager"}


@dataclass
class ActionRequest:
    action_type: str
    phase: str
    command: list[str] = field(default_factory=list)
    action_id: str | None = None
    finding_id: str | None = None
    severity: str | None = None
    requires_network: bool = False
    writes_outside_results: bool = False
    runs_target_code: bool = False
    privileged: bool = False
    in_sandbox: bool = False
    user_approved: bool = False
    approval_reason: str | None = None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "ActionRequest":
        return cls(
            action_type=str(payload.get("action_type", "")),
            phase=str(payload.get("phase", "")),
            command=list(payload.get("command") or []),
            action_id=payload.get("action_id"),
            finding_id=payload.get("finding_id"),
            severity=(payload.get("severity") or None),
            requires_network=bool(payload.get("requires_network", False)),
            writes_outside_results=bool(payload.get("writes_outside_results", False)),
            runs_target_code=bool(payload.get("runs_target_code", False)),
            privileged=bool(payload.get("privileged", False)),
            in_sandbox=bool(payload.get("in_sandbox", False)),
            user_approved=bool(payload.get("user_approved", False)),
            approval_reason=payload.get("approval_reason"),
        )


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    blocked_rules: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_action(request: ActionRequest) -> GateDecision:
    blocked: list[str] = []
    if not request.action_type:
        blocked.append("missing_action_type")
    if request.privileged:
        blocked.append("privileged_execution_blocked")
    if request.writes_outside_results:
        blocked.append("writes_outside_results_blocked")
    if request.requires_network:
        if request.action_type == "run_poc":
            blocked.append("poc_network_blocked")
        elif request.action_type in INSTALL_ACTIONS and not request.user_approved:
            blocked.append("network_install_requires_approval")
        elif request.action_type not in INSTALL_ACTIONS:
            blocked.append("network_access_blocked")
    if request.runs_target_code and not request.in_sandbox:
        blocked.append("target_code_outside_sandbox_blocked")
    if request.action_type == "run_poc":
        if not request.in_sandbox:
            blocked.append("poc_requires_sandbox")
        if (request.severity or "").lower() in HIGH_IMPACT and not request.user_approved:
            blocked.append("high_impact_poc_requires_user_approval")
    if request.action_type in INSTALL_ACTIONS and not request.user_approved:
        blocked.append("install_or_pull_requires_user_approval")
    if blocked:
        return GateDecision(False, "; ".join(blocked), blocked)
    return GateDecision(True, "allowed", [])


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    request = ActionRequest.from_json(payload)
    decision = evaluate_action(request)
    return {"request": asdict(request), "decision": decision.to_json()}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a BlackBox Hunter action gate request")
    parser.add_argument("request", help="JSON file containing an action request")
    parser.add_argument("--output", default="", help="Optional JSON output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.request).read_text(encoding="utf-8"))
    result = evaluate_payload(payload)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if result["decision"]["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
