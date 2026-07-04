#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.action_gate import ActionRequest, evaluate_action, evaluate_payload  # noqa: E402


def test_safe_low_poc_allowed_in_sandbox() -> None:
    decision = evaluate_action(ActionRequest(action_type="run_poc", phase="phase_3", severity="medium", command=["docker", "compose", "run"], runs_target_code=True, in_sandbox=True))
    assert decision.allowed is True


def test_high_poc_requires_approval() -> None:
    decision = evaluate_action(ActionRequest(action_type="run_poc", phase="phase_3", severity="high", command=["docker"], runs_target_code=True, in_sandbox=True))
    assert decision.allowed is False
    assert "high_impact_poc_requires_user_approval" in decision.blocked_rules


def test_target_code_outside_sandbox_blocked() -> None:
    decision = evaluate_action(ActionRequest(action_type="run_poc", phase="phase_3", severity="medium", command=["/pkg/usr/bin/demo"], runs_target_code=True, in_sandbox=False, user_approved=True))
    assert decision.allowed is False
    assert "target_code_outside_sandbox_blocked" in decision.blocked_rules
    assert "poc_requires_sandbox" in decision.blocked_rules


def test_poc_network_blocked_even_with_approval() -> None:
    decision = evaluate_action(ActionRequest(action_type="run_poc", phase="phase_3", severity="low", command=["docker"], requires_network=True, runs_target_code=True, in_sandbox=True, user_approved=True))
    assert decision.allowed is False
    assert "poc_network_blocked" in decision.blocked_rules


def test_install_requires_approval() -> None:
    decision = evaluate_action(ActionRequest(action_type="install_tool", phase="preflight", command=["sudo", "apt-get", "install", "checksec"], requires_network=True))
    assert decision.allowed is False
    assert "network_install_requires_approval" in decision.blocked_rules
    assert "install_or_pull_requires_user_approval" in decision.blocked_rules


def test_sandbox_image_build_requires_approval() -> None:
    decision = evaluate_action(ActionRequest(action_type="build_image", phase="phase_3", command=["docker", "build", "sandbox"], requires_network=True))
    assert decision.allowed is False
    assert "network_install_requires_approval" in decision.blocked_rules
    assert "install_or_pull_requires_user_approval" in decision.blocked_rules


def test_payload_round_trip() -> None:
    result = evaluate_payload({"action_type": "read_artifact", "phase": "track_b", "command": ["cat", "raw/file.txt"], "requires_network": False, "writes_outside_results": False, "runs_target_code": False, "privileged": False, "in_sandbox": False, "user_approved": False})
    assert result["decision"]["allowed"] is True
    assert result["request"]["action_type"] == "read_artifact"


def run_all() -> None:
    test_safe_low_poc_allowed_in_sandbox()
    test_high_poc_requires_approval()
    test_target_code_outside_sandbox_blocked()
    test_poc_network_blocked_even_with_approval()
    test_install_requires_approval()
    test_sandbox_image_build_requires_approval()
    test_payload_round_trip()


if __name__ == "__main__":
    run_all()
    print("action gate tests OK")
