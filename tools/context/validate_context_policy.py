#!/usr/bin/env python3
"""Validate BlackBox Hunter runtime context policy invariants.

This validator intentionally checks project-specific constraints in addition to
JSON syntax so future changes cannot silently expand default runtime context.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "tools" / "context" / "context_policy.json"
SKILL_PATH = ROOT / "SKILL.md"
AGENTS_PATH = ROOT / "AGENTS.md"


class PolicyError(AssertionError):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("context policy must be a JSON object")
    return data


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy.get("version") == 1, "policy version must be 1")

    default = policy.get("default") or {}
    require(default.get("max_prompt_tokens", 0) > 0, "max_prompt_tokens must be positive")
    require(default.get("max_untrusted_evidence_tokens", 0) > 0, "max_untrusted_evidence_tokens must be positive")
    require(default.get("max_raw_excerpt_chars", 0) > 0, "max_raw_excerpt_chars must be positive")
    require(default.get("fail_closed_on_budget_exceeded") is True, "budget overflow must fail closed")

    forbidden = set(policy.get("forbidden_runtime_context") or [])
    allowed = set(policy.get("allowed_runtime_context") or [])
    require(forbidden, "forbidden_runtime_context must not be empty")
    require(allowed, "allowed_runtime_context must not be empty")
    require("README.md" in forbidden, "README.md must be forbidden from default runtime context")
    require(any(item.startswith("raw") or "/raw/" in item for item in forbidden), "raw artifacts must be forbidden")
    require(forbidden.isdisjoint(allowed), "allowed and forbidden context entries must not overlap exactly")

    track_b = policy.get("track_b") or {}
    for mode in ("quick", "standard", "deep", "full"):
        require(mode in track_b, f"track_b.{mode} is required")
        mode_policy = track_b[mode]
        require("function_limit" in mode_policy, f"track_b.{mode}.function_limit is required")
        require("dimensions" in mode_policy, f"track_b.{mode}.dimensions is required")
        require(mode_policy.get("max_prompt_tokens_per_call", 0) > 0, f"track_b.{mode}.max_prompt_tokens_per_call must be positive")

    quick_dims = track_b["quick"]["dimensions"]
    require(isinstance(quick_dims, list), "track_b.quick.dimensions must be explicit")
    require("dangerous_functions" in quick_dims, "quick mode must include dangerous_functions")
    require("hardcoded_config" in quick_dims, "quick mode must include hardcoded_config")

    untrusted = policy.get("untrusted_evidence") or {}
    require(untrusted.get("wrapper_required") is True, "untrusted evidence wrapper must be required")
    require(untrusted.get("wrapper_tag") == "UNTRUSTED_EVIDENCE", "wrapper tag must be UNTRUSTED_EVIDENCE")
    require("decompiled_c" in set(untrusted.get("allowed_kinds") or []), "decompiled_c evidence kind must be allowed")

    manifest = policy.get("context_manifest") or {}
    require(manifest.get("required") is True, "context manifest must be required")
    require(manifest.get("output_dir") == "$SCAN_ROOT/context", "context manifest output_dir must be $SCAN_ROOT/context")


def validate_docs() -> None:
    skill = SKILL_PATH.read_text(encoding="utf-8")
    agents = AGENTS_PATH.read_text(encoding="utf-8")
    require("Runtime Context Loading Policy" in skill, "SKILL.md must include Runtime Context Loading Policy")
    require("tools/context/context_policy.json" in skill, "SKILL.md must reference context_policy.json")
    require("AGENTS.md" in skill, "SKILL.md must reference AGENTS.md")
    require("Context Boundary" in agents, "AGENTS.md must define Context Boundary")
    require("Tool Boundary" in agents, "AGENTS.md must define Tool Boundary")
    require("Evidence Boundary" in agents, "AGENTS.md must define Evidence Boundary")


def main() -> int:
    try:
        validate_policy(load_policy())
        validate_docs()
    except PolicyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("context policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
