#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "tools" / "context" / "context_policy.json"
VALIDATOR = ROOT / "tools" / "context" / "validate_context_policy.py"


def load_policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def load_validator_module():
    spec = importlib.util.spec_from_file_location("validate_context_policy", VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_policy_json_loads() -> None:
    data = load_policy()
    assert data["version"] == 1


def test_readme_is_not_runtime_context() -> None:
    data = load_policy()
    assert "README.md" in data["forbidden_runtime_context"]
    assert "README.md" not in data["allowed_runtime_context"]


def test_raw_artifacts_are_forbidden() -> None:
    data = load_policy()
    forbidden = data["forbidden_runtime_context"]
    assert any(item.startswith("raw") or "/raw/" in item for item in forbidden)


def test_untrusted_wrapper_required() -> None:
    data = load_policy()
    assert data["untrusted_evidence"]["wrapper_required"] is True
    assert data["untrusted_evidence"]["wrapper_tag"] == "UNTRUSTED_EVIDENCE"


def test_track_b_modes_exist() -> None:
    data = load_policy()
    for mode in ["quick", "standard", "deep", "full"]:
        assert mode in data["track_b"]
        assert data["track_b"][mode]["max_prompt_tokens_per_call"] > 0


def test_validator_accepts_policy() -> None:
    module = load_validator_module()
    module.validate_policy(load_policy())
    module.validate_docs()


def run_all() -> None:
    test_policy_json_loads()
    test_readme_is_not_runtime_context()
    test_raw_artifacts_are_forbidden()
    test_untrusted_wrapper_required()
    test_track_b_modes_exist()
    test_validator_accepts_policy()


if __name__ == "__main__":
    run_all()
    print("context policy tests OK")
