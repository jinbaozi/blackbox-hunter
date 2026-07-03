#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "prompts" / "track_b" / "manifest.json"
PHASE_1B = ROOT / "phases" / "phase-1b-ai-analysis.md"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_loads() -> None:
    data = load_manifest()
    assert data["version"] == 1
    assert data["base_contract"] == "prompts/track_b/base_contract.md"


def test_manifest_prompt_paths_exist() -> None:
    data = load_manifest()
    for key in ["base_contract", "evidence_wrapper", "output_contract"]:
        assert (ROOT / data[key]).is_file(), key

    for name, spec in data["dimensions"].items():
        assert (ROOT / spec["path"]).is_file(), name
        assert spec["max_context_tokens"] > 0, name
        assert isinstance(spec["requires"], list), name


def test_core_and_extended_dimensions_are_declared() -> None:
    data = load_manifest()
    dimensions = set(data["dimensions"])
    assert set(data["core_dimensions"]).issubset(dimensions)
    assert set(data["extended_dimensions"]).issubset(dimensions)
    assert "dangerous_functions" in dimensions
    assert "hardcoded_config" in dimensions
    assert "crypto_tls_auth" in dimensions


def test_mode_defaults_are_valid() -> None:
    data = load_manifest()
    dimensions = set(data["dimensions"])
    for mode, selection in data["mode_defaults"].items():
        if isinstance(selection, list):
            assert set(selection).issubset(dimensions), mode
        else:
            assert selection in {"core_dimensions", "all_dimensions"}, mode


def test_phase_1b_no_inline_prompt_templates() -> None:
    text = PHASE_1B.read_text(encoding="utf-8")
    assert "### Prompt Template" not in text
    assert "Check item 15" not in text
    assert "prompts/track_b/manifest.json" in text
    assert "Prompt Loading Contract" in text


def test_dimension_cards_are_single_purpose() -> None:
    for path in (ROOT / "prompts" / "track_b" / "dimensions").glob("*.md"):
        text = path.read_text(encoding="utf-8")
        assert text.startswith("# Dimension:"), path
        assert text.count("# Dimension:") == 1, path
        assert "Emit Finding Gate" in text, path
        assert "Reject Conditions" in text, path


def run_all() -> None:
    test_manifest_loads()
    test_manifest_prompt_paths_exist()
    test_core_and_extended_dimensions_are_declared()
    test_mode_defaults_are_valid()
    test_phase_1b_no_inline_prompt_templates()
    test_dimension_cards_are_single_purpose()


if __name__ == "__main__":
    run_all()
    print("prompt manifest tests OK")
