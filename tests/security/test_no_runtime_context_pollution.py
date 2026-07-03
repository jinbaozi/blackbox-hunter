#!/usr/bin/env python3
"""Regression checks for runtime context pollution.

These tests make sure the prompt builder preserves the progressive-disclosure
contract: stable prompt cards + selected dimension + bounded evidence only.
"""

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.prompt_builder import build_track_b_prompt  # noqa: E402


RAW_SECRET = "RAW_SECRET_CONTEXT_POLLUTION_SENTINEL"


def evidence_slice(tmp: Path) -> dict:
    raw = tmp / "raw" / "dangerous.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(RAW_SECRET, encoding="utf-8")
    return {
        "binary": "/usr/bin/no-pollution",
        "dimension": "dangerous_functions",
        "function": "parse_request",
        "address": "0x4012ab",
        "architecture": "x86_64",
        "attack_surface": {"type": "network", "entry_point": "tcp/8080"},
        "imports": ["recv", "strcpy"],
        "xrefs_summary": ["handle_client -> parse_request"],
        "body_excerpt": "bounded excerpt only: recv -> strcpy",
        "supporting_files": [str(raw)],
        "omitted": {str(raw): "full raw artifact kept on disk"},
        "truncated": False,
        "suspicious": False,
        "injection_findings": [],
    }


def test_prompt_builder_does_not_load_readme_or_unrelated_dimensions():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        built = build_track_b_prompt(
            root=ROOT,
            manifest_path=ROOT / "prompts/track_b/manifest.json",
            context_policy_path=ROOT / "tools/context/context_policy.json",
            dimension="dangerous_functions",
            evidence_json=evidence_slice(tmp),
            mode="quick",
            scan_id="BBH-20260703-sec001",
            target="/usr/bin/no-pollution",
            function="parse_request",
            context_manifest_path=tmp / "context_manifest.json",
        )

    assert "README.md" not in built.loaded_files
    assert "prompts/track_b/dimensions/dangerous_functions.md" in built.loaded_files
    assert all("memory_management" not in item for item in built.loaded_files)
    assert all("protocol_parsing" not in item for item in built.loaded_files)
    assert RAW_SECRET not in built.prompt
    assert "UNTRUSTED_EVIDENCE" in built.prompt
    assert "README.md" in built.excluded_files
    assert "raw/**" in built.excluded_files


def test_dimension_not_enabled_for_mode_fails_closed():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        try:
            build_track_b_prompt(
                root=ROOT,
                manifest_path=ROOT / "prompts/track_b/manifest.json",
                context_policy_path=ROOT / "tools/context/context_policy.json",
                dimension="memory_management",
                evidence_json=evidence_slice(tmp),
                mode="quick",
            )
        except ValueError as exc:
            assert "not enabled for mode" in str(exc)
        else:
            raise AssertionError("quick mode unexpectedly accepted memory_management")


if __name__ == "__main__":
    test_prompt_builder_does_not_load_readme_or_unrelated_dimensions()
    test_dimension_not_enabled_for_mode_fails_closed()
    print("runtime context pollution tests passed")
