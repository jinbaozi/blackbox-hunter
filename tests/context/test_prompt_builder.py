#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.prompt_builder import build_track_b_prompt  # noqa: E402


def sample_evidence() -> dict:
    return {
        "binary": "/usr/bin/demo",
        "dimension": "dangerous_functions",
        "function": "parse_request",
        "address": "0x4012ab",
        "imports": ["recv", "strcpy"],
        "xrefs_summary": ["called from handle_client"],
        "body_excerpt": "recv(fd, buf, 4096, 0); strcpy(local_80, buf);",
        "supporting_files": ["raw/track_b/demo/parse_request.ghidra.json"],
        "omitted": {},
        "truncated": False,
    }


def test_build_prompt_loads_only_selected_dimension() -> None:
    built = build_track_b_prompt(
        root=ROOT,
        manifest_path=ROOT / "prompts/track_b/manifest.json",
        context_policy_path=ROOT / "tools/context/context_policy.json",
        dimension="dangerous_functions",
        evidence_json=sample_evidence(),
        mode="quick",
        scan_id="BBH-20260703-a1b2c3",
        target="/usr/bin/demo",
        function="parse_request",
    )

    assert "# Track B Base Contract" in built.prompt
    assert "# Dimension: dangerous_functions" in built.prompt
    assert "# Dimension: memory_management" not in built.prompt
    assert "README.md" not in built.prompt
    assert "<UNTRUSTED_EVIDENCE" in built.prompt
    assert "raw/track_b/demo/parse_request.ghidra.json" in built.prompt
    assert built.estimated_tokens <= built.max_prompt_tokens
    assert "prompts/track_b/dimensions/dangerous_functions.md" in built.loaded_files
    assert "unrelated Track B dimension cards" in built.excluded_files


def test_prompt_builder_rejects_dimension_not_enabled_for_mode() -> None:
    try:
        build_track_b_prompt(
            root=ROOT,
            manifest_path=ROOT / "prompts/track_b/manifest.json",
            context_policy_path=ROOT / "tools/context/context_policy.json",
            dimension="input_validation",
            evidence_json={**sample_evidence(), "dimension": "input_validation"},
            mode="quick",
        )
    except ValueError as exc:
        assert "not enabled for mode" in str(exc)
    else:
        raise AssertionError("quick mode should reject input_validation")


def test_prompt_builder_writes_context_manifest() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "context.json"
        built = build_track_b_prompt(
            root=ROOT,
            manifest_path=ROOT / "prompts/track_b/manifest.json",
            context_policy_path=ROOT / "tools/context/context_policy.json",
            dimension="dangerous_functions",
            evidence_json=sample_evidence(),
            mode="quick",
            scan_id="BBH-20260703-a1b2c3",
            target="/usr/bin/demo",
            function="parse_request",
            context_manifest_path=manifest_path,
        )
        assert manifest_path.is_file()
        text = manifest_path.read_text(encoding="utf-8")
        assert "dangerous_functions" in text
        assert "README.md" in text
        assert built.context_manifest_path == str(manifest_path)


def run_all() -> None:
    test_build_prompt_loads_only_selected_dimension()
    test_prompt_builder_rejects_dimension_not_enabled_for_mode()
    test_prompt_builder_writes_context_manifest()


if __name__ == "__main__":
    run_all()
    print("prompt builder tests OK")
