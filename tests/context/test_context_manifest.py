#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.context_manifest import (  # noqa: E402
    ContextManifest,
    make_context_id,
    read_context_manifest,
    write_context_manifest,
)


def test_context_id_is_stable_and_readable() -> None:
    context_id = make_context_id(
        scan_id="BBH-20260703-a1b2c3",
        phase="track_b",
        dimension="dangerous_functions",
        target="/usr/bin/demo",
        function="parse_request",
    )
    assert context_id.startswith("CTX-BBH-20260703-a1b2c3-track_b-dangerous_functions")
    assert "usr_bin_demo" in context_id


def test_context_manifest_round_trip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "context.json"
        manifest = ContextManifest(
            context_id="CTX-1",
            phase="track_b",
            dimension="dangerous_functions",
            target="/usr/bin/demo",
            function="parse_request",
            loaded_files=["prompts/track_b/base_contract.md"],
            excluded_files=["README.md", "raw/**"],
            untrusted_sources=["raw/demo.txt"],
            token_budget={"max": 3000, "estimated": 1200},
            context_profile="track_b.v1.dangerous_functions",
        )
        write_context_manifest(path, manifest)
        loaded = read_context_manifest(path)
        assert loaded["context_id"] == "CTX-1"
        assert loaded["phase"] == "track_b"
        assert loaded["token_budget"]["estimated"] == 1200
        assert "created_at" in loaded


def run_all() -> None:
    test_context_id_is_stable_and_readable()
    test_context_manifest_round_trip()


if __name__ == "__main__":
    run_all()
    print("context manifest tests OK")
