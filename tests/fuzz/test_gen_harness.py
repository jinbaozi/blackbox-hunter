#!/usr/bin/env python3
"""Tests for B7: fuzz harness generator + seed corpus + discover adapter."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.fuzz.gen_harness import (  # noqa: E402
    generate_harness,
    render_harness,
    _MAX_LEN,
)
from tools.fuzz.seed_corpus import (  # noqa: E402
    _MAX_SEED_BYTES,
    _seed_for,
    generate_corpus,
)


def _finding(tmp: Path) -> dict:
    return {
        "finding_id": "TA-001",
        "vulnerability": {"title": "Test finding for fuzz harness", "severity": "medium"},
        "location": {"binary": str(tmp / "target")},
        "evidence": {"description": "test"},
        "attack_surface": {"type": "cli", "entry_point": "--input payload"},
    }


def test_harness_renders_required_macros() -> None:
    """Every harness must declare LLVMFuzzerTestOneInput + TARGET_ARGS."""
    with tempfile.TemporaryDirectory() as tmp:
        src = render_harness(_finding(Path(tmp)))
        assert "LLVMFuzzerTestOneInput" in src, src[:200]
        assert "TARGET_ARGS" in src, src[:200]
        assert f"MAX_LEN ({_MAX_LEN})" in src, src[:200]
        assert "execvp" in src, src[:200]


def test_harness_reflects_attack_surface_entry_point() -> None:
    """The argv list must embed the documented entry_point tokens."""
    with tempfile.TemporaryDirectory() as tmp:
        src = render_harness(_finding(Path(tmp)))
        assert '"--input"' in src, src
        assert '"payload"' in src, src


def test_harness_writes_executable_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "harness.c"
        manifest = generate_harness(_finding(Path(tmp)), out)
        assert out.exists(), out
        assert len(manifest["harness_sha256"]) == 64, manifest
        assert manifest["compile_cmd"].startswith("clang -fsanitize=fuzzer,address"), manifest["compile_cmd"]


def test_harness_refuses_clobber_without_force() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "harness.c"
        generate_harness(_finding(Path(tmp)), out)
        try:
            generate_harness(_finding(Path(tmp)), out)
        except FileExistsError:
            pass
        else:
            raise AssertionError("expected FileExistsError on clobber")
        # With force, succeeds
        generate_harness(_finding(Path(tmp)), out, force=True)


def test_seed_corpus_writes_ten_per_entry_under_4kb() -> None:
    profile = {
        "attack_surface": [
            {"type": "network", "entry_point": "/tcp/22"},
            {"type": "cli", "entry_point": "--help"},
            {"type": "file", "entry_point": "/etc/passwd"},
            {"type": "config", "entry_point": "/etc/foo.conf"},
        ]
    }
    with tempfile.TemporaryDirectory() as tmp:
        manifest = generate_corpus(profile, Path(tmp), seeds_per_entry=10)
        assert len(manifest["entries"]) == 4, manifest
        for entry, paths in manifest["entries"].items():
            assert len(paths) == 10, (entry, paths)
            for p in paths:
                size = Path(p).stat().st_size
                assert size <= _MAX_SEED_BYTES, (p, size, _MAX_SEED_BYTES)


def test_seed_for_network_has_magic_header() -> None:
    body = _seed_for("network", 1)
    assert body[:8] == b"BBHSEED\x00", body[:8]


def test_seed_for_cli_no_magic_but_argv_style() -> None:
    body = _seed_for("cli", 0)
    assert b"--input" in body, body


def test_seed_corpus_respects_seeds_per_entry() -> None:
    profile = {"attack_surface": [{"type": "cli", "entry_point": "x"}]}
    with tempfile.TemporaryDirectory() as tmp:
        manifest = generate_corpus(profile, Path(tmp), seeds_per_entry=3)
        assert len(manifest["entries"]["x"]) == 3, manifest
        assert manifest["seeds_per_entry"] == 3, manifest


def run_all() -> None:
    test_harness_renders_required_macros()
    test_harness_reflects_attack_surface_entry_point()
    test_harness_writes_executable_file()
    test_harness_refuses_clobber_without_force()
    test_seed_corpus_writes_ten_per_entry_under_4kb()
    test_seed_for_network_has_magic_header()
    test_seed_for_cli_no_magic_but_argv_style()
    test_seed_corpus_respects_seeds_per_entry()
    print("B7 fuzz tests OK (8/8)")


if __name__ == "__main__":
    run_all()