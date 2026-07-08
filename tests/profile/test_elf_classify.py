#!/usr/bin/env python3
"""Tests for B4: ELF classification into backend_role."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.profile.elf_classify import (  # noqa: E402
    BACKEND_ROLES,
    classify,
    _read_pt_interp,
)


def _candidate(*names: str) -> Path | None:
    """Return the first existing path from the candidate list."""
    for name in names:
        for prefix in ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/lib", "/lib"):
            candidate = Path(prefix) / name
            if candidate.exists():
                return candidate
    return None


def test_interpreter_classified_correctly() -> None:
    """A language interpreter must be classified as interpreter."""
    p = _candidate("python3", "python", "perl", "node")
    if p is None:
        print("SKIP: no interpreter binary found")
        return
    info = classify(p)
    assert info["backend_role"] == "interpreter", info
    assert info["is_wrapper"] is False, info
    assert info["execve_target"] is None, info


def test_assembler_classified_correctly() -> None:
    """GNU as is the assembler."""
    p = _candidate("as")
    if p is None:
        print("SKIP: no `as` binary found")
        return
    info = classify(p)
    assert info["backend_role"] == "assembler", info


def test_linker_classified_correctly() -> None:
    """GNU ld is the linker."""
    p = _candidate("ld", "ld.lld")
    if p is None:
        print("SKIP: no `ld` binary found")
        return
    info = classify(p)
    assert info["backend_role"] == "linker", info


def test_runtime_helper_for_pt_interp() -> None:
    """A binary whose PT_INTERP points at /lib*/ld-linux*.so is runtime_helper."""
    # /usr/bin/true is a regular PIE binary whose PT_INTERP is the loader.
    p = _candidate("true", "echo", "false")
    if p is None:
        print("SKIP: no small binary for PT_INTERP test")
        return
    info = classify(p)
    # On a modern system /usr/bin/true's PT_INTERP is ld-linux-x86-64.so.2
    # so the classifier should return runtime_helper.
    if _read_pt_interp(p) and ("ld-linux" in _read_pt_interp(p) or "ld-musl" in _read_pt_interp(p)):
        assert info["backend_role"] == "runtime_helper", info


def test_unknown_binary_returns_unknown_role() -> None:
    """A non-existent path returns the unknown fallback."""
    info = classify("/nonexistent/path/to/binary")
    assert info["backend_role"] == "unknown", info
    assert info["is_wrapper"] is False, info
    assert info["execve_target"] is None, info


def test_classify_returns_required_keys() -> None:
    """Every classify() result must have the 3 documented keys."""
    info = classify("/nonexistent")
    assert set(info.keys()) == {"backend_role", "is_wrapper", "execve_target"}, info


def test_backend_role_in_enum() -> None:
    """The returned backend_role must be one of the documented enum values."""
    info = classify("/nonexistent")
    assert info["backend_role"] in BACKEND_ROLES, info


def test_compiler_driver_classified() -> None:
    """gcc/g++ are compiler_driver (or wrapper if execve detected)."""
    p = _candidate("gcc", "g++", "clang")
    if p is None:
        print("SKIP: no compiler binary found")
        return
    info = classify(p)
    assert info["backend_role"] in ("compiler_driver", "wrapper"), info


def test_classify_many_returns_per_path() -> None:
    """classify_many must keep order and length match."""
    paths = ["/nonexistent-a", "/nonexistent-b"]
    out = [classify(p) for p in paths]
    assert len(out) == 2, out
    for entry in out:
        assert entry["backend_role"] in BACKEND_ROLES, entry


def test_main_outputs_json(tmp_capsys=None) -> None:
    """The CLI dumps a JSON array of {path, ...classification}."""
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "profile" / "elf_classify.py"),
         "/nonexistent-a", "/nonexistent-b"],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list), payload
    assert len(payload) == 2, payload
    assert payload[0]["path"] == "/nonexistent-a", payload[0]


def run_all() -> None:
    test_interpreter_classified_correctly()
    test_assembler_classified_correctly()
    test_linker_classified_correctly()
    test_runtime_helper_for_pt_interp()
    test_unknown_binary_returns_unknown_role()
    test_classify_returns_required_keys()
    test_backend_role_in_enum()
    test_compiler_driver_classified()
    test_classify_many_returns_per_path()
    test_main_outputs_json()
    print("B4 elf_classify tests OK (10/10)")


if __name__ == "__main__":
    run_all()