#!/usr/bin/env python3
"""Tests for B8: sanitizer options + build_sanitized_binary."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.sandbox.build_sanitized_binary import (  # noqa: E402
    SANITIZER_EXIT_CODES,
    SUPPORTED_SANITIZERS,
    _resolve_source,
    build_sanitized,
)


def test_supported_sanitizers_match_contract() -> None:
    """The supported sanitizer enum is documented as 4 values."""
    assert SUPPORTED_SANITIZERS == ("asan", "ubsan", "msan", "none"), SUPPORTED_SANITIZERS


def test_exit_codes_per_contract() -> None:
    """Exit codes must match the values exported as ASAN/MSAN/UBSAN_OPTIONS."""
    assert SANITIZER_EXIT_CODES["asan"] == 42
    assert SANITIZER_EXIT_CODES["msan"] == 77
    assert SANITIZER_EXIT_CODES["ubsan"] == 1
    assert SANITIZER_EXIT_CODES["none"] == 0


def test_dockerfile_poc_includes_sanitizer_packages() -> None:
    """The Dockerfile must declare clang + libasan + libubsan (B8 contract)."""
    df = (ROOT / "sandbox" / "Dockerfile.poc").read_text(encoding="utf-8")
    for pkg in ("clang", "compiler-rt", "libasan", "libubsan"):
        assert pkg in df, f"missing sanitizer package in Dockerfile.poc: {pkg}"


def test_docker_compose_sets_asan_options() -> None:
    """docker-compose must export ASAN_OPTIONS with abort_on_error=1."""
    compose = (ROOT / "sandbox" / "docker-compose.sandbox.yml").read_text(encoding="utf-8")
    assert "ASAN_OPTIONS" in compose, compose
    assert "abort_on_error=1" in compose, compose
    assert "MSAN_OPTIONS" in compose, compose
    assert "UBSAN_OPTIONS" in compose, compose
    assert "SANITIZER" in compose, compose


def test_run_poc_forwards_sanitizer_env() -> None:
    """run_poc.sh must export SANITIZER + ASAN/MSAN/UBSAN_OPTIONS."""
    run_poc = (ROOT / "sandbox" / "run_poc.sh").read_text(encoding="utf-8")
    for token in ("SANITIZER", "ASAN_OPTIONS", "MSAN_OPTIONS", "UBSAN_OPTIONS", "exitcode=42", "exitcode=77"):
        assert token in run_poc, f"run_poc.sh missing token: {token}"


def test_resolve_source_finds_sibling_c() -> None:
    """A .c file sitting next to the binary must be discovered."""
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "foo"
        binary.touch()
        source = Path(tmp) / "foo.c"
        source.write_text("int main(){return 0;}\n", encoding="utf-8")
        resolved = _resolve_source(binary)
        assert resolved == source, resolved


def test_resolve_source_falls_back_to_cc_and_cpp() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "bar"
        binary.touch()
        source = Path(tmp) / "bar.cpp"
        source.write_text("int main(){return 0;}\n", encoding="utf-8")
        resolved = _resolve_source(binary)
        assert resolved == source, resolved


def test_resolve_source_returns_none_when_no_source() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "orphan"
        binary.touch()
        assert _resolve_source(binary) is None


def test_build_sanitized_skips_none() -> None:
    out = build_sanitized("/nonexistent", "none", "/tmp/nope")
    assert out["skipped"] == "no_rebuild", out


def test_build_sanitized_refuses_msan() -> None:
    out = build_sanitized("/nonexistent", "msan", "/tmp/nope")
    assert "msan" in out["skipped"], out


def test_build_sanitized_unsupported_kind() -> None:
    out = build_sanitized("/nonexistent", "cov", "/tmp/nope")  # type: ignore[arg-type]
    assert "unsupported" in out["skipped"], out


def test_build_sanitized_missing_clang() -> None:
    """When clang is not on PATH, manifest must say so (not raise)."""
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "foo"
        binary.touch()
        source = Path(tmp) / "foo.c"
        source.write_text("int main(){return 0;}\n", encoding="utf-8")
        # Force shutil.which to return None for clang
        original = shutil.which
        try:
            shutil.which = lambda name: None if name == "clang" else original(name)
            out = build_sanitized(binary, "asan", tmp)
        finally:
            shutil.which = original
        assert out["skipped"] == "missing_clang", out


def test_build_sanitized_no_source_found() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "orphan"
        binary.touch()
        out = build_sanitized(binary, "asan", tmp)
        assert out["skipped"] == "no_source_found", out


def test_build_sanitized_real_compile_with_clang() -> None:
    """End-to-end smoke: if clang is available, we actually rebuild."""
    if shutil.which("clang") is None:
        print("SKIP: clang not available for live rebuild")
        return
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "foo"
        binary.touch()
        source = Path(tmp) / "foo.c"
        source.write_text("int main(){return 0;}\n", encoding="utf-8")
        out = build_sanitized(binary, "asan", tmp)
        assert out["skipped"] is None, out
        assert Path(out["sanitized"]).exists(), out


def run_all() -> None:
    test_supported_sanitizers_match_contract()
    test_exit_codes_per_contract()
    test_dockerfile_poc_includes_sanitizer_packages()
    test_docker_compose_sets_asan_options()
    test_run_poc_forwards_sanitizer_env()
    test_resolve_source_finds_sibling_c()
    test_resolve_source_falls_back_to_cc_and_cpp()
    test_resolve_source_returns_none_when_no_source()
    test_build_sanitized_skips_none()
    test_build_sanitized_refuses_msan()
    test_build_sanitized_unsupported_kind()
    test_build_sanitized_missing_clang()
    test_build_sanitized_no_source_found()
    test_build_sanitized_real_compile_with_clang()
    print("B8 sanitizer tests OK (14/14)")


if __name__ == "__main__":
    run_all()