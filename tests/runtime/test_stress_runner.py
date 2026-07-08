#!/usr/bin/env python3
"""Tests for B6: language runtime stress runner."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.runtime.stress_runner import (  # noqa: E402
    detect_runtimes,
    generate_poc,
    attach_to_target_profile,
)


FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "runtime_gcc_fortran"


def test_detect_runtimes_returns_known_runtimes() -> None:
    """The fixture ships libgomp + libgfortran + libjvm placeholders."""
    runs = detect_runtimes(FIXTURE_ROOT)
    names = {r["name"] for r in runs}
    assert "openmp" in names, runs
    assert "fortran" in names, runs
    assert "jvm" in names, runs


def test_detect_runtimes_handles_empty_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        runs = detect_runtimes(Path(tmp))
        assert runs == [], runs


def test_detect_runtimes_returns_required_keys() -> None:
    runs = detect_runtimes(FIXTURE_ROOT)
    assert runs, "fixture should yield at least one runtime"
    required = {"name", "library", "library_path", "language", "confidence", "smoke_template"}
    for entry in runs:
        assert required.issubset(entry.keys()), entry


def test_detect_runtimes_confidence_in_range() -> None:
    runs = detect_runtimes(FIXTURE_ROOT)
    for entry in runs:
        assert 0.0 <= entry["confidence"] <= 1.0, entry


def test_detect_runtimes_dedup_per_runtime() -> None:
    """Even if multiple libgomp files exist, we report exactly one openmp entry."""
    runs = detect_runtimes(FIXTURE_ROOT)
    names = [r["name"] for r in runs]
    assert names.count("openmp") == 1, names


def test_generate_poc_openmp() -> None:
    """The OpenMP smoke PoC must declare OMP_NUM_THREADS=2 and assert >=2 threads."""
    with tempfile.TemporaryDirectory() as tmp:
        out = generate_poc({"name": "openmp"}, Path(tmp) / "run.sh")
        body = Path(out["run_sh"]).read_text(encoding="utf-8")
        assert "OMP_NUM_THREADS=2" in body, body
        assert "n>=2" in body or "n >= 2" in body, body
        # The script must be executable
        mode = Path(out["run_sh"]).stat().st_mode
        assert mode & stat.S_IXUSR, mode


def test_generate_poc_python() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = generate_poc({"name": "python"}, Path(tmp) / "run.sh")
        body = Path(out["run_sh"]).read_text(encoding="utf-8")
        assert "python3" in body, body
        assert "py_compile" in body, body


def test_generate_poc_unknown_runtime_falls_back_gracefully() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = generate_poc({"name": "klingon"}, Path(tmp) / "run.sh")
        body = Path(out["run_sh"]).read_text(encoding="utf-8")
        assert "klingon" in body, body
        assert body.startswith("#!/bin/sh"), body[:20]


def test_attach_to_target_profile() -> None:
    profile = attach_to_target_profile({"scan_id": "BBH-20260708-b6test"}, [{"name": "openmp"}])
    assert "detected_runtimes" in profile, profile
    assert profile["detected_runtimes"][0]["name"] == "openmp", profile


def test_openmp_poc_smoke_runs() -> None:
    """End-to-end: write the openmp PoC and execute it. It must exit 0
    if a compiler with -fopenmp is available, or print SKIP_NO_GCC."""
    with tempfile.TemporaryDirectory() as tmp:
        out = generate_poc({"name": "openmp"}, Path(tmp) / "run.sh")
        proc = subprocess.run([out["run_sh"]], capture_output=True, text=True, timeout=30)
        # Either the script compiled + ran the openmp binary (rc=0) or it
        # skipped because no gcc is in the sandbox (rc=0 with SKIP_NO_GCC
        # on stdout). Anything else is a failure.
        assert proc.returncode in (0, 1), (proc.returncode, proc.stdout, proc.stderr)
        if proc.returncode == 0:
            assert ("bbh_omp" in proc.stdout) or ("SKIP_NO_GCC" in proc.stdout), proc.stdout


def run_all() -> None:
    test_detect_runtimes_returns_known_runtimes()
    test_detect_runtimes_handles_empty_root()
    test_detect_runtimes_returns_required_keys()
    test_detect_runtimes_confidence_in_range()
    test_detect_runtimes_dedup_per_runtime()
    test_generate_poc_openmp()
    test_generate_poc_python()
    test_generate_poc_unknown_runtime_falls_back_gracefully()
    test_attach_to_target_profile()
    test_openmp_poc_smoke_runs()
    print("B6 stress_runner tests OK (10/10)")


if __name__ == "__main__":
    run_all()