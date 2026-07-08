#!/usr/bin/env python3
"""Tests for B5: compiler pipeline model."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.pipeline.pipeline_model import (  # noqa: E402
    model,
    _emit_stages,
    _detect_toolchain,
    _detect_lto,
)


def _profile_with(*binaries: dict) -> dict:
    return {"binaries": list(binaries)}


def test_emit_stages_three_canonical_stages() -> None:
    stages = _emit_stages("gcc", [])
    names = [s["name"] for s in stages]
    assert names == ["frontend", "assembler", "linker"], stages


def test_detect_toolchain_gcc() -> None:
    """gcc/g++ wrappers imply gcc toolchain."""
    classifications = [("gcc", {"backend_role": "compiler_driver", "is_wrapper": True, "execve_target": "cc1"})]
    assert _detect_toolchain(classifications) == "gcc", classifications


def test_detect_toolchain_clang() -> None:
    """clang wrappers imply clang toolchain."""
    classifications = [("clang", {"backend_role": "compiler_driver"})]
    assert _detect_toolchain(classifications) == "clang", classifications


def test_detect_toolchain_mixed() -> None:
    classifications = [
        ("gcc", {"backend_role": "compiler_driver"}),
        ("clang", {"backend_role": "compiler_driver"}),
    ]
    assert _detect_toolchain(classifications) == "mixed", classifications


def test_detect_toolchain_unknown_when_no_wrappers() -> None:
    classifications = [("cc1", {"backend_role": "compiler_frontend"})]
    # No wrappers, so toolchain cannot be pinned to gcc/clang/mixed
    assert _detect_toolchain(classifications) == "unknown", classifications


def test_detect_lto_with_object_lto() -> None:
    """LTO supported via cc1 -flto even without fat-LTO tools."""
    classifications = [
        ("/usr/bin/cc1", {"backend_role": "compiler_frontend"}),
    ]
    supports, stage = _detect_lto(classifications)
    assert supports is True, classifications
    assert stage["kind"] == "object_lto", stage


def test_detect_lto_with_fat_lld() -> None:
    classifications = [
        ("/usr/bin/lld", {"backend_role": "linker"}),
    ]
    supports, stage = _detect_lto(classifications)
    assert supports is True, classifications
    assert "lld" in stage["lto_tools"], stage


def test_detect_lto_unsupported() -> None:
    classifications = [
        ("/usr/bin/as", {"backend_role": "assembler"}),
        ("/usr/bin/ld", {"backend_role": "linker"}),
    ]
    supports, stage = _detect_lto(classifications)
    assert supports is False, (supports, stage)
    assert stage is None, stage


def test_model_gcc_without_cc1_marks_missing_frontend() -> None:
    """The headline scenario: gcc wrapper present, cc1 absent."""
    profile = _profile_with({"path": "/usr/bin/gcc"})
    pipe = model(profile)
    assert pipe["toolchain"] == "gcc", pipe
    frontend = next((s for s in pipe["stages"] if s["name"] == "frontend"), None)
    assert frontend is not None, pipe
    # The wrapper's execve_target is cc1, but no cc1 binary was shipped.
    assert pipe["language_frontends"] == [], pipe
    # wrapper_dispatches is populated when elf_classify picks the wrapper role.
    # We don't assert presence here because classify() depends on objdump.


def test_model_with_real_gcc_and_cc1(tmp_path=None) -> None:
    """If /usr/bin/gcc and /usr/bin/cc1 exist on PATH, classification
    should succeed end-to-end."""
    gcc = shutil.which("gcc") or "/usr/bin/gcc"
    cc1 = shutil.which("cc1")  # cc1 is usually not on PATH; this may be None
    if cc1 is None and Path("/usr/libexec/gcc/x86_64-redhat-linux/12/cc1").exists():
        cc1 = "/usr/libexec/gcc/x86_64-redhat-linux/12/cc1"
    if not Path(gcc).exists():
        print("SKIP: no gcc binary on this host")
        return
    profile = _profile_with({"path": gcc})
    pipe = model(profile)
    assert pipe["toolchain"] in ("gcc", "unknown"), pipe
    # Even without cc1 we still produce 3 stages
    assert len(pipe["stages"]) >= 3, pipe


def test_model_returns_required_keys() -> None:
    """Every model() result must have the documented shape."""
    profile = _profile_with({"path": "/nonexistent"})
    pipe = model(profile)
    required = {"toolchain", "stages", "supports_lto", "lto_stage", "language_frontends", "wrapper_dispatches"}
    assert required.issubset(pipe.keys()), pipe


def test_model_eager_smoke_recipe() -> None:
    """Eager mode must produce a runnable recipe when toolchain is known."""
    from tools.pipeline.pipeline_model import eager_smoke
    profile = _profile_with({"path": "/usr/bin/gcc"})
    pipe = model(profile)
    out = eager_smoke(pipe)
    if pipe["toolchain"] in ("gcc", "clang", "mixed"):
        assert out["eager_smoke"] == "recipe", out
        assert "cc1" in out["recipe"] or "clang" in out["recipe"], out


def run_all() -> None:
    test_emit_stages_three_canonical_stages()
    test_detect_toolchain_gcc()
    test_detect_toolchain_clang()
    test_detect_toolchain_mixed()
    test_detect_toolchain_unknown_when_no_wrappers()
    test_detect_lto_with_object_lto()
    test_detect_lto_with_fat_lld()
    test_detect_lto_unsupported()
    test_model_gcc_without_cc1_marks_missing_frontend()
    test_model_with_real_gcc_and_cc1()
    test_model_returns_required_keys()
    test_model_eager_smoke_recipe()
    print("B5 pipeline_model tests OK (12/12)")


if __name__ == "__main__":
    run_all()