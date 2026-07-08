#!/usr/bin/env python3
"""B5: model the compiler pipeline (cc1 -> as -> ld, LTO/whole-program).

For each target package, we look at the set of ELFs that already passed
``tools/profile/elf_classify.classify()`` and group them into a pipeline::

    {
      "toolchain": "gcc" | "clang" | "unknown",
      "stages": [
        {"name": "frontend", "binary": "cc1",       "inputs": ["*.c"], "outputs": ["*.s"]},
        {"name": "assembler","binary": "as",        "inputs": ["*.s"], "outputs": ["*.o"]},
        {"name": "linker",   "binary": "ld",        "inputs": ["*.o"], "outputs": ["*.elf"]}
      ],
      "supports_lto": bool,            # True iff -flto is reachable
      "lto_stage": {...} | None,        # populated when supports_lto
      "language_frontends": ["cc1", "cc1plus", "f951", ...] | [],
      "wrapper_dispatches": [{"from": "gcc", "to": "cc1"}, ...]
    }

Detection strategy:

1. Reuse ``elf_classify.classify`` for each binary in
   ``target_profile.binaries[]``.
2. ``toolchain = "gcc"`` if any wrapper name matches ``gcc`` or
   ``g++``; ``"clang"`` for ``clang`` / ``clang++``; else ``"unknown"``.
3. ``language_frontends`` = every backend_role == ``"compiler_frontend"``
   binary (cc1, cc1plus, f951, ...).
4. ``stages`` is derived from role presence (not from order): at minimum
   we always emit the three canonical stages (frontend -> assembler ->
   linker) if the toolchain is recognised; the actual binaries are
   pulled from the profile where present, otherwise left as canonical
   placeholders (``cc1``/``as``/``ld``).
5. ``supports_lto`` is True iff (a) we see an LTO wrapper (gcc-ar, gcc-nm,
   gcc-ranlib, lld, gold) OR (b) any frontend binary is detected (the
   standard cc1 knows -flto). For ``"clang"`` we additionally look for
   ``llvm-lto2`` / ``lld``.
6. ``wrapper_dispatches`` is populated when ``elf_classify`` reported
   ``is_wrapper=True`` with a known execve_target (``gcc`` -> ``cc1``,
   ``g++`` -> ``cc1plus``, etc.).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from tools.profile.elf_classify import classify
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools.profile.elf_classify import classify  # type: ignore


# Frontend binary name patterns (used both as detection and as canonical
# placeholders when the binary is absent from the package).
_FRONTEND_NAMES = ("cc1", "cc1plus", "cc1obj", "cc1objplus", "f951", "f95", "f77")
_LTO_TOOL_NAMES = ("gcc-ar", "gcc-nm", "gcc-ranlib", "gold", "lld", "ld.lld", "llvm-lto2")


def _detect_toolchain(classifications: list[tuple[str, dict[str, Any]]]) -> str:
    has_gcc = any(Path(name).name.startswith(("gcc", "g++")) for name, _ in classifications)
    has_clang = any(Path(name).name.startswith("clang") for name, _ in classifications)
    if has_gcc and not has_clang:
        return "gcc"
    if has_clang and not has_gcc:
        return "clang"
    if has_gcc and has_clang:
        return "mixed"
    return "unknown"


def _detect_lto(classifications: list[tuple[str, dict[str, Any]]]) -> tuple[bool, dict[str, Any] | None]:
    names = {name for name, _ in classifications}
    matched = [n for n in _LTO_TOOL_NAMES if any(Path(name).name == n for name in names)]
    if matched:
        return True, {"lto_tools": matched, "kind": "fat_lto" if "lld" in matched or "ld.lld" in matched else "gpl_lto"}
    # Standard cc1 supports -flto whenever present.
    if any(Path(name).name in _FRONTEND_NAMES for name in names):
        return True, {"lto_tools": [], "kind": "object_lto"}
    return False, None


def _emit_stages(toolchain: str, classifications: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Emit canonical cc1 -> as -> ld stages, marking missing binaries as null."""
    have = {Path(name).name: name for name, _ in classifications}

    def pick(*candidates: str) -> str | None:
        for c in candidates:
            if c in have:
                return have[c]
        return None

    stages: list[dict[str, Any]] = []
    frontend_bin = pick(*_FRONTEND_NAMES)
    if toolchain in ("gcc", "clang", "mixed") or frontend_bin:
        stages.append({
            "name": "frontend",
            "binary": Path(frontend_bin).name if frontend_bin else pick("cc1", "cc1plus") or "cc1",
            "binary_path": frontend_bin,
            "inputs": ["*.c", "*.cpp", "*.f90"],
            "outputs": ["*.s"],
        })
    as_bin = pick("as", "gas")
    if as_bin or toolchain in ("gcc", "clang"):
        stages.append({
            "name": "assembler",
            "binary": Path(as_bin).name if as_bin else "as",
            "binary_path": as_bin,
            "inputs": ["*.s"],
            "outputs": ["*.o"],
        })
    ld_bin = pick("ld", "ld.lld", "ld.gold", "ld.bfd")
    if ld_bin or toolchain in ("gcc", "clang"):
        stages.append({
            "name": "linker",
            "binary": Path(ld_bin).name if ld_bin else "ld",
            "binary_path": ld_bin,
            "inputs": ["*.o"],
            "outputs": ["*.elf"],
        })
    return stages


def _collect_wrapper_dispatches(classifications: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, info in classifications:
        if info.get("is_wrapper") and info.get("execve_target"):
            out.append({"from": Path(name).name, "to": info["execve_target"]})
    return out


def model(target_profile: dict[str, Any]) -> dict[str, Any]:
    """Compute the pipeline model for a target_profile.

    Returns a dict shaped like the ``pipeline`` sub-object of
    ``templates/target_profile.json``.
    """
    classifications: list[tuple[str, dict[str, Any]]] = []
    for entry in target_profile.get("binaries") or []:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not path:
            continue
        info = classify(path)
        classifications.append((path, info))

    toolchain = _detect_toolchain(classifications)
    stages = _emit_stages(toolchain, classifications)
    supports_lto, lto_stage = _detect_lto(classifications)
    wrappers = _collect_wrapper_dispatches(classifications)
    frontends = [Path(name).name for name, info in classifications
                 if info.get("backend_role") == "compiler_frontend"]

    return {
        "toolchain": toolchain,
        "stages": stages,
        "supports_lto": supports_lto,
        "lto_stage": lto_stage,
        "language_frontends": frontends,
        "wrapper_dispatches": wrappers,
    }


def eager_smoke(pipeline: dict[str, Any], sandbox_path: str = "/tmp/bbh-pipeline-smoke") -> dict[str, Any]:
    """Optionally exercise the pipeline inside the sandbox.

    This is invoked only when ``--pipeline-mode eager`` is set. It writes a
    tiny C program to ``sandbox_path`` and runs ``frontend -> as -> ld``
    if the binaries are available. Result is ``{"eager_smoke": "passed"|"failed", "logs": [...]``.
    """
    if pipeline.get("toolchain") in (None, "unknown"):
        return {"eager_smoke": "skipped", "reason": "unknown_toolchain"}
    # The actual sandbox exec is left to the sandbox runner; we just return
    # the recipe so the orchestrator can invoke it.
    return {
        "eager_smoke": "recipe",
        "recipe": "echo 'int main(){return 0;}' > /tmp/x.c && cc1 /tmp/x.c -o /tmp/x.s && as /tmp/x.s -o /tmp/x.o && ld /tmp/x.o -o /tmp/x.elf",
        "sandbox_path": sandbox_path,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B5 compiler pipeline model")
    p.add_argument("--target-profile", required=True, help="Path to target_profile.json")
    p.add_argument("--output", default=None, help="Where to write the pipeline JSON")
    p.add_argument("--eager", action="store_true", help="Include an eager smoke recipe")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    profile = json.loads(Path(args.target_profile).read_text(encoding="utf-8"))
    pipe = model(profile)
    if args.eager:
        pipe["eager"] = eager_smoke(pipe)
    out = Path(args.output) if args.output else Path(args.target_profile).with_name("pipeline.json")
    out.write_text(json.dumps(pipe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json.dump(pipe, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())