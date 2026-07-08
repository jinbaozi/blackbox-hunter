#!/usr/bin/env python3
"""B8: rebuild a target binary with clang sanitizers when needed.

The PoC sandbox exposes ``SANITIZER=asan|msan|ubsan|none``. When the
host Phase 3 cannot find a pre-instrumented binary for the target, this
helper:

1. Finds a matching C/C++ source file for the binary (heuristic: a
   sibling ``<name>.c`` / ``<name>.cc`` / ``<name>.cpp``).
2. Re-compiles it with ``clang -fsanitize=<sanitizer>``.
3. Writes the new binary to ``<output-dir>/<name>.<sanitizer>``.
4. Returns a manifest mapping ``original_path -> sanitized_path`` so
   the orchestrator can swap binaries before Phase 3 launches.

MSan is intentionally refused: it requires an MSan-instrumented libc
which the imported rootfs cannot provide. The function returns
``{"skipped": "msan_unsupported"}`` for MSan rather than crashing.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SUPPORTED_SANITIZERS = ("asan", "ubsan", "msan", "none")

# Mapping from sanitizer -> clang -fsanitize= flag value
_SANITIZER_FLAG = {
    "asan": "address",
    "ubsan": "undefined",
    "msan": "memory",
    "none": "",
}

# Conventional exit codes per B8 contract (also exported as ASAN_OPTIONS etc)
SANITIZER_EXIT_CODES = {
    "asan": 42,
    "ubsan": 1,
    "msan": 77,
    "none": 0,
}


def _resolve_source(target_binary: Path) -> Path | None:
    """Best-effort: find a sibling source file matching the binary name."""
    candidates = [
        target_binary.with_suffix(".c"),
        target_binary.parent / f"{target_binary.name}.c",
        target_binary.parent / f"{target_binary.name}.cc",
        target_binary.parent / f"{target_binary.name}.cpp",
        target_binary.parent / "src" / f"{target_binary.name}.c",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def build_sanitized(
    target_binary: str | Path,
    sanitizer: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Re-compile ``target_binary``'s source with the given sanitizer.

    Returns a manifest dict::

        {
          "sanitizer": "asan",
          "original": "/path/to/binary",
          "sanitized": "/path/to/output/binary.asan",
          "source": "/path/to/binary.c",
          "skipped": null
        }

    On failure: ``{"sanitizer": sanitizer, "skipped": "<reason>", ...}``.
    """
    if sanitizer not in SUPPORTED_SANITIZERS:
        return {"sanitizer": sanitizer, "skipped": f"unsupported:{sanitizer}"}
    if sanitizer == "none":
        return {"sanitizer": "none", "skipped": "no_rebuild"}
    if sanitizer == "msan":
        return {"sanitizer": "msan", "skipped": "msan_requires_msan_libc"}

    clang = shutil.which("clang")
    if clang is None:
        return {"sanitizer": sanitizer, "skipped": "missing_clang"}

    src = _resolve_source(Path(target_binary))
    if src is None:
        return {
            "sanitizer": sanitizer,
            "skipped": "no_source_found",
            "original": str(target_binary),
        }

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sanitized_path = out_dir / f"{Path(target_binary).name}.{sanitizer}"

    flag = _SANITIZER_FLAG[sanitizer]
    cmd = [clang, f"-fsanitize={flag}", "-g", "-O1", str(src), "-o", str(sanitized_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "sanitizer": sanitizer,
            "skipped": f"compile_failed:{exc.__class__.__name__}",
            "source": str(src),
        }
    if proc.returncode != 0:
        return {
            "sanitizer": sanitizer,
            "skipped": f"compile_failed:rc={proc.returncode}",
            "source": str(src),
            "stderr": proc.stderr[-500:],
        }
    return {
        "sanitizer": sanitizer,
        "original": str(target_binary),
        "sanitized": str(sanitized_path),
        "source": str(src),
        "skipped": None,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B8 sanitizer rebuild helper")
    p.add_argument("--target", required=True, help="Path to the target binary")
    p.add_argument("--sanitizer", default="asan", choices=SUPPORTED_SANITIZERS)
    p.add_argument("--output-dir", required=True, help="Where to write the rebuilt binary")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    manifest = build_sanitized(args.target, args.sanitizer, args.output_dir)
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())