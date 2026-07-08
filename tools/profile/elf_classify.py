#!/usr/bin/env python3
"""B4: classify each ELF into a backend_role (wrapper vs frontend vs ...).

The plan documented 8 roles:
  - ``wrapper``             – pure dispatcher that execve()s another binary
  - ``compiler_driver``     – gcc/clang style (parse args, then exec cc1)
  - ``compiler_frontend``   – cc1, cc1plus (does the actual work)
  - ``assembler``           – as / gas
  - ``linker``              – ld / ld.lld / ld.gold
  - ``runtime_helper``      – ld.so, libgcc internals
  - ``language_runtime``    – libgomp, libgfortran, libgo, libjvm
  - ``interpreter``         – python3, lua, perl
  - ``unknown``             – heuristics gave up

Classification is heuristic but deterministic. We sample at most the first
``MAX_DISASM_BYTES`` bytes of disassembly output (default 64 KiB) and look
for:

1. ``execve`` / ``execvp`` / ``posix_spawn`` references in the disassembly
   (wrapper signal).
2. ``.interp`` PT_INTERP segment pointing at a libc loader (runtime_helper).
3. Binary name and known fingerprints:
   - ``cc1``, ``cc1plus``, ``cc1obj``, ``f951``       -> compiler_frontend
   - ``as``, ``gas``                                   -> assembler
   - ``ld``, ``ld.lld``, ``ld.gold``, ``ld.bfd``       -> linker
   - ``ld-linux*``, ``ld-musl*``                       -> runtime_helper
   - ``python``, ``perl``, ``lua``, ``node``           -> interpreter
   - ``gcc``, ``g++``, ``clang``, ``clang++``         -> compiler_driver
4. ``is_wrapper = True`` whenever ``execve_target`` is non-null.

The classifier never executes the target; it only inspects file headers
and a bounded slice of disassembly. If objdump is unavailable, the
classifier falls back to name-only heuristics.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_DISASM_BYTES = 64 * 1024  # 64 KiB; enough to surface execve references


# Backend role enum (mirrors templates/target_profile.json#binaries[].backend_role)
BACKEND_ROLES = (
    "wrapper",
    "compiler_driver",
    "compiler_frontend",
    "assembler",
    "linker",
    "runtime_helper",
    "language_runtime",
    "interpreter",
    "unknown",
)

# Exec syscall facades that signal wrapper behavior.
_EXEC_FACADES = ("execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp")
_EXEC_RE = re.compile(r"\b(" + "|".join(_EXEC_FACADES) + r")\b")

# Filename fingerprints (case-insensitive). Order matters: more specific
# first (cc1* before generic compiler_driver).
_FILENAME_RULES: list[tuple[str, str]] = [
    (r"^cc1(plus|obj|objplus|f95)?$", "compiler_frontend"),
    (r"^f951$", "compiler_frontend"),
    (r"^ld[\.\-](lld|gold|bfd|mold)$", "linker"),
    (r"^ld$", "linker"),
    (r"^ld-(linux|musl|freebsd).*", "runtime_helper"),
    (r"^as$|^as-[0-9].*$", "assembler"),
    (r"^(gcc|g\+\+|c\+\+|gcc-[0-9].*|g\+\+-[0-9].*)$", "compiler_driver"),
    (r"^clang(\+\+)?(-[0-9].*)?$", "compiler_driver"),
    (r"^(python[0-9.]*|perl|lua|node|nodejs|ruby|tclsh|wish)$", "interpreter"),
    # runtime libraries
    (r"^(libgomp|libgfortran|libgo|libjvm|libpython|libperl|libtcl)\.so", "language_runtime"),
]


def _read_pt_interp(path: Path) -> str | None:
    """Parse the ELF header and return the PT_INTERP path (or None).

    This is a defensive parser: if anything goes wrong we return None so the
    caller can fall back to name-only heuristics.
    """
    try:
        with path.open("rb") as fh:
            ident = fh.read(16)
            if ident[:4] != b"\x7fELF":
                return None
            ei_class = ident[4]  # 1=32-bit, 2=64-bit
            ei_data = ident[5]  # 1=little, 2=big
            if ei_data == 2:
                endian = ">"
            else:
                endian = "<"
            fmt_elf = ">" if ei_data == 2 else "<"
            if ei_class == 2:
                # 64-bit
                fmt = fmt_elf + "16s HHI QQQ I HHHHH H"
            elif ei_class == 1:
                fmt = fmt_elf + "16s HHII III HHHHH H"
            else:
                return None
            hdr = struct.unpack(fmt, fh.read(struct.calcsize(fmt)))
            # phoff is at offset 32 in 64-bit, 28 in 32-bit
            phoff = hdr[5] if ei_class == 2 else hdr[4]
            phentsize = hdr[9] if ei_class == 2 else hdr[8]
            phnum = hdr[10] if ei_class == 2 else hdr[9]
            if ei_class == 2:
                ph_fmt = fmt_elf + "IIQQQQQQ"
            else:
                ph_fmt = fmt_elf + "IIIIIIII"
            ph_size = struct.calcsize(ph_fmt)
            fh.seek(phoff)
            for i in range(phnum):
                ph = struct.unpack(ph_fmt, fh.read(ph_size))
                p_type = ph[0]
                PT_INTERP = 3
                if p_type == PT_INTERP:
                    p_offset = ph[1] if ei_class == 2 else ph[1]
                    fh.seek(p_offset)
                    # Read null-terminated string up to ~256 bytes
                    buf = b""
                    while len(buf) < 256:
                        ch = fh.read(1)
                        if ch in (b"\x00", b""):
                            break
                        buf += ch
                    return buf.decode("utf-8", errors="replace") or None
    except (OSError, struct.error):
        return None
    return None


def _maybe_disasm(path: Path, objdump: str | None) -> tuple[str | None, int]:
    """Return (first MAX_DISASM_BYTES of disassembly, or None on failure)."""
    if objdump is None:
        return None, 0
    try:
        proc = subprocess.run(
            [objdump, "-d", "--no-show-raw-insn", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, 0
    text = proc.stdout[:MAX_DISASM_BYTES]
    return text, len(proc.stdout)


def _guess_execve_target(disasm: str | None, name: str) -> str | None:
    """Try to infer what the wrapper execve()s.

    Heuristics:
    - Stripped path prefix from a ``mov $..."/foo", %rdi`` pattern.
    - Common compiler-driver names: ``gcc`` -> ``cc1``, ``g++`` -> ``cc1plus``,
      ``clang`` -> ``clang -cc1``.
    """
    if disasm:
        # Look for a string literal that looks like a binary path.
        for match in re.finditer(r'"(/[\w./-]+)"', disasm):
            candidate = match.group(1)
            if any(tok in candidate for tok in ("cc1", "as", "ld", "clang")):
                return Path(candidate).name
    # Name-driven fallback: gcc → cc1, g++ → cc1plus, clang → clang.
    name_lower = name.lower()
    if name_lower in ("gcc", "gcc-12", "gcc-13"):
        return "cc1"
    if name_lower in ("g++", "g++-12", "g++-13"):
        return "cc1plus"
    if name_lower in ("clang", "clang-15", "clang-16"):
        return "clang"
    return None


def _classify_by_name(name: str) -> str | None:
    name_lower = name.lower()
    for pattern, role in _FILENAME_RULES:
        if re.match(pattern, name_lower):
            return role
    return None


def classify(path: str | Path) -> dict[str, Any]:
    """Classify an ELF binary.

    Returns ``{"backend_role", "is_wrapper", "execve_target"}``. Always
    non-null; the fallback is ``{"backend_role": "unknown", "is_wrapper": False, "execve_target": None}``.
    """
    p = Path(path)
    name = p.name
    if not p.exists():
        return {"backend_role": "unknown", "is_wrapper": False, "execve_target": None}

    # Step 1: PT_INTERP -> runtime_helper
    interp = _read_pt_interp(p)
    if interp and ("ld-linux" in interp or "ld-musl" in interp):
        return {"backend_role": "runtime_helper", "is_wrapper": False, "execve_target": None}

    # Step 2: name fingerprint
    name_role = _classify_by_name(name)
    if name_role:
        # Compiler drivers and wrappers are special-cased below.
        if name_role in ("compiler_driver", "assembler", "linker", "compiler_frontend",
                          "interpreter", "language_runtime"):
            return {"backend_role": name_role, "is_wrapper": False, "execve_target": None}

    # Step 3: disassembly-based wrapper detection
    objdump = shutil.which("objdump") or shutil.which("llvm-objdump")
    disasm, _ = _maybe_disasm(p, objdump)
    if disasm is not None:
        exec_refs = _EXEC_RE.findall(disasm)
        if exec_refs:
            execve_target = _guess_execve_target(disasm, name)
            # If the name fingerprint already pinned the role, keep it.
            role = name_role or "wrapper"
            return {"backend_role": role, "is_wrapper": True, "execve_target": execve_target}

    # Step 4: bare name fallback
    if name_role:
        return {"backend_role": name_role, "is_wrapper": False, "execve_target": None}
    return {"backend_role": "unknown", "is_wrapper": False, "execve_target": None}


def classify_many(paths: list[str | Path]) -> list[dict[str, Any]]:
    return [classify(p) for p in paths]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Classify ELF binaries into backend roles")
    p.add_argument("path", nargs="+", help="One or more ELF binaries")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out = [{"path": str(Path(p)), **classify(p)} for p in args.path]
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())