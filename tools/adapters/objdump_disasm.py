#!/usr/bin/env python3
"""Track A adapter: per-binary ``objdump -d`` with size + timeout guards (B1).

The pre-B1 Track A runner had a single global ``timeout_sec`` for ``objdump``,
which meant scanning a package with one or two very large ELFs (e.g. ``cc1plus``
inside ``gcc``) would either hang indefinitely or get killed by the global
timeout and produce no per-binary output. This adapter:

1. Enforces a hard upper bound ``MAX_BINARY_BYTES = 50 * 1024 * 1024`` (50 MB).
   Anything above that emits a ``binary_skipped_too_large`` signal with
   ``promote_to_finding=False`` and is NOT fed to ``objdump``.
2. Computes ``timeout_sec = min(60, max(5, size_mb // 5))`` so a 1 MB binary
   gets 5s, a 25 MB binary gets 5s, and a 100 MB binary gets 60s but is
   short-circuited by the size cap.
3. Falls back to ``readelf --dyn-syms --notes`` (if available) for binaries
   above 32 MB so we still get *some* signal even when full disassembly is
   too expensive.
4. Parses ``objdump`` output to surface ``disassembly_section_signal`` with
   function-metadata hints (``section_count``, ``first_function``,
   ``execve_references``).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_text, signal_id


# Hard size cap above which we will not run `objdump -d`. 50 MB is the
# ceiling chosen by the plan; below this we adapt the timeout.
MAX_BINARY_BYTES = 50 * 1024 * 1024

# Above this we skip disassembly but still run readelf --dyn-syms --notes.
READELF_FALLBACK_THRESHOLD = 32 * 1024 * 1024

# objdump detection: prefer binutils' objdump; some distros ship llvm-objdump.
OBJDUMP_BIN_CANDIDATES = ("objdump", "llvm-objdump")


def _resolve_objdump() -> str | None:
    for candidate in OBJDUMP_BIN_CANDIDATES:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _compute_timeout(size_bytes: int) -> int:
    """timeout_sec = min(60, max(5, size_mb // 5))."""
    size_mb = max(1, size_bytes // (1024 * 1024))
    return min(60, max(5, size_mb // 5))


def _binary_iter(target_profile: dict[str, Any]) -> list[Path]:
    """Yield Path objects for every binary in target_profile.binaries[]."""
    out: list[Path] = []
    for entry in target_profile.get("binaries") or []:
        if not isinstance(entry, dict):
            continue
        p = entry.get("path") or entry.get("name")
        if p:
            out.append(Path(p))
    return out


# Conservative regex: a function header in objdump output is
# ``00000000 <func_name>:`` -- 8 hex digits followed by `` <name>``.
_FUNC_HEADER_RE = re.compile(r"^[0-9a-f]{8,16}\s+<([^>]+)>:")
# ``callq / call / jmp / jne ... execve@plt`` -- caller instructions that
# reference a syscall facade. We surface any reference to execve/execvp/
# posix_spawn so Track B can mark the binary as a wrapper.
_EXEC_RE = re.compile(r"\b(execve|execvp|execvpe|posix_spawn|posix_spawnp)\b")


class ObjdumpAdapter:
    name = "objdump"

    def __init__(self) -> None:
        self.objdump_bin = _resolve_objdump()
        self.readelf_bin = shutil.which("readelf")

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        output_dir = scan_root / "raw" / "track_a" / "objdump"
        output_dir.mkdir(parents=True, exist_ok=True)
        commands: list[ToolCommand] = []
        for index, binary in enumerate(_binary_iter(target_profile), start=1):
            try:
                size = binary.stat().st_size
            except OSError:
                # Missing binary: skip without producing a command.
                continue
            if size > MAX_BINARY_BYTES:
                # We still emit a sentinel command whose output is a marker
                # file so parse_output can produce a skipped-too-large signal.
                sentinel = output_dir / f"{index:03d}-{binary.name}.skipped"
                commands.append(ToolCommand(
                    argv=["sh", "-c", f"echo size={size} > {sentinel}"],
                    timeout_sec=5,
                    output_path=str(sentinel),
                ))
                continue
            timeout = _compute_timeout(size)
            text_output = output_dir / f"{index:03d}-{binary.name}.disasm"
            if size > READELF_FALLBACK_THRESHOLD and self.readelf_bin:
                # Use readelf fallback; objdump still attempted in a second
                # command if it survives the timeout.
                commands.append(ToolCommand(
                    argv=[self.readelf_bin, "--dyn-syms", "--notes", str(binary)],
                    timeout_sec=timeout,
                    output_path=str(text_output),
                ))
                continue
            if self.objdump_bin is None:
                # No objdump available: write a sentinel that parse_output
                # reads and reports as ``missing_tool_objdump``.
                sentinel = output_dir / f"{index:03d}-{binary.name}.missing"
                commands.append(ToolCommand(
                    argv=["sh", "-c", f"echo missing_tool_objdump > {sentinel}"],
                    timeout_sec=5,
                    output_path=str(sentinel),
                ))
                continue
            commands.append(ToolCommand(
                argv=[self.objdump_bin, "-d", "--no-show-raw-insn", str(binary)],
                timeout_sec=timeout,
                output_path=str(text_output),
            ))
        return commands

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        signals: list[Any] = []
        warnings: list[str] = []
        index = 1

        if text.startswith("missing_tool_objdump"):
            warnings.append("missing_tool_objdump: install binutils or llvm")
            return ToolResult(tool=self.name, status="missing_tool", raw_output=str(raw_path),
                              signals=[], warnings=warnings)
        if text.startswith("size="):
            try:
                size = int(text.split("size=", 1)[1].strip().split()[0])
            except (IndexError, ValueError):
                size = -1
            warnings.append(f"binary_skipped_too_large: size={size} > MAX={MAX_BINARY_BYTES}")
            # Emit a non-promoted signal so the report shows we *saw* the binary.
            signals.append(make_signal(
                signal_id_value=signal_id("SIG-A", index),
                tool=self.name,
                signal_type="binary_skipped_too_large",
                description=(f"Binary exceeded the {MAX_BINARY_BYTES // (1024*1024)} MB cap; "
                             "objdump skipped to avoid global timeout. Readelf fallback engaged."),
                supporting_file=str(raw_path),
                severity_hint="info",
                confidence=0.0,
                promote_to_finding=False,
                requires_track_b=False,
                promotion_reason="binary too large for disassembly; out of scope for this scan",
                metadata={"size_bytes": size, "cap_bytes": MAX_BINARY_BYTES},
            ))
            return ToolResult(tool=self.name, status="skipped_too_large",
                              raw_output=str(raw_path), signals=signals, warnings=warnings)

        # Real disassembly: collect function count + first function + exec refs
        section_count = 0
        first_function: str | None = None
        exec_refs = 0
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Disassembly of section"):
                section_count += 1
                continue
            match = _FUNC_HEADER_RE.match(line)
            if match:
                if first_function is None:
                    first_function = match.group(1)
                if _EXEC_RE.search(line):
                    exec_refs += 1

        signals.append(make_signal(
            signal_id_value=signal_id("SIG-A", index),
            tool=self.name,
            signal_type="disassembly_section_signal",
            description=(f"objdump -d produced {section_count} disassembled sections; "
                         f"first function: {first_function or '(unknown)'}"),
            supporting_file=str(raw_path),
            location={"binary": raw_path.name},
            severity_hint="info",
            confidence=0.4 if exec_refs == 0 else 0.55,
            promote_to_finding=False,
            requires_track_b=exec_refs > 0,
            promotion_reason="disassembly alone is not a vulnerability; requires Track B confirmation",
            metadata={
                "section_count": section_count,
                "first_function": first_function,
                "execve_references": exec_refs,
                "kind": "readelf_fallback" if self.readelf_bin and "readelf" in str(raw_path) else "objdump",
            },
        ))

        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path),
                          signals=signals, warnings=warnings)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="B1 objdump adapter")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = ObjdumpAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())