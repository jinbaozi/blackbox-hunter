#!/usr/bin/env python3
"""Normalize checksec output into Track A hardening signals."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_text, signal_id


CHECKS = [
    ("missing_stack_canary", "Canary", [r"canary[^\n]*(no|disabled|not found)", r"no canary"], "high", "CWE-120"),
    ("nx_disabled", "NX", [r"nx[^\n]*(disabled|no)", r"nx disabled"], "high", "CWE-120"),
    ("pie_disabled", "PIE", [r"pie[^\n]*(disabled|no|none)", r"no pie"], "medium", "CWE-119"),
    ("partial_or_no_relro", "RELRO", [r"no relro", r"partial relro"], "medium", "CWE-119"),
]


class ChecksecAdapter:
    name = "checksec"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        commands = []
        for item in target_profile.get("binaries", []):
            if not item.get("elf", True):
                continue
            binary = item.get("path")
            if not binary:
                continue
            output = scan_root / "raw" / "track_a" / "checksec" / (Path(binary).name + ".txt")
            commands.append(ToolCommand(argv=["checksec", "--file", binary], timeout_sec=60, output_path=str(output)))
        return commands

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        lowered = text.lower()
        binary = self._infer_binary(text, raw_path)
        signals = []
        index = 1
        for signal_type, label, patterns, severity, cwe in CHECKS:
            if any(re.search(pattern, lowered) for pattern in patterns):
                signals.append(
                    make_signal(
                        signal_id_value=signal_id("SIG-A", index),
                        tool=self.name,
                        signal_type=signal_type,
                        description=f"checksec indicates `{label}` hardening weakness for `{binary}`. Treat as hardening evidence, not proof of exploitability.",
                        supporting_file=str(raw_path),
                        location={"binary": binary},
                        severity_hint=severity,
                        confidence=0.55,
                        cwe_id=cwe,
                        promote_to_finding=False,
                        requires_track_b=False,
                        promotion_reason="Hardening weakness requires policy decision and impact context before promotion.",
                    )
                )
                index += 1
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path), signals=signals, warnings=[])

    def _infer_binary(self, text: str, raw_path: Path) -> str:
        for line in text.splitlines():
            if "file:" in line.lower():
                return line.split(":", 1)[-1].strip()
        return raw_path.stem


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize checksec output into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = ChecksecAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
