#!/usr/bin/env python3
"""Normalize YARA output into Track A finding signals."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_text, signal_id


RULE_MAP = {
    "dangerous_string_functions": ("dangerous_function_import", "high", "CWE-120"),
    "dangerous_memory_functions_without_fortify": ("dangerous_memory_import", "medium", "CWE-122"),
    "dangerous_command_execution": ("dangerous_command_execution_signal", "high", "CWE-78"),
    "dangerous_format_string": ("dangerous_format_string_signal", "high", "CWE-134"),
    "dangerous_temp_files": ("dangerous_tempfile_signal", "medium", "CWE-377"),
    "dangerous_random": ("weak_random_signal", "medium", "CWE-330"),
}


class YaraAdapter:
    name = "yara"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        output = scan_root / "raw" / "track_a" / "yara.txt"
        return [
            ToolCommand(
                argv=["yara", "-r", "tools/rules", str(scan_root / "extracted")],
                timeout_sec=300,
                output_path=str(output),
            )
        ]

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        signals = []
        warnings: list[str] = []
        index = 1
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("warning:"):
                if line:
                    warnings.append(line)
                continue
            parts = line.split()
            if len(parts) < 2:
                warnings.append(f"unparsed YARA line: {line}")
                continue
            rule = parts[0]
            target = parts[-1]
            signal_type, severity, cwe = RULE_MAP.get(rule, ("yara_rule_match", "info", None))
            signals.append(
                make_signal(
                    signal_id_value=signal_id("SIG-A", index),
                    tool=self.name,
                    signal_type=signal_type,
                    description=f"YARA rule `{rule}` matched `{target}`. This is a signal and requires contextual confirmation before vulnerability promotion.",
                    supporting_file=str(raw_path),
                    location={"binary": target},
                    severity_hint=severity,
                    confidence=0.35,
                    cwe_id=cwe,
                    promote_to_finding=False,
                    requires_track_b=True,
                    promotion_reason="YARA matches indicate suspicious patterns but do not prove reachability or exploitability.",
                    metadata={"rule": rule, "raw_line": line},
                )
            )
            index += 1
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path), signals=signals, warnings=warnings)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize YARA output into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = YaraAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
