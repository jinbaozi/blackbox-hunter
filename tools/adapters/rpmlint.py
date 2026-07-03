#!/usr/bin/env python3
"""Normalize rpmlint output into Track A package metadata signals."""
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


SEVERITY_MAP = {"E": "high", "W": "medium", "I": "info"}


class RpmlintAdapter:
    name = "rpmlint"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        package_path = target_profile.get("package", {}).get("path", "")
        output = scan_root / "raw" / "track_a" / "rpmlint.txt"
        return [ToolCommand(argv=["rpmlint", package_path], timeout_sec=300, output_path=str(output))]

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        signals = []
        warnings = []
        index = 1
        for line in text.splitlines():
            line = line.strip()
            if not line or line.endswith("packages and 0 specfiles checked"):
                continue
            parsed = self._parse_line(line)
            if not parsed:
                warnings.append(f"unparsed rpmlint line: {line}")
                continue
            target, level, tag, detail = parsed
            severity = SEVERITY_MAP.get(level, "info")
            signals.append(
                make_signal(
                    signal_id_value=signal_id("SIG-A", index),
                    tool=self.name,
                    signal_type=f"rpmlint:{tag}",
                    description=f"rpmlint reported `{tag}` for `{target}`. RPM metadata/script findings require context review before promotion.",
                    supporting_file=str(raw_path),
                    location={"file": target},
                    severity_hint=severity,
                    confidence=0.45,
                    promote_to_finding=False,
                    requires_track_b=False,
                    promotion_reason="rpmlint output is a package-quality/security signal and should be reviewed in context.",
                    metadata={"level": level, "target": target, "tag": tag, "detail": detail, "raw_line": line},
                )
            )
            index += 1
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path), signals=signals, warnings=warnings)

    def _parse_line(self, line: str) -> tuple[str, str, str, str] | None:
        match = re.match(r"^([^:]+):\s+([EWI]):\s+([^\s]+)\s*(.*)$", line)
        if match:
            return match.group(1), match.group(2), match.group(3), match.group(4).strip()
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize rpmlint output into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = RpmlintAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
