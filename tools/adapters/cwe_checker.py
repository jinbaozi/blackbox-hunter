#!/usr/bin/env python3
"""Normalize cwe_checker output into Track A CWE signals."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id


class CweCheckerAdapter:
    name = "cwe_checker"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        commands = []
        for item in target_profile.get("binaries", []):
            binary = item.get("path")
            if not binary:
                continue
            output = scan_root / "raw" / "track_a" / "cwe_checker" / (Path(binary).name + ".json")
            commands.append(ToolCommand(argv=["cwe_checker", binary, "--json"], timeout_sec=300, output_path=str(output)))
        return commands

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        rows = self._parse_rows(text, raw_path)
        signals = []
        for index, row in enumerate(rows, start=1):
            cwe = self._extract_cwe(row)
            address = str(row.get("address") or row.get("address_offset") or row.get("location") or "")
            binary = row.get("binary") or row.get("file") or raw_path.stem
            signals.append(
                make_signal(
                    signal_id_value=signal_id("SIG-A", index),
                    tool=self.name,
                    signal_type="binary_cwe_pattern",
                    description=f"cwe_checker reported `{cwe or 'CWE pattern'}` for `{binary}`. Confirm reachability and source-to-sink context before promotion.",
                    supporting_file=str(raw_path),
                    location={"binary": str(binary), "address_offset": address} if address.startswith("0x") else {"binary": str(binary)},
                    severity_hint="medium",
                    confidence=0.6,
                    cwe_id=cwe,
                    promote_to_finding=False,
                    requires_track_b=True,
                    promotion_reason="Static CWE pattern requires contextual reachability confirmation.",
                    metadata={"raw": row},
                )
            )
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path), signals=signals, warnings=[])

    def _parse_rows(self, text: str, raw_path: Path) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        try:
            loaded = read_json(raw_path)
            if isinstance(loaded, list):
                return [item for item in loaded if isinstance(item, dict)]
            if isinstance(loaded, dict):
                for key in ("warnings", "results", "cwes", "matches"):
                    value = loaded.get(key)
                    if isinstance(value, list):
                        return [item for item in value if isinstance(item, dict)]
                return [loaded]
        except Exception:
            pass
        rows = []
        for line in text.splitlines():
            match = re.search(r"(CWE-[0-9]+).*?(0x[0-9a-fA-F]+)?", line)
            if match:
                rows.append({"cwe": match.group(1), "address": match.group(2) or "", "raw_line": line})
        return rows

    def _extract_cwe(self, row: dict[str, Any]) -> str | None:
        for key in ("cwe", "cwe_id", "name", "check_name"):
            value = str(row.get(key, ""))
            match = re.search(r"CWE-[0-9]+", value)
            if match:
                return match.group(0)
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize cwe_checker output into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = CweCheckerAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
