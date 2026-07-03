#!/usr/bin/env python3
"""Normalize cve-bin-tool output into Track A CVE signals."""
from __future__ import annotations

import argparse
import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id


class CveBinToolAdapter:
    name = "cve-bin-tool"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        output = scan_root / "raw" / "track_a" / "cve-bin-tool.json"
        package_root = target_profile.get("extraction", {}).get("root") or str(scan_root / "extracted")
        return [ToolCommand(argv=["cve-bin-tool", "--format", "json", "--output", str(output), package_root], timeout_sec=900, output_path=str(output))]

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        rows = self._parse_rows(text, raw_path)
        signals = []
        for index, row in enumerate(rows, start=1):
            cve = row.get("cve") or row.get("cve_id") or row.get("CVE") or row.get("cve_number") or ""
            product = row.get("product") or row.get("package") or row.get("component") or row.get("Product") or "unknown-component"
            version = row.get("version") or row.get("Version") or "unknown-version"
            severity = (row.get("severity") or row.get("Severity") or "medium").lower()
            signals.append(
                make_signal(
                    signal_id_value=signal_id("SIG-A", index),
                    tool=self.name,
                    signal_type="cve_version_match",
                    description=f"cve-bin-tool reported `{cve or 'unknown CVE'}` for `{product}` version `{version}`. Confirm package versioning and vendor backports before promotion.",
                    supporting_file=str(raw_path),
                    location={"file": row.get("path") or row.get("filename") or row.get("File") or product},
                    severity_hint=severity if severity in {"critical", "high", "medium", "low", "info"} else "medium",
                    confidence=0.55,
                    cve_id=cve if cve.startswith("CVE-") else None,
                    promote_to_finding=False,
                    requires_track_b=False,
                    promotion_reason="CVE version matches require version-range, package source, and backport confirmation before promotion.",
                    metadata={"product": product, "version": version, "raw": row},
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
                for key in ("vulnerabilities", "cves", "results", "data"):
                    value = loaded.get(key)
                    if isinstance(value, list):
                        return [item for item in value if isinstance(item, dict)]
                return [loaded]
        except Exception:
            pass
        reader = csv.DictReader(StringIO(text))
        return [dict(row) for row in reader]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize cve-bin-tool output into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = CveBinToolAdapter().parse_output(Path(args.raw_output)).to_json()
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
