#!/usr/bin/env python3
"""Normalize dependency/import metadata into Track A dependency signals."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_json, read_text, signal_id


SENSITIVE_IMPORTS = {
    "libssl": "crypto_dependency",
    "libcrypto": "crypto_dependency",
    "libcurl": "network_dependency",
    "openssl": "crypto_dependency",
    "busybox": "multi_call_dependency",
}


def _extend_imports(out: list[str], value: Any) -> None:
    if isinstance(value, str):
        if value:
            out.append(value)
    elif isinstance(value, list):
        for item in value:
            _extend_imports(out, item)


def imports_from_profile(profile: dict[str, Any]) -> list[str]:
    imports: list[str] = []
    metadata = profile.get("metadata") or {}
    _extend_imports(imports, metadata.get("imports"))
    _extend_imports(imports, metadata.get("dependencies"))
    package = profile.get("package") or {}
    _extend_imports(imports, package.get("dependencies"))
    for binary in profile.get("binaries") or []:
        if isinstance(binary, dict):
            for key in ("imports", "linked_libraries", "libraries", "needed", "dependencies"):
                _extend_imports(imports, binary.get(key))
    seen: set[str] = set()
    deduped: list[str] = []
    for item in imports:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


class DependencyParserAdapter:
    name = "dependency-parser"

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        output = scan_root / "raw" / "track_a" / "dependencies.json"
        return [
            ToolCommand(
                argv=["python3", "tools/adapters/dependency_parser.py", str(scan_root / "target_profile.json"), "--emit-raw", "--output", str(output)],
                timeout_sec=60,
                output_path=str(output),
            )
        ]

    def parse_output(self, raw_path: Path) -> ToolResult:
        data = self._load(raw_path)
        imports = data.get("imports") if isinstance(data, dict) else []
        if not isinstance(imports, list):
            imports = []
        signals = []
        index = 1
        for item in imports:
            value = str(item)
            lowered = value.lower()
            for key, signal_type in SENSITIVE_IMPORTS.items():
                if key in lowered:
                    signals.append(
                        make_signal(
                            signal_id_value=signal_id("SIG-A", index),
                            tool=self.name,
                            signal_type=signal_type,
                            description=f"Dependency/import `{value}` is security-relevant and may influence Track B prioritization.",
                            supporting_file=str(raw_path),
                            location={"file": value},
                            severity_hint="info",
                            confidence=0.25,
                            promote_to_finding=False,
                            requires_track_b=True,
                            promotion_reason="Dependency presence is prioritization context, not a vulnerability.",
                            metadata={"import": value},
                        )
                    )
                    index += 1
                    break
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path), signals=signals, warnings=[])

    def _load(self, raw_path: Path) -> dict[str, Any]:
        try:
            value = read_json(raw_path)
            return value if isinstance(value, dict) else {}
        except Exception:
            imports = [line.strip() for line in read_text(raw_path).splitlines() if line.strip()]
            return {"imports": imports}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize dependency/import metadata into finding signals")
    parser.add_argument("raw_output")
    parser.add_argument("--output", default="")
    parser.add_argument("--emit-raw", action="store_true", help="Extract raw dependency/import metadata from a target_profile.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.raw_output)
    if args.emit_raw:
        profile = read_json(input_path)
        payload = json.dumps({"imports": imports_from_profile(profile if isinstance(profile, dict) else {})}, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    else:
        result = DependencyParserAdapter().parse_output(input_path).to_json()
        payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
