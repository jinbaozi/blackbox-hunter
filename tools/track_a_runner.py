#!/usr/bin/env python3
"""Minimal Track A runner for real-tool smoke coverage."""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ADAPTERS = {
    "yara": "tools.adapters.yara_scan:YaraAdapter",
    "checksec": "tools.adapters.checksec:ChecksecAdapter",
    "cve-bin-tool": "tools.adapters.cve_bin_tool:CveBinToolAdapter",
    "cwe_checker": "tools.adapters.cwe_checker:CweCheckerAdapter",
    "lintian": "tools.adapters.lintian:LintianAdapter",
    "rpmlint": "tools.adapters.rpmlint:RpmlintAdapter",
    "dependency-parser": "tools.adapters.dependency_parser:DependencyParserAdapter",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_adapter(name: str):
    spec = ADAPTERS.get(name)
    if not spec:
        return None
    module_name, class_name = spec.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, class_name)()


def available_tools(env: dict[str, Any]) -> set[str]:
    return {tool["name"] for tool in env.get("tools", []) if tool.get("status") in {"available", "fallback_active"}}


def run_command(argv: list[str], output_path: Path, timeout: int) -> tuple[int, str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        output_path.write_text((exc.stdout or "") + "\nTIMEOUT\n", encoding="utf-8", errors="replace")
        return 124, "timeout"
    output_path.write_text(result.stdout or "", encoding="utf-8", errors="replace")
    return result.returncode, ""


def run_track_a(scan_root: Path, env: dict[str, Any], target_profile: dict[str, Any], selected: list[str] | None = None) -> dict[str, Any]:
    start = time.time()
    allowed = available_tools(env)
    tools_to_consider = selected or sorted(ADAPTERS)
    executed: list[str] = []
    tool_results: list[str] = []
    warnings: list[str] = []
    signals_count = 0

    for tool_name in tools_to_consider:
        if tool_name not in allowed:
            warnings.append(f"{tool_name} skipped: not available in env_check")
            continue
        adapter = load_adapter(tool_name)
        if adapter is None:
            warnings.append(f"{tool_name} skipped: no adapter")
            continue
        commands = adapter.build_commands(target_profile, scan_root)
        if not commands:
            warnings.append(f"{tool_name} skipped: no commands for target")
            continue
        for index, command in enumerate(commands, start=1):
            output_path = Path(command.output_path)
            rc, error = run_command(command.argv, output_path, command.timeout_sec)
            if rc not in (0, 1) and error:
                warnings.append(f"{tool_name} command {index} failed: {error}")
            result = adapter.parse_output(output_path).to_json()
            result["metadata"]["command_rc"] = rc
            result_path = scan_root / "raw" / "track_a" / "normalized" / f"{tool_name}-{index}.json"
            write_json(result_path, result)
            executed.append(tool_name)
            tool_results.append(str(result_path))
            signals_count += len(result.get("signals") or [])

    payload = {
        "agent_id": "track-a-toolscan",
        "agent_role": "traditional-tooling",
        "phase": "track_a",
        "status": "success" if not warnings else "partial",
        "findings": [],
        "findings_count": 0,
        "warnings": warnings,
        "execution_time_ms": int((time.time() - start) * 1000),
        "metadata": {
            "tools_executed": sorted(set(executed)),
            "tool_results": tool_results,
            "signals_count": signals_count,
            "signals_promoted": 0,
        },
    }
    write_json(scan_root / "track_a_findings.json", payload)
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run available Track A tools")
    parser.add_argument("--scan-root", required=True)
    parser.add_argument("--tools", default="", help="Comma-separated tool allowlist")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scan_root = Path(args.scan_root).resolve()
    env = read_json(scan_root / "env_check.json")
    profile = read_json(scan_root / "target_profile.json")
    selected = [item for item in args.tools.split(",") if item] if args.tools else None
    result = run_track_a(scan_root, env, profile, selected)
    print(json.dumps({"signals_count": result["metadata"]["signals_count"], "warnings": result["warnings"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
