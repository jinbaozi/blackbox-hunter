#!/usr/bin/env python3
"""Generate a report with required BlackBox Hunter sections."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REQUIRED_SECTION_TITLES = [
    "Executive Summary",
    "Preflight Environment Summary",
    "Target Profile Summary",
    "Track A Summary",
    "Track B Summary",
    "Merge and Lifecycle Summary",
    "Verification Summary",
    "Coverage Gaps",
    "Sandbox Limitations",
    "Findings by Lifecycle",
    "Appendix Evidence Paths",
]


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def lifecycle_counts(merged: dict[str, Any]) -> dict[str, int]:
    stats = {"verified": 0, "confirmed_static": 0, "candidate": 0, "inconclusive": 0, "false_positive": 0}
    for item in merged.get("merged_findings") or []:
        finding = item.get("finding") or {}
        status = str(finding.get("finding_status", "candidate"))
        stats[status] = stats.get(status, 0) + 1
    for key, value in (merged.get("lifecycle_stats") or {}).items():
        if isinstance(value, int):
            stats[key] = value
    return stats


def artifact_paths(scan_root: Path) -> list[str]:
    names = [
        "env_check.json",
        "target_profile.json",
        "scan_strategy.json",
        "coverage_plan.json",
        "track_a_findings.json",
        "track_b_findings.json",
        "merged_findings.json",
        "coverage_report.json",
        "verified_findings.json",
        "scan_state.json",
    ]
    return [str(scan_root / name) for name in names]


def generate_report(scan_root: Path) -> str:
    env = read_json(scan_root / "env_check.json")
    profile = read_json(scan_root / "target_profile.json")
    track_a = read_json(scan_root / "track_a_findings.json")
    track_b = read_json(scan_root / "track_b_findings.json")
    merged = read_json(scan_root / "merged_findings.json")
    coverage = read_json(scan_root / "coverage_report.json")
    verified = read_json(scan_root / "verified_findings.json")
    sandbox = verified.get("sandbox_info") or read_json(scan_root / "sandbox_status.json")
    state = read_json(scan_root / "scan_state.json")

    counts = lifecycle_counts(merged)
    lines: list[str] = ["# BlackBox Security Test Report", ""]
    lines.extend([
        "## Executive Summary",
        f"scan_id: {state.get('scan_id', profile.get('scan_id', 'unknown'))}",
        f"total_findings: {sum(counts.values())}",
        "",
        "## Preflight Environment Summary",
        f"package_manager: {env.get('package_manager', 'unknown')}",
        f"blocked_tools: {', '.join(env.get('block_decision', {}).get('blocked_tools', [])) or 'none'}",
        f"fallback_or_degradation: {', '.join(env.get('block_decision', {}).get('warnings', [])) or 'none'}",
        "",
        "## Target Profile Summary",
        f"package_type: {(profile.get('package') or {}).get('type', 'unknown')}",
        f"extraction_method: {(profile.get('extraction') or {}).get('method', 'unknown')}",
        f"architectures: {', '.join(profile.get('architectures') or []) or 'unknown'}",
        "",
        "## Track A Summary",
        f"status: {track_a.get('status', 'missing')}",
        f"signals_count: {(track_a.get('metadata') or {}).get('signals_count', 0)}",
        "",
        "## Track B Summary",
        f"status: {track_b.get('status', 'missing')}",
        f"dimensions: {', '.join((track_b.get('metadata') or {}).get('dimensions_analyzed', [])) or 'none'}",
        "",
        "## Merge and Lifecycle Summary",
        f"dedup_stats: {json.dumps(merged.get('dedup_stats', {}), sort_keys=True)}",
        f"lifecycle_stats: {json.dumps(counts, sort_keys=True)}",
        "",
        "## Verification Summary",
        f"verification_stats: {json.dumps(verified.get('verification_stats', {}), sort_keys=True)}",
        "",
        "## Coverage Gaps",
        f"gaps: {json.dumps(coverage.get('gaps', []), sort_keys=True)}",
        "",
        "## Sandbox Limitations",
        f"engine: {sandbox.get('engine', 'none')}",
        f"limitations: {json.dumps(sandbox.get('limitations', []), sort_keys=True)}",
        "",
        "## Findings by Lifecycle",
    ])
    for status in ["verified", "confirmed_static", "candidate", "inconclusive", "false_positive"]:
        lines.append(f"- {status}: {counts.get(status, 0)}")
    lines.extend(["", "## Appendix Evidence Paths"])
    for path in artifact_paths(scan_root):
        lines.append(f"- {path}")
    lines.append("")
    return "\n".join(lines)


def validate_required_sections(report: str) -> list[str]:
    missing = []
    for title in REQUIRED_SECTION_TITLES:
        if f"## {title}" not in report:
            missing.append(title)
    return missing


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate BlackBox Hunter report")
    parser.add_argument("scan_root")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = generate_report(Path(args.scan_root))
    missing = validate_required_sections(report)
    if missing:
        raise SystemExit("missing report sections: " + ", ".join(missing))
    output = Path(args.output) if args.output else Path(args.scan_root) / "report" / "blackbox-security-report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
