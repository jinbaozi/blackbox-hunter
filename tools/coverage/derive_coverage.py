#!/usr/bin/env python3
"""Derive coverage_report.json from real scan artifacts (A3).

Replaces the hand-written 5-line coverage derivation in
``tools/bbh_scan.py:write_merge_verify_artifacts``. The new generator:

* Computes the 5 documented percentages from the actual artifacts:
  - ``binary_coverage_pct``:  fraction of ``target_profile.binaries[]``
    that produced at least one Track A or Track B finding.
  - ``config_coverage_pct``:  fraction of declared ``config_files[]``
    that were inspected (heuristic: any finding references the file).
  - ``dependency_coverage_pct``:  fraction of declared deps whose
    resolved binary got at least one signal.
  - ``attack_surface_coverage_pct``:  fraction of
    ``attack_surface[]`` entries referenced by any finding.
  - ``tool_coverage_pct``:  fraction of Track A adapters selected by
    the registry that actually produced a finding.
* Emits a structured ``gaps[]`` list. Each entry is
  ``{kind, target, reason}`` where ``kind`` is one of:
  - ``missing_adapter``     – registry advertises a tool but it didn't run
  - ``uncovered_binary``    – a binary had zero signals
  - ``uncovered_config``    – a declared config file was never referenced
  - ``uncovered_dependency``– a declared dep had no resolved binary
  - ``phase_block``         – preflight blocked a phase (kept for back-compat)

The output conforms to ``templates/coverage_report.json`` (5 numeric fields
plus ``gaps[]``) so existing readers and validators keep working.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _pct(num: int, denom: int) -> float:
    if denom <= 0:
        return 0.0
    return round(100.0 * num / denom, 2)


def _binary_names_referenced(findings: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("findings", "merged_findings"):
        for item in findings.get(key) or []:
            binary = (item.get("location") or {}).get("binary")
            if binary:
                names.add(Path(binary).name)
            # Track B findings often key by analysis_dimension, so also
            # pull binaries from the track_b raw output if present.
    raw = findings.get("raw") or {}
    for entry in raw.get("track_b") or []:
        if isinstance(entry, dict):
            for sig in entry.get("signals") or []:
                if not isinstance(sig, dict):
                    continue
                binary = (sig.get("location") or {}).get("binary")
                if binary:
                    names.add(Path(binary).name)
    return names


def _config_names_referenced(profile: dict[str, Any], findings: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in findings.get("merged_findings") or []:
        loc = item.get("location") or {}
        file_path = loc.get("file")
        if file_path:
            names.add(Path(file_path).name)
    return names


def _dependency_resolved_bins(profile: dict[str, Any]) -> list[str]:
    """Best-effort: declared dependencies that resolved to a binary path."""
    resolved: list[str] = []
    for dep in profile.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        bin_path = dep.get("binary") or dep.get("resolved_path")
        if bin_path:
            resolved.append(bin_path)
    return resolved


def _attack_surface_ids(profile: dict[str, Any]) -> list[str]:
    surfaces = profile.get("attack_surface") or []
    if isinstance(surfaces, list):
        return [str(s.get("id") or s.get("type") or i) for i, s in enumerate(surfaces) if isinstance(s, dict)]
    return []


def compute(
    track_a: dict[str, Any],
    track_b: dict[str, Any],
    target_profile: dict[str, Any],
    env_check: dict[str, Any],
    *,
    registry_tools: list[str] | None = None,
) -> dict[str, Any]:
    """Compute coverage_report.json content from real artifacts.

    ``registry_tools`` is an optional override; when omitted, falls back to
    the names declared in ``track_a.metadata.tools_selected``.
    """
    findings_combined = {
        "findings": (track_a.get("findings") or []) + (track_b.get("findings") or []),
        "merged_findings": [],
        "raw": {"track_b": track_b.get("raw_findings") or track_b.get("outputs") or []},
    }

    binaries = target_profile.get("binaries") or []
    binary_names = [
        Path(b.get("path") or b.get("name") or "").name
        for b in binaries
        if isinstance(b, dict) and (b.get("path") or b.get("name"))
    ]
    referenced_bins = _binary_names_referenced(findings_combined)
    covered_bins = [b for b in binary_names if b in referenced_bins]
    binary_pct = _pct(len(covered_bins), len(binary_names))

    configs = target_profile.get("config_files") or []
    config_names = [Path(c.get("path") or c.get("name") or "").name for c in configs if isinstance(c, dict)]
    referenced_configs = _config_names_referenced(target_profile, findings_combined)
    covered_configs = [c for c in config_names if c in referenced_configs]
    config_pct = _pct(len(covered_configs), len(config_names)) if config_names else 100.0

    dep_bins = _dependency_resolved_bins(target_profile)
    dep_names = [Path(p).name for p in dep_bins]
    covered_deps = [p for p in dep_names if p in referenced_bins]
    dep_pct = _pct(len(covered_deps), len(dep_names))

    surfaces = _attack_surface_ids(target_profile)
    # Heuristic: a surface is covered if at least one finding has a matching
    # attack_surface.type or entry_point substring.
    surface_covered: set[str] = set()
    for item in findings_combined["findings"]:
        asurf = item.get("attack_surface") or {}
        if not isinstance(asurf, dict):
            continue
        as_type = asurf.get("type")
        if as_type and as_type in surfaces:
            surface_covered.add(as_type)
        entry = asurf.get("entry_point")
        if entry:
            for s in surfaces:
                if s in str(entry):
                    surface_covered.add(s)
    surface_pct = _pct(len(surface_covered), len(surfaces))

    tools_selected = registry_tools or track_a.get("metadata", {}).get("tools_selected") or []
    tools_executed = track_a.get("metadata", {}).get("tools_executed") or []
    tool_pct = _pct(len(tools_executed), len(tools_selected)) if tools_selected else (
        100.0 if tools_executed else 0.0
    )

    # B7: fuzz_coverage_pct. By default we report 0 because fuzz is opt-in
    # and ``duration_sec=0`` short-circuits the adapter. When a fuzz run
    # actually executed we read ``metadata.fuzz_coverage_pct`` from Track A.
    fuzz_coverage_pct = float(track_a.get("metadata", {}).get("fuzz_coverage_pct", 0.0) or 0.0)

    gaps: list[dict[str, Any]] = []

    # uncovered_binary
    for b in binary_names:
        if b not in referenced_bins:
            gaps.append({
                "kind": "uncovered_binary",
                "target": b,
                "reason": "binary produced no Track A or Track B signal",
            })
    # uncovered_config
    for c in config_names:
        if c not in referenced_configs:
            gaps.append({
                "kind": "uncovered_config",
                "target": c,
                "reason": "config file not referenced by any finding",
            })
    # uncovered_dependency
    for d in dep_names:
        if d not in referenced_bins:
            gaps.append({
                "kind": "uncovered_dependency",
                "target": d,
                "reason": "declared dependency had no resolved binary signal",
            })
    # missing_adapter
    for tool in tools_selected:
        if tool not in tools_executed:
            gaps.append({
                "kind": "missing_adapter",
                "target": tool,
                "reason": "registry advertised tool but adapter did not execute",
            })
    # phase_block (back-compat with the previous hand-written shape)
    for block in (env_check.get("block_decision") or {}).get("phase_blocks") or []:
        gaps.append({
            "kind": "phase_block",
            "target": block.get("tool") or "unknown",
            "reason": block.get("reason") or "preflight phase block",
        })

    return {
        "binary_coverage_pct": binary_pct,
        "config_coverage_pct": config_pct,
        "dependency_coverage_pct": dep_pct,
        "attack_surface_coverage_pct": surface_pct,
        "tool_coverage_pct": tool_pct,
        "fuzz_coverage_pct": fuzz_coverage_pct,
        "gaps": gaps,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Derive coverage_report.json from scan artifacts")
    p.add_argument("--scan-root", required=True, help="$SCAN_ROOT with track_*/target_profile/env_check")
    p.add_argument(
        "--registry",
        default=None,
        help="Optional path to tool_registry.json for fallback tool list",
    )
    p.add_argument("--output", default=None, help="Override output path (default: <scan-root>/coverage_report.json)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    scan_root = Path(args.scan_root)
    track_a = json.loads((scan_root / "track_a_findings.json").read_text(encoding="utf-8")) if (scan_root / "track_a_findings.json").exists() else {}
    track_b = json.loads((scan_root / "track_b_findings.json").read_text(encoding="utf-8")) if (scan_root / "track_b_findings.json").exists() else {}
    profile = json.loads((scan_root / "target_profile.json").read_text(encoding="utf-8")) if (scan_root / "target_profile.json").exists() else {}
    env_check = json.loads((scan_root / "env_check.json").read_text(encoding="utf-8")) if (scan_root / "env_check.json").exists() else {}

    registry_tools: list[str] | None = None
    if args.registry:
        try:
            reg = json.loads(Path(args.registry).read_text(encoding="utf-8"))
            registry_tools = [
                t.get("name") for t in reg.get("tools") or [] if t.get("name")
            ]
        except (OSError, json.JSONDecodeError):
            registry_tools = None

    coverage = compute(track_a, track_b, profile, env_check, registry_tools=registry_tools)
    out = Path(args.output) if args.output else scan_root / "coverage_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(coverage, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json.dump(coverage, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())