#!/usr/bin/env python3
"""Merge Track A and Track B outputs with deterministic deduplication."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.merge.confidence_scoring import ScoringContext, apply_confidence, lifecycle_stats
except ModuleNotFoundError:
    from confidence_scoring import ScoringContext, apply_confidence, lifecycle_stats


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    loc = finding.get("location") or {}
    vuln = finding.get("vulnerability") or {}
    attack = finding.get("attack_surface") or {}
    binary = str(loc.get("binary") or loc.get("file") or "")
    if vuln.get("cve_id"):
        return binary, "cve", str(vuln["cve_id"])
    if loc.get("address_offset"):
        return binary, "address", str(loc["address_offset"])
    if vuln.get("cwe_id") and loc.get("function"):
        return binary, "cwe_function", f"{vuln['cwe_id']}:{loc['function']}"
    title = normalize_title(str(vuln.get("title") or "untitled"))
    return binary, "title_surface", f"{title}:{attack.get('entry_point', '')}"


def collect_findings(*wrappers: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for wrapper in wrappers:
        for finding in wrapper.get("findings") or []:
            if isinstance(finding, dict):
                out.append(finding)
    return out


def collect_signals(track_a: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = track_a.get("metadata") or {}
    signals: list[dict[str, Any]] = []
    for item in metadata.get("signals") or []:
        if isinstance(item, dict):
            signals.append(item)
    for result in metadata.get("tool_results") or []:
        if isinstance(result, dict):
            signals.extend(signal for signal in result.get("signals", []) if isinstance(signal, dict))
    return signals


def signal_matches(signal: dict[str, Any], finding: dict[str, Any]) -> bool:
    sig_loc = signal.get("location") or {}
    f_loc = finding.get("location") or {}
    sig_cwe = signal.get("cwe_id")
    sig_cve = signal.get("cve_id")
    vuln = finding.get("vulnerability") or {}
    if sig_cve and sig_cve == vuln.get("cve_id"):
        return True
    if sig_cwe and sig_cwe == vuln.get("cwe_id"):
        if sig_loc.get("binary") and f_loc.get("binary") and sig_loc.get("binary") != f_loc.get("binary"):
            return False
        return True
    if sig_loc.get("address_offset") and sig_loc.get("address_offset") == f_loc.get("address_offset"):
        return True
    return False


def merge_findings(track_a: dict[str, Any], track_b: dict[str, Any]) -> dict[str, Any]:
    all_findings = collect_findings(track_a, track_b)
    signals = collect_signals(track_a)
    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    input_count = len(all_findings)

    for finding in all_findings:
        key = finding_key(finding)
        fid = str(finding.get("finding_id", "unknown"))
        if key not in buckets:
            buckets[key] = {"finding": dict(finding), "merged_from": [fid], "rule": key[1]}
        else:
            bucket = buckets[key]
            bucket["merged_from"].append(fid)
            existing = bucket["finding"]
            if (finding.get("vulnerability") or {}).get("confidence", 0) > (existing.get("vulnerability") or {}).get("confidence", 0):
                bucket["finding"] = dict(finding)

    merged_items: list[dict[str, Any]] = []
    confidence_scores: dict[str, Any] = {}
    for bucket in buckets.values():
        finding = bucket["finding"]
        refs = [signal["signal_id"] for signal in signals if signal.get("signal_id") and signal_matches(signal, finding)]
        context = ScoringContext(
            track_a_agrees=bool(refs),
            track_b_agrees=(finding.get("source") or {}).get("track") == "B",
            has_source_to_sink=bool((finding.get("evidence") or {}).get("source_to_sink")),
            has_function_or_address=bool((finding.get("location") or {}).get("function") or (finding.get("location") or {}).get("address_offset")),
            static_evidence_complete=bool((finding.get("evidence") or {}).get("guard_analysis")),
        )
        scored = apply_confidence(finding, context)
        if refs:
            scored.setdefault("evidence", {}).setdefault("signal_refs", refs)
        confidence_scores[scored["finding_id"]] = scored["confidence_breakdown"]
        dedup = {"merged_from": sorted(set(bucket["merged_from"])), "rule": bucket["rule"]}
        if refs:
            dedup["signal_refs"] = refs
        merged_items.append({"finding": scored, "dedup_info": dedup})

    findings_only = [item["finding"] for item in merged_items]
    return {
        "merged_findings": merged_items,
        "dedup_stats": {"input_findings": input_count, "merged_findings": len(merged_items), "signals_considered": len(signals)},
        "confidence_scores": confidence_scores,
        "lifecycle_stats": lifecycle_stats(findings_only),
        "coverage_summary": {"track_a_status": track_a.get("status"), "track_b_status": track_b.get("status")},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge Track A and Track B findings")
    parser.add_argument("--track-a", required=True)
    parser.add_argument("--track-b", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    merged = merge_findings(read_json(Path(args.track_a)), read_json(Path(args.track_b)))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(merged, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
