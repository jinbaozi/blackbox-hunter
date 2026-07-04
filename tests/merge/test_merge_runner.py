#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.merge.merge_runner import merge_findings  # noqa: E402


def finding(fid: str, confidence: float = 0.7, *, binary: str = "/usr/bin/demo", function: str = "parse_request", cwe: str = "CWE-120", address: str = "0x4012ab") -> dict:
    return {
        "finding_id": fid,
        "finding_status": "confirmed_static",
        "source": {"track": "B", "tool": "track-b-ai"},
        "vulnerability": {"title": "Unchecked copy into fixed stack buffer", "cwe_id": cwe, "severity": "high", "confidence": confidence},
        "confidence_breakdown": {"evidence": confidence, "reachability": 0.5, "tool_reliability": 0.6, "verification": 0.5, "final": confidence, "caps_applied": [], "adjustments": [], "reason": "fixture"},
        "location": {"binary": binary, "function": function, "address_offset": address},
        "evidence": {"description": "The function copies external input into a fixed buffer without enforcing a length guard.", "supporting_files": ["context/evidence.json"], "source_to_sink": "recv -> parse_request -> strcpy", "guard_analysis": "No length guard."},
        "attack_surface": {"type": "network", "entry_point": "tcp/8080"},
        "verification": {"poc_status": "untested"},
        "remediation": {"suggestion": "Use bounded parsing and reject oversized requests before copying into the fixed buffer.", "effort": "medium"},
    }


def track_wrapper(phase: str, findings: list[dict], metadata: dict | None = None) -> dict:
    return {"agent_id": phase, "agent_role": phase, "phase": phase, "status": "success", "findings": findings, "findings_count": len(findings), "warnings": [], "execution_time_ms": 0, "metadata": metadata or {}}


def test_dedup_by_cwe_function_and_signal_refs() -> None:
    signal = {"signal_id": "SIG-A-yara-12345678-001", "cwe_id": "CWE-120", "location": {"binary": "/usr/bin/demo"}}
    track_a = track_wrapper("track_a", [finding("TA-001", 0.55)], {"signals": [signal]})
    track_b = track_wrapper("track_b", [finding("TB-001", 0.78)])
    result = merge_findings(track_a, track_b)
    assert result["dedup_stats"]["input_findings"] == 2
    assert result["dedup_stats"]["merged_findings"] == 1
    item = result["merged_findings"][0]
    assert set(item["dedup_info"]["merged_from"]) == {"TA-001", "TB-001"}
    assert item["dedup_info"]["signal_refs"] == ["SIG-A-yara-12345678-001"]
    assert item["finding"]["evidence"]["signal_refs"] == ["SIG-A-yara-12345678-001"]


def test_distinct_attack_surface_not_merged_when_no_strong_key() -> None:
    a = finding("TB-010", address="", function="", cwe="CWE-999")
    b = finding("TB-011", address="", function="", cwe="CWE-999")
    a["vulnerability"]["title"] = "Weak default configuration value"
    b["vulnerability"]["title"] = "Weak default configuration value"
    a["attack_surface"] = {"type": "cli", "entry_point": "/usr/bin/a"}
    b["attack_surface"] = {"type": "network", "entry_point": "tcp/9000"}
    result = merge_findings(track_wrapper("track_a", []), track_wrapper("track_b", [a, b]))
    assert result["dedup_stats"]["merged_findings"] == 2


def run_all() -> None:
    test_dedup_by_cwe_function_and_signal_refs()
    test_distinct_attack_surface_not_merged_when_no_strong_key()


if __name__ == "__main__":
    run_all()
    print("merge runner tests OK")
