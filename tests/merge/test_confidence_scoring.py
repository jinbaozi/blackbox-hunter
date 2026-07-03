#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.merge.confidence_scoring import (  # noqa: E402
    ScoringContext,
    apply_confidence,
    compute_confidence_breakdown,
    infer_finding_status,
    lifecycle_stats,
)


def sample_finding(poc_status="untested"):
    return {
        "finding_id": "TB-001",
        "source": {"track": "B", "tool": "ghidra"},
        "vulnerability": {
            "title": "Unchecked copy into fixed stack buffer",
            "cwe_id": "CWE-120",
            "severity": "high",
            "confidence": 0.72,
        },
        "location": {
            "binary": "/usr/bin/sampled",
            "function": "parse_request",
            "address_offset": "0x4012ab",
        },
        "evidence": {
            "description": "The function copies external input into a fixed buffer without enforcing a length guard.",
            "source_to_sink": "recv -> parse_request -> strcpy",
            "guard_analysis": "No bounds check is visible before the copy.",
            "supporting_files": ["raw/track_b/parse_request.ghidra.json"],
        },
        "attack_surface": {"type": "network", "entry_point": "tcp/8080"},
        "verification": {"poc_status": poc_status},
        "remediation": {
            "suggestion": "Use bounded parsing and reject oversized requests before copying into the fixed buffer.",
            "effort": "medium",
        },
    }


def test_string_only_signal_is_capped_candidate():
    finding = sample_finding()
    breakdown = compute_confidence_breakdown(
        finding,
        ScoringContext(string_hit_only=True),
    )
    assert breakdown.final <= 0.35
    assert "string_hit_only_cap_0.35" in breakdown.caps_applied
    assert infer_finding_status(finding, breakdown, ScoringContext(string_hit_only=True)) == "candidate"


def test_static_evidence_becomes_confirmed_static():
    finding = sample_finding()
    context = ScoringContext(
        track_a_agrees=True,
        track_b_agrees=True,
        has_source_to_sink=True,
        has_function_or_address=True,
        static_evidence_complete=True,
    )
    updated = apply_confidence(finding, context)
    assert updated["finding_status"] == "confirmed_static"
    assert updated["confidence_breakdown"]["final"] >= 0.65
    assert updated["vulnerability"]["confidence"] == updated["confidence_breakdown"]["final"]


def test_verified_poc_sets_verified_status_and_floor():
    finding = sample_finding("verified")
    updated = apply_confidence(finding, ScoringContext(static_evidence_complete=True))
    assert updated["finding_status"] == "verified"
    assert updated["confidence_breakdown"]["verification"] == 1.0
    assert updated["confidence_breakdown"]["final"] >= 0.90


def test_sandbox_error_is_unknown_not_false_positive():
    finding = sample_finding("sandbox_error")
    context = ScoringContext(static_evidence_complete=True, has_source_to_sink=True)
    updated = apply_confidence(finding, context)
    assert updated["finding_status"] == "confirmed_static"
    assert updated["verification"]["poc_status"] == "sandbox_error"
    assert updated["confidence_breakdown"]["verification"] == 0.5
    assert "verification unknown" in updated["confidence_breakdown"]["reason"]


def test_lifecycle_stats_counts_statuses():
    findings = [
        {"finding_status": "candidate"},
        {"finding_status": "confirmed_static"},
        {"finding_status": "verified"},
        {"finding_status": "verified"},
    ]
    stats = lifecycle_stats(findings)
    assert stats["candidate"] == 1
    assert stats["confirmed_static"] == 1
    assert stats["verified"] == 2


if __name__ == "__main__":
    test_string_only_signal_is_capped_candidate()
    test_static_evidence_becomes_confirmed_static()
    test_verified_poc_sets_verified_status_and_floor()
    test_sandbox_error_is_unknown_not_false_positive()
    test_lifecycle_stats_counts_statuses()
    print("confidence scoring tests passed")
