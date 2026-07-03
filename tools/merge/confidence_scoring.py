#!/usr/bin/env python3
"""Confidence scoring and lifecycle helpers for Phase 2 merge.

This module is intentionally dependency-free so it can run in constrained
scanner environments. It keeps Track A/Track B evidence confidence, reachability,
tool reliability, and verification confidence separate before producing a final
score.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


FINDING_STATUSES = {
    "candidate",
    "confirmed_static",
    "verified",
    "false_positive",
    "inconclusive",
}

POC_STATUS_TO_VERIFICATION = {
    "verified": 1.0,
    "failed": 0.25,
    "untested": 0.50,
    "skipped": 0.50,
    "inconclusive": 0.50,
    "poc_error": 0.50,
    "sandbox_error": 0.50,
}


@dataclass
class ScoringContext:
    """Optional Phase 2 context used to adjust confidence.

    The defaults are conservative and preserve backwards compatibility for
    fixtures that only contain a finding object.
    """

    track_a_agrees: bool = False
    track_b_agrees: bool = False
    offline_cve_warning: bool = False
    architecture_fallback: bool = False
    has_source_to_sink: bool = False
    has_function_or_address: bool = False
    imported_symbol_only: bool = False
    string_hit_only: bool = False
    cve_version_unconfirmed: bool = False
    static_evidence_complete: bool = False
    explicit_false_positive: bool = False


@dataclass
class ConfidenceBreakdown:
    evidence: float
    reachability: float
    tool_reliability: float
    verification: float
    final: float
    caps_applied: list[str]
    adjustments: list[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 3)


def poc_status(finding: dict[str, Any]) -> str:
    return str((finding.get("verification") or {}).get("poc_status", "untested"))


def base_confidence(finding: dict[str, Any]) -> float:
    value = (finding.get("vulnerability") or {}).get("confidence", 0.5)
    try:
        return clamp(float(value))
    except (TypeError, ValueError):
        return 0.5


def has_location_detail(finding: dict[str, Any]) -> bool:
    loc = finding.get("location") or {}
    return bool(loc.get("function") or loc.get("address_offset") or loc.get("file"))


def has_attack_surface(finding: dict[str, Any]) -> bool:
    attack_surface = finding.get("attack_surface") or {}
    return bool(attack_surface.get("type") or attack_surface.get("entry_point"))


def compute_confidence_breakdown(
    finding: dict[str, Any],
    context: ScoringContext | None = None,
) -> ConfidenceBreakdown:
    context = context or ScoringContext()
    adjustments: list[str] = []
    caps: list[str] = []

    evidence = base_confidence(finding)
    if context.has_source_to_sink or (finding.get("evidence") or {}).get("source_to_sink"):
        evidence += 0.10
        adjustments.append("source-to-sink evidence +0.10")
    if context.has_function_or_address or has_location_detail(finding):
        evidence += 0.05
        adjustments.append("function/address evidence +0.05")
    if context.cve_version_unconfirmed:
        evidence -= 0.10
        adjustments.append("unconfirmed CVE version/backport -0.10")
    evidence = clamp(evidence)

    reachability = 0.35
    if has_attack_surface(finding):
        reachability += 0.15
        adjustments.append("attack surface identified +0.15")
    if context.has_source_to_sink or (finding.get("evidence") or {}).get("source_to_sink"):
        reachability += 0.25
        adjustments.append("source-to-sink reachability +0.25")
    if context.has_function_or_address or has_location_detail(finding):
        reachability += 0.10
        adjustments.append("location-level reachability +0.10")
    reachability = clamp(reachability)

    tool = 0.60
    if context.track_a_agrees and context.track_b_agrees:
        tool += 0.15
        adjustments.append("Track A and Track B agree +0.15")
    elif context.track_a_agrees or context.track_b_agrees:
        tool += 0.05
        adjustments.append("single track support +0.05")
    if context.offline_cve_warning:
        tool -= 0.15
        adjustments.append("offline CVE database warning -0.15")
    if context.architecture_fallback:
        tool -= 0.20
        adjustments.append("architecture fallback without decompiler -0.20")
    tool = clamp(tool)

    verification = POC_STATUS_TO_VERIFICATION.get(poc_status(finding), 0.50)
    if poc_status(finding) in {"poc_error", "sandbox_error"}:
        adjustments.append(f"{poc_status(finding)} treated as verification unknown, not false positive")
    elif poc_status(finding) == "verified":
        adjustments.append("PoC verified signal observed")
    elif poc_status(finding) == "failed":
        adjustments.append("PoC executed without expected signal")

    final = (
        0.45 * evidence
        + 0.25 * reachability
        + 0.15 * tool
        + 0.15 * verification
    )

    if context.imported_symbol_only:
        final = min(final, 0.45)
        caps.append("imported_symbol_only_cap_0.45")
    if context.string_hit_only:
        final = min(final, 0.35)
        caps.append("string_hit_only_cap_0.35")
    if poc_status(finding) == "verified":
        final = max(final, 0.90)
        adjustments.append("verified floor 0.90")
    if context.explicit_false_positive:
        final = 0.0
        caps.append("explicit_false_positive_zero")

    final = clamp(final)
    reason = "; ".join(adjustments + caps) or "base confidence only"

    return ConfidenceBreakdown(
        evidence=evidence,
        reachability=reachability,
        tool_reliability=tool,
        verification=verification,
        final=final,
        caps_applied=caps,
        adjustments=adjustments,
        reason=reason,
    )


def infer_finding_status(
    finding: dict[str, Any],
    breakdown: ConfidenceBreakdown,
    context: ScoringContext | None = None,
) -> str:
    context = context or ScoringContext()
    poc = poc_status(finding)

    if context.explicit_false_positive:
        return "false_positive"
    if poc == "verified":
        return "verified"
    if context.imported_symbol_only or context.string_hit_only:
        return "candidate"
    if poc == "failed" and breakdown.final < 0.50:
        return "inconclusive"
    if poc in {"poc_error", "sandbox_error", "inconclusive"} and breakdown.final >= 0.60:
        return "confirmed_static"
    if context.static_evidence_complete or breakdown.final >= 0.65:
        return "confirmed_static"
    if breakdown.final < 0.45:
        return "candidate"
    return "candidate"


def apply_confidence(
    finding: dict[str, Any],
    context: ScoringContext | None = None,
) -> dict[str, Any]:
    updated = dict(finding)
    breakdown = compute_confidence_breakdown(updated, context)
    updated["confidence_breakdown"] = breakdown.to_dict()
    updated["finding_status"] = infer_finding_status(updated, breakdown, context)
    updated.setdefault("vulnerability", {})
    updated["vulnerability"]["confidence"] = breakdown.final
    return updated


def lifecycle_stats(findings: list[dict[str, Any]]) -> dict[str, int]:
    stats = {status: 0 for status in sorted(FINDING_STATUSES)}
    for finding in findings:
        status = str(finding.get("finding_status", "candidate"))
        stats[status] = stats.get(status, 0) + 1
    return stats
