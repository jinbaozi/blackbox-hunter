#!/usr/bin/env python3
"""Map strict Track B model output into BlackBox Hunter finding records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

POSITIVE_KEYS = {
    "finding_present",
    "finding_status",
    "title",
    "cwe_id",
    "cve_id",
    "severity",
    "confidence",
    "location",
    "evidence",
    "attack_surface",
    "verification",
    "remediation",
    "references",
}
NEGATIVE_KEYS = {"finding_present", "finding_status", "evidence"}
VALID_STATUSES = {"candidate", "confirmed_static", "inconclusive"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _error(reason: str, *, raw: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": "error", "finding": None, "reason": reason}
    if raw is not None:
        payload["raw"] = raw
    return payload


def _confidence_breakdown(confidence: float) -> dict[str, Any]:
    value = max(0.0, min(1.0, float(confidence)))
    return {
        "evidence": value,
        "reachability": 0.5,
        "tool_reliability": 0.6,
        "verification": 0.5,
        "final": round(value, 3),
        "caps_applied": [],
        "adjustments": ["Track B mapper initial confidence"],
        "reason": "initial Track B mapped confidence; Phase 2 may rescore",
    }


def _validate_common(payload: dict[str, Any]) -> dict[str, Any] | None:
    if "finding_present" not in payload or not isinstance(payload["finding_present"], bool):
        return _error("missing or non-boolean finding_present", raw=payload)
    allowed = POSITIVE_KEYS if payload["finding_present"] else NEGATIVE_KEYS
    extra = sorted(set(payload) - allowed)
    if extra:
        return _error("unexpected keys in Track B output: " + ", ".join(extra), raw=payload)
    return None


def _validate_supporting_files(evidence: dict[str, Any]) -> dict[str, Any] | None:
    files = evidence.get("supporting_files")
    if not isinstance(files, list) or not files or not all(isinstance(item, str) and item for item in files):
        return _error("positive Track B finding requires non-empty evidence.supporting_files")
    return None


def map_track_b_output(
    payload: dict[str, Any],
    *,
    finding_id: str,
    dimension: str,
    tool: str = "track-b-ai",
    agent_id: str = "track-b-ai",
) -> dict[str, Any]:
    common_error = _validate_common(payload)
    if common_error:
        return common_error

    if not payload["finding_present"]:
        evidence = payload.get("evidence") or {}
        return {
            "status": "no_finding",
            "finding": None,
            "reason": str(evidence.get("description") or "Track B reported no finding"),
            "checked_evidence": evidence,
        }

    status = str(payload.get("finding_status", ""))
    if status not in VALID_STATUSES:
        return _error(f"invalid finding_status for Track B mapped finding: {status!r}", raw=payload)
    severity = str(payload.get("severity", ""))
    if severity not in VALID_SEVERITIES:
        return _error(f"invalid severity: {severity!r}", raw=payload)

    evidence = payload.get("evidence") or {}
    if not isinstance(evidence, dict):
        return _error("evidence must be an object", raw=payload)
    support_error = _validate_supporting_files(evidence)
    if support_error:
        return support_error

    location = payload.get("location") or {}
    if not isinstance(location, dict) or not (location.get("binary") or location.get("file")):
        return _error("location must include binary or file", raw=payload)

    confidence = float(payload.get("confidence", 0.5))
    vulnerability: dict[str, Any] = {
        "title": str(payload.get("title") or "Untitled Track B finding"),
        "severity": severity,
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
    }
    if payload.get("cwe_id"):
        vulnerability["cwe_id"] = payload["cwe_id"]
    if payload.get("cve_id"):
        vulnerability["cve_id"] = payload["cve_id"]

    remediation = payload.get("remediation") or {}
    if not isinstance(remediation, dict) or not remediation.get("suggestion"):
        return _error("remediation.suggestion is required", raw=payload)

    finding = {
        "finding_id": finding_id,
        "finding_status": status,
        "source": {"track": "B", "tool": tool, "analysis_dimension": dimension, "agent_id": agent_id},
        "vulnerability": vulnerability,
        "confidence_breakdown": _confidence_breakdown(vulnerability["confidence"]),
        "location": {key: value for key, value in location.items() if value not in (None, "", [])},
        "evidence": evidence,
        "verification": payload.get("verification") or {"poc_status": "untested"},
        "remediation": remediation,
        "references": payload.get("references") or [],
        "metadata": {"mapper": "track_b_output_mapper"},
    }
    if payload.get("attack_surface"):
        finding["attack_surface"] = payload["attack_surface"]
    return {"status": "success", "finding": finding, "reason": "mapped Track B output"}


def map_text(text: str, **kwargs: Any) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return _error(f"malformed Track B JSON: {exc}")
    if not isinstance(payload, dict):
        return _error("Track B output must be a JSON object", raw=payload)
    return map_track_b_output(payload, **kwargs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Map Track B JSON output into finding schema shape")
    parser.add_argument("input")
    parser.add_argument("--finding-id", default="TB-001")
    parser.add_argument("--dimension", required=True)
    parser.add_argument("--tool", default="track-b-ai")
    parser.add_argument("--agent-id", default="track-b-ai")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = map_text(
        Path(args.input).read_text(encoding="utf-8"),
        finding_id=args.finding_id,
        dimension=args.dimension,
        tool=args.tool,
        agent_id=args.agent_id,
    )
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if result["status"] in {"success", "no_finding"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
