#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.track_b_output_mapper import map_text, map_track_b_output  # noqa: E402


def positive_payload() -> dict:
    return {
        "finding_present": True,
        "finding_status": "confirmed_static",
        "title": "Unchecked copy into fixed stack buffer",
        "cwe_id": "CWE-120",
        "severity": "high",
        "confidence": 0.78,
        "location": {"binary": "/usr/bin/demo", "function": "parse_request", "address_offset": "0x4012ab"},
        "evidence": {
            "description": "The code copies attacker-controlled input into a fixed buffer without a visible length guard.",
            "supporting_files": ["context/evidence_slice.json"],
            "source_to_sink": "recv -> parse_request -> strcpy",
            "guard_analysis": "No bounds check before copy.",
        },
        "attack_surface": {"type": "network", "entry_point": "tcp/8080"},
        "verification": {"poc_status": "untested"},
        "remediation": {"suggestion": "Use bounded parsing and reject oversized fields before copying.", "effort": "medium"},
        "references": ["https://cwe.mitre.org/data/definitions/120.html"],
    }


def test_positive_maps_to_finding() -> None:
    result = map_track_b_output(positive_payload(), finding_id="TB-123", dimension="dangerous_functions")
    assert result["status"] == "success", result
    finding = result["finding"]
    assert finding["finding_id"] == "TB-123"
    assert finding["source"]["analysis_dimension"] == "dangerous_functions"
    assert finding["vulnerability"]["cwe_id"] == "CWE-120"
    assert finding["evidence"]["supporting_files"] == ["context/evidence_slice.json"]


def test_no_finding_does_not_emit_finding() -> None:
    result = map_track_b_output({"finding_present": False, "finding_status": "inconclusive", "evidence": {"description": "Checked bounded excerpt; no issue confirmed.", "supporting_files": []}}, finding_id="TB-124", dimension="hardcoded_config")
    assert result["status"] == "no_finding"
    assert result["finding"] is None


def test_extra_key_fails_closed() -> None:
    payload = positive_payload()
    payload["unexpected"] = True
    result = map_track_b_output(payload, finding_id="TB-125", dimension="dangerous_functions")
    assert result["status"] == "error"
    assert "unexpected keys" in result["reason"]
    assert result["finding"] is None


def test_missing_supporting_files_fails_closed() -> None:
    payload = positive_payload()
    payload["evidence"]["supporting_files"] = []
    result = map_track_b_output(payload, finding_id="TB-126", dimension="dangerous_functions")
    assert result["status"] == "error"
    assert "supporting_files" in result["reason"]


def test_malformed_json_fails_closed() -> None:
    result = map_text("{not json", finding_id="TB-127", dimension="dangerous_functions")
    assert result["status"] == "error"
    assert "malformed" in result["reason"]


def run_all() -> None:
    test_positive_maps_to_finding()
    test_no_finding_does_not_emit_finding()
    test_extra_key_fails_closed()
    test_missing_supporting_files_fails_closed()
    test_malformed_json_fails_closed()


if __name__ == "__main__":
    run_all()
    print("Track B output mapper tests OK")
