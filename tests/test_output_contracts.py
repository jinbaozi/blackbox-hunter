#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.output_contracts import validate_phase_outputs  # noqa: E402


SCAN_ID = "BBH-20260707-ctr001"


def write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def valid_finding() -> dict:
    return {
        "finding_id": "TB-001",
        "finding_status": "confirmed_static",
        "source": {"track": "B", "tool": "track-b-ai", "analysis_dimension": "dangerous_functions", "agent_id": "track-b-ai"},
        "vulnerability": {"title": "Unchecked copy into fixed stack buffer", "cwe_id": "CWE-120", "severity": "high", "confidence": 0.78},
        "confidence_breakdown": {
            "evidence": 0.8,
            "reachability": 0.7,
            "tool_reliability": 0.7,
            "verification": 0.5,
            "final": 0.78,
            "caps_applied": [],
            "adjustments": [],
            "reason": "static evidence only",
        },
        "location": {"binary": "/usr/bin/sample", "function": "parse", "address_offset": "0x401000"},
        "evidence": {"description": "The function copies input into a fixed buffer without a visible length guard.", "supporting_files": ["context/evidence.json"]},
        "attack_surface": {"type": "cli", "entry_point": "/usr/bin/sample"},
        "verification": {"poc_status": "untested"},
        "remediation": {"suggestion": "Use bounded parsing and reject oversized input before copying.", "effort": "medium"},
        "references": [],
        "metadata": {"scan_id": SCAN_ID, "detection_time_ms": 1, "tool_version": "fixture"},
    }


def populate_contract_files(scan: Path) -> None:
    finding = valid_finding()
    write(scan / "env_check.json", {"checked_at": "2026-07-07T00:00:00Z", "platform": "linux", "offline_mode": True, "check_only": True, "package_type": "deb", "package_manager": "apt", "tools": [], "path_patched": False, "path_warnings": [], "extended_dirs_scanned": [], "rootfs_status": "not_imported", "engine_status": "unavailable", "block_decision": {"blocked": False, "blocked_tools": [], "install_hints": [], "warnings": [], "phase_blocks": []}, "confidence_ceiling": 0.8, "output_path": str(scan / "env_check.json")})
    write(scan / "target_profile.json", {"scan_id": SCAN_ID, "package": {"path": "/tmp/sample.deb", "type": "deb", "name": "sample", "version": "", "architecture": "script", "size_bytes": 1}, "extraction": {"status": "success", "root": str(scan / "extracted"), "method": "fixture", "warnings": []}, "binaries": [], "attack_surface": [], "architectures": ["script"], "metadata": {}})
    write(scan / "scan_strategy.json", {"scan_id": SCAN_ID, "mode": "quick", "track_a_tools": [], "track_b_focus": [], "disassembly_engine": "strings_only", "attack_surfaces": [], "estimated_duration_min": 1, "token_budget": 1})
    write(scan / "coverage_plan.json", {"scan_id": SCAN_ID, "mode": "quick", "targets": [], "tracks": {"track_a": [], "track_b": []}, "limits": {}})
    write(scan / "sandbox_status.json", {"base_image_ref": "bbh-base:local", "base_image_source": "imported_rootfs_tarball", "docker_available": False, "podman_available": False, "sandbox_ready": False, "engine": "none", "limitations": []})
    (scan / "extracted").mkdir()
    write(scan / "track_a_findings.json", {"agent_id": "track-a", "agent_role": "traditional-tooling", "phase": "track_a", "status": "skipped", "findings": [], "findings_count": 0, "warnings": [], "execution_time_ms": 0, "metadata": {}})
    (scan / "raw" / "track_a").mkdir(parents=True)
    write(scan / "track_b_findings.json", {"agent_id": "track-b", "agent_role": "ai-binary-analysis", "phase": "track_b", "status": "success", "findings": [finding], "findings_count": 1, "warnings": [], "execution_time_ms": 0, "metadata": {}})
    write(scan / "merged_findings.json", {"merged_findings": [{"finding": finding, "dedup_info": {"merged_from": ["TB-001"], "rule": "single-source", "signal_refs": []}}], "dedup_stats": {"input_findings": 1, "merged_findings": 1}, "confidence_scores": {"TB-001": finding["confidence_breakdown"]}, "lifecycle_stats": {"candidate": 0, "confirmed_static": 1, "verified": 0, "false_positive": 0, "inconclusive": 0}, "coverage_summary": {}})
    write(scan / "coverage_report.json", {"binary_coverage_pct": 100, "config_coverage_pct": 100, "dependency_coverage_pct": 0, "attack_surface_coverage_pct": 100, "tool_coverage_pct": 0, "gaps": []})
    skipped = dict(finding)
    skipped["verification"] = {"poc_status": "skipped", "failure_reason": "sandbox unavailable"}
    write(scan / "verified_findings.json", {"verified_findings": [{"finding": skipped, "poc_result": {"status": "skipped", "reason": "sandbox unavailable"}}], "verification_stats": {"verified": 0, "skipped": 1, "unverified": 1}, "sandbox_info": {"base_image_ref": "bbh-base:local", "base_image_source": "imported_rootfs_tarball", "docker_available": False, "podman_available": False, "sandbox_ready": False, "engine": "none", "limitations": []}})
    (scan / "poc_results").mkdir()
    write(scan / "report" / "findings.json", {"schema_version": 1, "scan_id": SCAN_ID, "findings": [skipped], "summary": {"total": 1, "by_status": {"skipped": 1}}, "generated_at": "2026-07-07T00:00:00Z"})
    (scan / "report" / "blackbox-security-report.md").write_text("# BlackBox Hunter\n", encoding="utf-8")


def test_valid_contracts_pass() -> None:
    with tempfile.TemporaryDirectory() as td:
        scan = Path(td) / SCAN_ID
        scan.mkdir()
        populate_contract_files(scan)
        for phase in ["preflight", "phase_0", "track_a", "track_b", "phase_2", "phase_3", "phase_4"]:
            assert validate_phase_outputs(scan, phase, ROOT / "templates") == []


def test_missing_directory_is_reported() -> None:
    with tempfile.TemporaryDirectory() as td:
        scan = Path(td) / SCAN_ID
        scan.mkdir()
        populate_contract_files(scan)
        (scan / "poc_results").rmdir()
        errors = validate_phase_outputs(scan, "phase_3", ROOT / "templates")
        assert any("poc_results" in error and "missing directory" in error for error in errors), errors


def test_schema_error_is_reported() -> None:
    with tempfile.TemporaryDirectory() as td:
        scan = Path(td) / SCAN_ID
        scan.mkdir()
        populate_contract_files(scan)
        write(scan / "report" / "findings.json", {"findings": []})
        errors = validate_phase_outputs(scan, "phase_4", ROOT / "templates")
        assert any("report/findings.json" in error and "schema" in error for error in errors), errors


def run_all() -> None:
    test_valid_contracts_pass()
    test_missing_directory_is_reported()
    test_schema_error_is_reported()


if __name__ == "__main__":
    run_all()
    print("output contract tests OK")
