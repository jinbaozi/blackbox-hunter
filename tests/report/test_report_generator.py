#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.report.report_generator import REQUIRED_SECTION_TITLES, generate_report, validate_required_sections  # noqa: E402


def write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_scan_root(root: Path) -> Path:
    scan = root / "BBH-20260704-report1"
    scan.mkdir()
    write(scan / "env_check.json", {"package_manager": "dnf", "block_decision": {"blocked_tools": [], "warnings": ["yara unavailable: missing"]}})
    write(scan / "target_profile.json", {"scan_id": "BBH-20260704-report1", "package": {"type": "rpm"}, "extraction": {"method": "rpm2cpio+cpio"}, "architectures": ["script"]})
    write(scan / "track_a_findings.json", {"status": "partial", "metadata": {"signals_count": 2}})
    write(scan / "track_b_findings.json", {"status": "success", "metadata": {"dimensions_analyzed": ["dangerous_functions"]}})
    write(scan / "merged_findings.json", {"merged_findings": [], "dedup_stats": {"input_findings": 0, "merged_findings": 0}, "lifecycle_stats": {"verified": 0, "confirmed_static": 0, "candidate": 0, "inconclusive": 0, "false_positive": 0}})
    write(scan / "coverage_report.json", {"gaps": [{"phase": "phase_3", "reason": "docker unavailable"}]})
    write(scan / "sandbox_status.json", {"engine": "none", "limitations": ["docker unavailable"]})
    write(scan / "verified_findings.json", {"verification_stats": {"verified": 0, "skipped": 0}, "sandbox_info": {"engine": "none", "limitations": ["docker unavailable"]}})
    write(scan / "scan_state.json", {"scan_id": "BBH-20260704-report1"})
    return scan


def test_report_contains_required_sections() -> None:
    with tempfile.TemporaryDirectory() as td:
        scan = make_scan_root(Path(td))
        report = generate_report(scan)
        assert validate_required_sections(report) == []
        for title in REQUIRED_SECTION_TITLES:
            assert f"## {title}" in report
        assert "## 执行摘要" in report
        assert "## 发现项生命周期汇总" in report
        assert "## 附录证据路径" in report
        assert "Executive Summary" not in report
        assert "Findings by Lifecycle" not in report
        assert "包管理器: dnf" in report
        assert "yara unavailable" in report
        assert "docker unavailable" in report
        assert str(scan / "merged_findings.json") in report


def test_missing_section_detector() -> None:
    missing = validate_required_sections("# 报告\n\n## 执行摘要\n")
    assert "Track A 汇总" in missing


def test_report_localizes_common_display_values() -> None:
    with tempfile.TemporaryDirectory() as td:
        report = generate_report(make_scan_root(Path(td)))
        assert "- 已验证: 0" in report
        assert "- 静态确认: 0" in report
        assert "- 候选: 0" in report
        assert "- 结论不足: 0" in report
        assert "- 误报: 0" in report
        assert "架构: script" in report
        assert "引擎: 无" in report
        assert "未知" not in report


def run_all() -> None:
    test_report_contains_required_sections()
    test_missing_section_detector()
    test_report_localizes_common_display_values()


if __name__ == "__main__":
    run_all()
    print("report generator tests OK")
