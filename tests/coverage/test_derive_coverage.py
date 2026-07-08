#!/usr/bin/env python3
"""Tests for A3: derive coverage_report.json from real scan artifacts."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.coverage.derive_coverage import compute  # noqa: E402


def _finding(binary: str = "gcc", attack_type: str | None = None) -> dict:
    f = {
        "finding_id": "TA-001",
        "location": {"binary": binary},
    }
    if attack_type:
        f["attack_surface"] = {"type": attack_type, "entry_point": attack_type}
    return f


def test_binary_coverage_pct_uses_referenced_binaries() -> None:
    profile = {"binaries": [{"path": "/usr/bin/gcc"}, {"path": "/usr/bin/cc1"}]}
    track_a = {"findings": [_finding("gcc")], "metadata": {}}
    track_b = {"findings": []}
    env = {"block_decision": {}}
    cov = compute(track_a, track_b, profile, env)
    # 1 of 2 binaries produced a signal -> 50%
    assert cov["binary_coverage_pct"] == 50.0, cov


def test_uncovered_binaries_become_gaps() -> None:
    profile = {"binaries": [{"path": "/usr/bin/gcc"}, {"path": "/usr/bin/cc1"}]}
    track_a = {"findings": [_finding("gcc")]}
    track_b = {"findings": []}
    cov = compute(track_a, {}, profile, {})
    kinds = {g["kind"] for g in cov["gaps"]}
    assert "uncovered_binary" in kinds, cov["gaps"]
    uncovered = [g for g in cov["gaps"] if g["kind"] == "uncovered_binary"]
    assert any(g["target"] == "cc1" for g in uncovered), uncovered


def test_missing_adapter_gap_when_tool_not_executed() -> None:
    profile = {"binaries": []}
    track_a = {
        "findings": [],
        "metadata": {"tools_selected": ["cve-bin-tool", "checksec"], "tools_executed": ["cve-bin-tool"]},
    }
    cov = compute(track_a, {}, profile, {})
    missing = [g for g in cov["gaps"] if g["kind"] == "missing_adapter"]
    assert any(g["target"] == "checksec" for g in missing), missing


def test_phase_blocks_preserved_as_gaps() -> None:
    """Back-compat: pre-existing block_decision.phase_blocks must surface."""
    profile = {"binaries": []}
    env = {"block_decision": {"phase_blocks": [{"phase": "phase_3", "tool": "rootfs", "reason": "stale"}]}}
    cov = compute({}, {}, profile, env)
    phase_blocks = [g for g in cov["gaps"] if g["kind"] == "phase_block"]
    assert len(phase_blocks) == 1, phase_blocks
    assert phase_blocks[0]["target"] == "rootfs", phase_blocks[0]
    assert "stale" in phase_blocks[0]["reason"], phase_blocks[0]


def test_attack_surface_coverage_pct() -> None:
    profile = {
        "binaries": [],
        "attack_surface": [{"id": "cli", "type": "cli"}, {"id": "file", "type": "file"}],
    }
    track_a = {"findings": [_finding(attack_type="cli")]}
    cov = compute(track_a, {}, profile, {})
    assert cov["attack_surface_coverage_pct"] == 50.0, cov


def test_tool_coverage_pct() -> None:
    profile = {"binaries": []}
    track_a = {
        "findings": [],
        "metadata": {"tools_selected": ["cve-bin-tool", "checksec"], "tools_executed": ["cve-bin-tool", "checksec"]},
    }
    cov = compute(track_a, {}, profile, {})
    assert cov["tool_coverage_pct"] == 100.0, cov


def test_dependency_coverage_pct() -> None:
    profile = {
        "binaries": [{"path": "/usr/bin/gcc"}],
        "dependencies": [
            {"name": "libgcc", "binary": "/usr/lib/libgcc.so"},
            {"name": "glibc", "binary": "/usr/lib/libc.so"},
        ],
    }
    track_a = {"findings": [_finding("libgcc.so")]}
    cov = compute(track_a, {}, profile, {})
    # libgcc covered, glibc not -> 50%
    assert cov["dependency_coverage_pct"] == 50.0, cov
    uncovered = [g for g in cov["gaps"] if g["kind"] == "uncovered_dependency"]
    assert any(g["target"] == "libc.so" for g in uncovered), uncovered


def test_no_binaries_yields_zero_percent() -> None:
    profile = {"binaries": []}
    cov = compute({}, {}, profile, {})
    assert cov["binary_coverage_pct"] == 0.0, cov


def test_gap_entry_shape() -> None:
    """Every gap entry must be {kind, target, reason} - no exceptions."""
    profile = {"binaries": [{"path": "/usr/bin/a"}, {"path": "/usr/bin/b"}]}
    env = {"block_decision": {"phase_blocks": [{"tool": "rootfs", "reason": "missing"}]}}
    cov = compute({}, {}, profile, env)
    for g in cov["gaps"]:
        assert set(g.keys()) == {"kind", "target", "reason"}, g


def test_main_writes_coverage_report(tmp_path_factory=None) -> None:
    """End-to-end smoke: main() reads artifacts from a scan_root and writes coverage."""
    import subprocess
    with tempfile.TemporaryDirectory() as tmp:
        scan_root = Path(tmp)
        (scan_root / "track_a_findings.json").write_text(json.dumps({
            "findings": [_finding("gcc")],
            "metadata": {"tools_selected": ["cve-bin-tool"], "tools_executed": ["cve-bin-tool"]},
        }), encoding="utf-8")
        (scan_root / "track_b_findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
        (scan_root / "target_profile.json").write_text(json.dumps({"binaries": [{"path": "/usr/bin/gcc"}]}), encoding="utf-8")
        (scan_root / "env_check.json").write_text(json.dumps({"block_decision": {}}), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "coverage" / "derive_coverage.py"),
             "--scan-root", str(scan_root)],
            capture_output=True, text=True, check=True,
        )
        report_path = scan_root / "coverage_report.json"
        assert report_path.exists(), proc.stdout
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["binary_coverage_pct"] == 100.0, report


def run_all() -> None:
    test_binary_coverage_pct_uses_referenced_binaries()
    test_uncovered_binaries_become_gaps()
    test_missing_adapter_gap_when_tool_not_executed()
    test_phase_blocks_preserved_as_gaps()
    test_attack_surface_coverage_pct()
    test_tool_coverage_pct()
    test_dependency_coverage_pct()
    test_no_binaries_yields_zero_percent()
    test_gap_entry_shape()
    test_main_writes_coverage_report()
    print("A3 derive_coverage tests OK (10/10)")


if __name__ == "__main__":
    run_all()