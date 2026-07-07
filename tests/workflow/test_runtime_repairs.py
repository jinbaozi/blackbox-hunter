#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import bbh_scan  # noqa: E402
from tools import preflight  # noqa: E402


def test_auto_rootfs_import_runs_importer_and_reruns_preflight(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    calls: list[str] = []
    args = argparse.Namespace(registry="", no_auto_rootfs_import=False)
    package = tmp_path / "pkg.deb"
    package.write_text("fixture", encoding="utf-8")

    def fake_import(scan_root: Path) -> None:
        calls.append(f"import:{scan_root.name}")

    def fake_preflight(args_obj, scan_root: Path, package_type: str, package_path: Path):
        calls.append(f"preflight:{package_type}:{package_path.name}")
        return {
            "rootfs_status": "imported",
            "engine_status": "ready",
            "imported_image_ref": "bbh-base:local-imported",
            "block_decision": {"blocked": False, "phase_blocks": []},
        }

    bbh_scan.run_rootfs_import = fake_import  # type: ignore[attr-defined]
    bbh_scan.run_preflight = fake_preflight  # type: ignore[assignment]
    initial_env = {
        "rootfs_status": "not_imported",
        "engine_status": "ready",
        "block_decision": {"blocked": False, "phase_blocks": [{"phase": "phase_3", "tool": "rootfs", "reason": "not_imported"}]},
    }

    env = bbh_scan.ensure_rootfs_imported(args, tmp_path / "scan", "deb", package, initial_env)

    assert calls == ["import:scan", "preflight:deb:pkg.deb"]
    assert env["rootfs_status"] == "imported"


def test_phase3_sandbox_failure_without_status_is_failed(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    (scan_root / "extracted").mkdir()
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bbh_scan.write_json(
        scan_root / "sandbox_status.json",
        {
            "base_image_ref": "bbh-base:local-imported",
            "base_image_source": "imported_rootfs_tarball",
            "docker_available": True,
            "podman_available": False,
            "sandbox_ready": True,
            "engine": "docker",
            "limitations": [],
        },
    )
    bbh_scan.write_json(scan_root / "merged_findings.json", {"merged_findings": []})
    args = argparse.Namespace(
        scan_id="BBH-20260707-test",
        poc_dir=str(tmp_path / "poc"),
        poc_script="/poc/run.sh",
        poc_timeout=30,
        poc_severity="medium",
        poc_approved=False,
    )

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(["docker"], 125, "", "compose failed")

    original_run = bbh_scan.subprocess.run
    bbh_scan.subprocess.run = fake_run  # type: ignore[assignment]
    try:
        result = bbh_scan.run_phase3_sandbox(args, scan_root)
    finally:
        bbh_scan.subprocess.run = original_run  # type: ignore[assignment]

    assert result["status"] == "sandbox_error"
    assert (scan_root / "poc_results" / "status.txt").read_text(encoding="utf-8").strip() == "sandbox_error"


def test_preflight_engine_block_uses_diagnostic_reason() -> None:
    decision = {"blocked": False, "phase_blocks": [], "reason": ""}

    preflight.reconcile_engine_phase_blocks(decision, "unavailable")

    block = decision["phase_blocks"][0]
    assert block["phase"] == "phase_3"
    assert block["tool"] == "docker"
    assert block["reason"] == "daemon_unreachable"


def run_all() -> None:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        test_auto_rootfs_import_runs_importer_and_reruns_preflight(Path(tmp) / "auto")
    with TemporaryDirectory() as tmp:
        test_phase3_sandbox_failure_without_status_is_failed(Path(tmp) / "phase3")
    test_preflight_engine_block_uses_diagnostic_reason()


if __name__ == "__main__":
    run_all()
    print("runtime repair workflow tests OK")
