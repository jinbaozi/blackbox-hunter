#!/usr/bin/env python3
"""Tests for B10: stale rootfs hard-blocks the scan.

Verifies that ``tools/preflight.py`` returns ``block_decision.blocked = True``
when ``detect_rootfs`` reports ``status="stale"``, and that the
``STALE_BLOCKS_SCAN=0`` environment variable restores the legacy warning-only
behaviour for users who explicitly opt out.

We patch ``parse_args`` (to point ``--output`` at a tempfile) and
``detect_rootfs`` (to inject the rootfs state) because the preflight hardcodes
its repo root to the actual skill directory
(``Path(__file__).resolve().parent.parent``) and ``main()`` takes no args.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import tools.preflight as preflight_mod  # noqa: E402


def _run_preflight_with_rootfs_status(
    rootfs_status: str,
    *,
    env_extra: dict[str, str] | None = None,
) -> dict:
    """Invoke the preflight ``main`` in-process with a mocked ``detect_rootfs``."""
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "env_check.json"
        # Build a Namespace that mirrors parse_args() output
        fake_args = argparse.Namespace(
            check_only=False, force=False, offline=False, auto_fix=False,
            package_type="", package_path="",
            output=str(out_path), scan_root="",
            registry=str(ROOT / "tools" / "tool_registry.json"),
        )

        # Save env state for the STALE_BLOCKS_SCAN test
        old_env = os.environ.copy()
        try:
            if env_extra:
                os.environ.update(env_extra)

            with mock.patch.object(preflight_mod, "parse_args", return_value=fake_args), \
                 mock.patch.object(preflight_mod, "detect_rootfs", return_value={
                     "rootfs_status": rootfs_status,
                     "imported_image_ref": "bbh-rootfs:v11-2503" if rootfs_status == "imported" else None,
                 }):
                preflight_mod.main()
        finally:
            os.environ.clear()
            os.environ.update(old_env)

        assert out_path.exists(), "preflight did not write env_check.json"
        return json.loads(out_path.read_text(encoding="utf-8"))


def test_stale_rootfs_hard_blocks_scan() -> None:
    """Stale rootfs -> block_decision.blocked must be True."""
    report = _run_preflight_with_rootfs_status("stale")
    bd = report.get("block_decision", {})
    assert bd.get("blocked") is True, bd
    assert "rootfs_image_stale" in (bd.get("reason") or ""), bd
    assert bd.get("stale_blocks_scan") is True, bd
    phase_blocks = bd.get("phase_blocks", [])
    assert any(p.get("phase") == "phase_3" and p.get("tool") == "rootfs" for p in phase_blocks), phase_blocks


def test_not_imported_rootfs_hard_blocks_scan() -> None:
    """not_imported rootfs -> block_decision.blocked must be True (also new in B10)."""
    report = _run_preflight_with_rootfs_status("not_imported")
    bd = report.get("block_decision", {})
    assert bd.get("blocked") is True, bd
    assert "import_rootfs.py" in (bd.get("reason") or ""), bd


def test_missing_rootfs_hard_blocks_scan() -> None:
    """Missing rootfs tarball must still hard-block (pre-existing behaviour)."""
    report = _run_preflight_with_rootfs_status("missing")
    bd = report.get("block_decision", {})
    assert bd.get("blocked") is True, bd
    assert "git lfs pull" in (bd.get("reason") or ""), bd


def test_imported_rootfs_does_not_block() -> None:
    """Healthy imported rootfs must NOT add a stale block."""
    report = _run_preflight_with_rootfs_status("imported")
    bd = report.get("block_decision", {})
    assert "rootfs_image_stale" not in (bd.get("reason") or ""), bd
    assert not any(
        p.get("tool") == "rootfs" and p.get("reason") == "stale"
        for p in bd.get("phase_blocks", [])
    ), bd.get("phase_blocks", [])
    # stale_blocks_scan is only set when we actually went through the stale branch
    # so it should not be present on a healthy imported rootfs.
    assert "stale_blocks_scan" not in bd, bd


def test_stale_rootfs_opt_out_via_env_var() -> None:
    """STALE_BLOCKS_SCAN=0 restores the legacy warning-only behaviour."""
    report = _run_preflight_with_rootfs_status(
        "stale", env_extra={"STALE_BLOCKS_SCAN": "0"}
    )
    bd = report.get("block_decision", {})
    # stale path does NOT escalate to blocked when env says so
    assert bd.get("stale_blocks_scan") is False, bd
    # The stale phase block is still recorded (legacy behaviour) so the report
    # surfaces it but does not block
    phase_blocks = bd.get("phase_blocks", [])
    assert any(p.get("phase") == "phase_3" and p.get("tool") == "rootfs" for p in phase_blocks), phase_blocks
    warnings = bd.get("warnings", [])
    assert any("import_rootfs.py" in w for w in warnings), warnings


def run_all() -> None:
    test_stale_rootfs_hard_blocks_scan()
    test_not_imported_rootfs_hard_blocks_scan()
    test_missing_rootfs_hard_blocks_scan()
    test_imported_rootfs_does_not_block()
    test_stale_rootfs_opt_out_via_env_var()
    print("B10 rootfs stale hard-block tests OK (5/5)")


if __name__ == "__main__":
    run_all()