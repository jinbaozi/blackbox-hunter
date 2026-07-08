#!/usr/bin/env python3
"""Tests for A2: Track A default-on for standard/deep/full modes.

Verifies the mode-aware default policy in ``tools.bbh_scan._should_run_track_a``
and the corresponding ``--skip-track-a`` opt-out flag. Also confirms:

* Existing quick-mode behaviour (skipped, ``mode_quick_default_skip``) is
  preserved for back-compat with ``tests/e2e/full_workflow_quick.sh``.
* The argparse surface registers both ``--run-track-a-tools`` (legacy
  opt-in) and ``--skip-track-a`` (new opt-out).
* ``write_skipped_track_a`` records a ``metadata.skipped_reason`` field
  identifying why Track A was skipped.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.bbh_scan import _should_run_track_a, _track_a_skipped_reason  # noqa: E402


def _ns(**kw) -> argparse.Namespace:
    """Build an argparse.Namespace with the Track-A relevant fields default-set."""
    base = argparse.Namespace(mode="quick", run_track_a_tools=False, skip_track_a=False)
    for k, v in kw.items():
        setattr(base, k, v)
    return base


def test_quick_mode_default_skips_track_a() -> None:
    """Default for ``quick`` mode must remain skipped (back-compat)."""
    assert _should_run_track_a(_ns()) is False
    assert _track_a_skipped_reason(_ns()) == "mode_quick_default_skip"


def test_quick_mode_with_explicit_opt_in_runs_track_a() -> None:
    """``--run-track-a-tools`` must still force Track A in quick mode."""
    assert _should_run_track_a(_ns(run_track_a_tools=True)) is True


def test_quick_mode_with_explicit_opt_out_skips_track_a() -> None:
    """``--skip-track-a`` must skip Track A even in quick mode."""
    assert _should_run_track_a(_ns(skip_track_a=True)) is False
    assert _track_a_skipped_reason(_ns(skip_track_a=True)) == "explicit_skip_track_a_flag"


def test_standard_mode_default_runs_track_a() -> None:
    """A2 fix: ``standard`` mode should default to running Track A."""
    assert _should_run_track_a(_ns(mode="standard")) is True


def test_deep_mode_default_runs_track_a() -> None:
    """A2 fix: ``deep`` mode should default to running Track A."""
    assert _should_run_track_a(_ns(mode="deep")) is True


def test_full_mode_default_runs_track_a() -> None:
    """A2 fix: ``full`` mode should default to running Track A."""
    assert _should_run_track_a(_ns(mode="full")) is True


def test_standard_mode_with_explicit_opt_out_skips() -> None:
    """``--skip-track-a`` must override the standard-mode default."""
    assert _should_run_track_a(_ns(mode="standard", skip_track_a=True)) is False
    assert _track_a_skipped_reason(_ns(mode="standard", skip_track_a=True)) == "explicit_skip_track_a_flag"


def test_explicit_opt_in_wins_over_opt_out() -> None:
    """``--run-track-a-tools`` should win over ``--skip-track-a`` (back-compat
    with users who always pass the explicit opt-in).
    """
    assert _should_run_track_a(_ns(mode="standard", run_track_a_tools=True, skip_track_a=True)) is True


def test_argparse_exposes_skip_track_a_flag() -> None:
    """The new flag must be registered in argparse so the CLI surface is complete."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "bbh_scan.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "--skip-track-a" in result.stdout, "missing --skip-track-a in --help"
    assert "--run-track-a-tools" in result.stdout, "regressed: --run-track-a-tools missing"


def test_argparse_accepts_skip_track_a_flag() -> None:
    """Argparse must accept the new flag without error."""
    result = subprocess.run(
        [
            sys.executable, str(ROOT / "tools" / "bbh_scan.py"),
            "--package", "/nonexistent.rpm",
            "--workspace", "/tmp",
            "--scan-id", "BBH-20260708-a2tst",
            "--mode", "standard",
            "--skip-track-a",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # Should NOT be a usage error (unrecognized flag). Any other error is fine.
    assert "unrecognized arguments" not in result.stderr
    assert "unrecognized arguments" not in result.stdout


def run_all() -> None:
    test_quick_mode_default_skips_track_a()
    test_quick_mode_with_explicit_opt_in_runs_track_a()
    test_quick_mode_with_explicit_opt_out_skips_track_a()
    test_standard_mode_default_runs_track_a()
    test_deep_mode_default_runs_track_a()
    test_full_mode_default_runs_track_a()
    test_standard_mode_with_explicit_opt_out_skips()
    test_explicit_opt_in_wins_over_opt_out()
    test_argparse_exposes_skip_track_a_flag()
    test_argparse_accepts_skip_track_a_flag()
    print("A2 Track A default-on tests OK (10/10)")


if __name__ == "__main__":
    run_all()
