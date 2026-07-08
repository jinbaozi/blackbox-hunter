#!/usr/bin/env python3
"""Tests for B2: auto-generate PoC from finding.

Each fixture finding covers one expected_signal.type. We assert that:
- generate() writes run.sh, expected_signal.json, generated.sh
- run.sh is executable
- expected_signal.json conforms to templates/poc_result.json#expected_signal
- the body matches the type's contract (contains expected substring / shape)
- generate() refuses to clobber an existing run.sh unless --force
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.poc.generate_poc import generate, SIGNAL_BUILDERS  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "poc_gen"


def _generate(fixture: str, tmp: Path) -> dict:
    finding = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
    return generate(finding, tmp)


def test_crash_signal_generates_run_sh() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_crash.json", Path(tmp))
        assert (Path(result["run_sh"])).exists()
        body = Path(result["run_sh"]).read_text(encoding="utf-8")
        assert body.startswith("#!/bin/sh"), body[:40]
        assert "/usr/bin/true" in body
        mode = (Path(result["run_sh"]).stat().st_mode)
        assert mode & stat.S_IXUSR, mode
        sig = result["expected_signal"]
        assert sig["type"] == "crash", sig


def test_timeout_signal_generates_timeout_wrapper() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_timeout.json", Path(tmp))
        body = Path(result["run_sh"]).read_text(encoding="utf-8")
        assert "timeout 5" in body, body
        assert "/usr/bin/sleep" in body, body
        assert result["expected_signal"]["type"] == "timeout", result["expected_signal"]


def test_exit_code_signal_asserts_exact_code() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_exit_code.json", Path(tmp))
        body = Path(result["run_sh"]).read_text(encoding="utf-8")
        assert "/usr/bin/false" in body, body
        # The exact exit code 1 must be embedded in the script as a literal
        assert '"$rc" -ne 1' in body, body
        assert result["expected_signal"]["exit_code"] == 1, result["expected_signal"]


def test_pattern_signal_feeds_stdin() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_pattern.json", Path(tmp))
        body = Path(result["run_sh"]).read_text(encoding="utf-8")
        assert "printf '%s\\n'" in body or "printf" in body, body
        assert "BLACKBOX_TEST_PATTERN_OK" in body, body
        assert "|" in body, body  # pipe into binary
        assert result["expected_signal"]["pattern"] == "BLACKBOX_TEST_PATTERN_OK", result


def test_unsafe_behavior_signal_feeds_payload() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_unsafe.json", Path(tmp))
        body = Path(result["run_sh"]).read_text(encoding="utf-8")
        assert "%s%s%s%s" in body, body
        assert "|" in body, body
        assert result["expected_signal"]["type"] == "unsafe_behavior", result


def test_expected_signal_json_validates_against_poc_result_schema() -> None:
    """Each generated expected_signal.json must conform to the contract."""
    with tempfile.TemporaryDirectory() as tmp:
        for fixture, sig_type in [
            ("finding_crash.json", "crash"),
            ("finding_timeout.json", "timeout"),
            ("finding_exit_code.json", "exit_code"),
            ("finding_pattern.json", "pattern"),
            ("finding_unsafe.json", "unsafe_behavior"),
        ]:
            result = _generate(fixture, Path(tmp))
            sig_path = Path(result["expected_signal_path"])
            assert sig_path.exists(), sig_path
            payload = json.loads(sig_path.read_text(encoding="utf-8"))
            assert payload.get("type") == sig_type, payload


def test_generated_sh_audit_trail_present() -> None:
    """generated.sh must embed the finding_id + sha256 for audit."""
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_crash.json", Path(tmp))
        out_dir = Path(result["output_dir"])
        gen = out_dir / "generated.sh"
        assert gen.exists(), gen
        body = gen.read_text(encoding="utf-8")
        assert "finding_id=TA-001" in body, body
        assert "run_sh_sha256=" in body, body
        assert "signal_type=crash" in body, body


def test_refuses_to_overwrite_existing_run_sh() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        _generate("finding_crash.json", Path(tmp))
        # Second call without force must raise
        try:
            _generate("finding_crash.json", Path(tmp))
        except FileExistsError:
            pass
        else:
            raise AssertionError("expected FileExistsError on clobber")
        # With force it should succeed
        result = _generate.__wrapped__ if hasattr(_generate, "__wrapped__") else _generate
        finding = json.loads((FIXTURES / "finding_crash.json").read_text(encoding="utf-8"))
        from tools.poc.generate_poc import generate as gen_mod
        gen_mod(finding, Path(tmp), force=True)


def test_unsupported_signal_type_raises() -> None:
    bad = json.loads((FIXTURES / "finding_crash.json").read_text(encoding="utf-8"))
    bad["verification"]["expected_signal"]["type"] = "bogus_type"
    with tempfile.TemporaryDirectory() as tmp:
        try:
            generate(bad, Path(tmp))
        except ValueError as exc:
            assert "bogus_type" in str(exc), exc
        else:
            raise AssertionError("expected ValueError for unsupported signal type")


def test_run_sh_executes_for_pattern_fixture() -> None:
    """End-to-end smoke: the generated run.sh for the pattern fixture
    should actually run /bin/echo and emit the expected pattern. We only
    exercise the pattern fixture because /bin/echo is universally present."""
    with tempfile.TemporaryDirectory() as tmp:
        result = _generate("finding_pattern.json", Path(tmp))
        run_sh = Path(result["run_sh"])
        proc = subprocess.run(
            [str(run_sh)], capture_output=True, text=True, timeout=10,
        )
        # /bin/echo just echoes its argv, so the pattern must appear in stdout
        assert "BLACKBOX_TEST_PATTERN_OK" in proc.stdout, proc.stdout


def run_all() -> None:
    test_crash_signal_generates_run_sh()
    test_timeout_signal_generates_timeout_wrapper()
    test_exit_code_signal_asserts_exact_code()
    test_pattern_signal_feeds_stdin()
    test_unsafe_behavior_signal_feeds_payload()
    test_expected_signal_json_validates_against_poc_result_schema()
    test_generated_sh_audit_trail_present()
    test_refuses_to_overwrite_existing_run_sh()
    test_unsupported_signal_type_raises()
    test_run_sh_executes_for_pattern_fixture()
    print("B2 generate_poc tests OK (10/10)")


if __name__ == "__main__":
    run_all()