#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandbox.result_interpreter import ExpectedSignal, RunnerResult, interpret_payload, interpret_result  # noqa: E402


def make_output(tmp: Path, stdout: str = "", stderr: str = "") -> tuple[str, str]:
    stdout_path = tmp / "stdout.txt"
    stderr_path = tmp / "stderr.txt"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    return str(stdout_path), str(stderr_path)


def test_completed_without_expected_signal_is_failed_not_verified() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        stdout, stderr = make_output(Path(tmp), stdout="normal exit")
        decision = interpret_result(ExpectedSignal(type="pattern", pattern="CRASH"), RunnerResult(status="completed", exit_code=0, timeout=False, stdout_path=stdout, stderr_path=stderr))
        assert decision.poc_status == "failed"
        assert decision.finding_status == "confirmed_static"


def test_pattern_signal_verified() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        stdout, stderr = make_output(Path(tmp), stderr="target emitted VERIFY_SIGNAL")
        decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY_SIGNAL"), RunnerResult(status="completed", exit_code=0, timeout=False, stdout_path=stdout, stderr_path=stderr))
        assert decision.poc_status == "verified"
        assert decision.finding_status == "verified"


def test_crash_signal_verified() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        stdout, stderr = make_output(Path(tmp))
        decision = interpret_result(ExpectedSignal(type="crash", crash_signal="SIGSEGV"), RunnerResult(status="crash", exit_code=139, timeout=False, stdout_path=stdout, stderr_path=stderr, crash_signal="SIGSEGV"))
        assert decision.poc_status == "verified"
        assert decision.finding_status == "verified"
        assert decision.crash_signal == "SIGSEGV"


def test_crash_signal_mismatch_is_inconclusive() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        stdout, stderr = make_output(Path(tmp))
        decision = interpret_result(ExpectedSignal(type="crash", crash_signal="SIGABRT"), RunnerResult(status="crash", exit_code=139, timeout=False, stdout_path=stdout, stderr_path=stderr, crash_signal="SIGSEGV"))
        assert decision.poc_status == "inconclusive"
        assert decision.finding_status == "confirmed_static"


def test_timeout_expected_verified() -> None:
    decision = interpret_result(ExpectedSignal(type="timeout"), RunnerResult(status="timeout", exit_code=124, timeout=True))
    assert decision.poc_status == "verified"
    assert decision.finding_status == "verified"
    assert decision.timeout is True


def test_unexpected_timeout_inconclusive() -> None:
    decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY"), RunnerResult(status="timeout", exit_code=124, timeout=True))
    assert decision.poc_status == "inconclusive"
    assert decision.finding_status == "confirmed_static"


def test_poc_error_is_not_false_positive() -> None:
    decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY"), RunnerResult(status="poc_error", exit_code=1, timeout=False, failure_reason="script missing"))
    assert decision.poc_status == "poc_error"
    assert decision.finding_status == "confirmed_static"


def test_sandbox_error_is_not_false_positive() -> None:
    decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY"), RunnerResult(status="sandbox_error", exit_code=1, timeout=False, failure_reason="image build failed"))
    assert decision.poc_status == "sandbox_error"
    assert decision.finding_status == "confirmed_static"


def test_payload_interpretation() -> None:
    result = interpret_payload({"expected_signal": {"type": "exit_code", "exit_code": 42}, "runner_result": {"status": "failed", "exit_code": 42, "timeout": False}})
    assert result["decision"]["poc_status"] == "verified"
    assert result["decision"]["finding_status"] == "verified"


def run_all() -> None:
    test_completed_without_expected_signal_is_failed_not_verified()
    test_pattern_signal_verified()
    test_crash_signal_verified()
    test_crash_signal_mismatch_is_inconclusive()
    test_timeout_expected_verified()
    test_unexpected_timeout_inconclusive()
    test_poc_error_is_not_false_positive()
    test_sandbox_error_is_not_false_positive()
    test_payload_interpretation()


if __name__ == "__main__":
    run_all()
    print("sandbox result interpreter tests OK")
