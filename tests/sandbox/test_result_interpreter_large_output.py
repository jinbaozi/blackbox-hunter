#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandbox.result_interpreter import ExpectedSignal, RunnerResult, interpret_result  # noqa: E402


def make_large_output(tmp: Path, prefix: str = "", suffix: str = "") -> tuple[str, str]:
    stdout = tmp / "stdout.txt"
    stderr = tmp / "stderr.txt"
    stdout.write_text(prefix + ("A" * (1024 * 1024 + 32)) + suffix, encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    return str(stdout), str(stderr)


def test_large_output_pattern_near_start_verified_and_truncated() -> None:
    with tempfile.TemporaryDirectory() as td:
        stdout, stderr = make_large_output(Path(td), prefix="VERIFY_SIGNAL\n")
        decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY_SIGNAL"), RunnerResult(status="completed", exit_code=0, timeout=False, stdout_path=stdout, stderr_path=stderr))
        assert decision.poc_status == "verified"
        assert decision.truncated_output is True


def test_large_output_pattern_after_limit_inconclusive() -> None:
    with tempfile.TemporaryDirectory() as td:
        stdout, stderr = make_large_output(Path(td), suffix="VERIFY_AFTER_LIMIT")
        decision = interpret_result(ExpectedSignal(type="pattern", pattern="VERIFY_AFTER_LIMIT"), RunnerResult(status="completed", exit_code=0, timeout=False, stdout_path=stdout, stderr_path=stderr))
        assert decision.poc_status == "inconclusive"
        assert decision.finding_status == "confirmed_static"
        assert decision.truncated_output is True


def test_large_stderr_does_not_oom() -> None:
    with tempfile.TemporaryDirectory() as td:
        stdout = Path(td) / "stdout.txt"
        stderr = Path(td) / "stderr.txt"
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("B" * (1024 * 1024 + 32), encoding="utf-8")
        decision = interpret_result(ExpectedSignal(type="pattern", pattern="NOPE"), RunnerResult(status="completed", exit_code=0, timeout=False, stdout_path=str(stdout), stderr_path=str(stderr)))
        assert decision.poc_status == "inconclusive"
        assert decision.truncated_output is True


def run_all() -> None:
    test_large_output_pattern_near_start_verified_and_truncated()
    test_large_output_pattern_after_limit_inconclusive()
    test_large_stderr_does_not_oom()


if __name__ == "__main__":
    run_all()
    print("large output interpreter tests OK")
