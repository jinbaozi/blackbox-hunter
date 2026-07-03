#!/usr/bin/env python3
"""Interpret sandbox runner results against expected PoC signals."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MAX_OUTPUT_READ_BYTES = 1024 * 1024


@dataclass
class ExpectedSignal:
    type: str
    pattern: str | None = None
    exit_code: int | None = None
    crash_signal: str | None = None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "ExpectedSignal":
        return cls(str(payload.get("type", "")), payload.get("pattern"), payload.get("exit_code"), payload.get("crash_signal"))


@dataclass
class RunnerResult:
    status: str
    exit_code: int
    timeout: bool
    stdout_path: str = ""
    stderr_path: str = ""
    monitor_path: str | None = None
    pre_state_path: str | None = None
    post_state_path: str | None = None
    result_dir: str | None = None
    failure_reason: str | None = None
    crash_signal: str | None = None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "RunnerResult":
        return cls(
            status=str(payload.get("status", "")),
            exit_code=int(payload.get("exit_code", 0)),
            timeout=bool(payload.get("timeout", False)),
            stdout_path=str(payload.get("stdout_path", "")),
            stderr_path=str(payload.get("stderr_path", "")),
            monitor_path=payload.get("monitor_path"),
            pre_state_path=payload.get("pre_state_path"),
            post_state_path=payload.get("post_state_path"),
            result_dir=payload.get("result_dir"),
            failure_reason=payload.get("failure_reason"),
            crash_signal=payload.get("crash_signal"),
        )


@dataclass
class VerificationDecision:
    poc_status: str
    finding_status: str
    reason: str
    evidence_paths: list[str] = field(default_factory=list)
    crash_signal: str | None = None
    timeout: bool = False
    truncated_output: bool = False

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _path_text(path_value: str | None, limit: int = MAX_OUTPUT_READ_BYTES) -> tuple[str, bool]:
    if not path_value:
        return "", False
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return "", False
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def _evidence_paths(runner: RunnerResult) -> list[str]:
    paths = [runner.stdout_path, runner.stderr_path, runner.monitor_path, runner.pre_state_path, runner.post_state_path]
    return [str(item) for item in paths if item]


def _combined_output(runner: RunnerResult) -> tuple[str, bool]:
    stdout, out_truncated = _path_text(runner.stdout_path)
    stderr, err_truncated = _path_text(runner.stderr_path)
    return stdout + "\n" + stderr, out_truncated or err_truncated


def _decision(
    poc_status: str,
    finding_status: str,
    reason: str,
    runner: RunnerResult,
    evidence: list[str],
    *,
    crash_signal: str | None = None,
    truncated_output: bool = False,
) -> VerificationDecision:
    if truncated_output:
        reason = reason + "; stdout/stderr were read with bounded truncation"
    return VerificationDecision(
        poc_status,
        finding_status,
        reason,
        evidence,
        crash_signal=crash_signal,
        timeout=runner.timeout,
        truncated_output=truncated_output,
    )


def interpret_result(expected: ExpectedSignal, runner: RunnerResult) -> VerificationDecision:
    evidence = _evidence_paths(runner)
    status = runner.status
    if status == "sandbox_error":
        return _decision("sandbox_error", "confirmed_static", runner.failure_reason or "sandbox infrastructure failed", runner, evidence)
    if status == "poc_error":
        return _decision("poc_error", "confirmed_static", runner.failure_reason or "PoC artifact failed before exercising target", runner, evidence)
    if runner.timeout:
        if expected.type == "timeout":
            return _decision("verified", "verified", "expected timeout/hang signal observed", runner, evidence)
        return _decision("inconclusive", "confirmed_static", "PoC timed out before expected signal was confirmed", runner, evidence)
    if expected.type == "crash" and (status == "crash" or runner.exit_code > 128):
        if expected.crash_signal and runner.crash_signal and expected.crash_signal != runner.crash_signal:
            return _decision("inconclusive", "confirmed_static", "crash observed but signal did not match expected signal", runner, evidence, crash_signal=runner.crash_signal)
        return _decision("verified", "verified", "expected crash signal observed", runner, evidence, crash_signal=runner.crash_signal)
    if expected.type == "exit_code" and expected.exit_code is not None and runner.exit_code == expected.exit_code:
        return _decision("verified", "verified", f"expected exit code observed: {runner.exit_code}", runner, evidence)
    if expected.type == "pattern" and expected.pattern:
        combined, truncated = _combined_output(runner)
        if expected.pattern in combined:
            return _decision("verified", "verified", "expected output pattern observed", runner, evidence, truncated_output=truncated)
        if truncated:
            return _decision("inconclusive", "confirmed_static", "expected pattern absent from bounded output excerpt", runner, evidence, truncated_output=True)
    if status == "completed":
        return _decision("failed", "confirmed_static", "PoC completed but expected verification signal was absent", runner, evidence)
    if status in {"failed", "crash"}:
        return _decision("inconclusive", "confirmed_static", "runner result did not prove or disprove the finding", runner, evidence, crash_signal=runner.crash_signal)
    return _decision("inconclusive", "confirmed_static", f"unrecognized runner status: {status}", runner, evidence)


def interpret_payload(payload: dict[str, Any]) -> dict[str, Any]:
    expected = ExpectedSignal.from_json(payload.get("expected_signal") or {})
    runner = RunnerResult.from_json(payload.get("runner_result") or {})
    decision = interpret_result(expected, runner)
    return {"expected_signal": asdict(expected), "runner_result": asdict(runner), "decision": decision.to_json()}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interpret sandbox PoC runner result")
    parser.add_argument("input", help="JSON file with expected_signal and runner_result")
    parser.add_argument("--output", default="", help="Optional output JSON path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    result = interpret_payload(payload)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
