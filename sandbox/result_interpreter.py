#!/usr/bin/env python3
"""Interpret sandbox runner results against expected PoC signals."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


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

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _path_text(path_value: str | None) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _evidence_paths(runner: RunnerResult) -> list[str]:
    paths = [runner.stdout_path, runner.stderr_path, runner.monitor_path, runner.pre_state_path, runner.post_state_path]
    return [str(item) for item in paths if item]


def _combined_output(runner: RunnerResult) -> str:
    return _path_text(runner.stdout_path) + "\n" + _path_text(runner.stderr_path)


def interpret_result(expected: ExpectedSignal, runner: RunnerResult) -> VerificationDecision:
    evidence = _evidence_paths(runner)
    status = runner.status
    if status == "sandbox_error":
        return VerificationDecision("sandbox_error", "confirmed_static", runner.failure_reason or "sandbox infrastructure failed", evidence, timeout=runner.timeout)
    if status == "poc_error":
        return VerificationDecision("poc_error", "confirmed_static", runner.failure_reason or "PoC artifact failed before exercising target", evidence, timeout=runner.timeout)
    if runner.timeout:
        if expected.type == "timeout":
            return VerificationDecision("verified", "verified", "expected timeout/hang signal observed", evidence, timeout=True)
        return VerificationDecision("inconclusive", "confirmed_static", "PoC timed out before expected signal was confirmed", evidence, timeout=True)
    if expected.type == "crash" and (status == "crash" or runner.exit_code > 128):
        if expected.crash_signal and runner.crash_signal and expected.crash_signal != runner.crash_signal:
            return VerificationDecision("inconclusive", "confirmed_static", "crash observed but signal did not match expected signal", evidence, runner.crash_signal, False)
        return VerificationDecision("verified", "verified", "expected crash signal observed", evidence, runner.crash_signal, False)
    if expected.type == "exit_code" and expected.exit_code is not None and runner.exit_code == expected.exit_code:
        return VerificationDecision("verified", "verified", f"expected exit code observed: {runner.exit_code}", evidence, timeout=False)
    if expected.type == "pattern" and expected.pattern and expected.pattern in _combined_output(runner):
        return VerificationDecision("verified", "verified", "expected output pattern observed", evidence, timeout=False)
    if status == "completed":
        return VerificationDecision("failed", "confirmed_static", "PoC completed but expected verification signal was absent", evidence, timeout=False)
    if status in {"failed", "crash"}:
        return VerificationDecision("inconclusive", "confirmed_static", "runner result did not prove or disprove the finding", evidence, runner.crash_signal, False)
    return VerificationDecision("inconclusive", "confirmed_static", f"unrecognized runner status: {status}", evidence, timeout=runner.timeout)


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
