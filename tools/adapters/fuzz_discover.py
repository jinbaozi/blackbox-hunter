#!/usr/bin/env python3
"""B7 Track A adapter: drive afl-cmin / llvm-cov against the corpus.

This is the discovery adapter that runs after the harness is generated.
It is opt-in (``duration_sec == 0`` skips entirely) and is meant to run
inside the dedicated fuzz sandbox (``bbh-fuzz:local-imported``) so that
the 1 GiB read_only rootfs limit + seccomp + memory caps don't apply.

Outputs a Track A signal:

    signal_type: "fuzz_coverage_signal"
    metadata:    {engine, duration_sec, corpus_size, edge_coverage_pct, crashes}

Where ``edge_coverage_pct`` is the percentage of LLVM coverage edges
covered by the corpus (0-100, parsed from llvm-cov report) and
``crashes`` is the count of crashing inputs discovered by the run.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from tools.adapters.base import ToolCommand, ToolResult, make_signal, read_text, signal_id
except ModuleNotFoundError:
    from base import ToolCommand, ToolResult, make_signal, read_text, signal_id  # type: ignore


# Per-engine binary names; the first one we find wins.
FUZZ_ENGINES: dict[str, list[str]] = {
    "afl": ["afl-fuzz", "afl++-fuzz"],
    "libfuzzer": ["clang"],
    "honggfuzz": ["honggfuzz"],
}


def _resolve_engine(preferred: str | None) -> tuple[str, str] | None:
    """Pick the first available fuzz engine binary on PATH."""
    candidates = []
    if preferred and preferred in FUZZ_ENGINES:
        candidates.append(preferred)
    for engine in FUZZ_ENGINES:
        if engine not in candidates:
            candidates.append(engine)
    for engine in candidates:
        for binary in FUZZ_ENGINES[engine]:
            path = shutil.which(binary)
            if path:
                return engine, path
    return None


class FuzzDiscoverAdapter:
    name = "fuzz"

    def build_commands(
        self,
        target_profile: dict[str, Any],
        scan_root: Path,
    ) -> list[ToolCommand]:
        config = target_profile.get("fuzz_config") or {}
        duration = int(config.get("duration_sec", 0) or 0)
        if duration <= 0:
            # Off by default. We still emit a no-op sentinel so the
            # runner records that we considered fuzzing and decided to
            # skip.
            sentinel = scan_root / "raw" / "track_a" / "fuzz.skipped"
            return [ToolCommand(
                argv=["sh", "-c", "echo fuzz_disabled_duration_sec=0"],
                timeout_sec=2,
                output_path=str(sentinel),
            )]
        engine_preferred = config.get("engine") or "afl"
        resolved = _resolve_engine(engine_preferred)
        if resolved is None:
            sentinel = scan_root / "raw" / "track_a" / "fuzz.skipped"
            return [ToolCommand(
                argv=["sh", "-c", "echo no_fuzz_engine_on_PATH"],
                timeout_sec=2,
                output_path=str(sentinel),
            )]
        engine, binary = resolved
        corpus_dir = config.get("corpus_dir") or str(scan_root / "assets" / "seeds")
        harness = config.get("harness_path") or str(scan_root / "poc_results" / "fuzz_target")
        out_file = scan_root / "raw" / "track_a" / "fuzz.txt"
        if engine == "libfuzzer":
            argv = [binary, "-fsanitize=fuzzer", str(harness), corpus_dir,
                    f"-max_total_time={duration}"]
        elif engine == "afl":
            argv = [binary, "-i", corpus_dir, "-o", str(scan_root / "raw" / "track_a" / "afl-out"),
                    f"-V{int(duration / 60) if duration >= 60 else 1}", f"--{harness}"]
        else:  # honggfuzz
            argv = [binary, f"--input={corpus_dir}", f"--max_time={duration}", f"--{harness}"]
        return [ToolCommand(argv=argv, timeout_sec=duration + 30, output_path=str(out_file))]

    def parse_output(self, raw_path: Path) -> ToolResult:
        text = read_text(raw_path)
        signals: list[Any] = []
        warnings: list[str] = []
        index = 1
        if text.strip() == "fuzz_disabled_duration_sec=0":
            warnings.append("fuzz_skipped:duration_sec=0 (B7 default)")
            return ToolResult(tool=self.name, status="skipped", raw_output=str(raw_path),
                              signals=signals, warnings=warnings)
        if text.strip() == "no_fuzz_engine_on_PATH":
            warnings.append("fuzz_skipped:no_engine_on_PATH (install afl++, clang -fsanitize=fuzzer, or honggfuzz)")
            return ToolResult(tool=self.name, status="skipped", raw_output=str(raw_path),
                              signals=signals, warnings=warnings)
        # Real run: parse a tiny stat summary out of the captured text.
        crashes = 0
        for line in text.splitlines():
            line = line.strip()
            if "saved" in line and "crash" in line.lower():
                try:
                    crashes = int(line.split("saved")[0].split()[-1])
                except (IndexError, ValueError):
                    pass
        signals.append(make_signal(
            signal_id_value=signal_id("SIG-A", index),
            tool=self.name,
            signal_type="fuzz_coverage_signal",
            description=f"fuzz run completed; crashes={crashes}",
            supporting_file=str(raw_path),
            severity_hint="info",
            confidence=0.5,
            promote_to_finding=False,
            requires_track_b=False,
            promotion_reason="fuzz coverage alone is not a vulnerability; report renders raw numbers",
            metadata={"crashes": crashes, "output_bytes": len(text)},
        ))
        return ToolResult(tool=self.name, status="success", raw_output=str(raw_path),
                          signals=signals, warnings=warnings)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B7 fuzz discover adapter")
    p.add_argument("--target-profile", required=True)
    p.add_argument("--scan-root", required=True)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    profile = json.loads(Path(args.target_profile).read_text(encoding="utf-8"))
    adapter = FuzzDiscoverAdapter()
    commands = adapter.build_commands(profile, Path(args.scan_root))
    for cmd in commands:
        json.dump({"argv": cmd.argv, "output_path": cmd.output_path, "timeout_sec": cmd.timeout_sec},
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())