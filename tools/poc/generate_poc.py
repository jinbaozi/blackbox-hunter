#!/usr/bin/env python3
"""Auto-generate a PoC script + expected signal from a finding.

Replaces the hand-written ``templates/poc_testcase.md`` workflow with a
deterministic generator that dispatches on ``expected_signal.type``:

* ``crash``            -> ``<binary> <args>`` then echo $?
* ``timeout``          -> ``timeout 5 <binary> <args>``
* ``exit_code``        -> ``<binary> <args>`` assert exact exit code
* ``pattern``          -> ``printf '<pattern>' | <binary>`` (substring match)
* ``unsafe_behavior``  -> stdio fuzz sequence (random-ish payload)

The generator writes three files per finding into
``poc_results/<finding_id>/``:

* ``run.sh``           - the executable harness (chmod 0755)
* ``expected_signal.json`` - the signal the harness expects (matches the
                              ``expected_signal`` shape in
                              ``templates/poc_result.json``)
* ``generated.sh``     - a frozen copy for audit (sha256 + generation time)

Usage::

    python3 tools/poc/generate_poc.py \\
        --finding tests/fixtures/poc_gen/finding_crash.json \\
        --output-root /tmp/bbh/poc_results

The generator refuses to clobber an existing ``run.sh`` unless ``--force``
is passed; this matches the existing Phase 3 contract that ``run.sh`` is
a reviewable artifact before it gets executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any


# Maps expected_signal.type -> a builder returning (run_sh_body, expected_signal)
SIGNAL_BUILDERS: dict[str, str] = {
    "crash": "_build_crash",
    "timeout": "_build_timeout",
    "exit_code": "_build_exit_code",
    "pattern": "_build_pattern",
    "unsafe_behavior": "_build_unsafe_behavior",
}


def _shell_quote(value: str) -> str:
    """Single-quote a string for POSIX shell, escaping embedded single quotes."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _extract_args(finding: dict[str, Any]) -> list[str]:
    """Best-effort argument extraction from attack_surface + reproduction_hint."""
    args: list[str] = []
    attack_surface = finding.get("attack_surface") or {}
    entry = attack_surface.get("entry_point")
    if entry:
        args.extend(shlex.split(str(entry)))
    repro = (finding.get("evidence") or {}).get("reproduction_hint") or ""
    if repro and "--help" not in " ".join(args):
        # Pull out the first command-looking token after the binary name.
        # We deliberately avoid running shlex on the full string because the
        # hint may contain commentary; we take only the first word.
        first = repro.strip().split()
        if first and first[0] not in {"see", "use", "run", "try", "via", "the", "with"}:
            args.append(first[0])
    return args


def _binary_path(finding: dict[str, Any], target: Path | None) -> Path:
    """Resolve the binary to execute; defaults to a workspace-relative path."""
    if target is not None:
        return target
    location = finding.get("location") or {}
    binary = location.get("binary")
    if binary:
        return Path(binary)
    raise ValueError("finding has no location.binary and no --target supplied")


def _build_crash(
    finding: dict[str, Any], target: Path | None
) -> tuple[str, dict[str, Any]]:
    binary = _binary_path(finding, target)
    args = _extract_args(finding)
    body = (
        "#!/bin/sh\n"
        "set -u\n"
        f"binary={_shell_quote(str(binary))}\n"
        f"# crash signal expected: SIGSEGV / SIGABRT / SIGBUS\n"
        f"{_shell_quote(str(binary))} {' '.join(_shell_quote(a) for a in args)}\n"
        "rc=$?\n"
        "echo \"exit_code=$rc\"\n"
        "exit \"$rc\"\n"
    )
    return body, {"type": "crash", "crash_signal": "SIGSEGV"}


def _build_timeout(
    finding: dict[str, Any], target: Path | None
) -> tuple[str, dict[str, Any]]:
    binary = _binary_path(finding, target)
    args = _extract_args(finding)
    body = (
        "#!/bin/sh\n"
        "set -u\n"
        f"binary={_shell_quote(str(binary))}\n"
        f"# expects timeout after 5s\n"
        f"timeout 5 {_shell_quote(str(binary))} {' '.join(_shell_quote(a) for a in args)}\n"
        "rc=$?\n"
        "echo \"exit_code=$rc\"\n"
        "if [ \"$rc\" -eq 124 ]; then\n"
        "  echo TIMEOUT_OBSERVED\n"
        "fi\n"
        "exit \"$rc\"\n"
    )
    return body, {"type": "timeout"}


def _build_exit_code(
    finding: dict[str, Any], target: Path | None
) -> tuple[str, dict[str, Any]]:
    binary = _binary_path(finding, target)
    args = _extract_args(finding)
    expected = int((finding.get("verification") or {}).get("expected_exit_code", 1))
    body = (
        "#!/bin/sh\n"
        "set -u\n"
        f"binary={_shell_quote(str(binary))}\n"
        f"# expects exact exit code {expected}\n"
        f"{_shell_quote(str(binary))} {' '.join(_shell_quote(a) for a in args)}\n"
        "rc=$?\n"
        "echo \"exit_code=$rc expected={expected}\"\n".format(expected=expected) +
        f"if [ \"$rc\" -ne {expected} ]; then\n"
        "  echo EXIT_CODE_MISMATCH\n"
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    )
    return body, {"type": "exit_code", "exit_code": expected}


def _build_pattern(
    finding: dict[str, Any], target: Path | None
) -> tuple[str, dict[str, Any]]:
    binary = _binary_path(finding, target)
    args = _extract_args(finding)
    pattern = str((finding.get("evidence") or {}).get("pattern") or "POC_PATTERN")
    # We deliberately echo the pattern BOTH on stdin and in argv: the
    # runner_result_interpreter accepts either stdout/stderr matching.
    body = (
        "#!/bin/sh\n"
        "set -u\n"
        f"binary={_shell_quote(str(binary))}\n"
        f"# expects to see '{pattern}' on stdout/stderr\n"
        f"printf '%s\\n' {_shell_quote(pattern)} | {_shell_quote(str(binary))} "
        f"{' '.join(_shell_quote(a) for a in args)}\n"
        "rc=$?\n"
        "echo \"exit_code=$rc\"\n"
        "exit \"$rc\"\n"
    )
    return body, {"type": "pattern", "pattern": pattern}


def _build_unsafe_behavior(
    finding: dict[str, Any], target: Path | None
) -> tuple[str, dict[str, Any]]:
    binary = _binary_path(finding, target)
    args = _extract_args(finding)
    payload = (finding.get("evidence") or {}).get("unsafe_payload") or "AAAA%n%n%n%n"
    body = (
        "#!/bin/sh\n"
        "set -u\n"
        f"binary={_shell_quote(str(binary))}\n"
        f"# feeds a payload intended to trigger format-string / OOB-write\n"
        f"printf '%s\\n' {_shell_quote(str(payload))} | {_shell_quote(str(binary))} "
        f"{' '.join(_shell_quote(a) for a in args)}\n"
        "rc=$?\n"
        "echo \"exit_code=$rc\"\n"
        "exit \"$rc\"\n"
    )
    return body, {"type": "unsafe_behavior"}


_BUILDERS = {
    "_build_crash": _build_crash,
    "_build_timeout": _build_timeout,
    "_build_exit_code": _build_exit_code,
    "_build_pattern": _build_pattern,
    "_build_unsafe_behavior": _build_unsafe_behavior,
}


def generate(
    finding: dict[str, Any],
    output_root: Path,
    target: Path | None = None,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Generate a PoC for ``finding`` under ``output_root/<finding_id>/``.

    Returns a dict with paths + signal for caller inspection. Raises
    ``FileExistsError`` if ``run.sh`` already exists and ``force`` is False.
    """
    finding_id = str(finding.get("finding_id") or "").strip()
    if not finding_id:
        raise ValueError("finding.finding_id is required")
    sig_type = ((finding.get("verification") or {}).get("expected_signal") or {}).get(
        "type"
    ) or (finding.get("evidence") or {}).get("signal_type")
    if sig_type not in SIGNAL_BUILDERS:
        raise ValueError(
            f"unsupported expected_signal.type: {sig_type!r}; "
            f"supported: {sorted(SIGNAL_BUILDERS)}"
        )

    out_dir = output_root / finding_id
    out_dir.mkdir(parents=True, exist_ok=True)

    run_sh_path = out_dir / "run.sh"
    if run_sh_path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite {run_sh_path} (use --force)")

    builder_name = SIGNAL_BUILDERS[sig_type]
    run_sh_body, signal = _BUILDERS[builder_name](finding, target)
    run_sh_path.write_text(run_sh_body, encoding="utf-8")
    os.chmod(run_sh_path, 0o755)

    signal_path = out_dir / "expected_signal.json"
    signal_path.write_text(
        json.dumps(signal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    sha = hashlib.sha256(run_sh_body.encode("utf-8")).hexdigest()
    audit = {
        "finding_id": finding_id,
        "signal_type": sig_type,
        "run_sh_sha256": sha,
        "generated_at_epoch": int(os.environ.get("SOURCE_DATE_EPOCH", "0")) or None,
    }
    # Drop None so sort_keys doesn't choke (same defensive idiom used elsewhere)
    audit = {k: v for k, v in audit.items() if v is not None}
    (out_dir / "generated.sh").write_text(
        "#!/bin/sh\n# Generated PoC metadata (audit trail)\n"
        + "".join(f"# {k}={v}\n" for k, v in audit.items())
        + run_sh_body,
        encoding="utf-8",
    )
    os.chmod(out_dir / "generated.sh", 0o644)

    return {
        "finding_id": finding_id,
        "output_dir": str(out_dir),
        "run_sh": str(run_sh_path),
        "expected_signal": signal,
        "expected_signal_path": str(signal_path),
        "run_sh_sha256": sha,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--finding", required=True, help="Path to finding JSON")
    parser.add_argument(
        "--output-root", required=True, help="Where to write poc_results/<id>/"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Override location.binary (when finding is metadata-only)",
    )
    parser.add_argument(
        "--force", action="store_true", help="Overwrite existing run.sh"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    target = Path(args.target) if args.target else None
    result = generate(finding, Path(args.output_root), target=target, force=args.force)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())