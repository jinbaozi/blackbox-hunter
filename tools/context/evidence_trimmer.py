#!/usr/bin/env python3
"""Build bounded evidence slices for LLM-visible Track B prompts.

Full raw artifacts stay on disk. This module emits a compact evidence slice
containing bounded excerpts, supporting file paths, and prompt-injection filter
metadata for untrusted target-derived evidence.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    from tools.context.injection_filter import detect_injection
except ModuleNotFoundError:  # allow direct execution from tools/context
    from injection_filter import detect_injection


TRUNCATION_MARKER = "\n\n...[TRUNCATED: full artifact retained on disk]...\n\n"


@dataclass
class EvidenceSlice:
    binary: str
    dimension: str
    function: str | None = None
    address: str | None = None
    architecture: str | None = None
    attack_surface: dict[str, Any] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    xrefs_summary: list[str] = field(default_factory=list)
    body_excerpt: str = ""
    supporting_files: list[str] = field(default_factory=list)
    omitted: dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    suspicious: bool = False
    injection_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def trim_text(text: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if len(text) <= max_chars:
        return text, False
    if max_chars <= len(TRUNCATION_MARKER) + 20:
        return text[:max_chars], True
    half = (max_chars - len(TRUNCATION_MARKER)) // 2
    return text[:half] + TRUNCATION_MARKER + text[-half:], True


def read_artifact_excerpt(path: Path, max_chars: int) -> tuple[str, bool, dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    injection_result = detect_injection(text).to_json()
    excerpt, truncated = trim_text(text, max_chars)
    return f"### {path}\n{excerpt}", truncated, injection_result


def build_evidence_slice(
    *,
    binary: str,
    dimension: str,
    raw_paths: list[Path],
    function: str | None = None,
    address: str | None = None,
    architecture: str | None = None,
    attack_surface: dict[str, Any] | None = None,
    imports: list[str] | None = None,
    xrefs_summary: list[str] | None = None,
    max_excerpt_chars: int = 12000,
) -> EvidenceSlice:
    if max_excerpt_chars <= 0:
        raise ValueError("max_excerpt_chars must be positive")

    existing_paths = [path for path in raw_paths if path.exists() and path.is_file()]
    per_file_budget = max(1, max_excerpt_chars // max(1, len(existing_paths)))

    excerpts: list[str] = []
    supporting_files: list[str] = []
    omitted: dict[str, str] = {}
    injection_findings: list[dict[str, Any]] = []
    any_truncated = False
    any_suspicious = False

    for path in existing_paths:
        excerpt, truncated, injection_result = read_artifact_excerpt(path, per_file_budget)
        excerpts.append(excerpt)
        supporting_files.append(str(path))
        if truncated:
            omitted[str(path)] = "full artifact retained on disk; excerpt was truncated"
            any_truncated = True
        if injection_result.get("suspicious"):
            any_suspicious = True
            injection_findings.append({"source": str(path), **injection_result})

    missing_paths = [path for path in raw_paths if path not in existing_paths]
    for path in missing_paths:
        omitted[str(path)] = "artifact missing when evidence slice was built"

    return EvidenceSlice(
        binary=binary,
        dimension=dimension,
        function=function,
        address=address,
        architecture=architecture,
        attack_surface=attack_surface or {},
        imports=imports or [],
        xrefs_summary=xrefs_summary or [],
        body_excerpt="\n\n".join(excerpts),
        supporting_files=supporting_files,
        omitted=omitted,
        truncated=any_truncated,
        suspicious=any_suspicious,
        injection_findings=injection_findings,
    )


def wrap_untrusted_evidence(*, evidence_json: dict[str, Any], source: str = "bounded_evidence_slice", kind: str = "metadata") -> str:
    payload = json.dumps(evidence_json, ensure_ascii=False, indent=2, sort_keys=True)
    return (
        f'<UNTRUSTED_EVIDENCE source="{source}" kind="{kind}">\n'
        f"{payload}\n"
        "</UNTRUSTED_EVIDENCE>"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a bounded BlackBox Hunter evidence slice")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--dimension", required=True)
    parser.add_argument("--function", default="")
    parser.add_argument("--address", default="")
    parser.add_argument("--architecture", default="")
    parser.add_argument("--max-excerpt-chars", type=int, default=12000)
    parser.add_argument("--raw", action="append", default=[], help="Raw artifact path; may be supplied multiple times")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    evidence = build_evidence_slice(
        binary=args.binary,
        dimension=args.dimension,
        function=args.function or None,
        address=args.address or None,
        architecture=args.architecture or None,
        raw_paths=[Path(item) for item in args.raw],
        max_excerpt_chars=args.max_excerpt_chars,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence.to_json(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
