#!/usr/bin/env python3
"""Manifest-driven Track B prompt builder.

This module builds cache-friendly, minimal prompts from stable prompt cards and
bounded evidence slices. It does not read README.md, full raw artifacts, or
unrelated dimension cards.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    from tools.context.context_manifest import ContextManifest, make_context_id, write_context_manifest
    from tools.context.evidence_trimmer import wrap_untrusted_evidence
    from tools.context.token_budget import ensure_within_budget, estimate_tokens
except ModuleNotFoundError:  # allow direct execution from tools/context
    from context_manifest import ContextManifest, make_context_id, write_context_manifest
    from evidence_trimmer import wrap_untrusted_evidence
    from token_budget import ensure_within_budget, estimate_tokens


@dataclass
class BuiltPrompt:
    prompt: str
    loaded_files: list[str]
    excluded_files: list[str]
    untrusted_sources: list[str]
    estimated_tokens: int
    max_prompt_tokens: int
    context_profile: str
    context_manifest_path: str | None = None

    def metadata(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("prompt", None)
        return payload


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_text(root: Path, rel_path: str) -> str:
    path = root / rel_path
    if not path.is_file():
        raise FileNotFoundError(f"prompt component not found: {rel_path}")
    return path.read_text(encoding="utf-8")


def resolve_mode_dimensions(manifest: dict[str, Any], mode: str) -> list[str]:
    selection = manifest["mode_defaults"][mode]
    if isinstance(selection, list):
        return selection
    if selection == "core_dimensions":
        return manifest["core_dimensions"]
    if selection == "all_dimensions":
        return manifest["core_dimensions"] + manifest.get("extended_dimensions", [])
    raise ValueError(f"unsupported dimension selection alias: {selection}")


def max_tokens_for_mode(policy: dict[str, Any], mode: str, fallback: int) -> int:
    track_b = policy.get("track_b") or {}
    mode_policy = track_b.get(mode) or {}
    return int(mode_policy.get("max_prompt_tokens_per_call") or fallback)


def validate_dimension_allowed(manifest: dict[str, Any], mode: str, dimension: str) -> None:
    if dimension not in manifest["dimensions"]:
        raise ValueError(f"unknown Track B dimension: {dimension}")
    allowed = set(resolve_mode_dimensions(manifest, mode))
    if dimension not in allowed:
        raise ValueError(f"dimension {dimension!r} is not enabled for mode {mode!r}")


def build_track_b_prompt(
    *,
    root: Path,
    manifest_path: Path,
    context_policy_path: Path,
    dimension: str,
    evidence_json: dict[str, Any],
    mode: str,
    scan_id: str | None = None,
    target: str | None = None,
    function: str | None = None,
    context_manifest_path: Path | None = None,
) -> BuiltPrompt:
    manifest = load_json(manifest_path)
    policy = load_json(context_policy_path)
    validate_dimension_allowed(manifest, mode, dimension)

    dimension_spec = manifest["dimensions"][dimension]
    loaded_files = [
        manifest["base_contract"],
        manifest["evidence_wrapper"],
        manifest["output_contract"],
        dimension_spec["path"],
    ]

    stable_prefix = "\n\n".join(load_text(root, item) for item in loaded_files)
    evidence_kind = evidence_json.get("dimension") or dimension
    evidence_source = ",".join(evidence_json.get("supporting_files") or ["bounded_evidence_slice"])
    evidence_block = wrap_untrusted_evidence(
        evidence_json=evidence_json,
        source=evidence_source,
        kind=str(evidence_kind),
    )

    dynamic_suffix = f"""
# Runtime Parameters

mode: {mode}
dimension: {dimension}
target: {target or evidence_json.get('binary', '')}
function: {function or evidence_json.get('function', '')}

# Bounded Evidence Slice

{evidence_block}
""".strip()

    prompt = stable_prefix + "\n\n" + dynamic_suffix + "\n"
    estimated = estimate_tokens(prompt)
    max_tokens = min(
        max_tokens_for_mode(policy, mode, fallback=policy.get("default", {}).get("max_prompt_tokens", 6000)),
        int(dimension_spec["max_context_tokens"]) + estimate_tokens(stable_prefix) + 256,
    )
    ensure_within_budget(estimated_tokens=estimated, max_tokens=max_tokens, label=f"track_b.{dimension}")

    excluded_files = [
        "README.md",
        "raw/**",
        "$SCAN_ROOT/raw/**",
        "$SCAN_ROOT/logs/**",
        "unrelated Track B dimension cards",
    ]
    untrusted_sources = list(evidence_json.get("supporting_files") or [])
    context_profile = f"track_b.v{manifest['version']}.{dimension}"

    written_manifest_path: str | None = None
    if context_manifest_path is not None:
        context_id = make_context_id(
            scan_id=scan_id,
            phase="track_b",
            dimension=dimension,
            target=target or evidence_json.get("binary"),
            function=function or evidence_json.get("function"),
        )
        manifest_record = ContextManifest(
            context_id=context_id,
            phase="track_b",
            dimension=dimension,
            target=target or evidence_json.get("binary"),
            function=function or evidence_json.get("function"),
            loaded_files=loaded_files,
            excluded_files=excluded_files,
            untrusted_sources=untrusted_sources,
            token_budget={"max": max_tokens, "estimated": estimated},
            injection_findings=[],
            context_profile=context_profile,
        )
        write_context_manifest(context_manifest_path, manifest_record)
        written_manifest_path = str(context_manifest_path)

    return BuiltPrompt(
        prompt=prompt,
        loaded_files=loaded_files,
        excluded_files=excluded_files,
        untrusted_sources=untrusted_sources,
        estimated_tokens=estimated,
        max_prompt_tokens=max_tokens,
        context_profile=context_profile,
        context_manifest_path=written_manifest_path,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Track B prompt from manifest and evidence slice")
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest", default="prompts/track_b/manifest.json")
    parser.add_argument("--context-policy", default="tools/context/context_policy.json")
    parser.add_argument("--dimension", required=True)
    parser.add_argument("--mode", required=True, choices=["quick", "standard", "deep", "full"])
    parser.add_argument("--evidence", required=True, help="Path to bounded evidence JSON")
    parser.add_argument("--scan-id", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--function", default="")
    parser.add_argument("--context-manifest", default="")
    parser.add_argument("--output", required=True, help="Prompt output path")
    parser.add_argument("--metadata-output", default="", help="Optional JSON metadata output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    evidence = load_json(Path(args.evidence).resolve())
    built = build_track_b_prompt(
        root=root,
        manifest_path=(root / args.manifest).resolve(),
        context_policy_path=(root / args.context_policy).resolve(),
        dimension=args.dimension,
        evidence_json=evidence,
        mode=args.mode,
        scan_id=args.scan_id or None,
        target=args.target or None,
        function=args.function or None,
        context_manifest_path=Path(args.context_manifest).resolve() if args.context_manifest else None,
    )

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(built.prompt, encoding="utf-8")

    if args.metadata_output:
        metadata = Path(args.metadata_output).resolve()
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text(json.dumps(built.metadata(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
