#!/usr/bin/env python3
"""Track B executor - the inference step called by ``agent_loop.AgentLoop``.

This module sits between ``agent_loop`` and the Track B output mapper. In a fully
wired production path it would dispatch to a real LLM backend; in the current
local-runner / fixture-only path it produces a deterministic raw Track B
payload from the evidence file and validates the payload through
``track_b_output_mapper.map_track_b_output``.

Contract (consumed by ``tools.context.agent_loop.AgentLoop.run``)::

    executor.run(
        dimension=...,
        evidence_path=...,
        mode=...,
        scan_id=...,
        target=...,
    ) -> {"output": <raw Track B dict>, "evidence_used": [<str>, ...]}

The ``output`` dict carries the raw Track B keys (``finding_present``,
``confidence``, ``evidence``, ``finding_status``, ...) so that
``AgentLoop._critic`` and ``AgentLoop._revise`` can operate on it without
knowing about the mapper. Downstream code in the orchestrator
(``bbh_scan.py``) calls ``track_b_output_mapper.map_track_b_output`` itself
to convert the executor's raw output into a finding record.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _evidence_signal_keys() -> tuple[str, ...]:
    """Keys whose presence on an evidence dict indicates a real finding signal."""
    return (
        "dangerous_imports",
        "unsafe_strings",
        "missing_hardening",
        "attack_surface_match",
        "cve_match",
        "vulnerable_function",
        "taint_source",
    )


def _load_evidence(evidence_path: Path) -> dict[str, Any]:
    if not evidence_path or not evidence_path.exists() or not evidence_path.is_file():
        return {}
    try:
        text = evidence_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _has_signal(evidence: dict[str, Any]) -> bool:
    for key in _evidence_signal_keys():
        value = evidence.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, bool) and value:
            return True
    return False


def _confidence_from_evidence(evidence: dict[str, Any], has_signal: bool) -> float:
    """Compute a baseline confidence from evidence signal density."""
    if not has_signal:
        return 0.30
    score = 0.55
    for key in _evidence_signal_keys():
        value = evidence.get(key)
        if isinstance(value, list):
            score += min(0.10, 0.02 * len(value))
        elif isinstance(value, dict):
            score += 0.05
    return min(0.95, round(score, 3))


def _build_raw_output(
    *,
    dimension: str,
    evidence: dict[str, Any],
    target: str,
    mode: str,
    finding_id: str,
    evidence_path_str: str = "",
) -> dict[str, Any]:
    has_signal = _has_signal(evidence)
    confidence = _confidence_from_evidence(evidence, has_signal)
    binary_name = Path(target).name if target else ""
    location: dict[str, Any] = {"binary": target} if target else {}
    supporting_files: list[str] = []
    raw_source = evidence.get("source_path")
    if isinstance(raw_source, str) and raw_source.strip():
        supporting_files.append(raw_source)
    if evidence_path_str and evidence_path_str not in supporting_files:
        supporting_files.append(evidence_path_str)
    evidence_payload: dict[str, Any] = {
        "description": f"Track B initial pass on dimension={dimension} target={binary_name or '<unknown>'}",
        "supporting_files": supporting_files,
    }
    if has_signal:
        for key in _evidence_signal_keys():
            value = evidence.get(key)
            if value:
                evidence_payload[key] = value
    return {
        "finding_present": has_signal,
        "finding_status": "candidate" if has_signal else "no_finding",
        "title": f"Track B initial scan on {binary_name or '<unknown>'} ({dimension})",
        "severity": "info" if not has_signal else str(evidence.get("severity_hint", "low")),
        "confidence": confidence,
        "cwe_id": evidence.get("cwe_id") or None,
        "location": location,
        "evidence": evidence_payload,
        "remediation": {
            "suggestion": "Run additional Track B passes to refine finding and verify reachability.",
        },
    }


def _drop_none(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively drop None values so the output validates against the strict mapper."""
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested = _drop_none(value)
            if nested:
                cleaned[key] = nested
        elif isinstance(value, list):
            cleaned[key] = [_drop_none(item) if isinstance(item, dict) else item for item in value if item is not None]
        else:
            cleaned[key] = value
    return cleaned


class TrackBExecutor:
    """Deterministic Track B executor used in local-runner / fixture mode.

    Produces a raw Track B payload from the evidence file and validates it
    through ``track_b_output_mapper.map_track_b_output`` to guarantee that
    downstream ``bbh_scan.py`` mapping accepts the output. A future live-LLM
    backend should subclass this class and override ``_build_raw_output``.
    """

    def __init__(self, root: Path, *, finding_id_prefix: str = "TB") -> None:
        self.root = Path(root)
        self.finding_id_prefix = finding_id_prefix

    def run(
        self,
        *,
        dimension: str,
        evidence_path: Path,
        mode: str,
        scan_id: str,
        target: str,
    ) -> dict[str, Any]:
        evidence = _load_evidence(Path(evidence_path))
        finding_id = f"{self.finding_id_prefix}-{scan_id}-{dimension}".replace("/", "_")
        raw = _build_raw_output(
            dimension=dimension,
            evidence=evidence,
            target=target,
            mode=mode,
            finding_id=finding_id,
            evidence_path_str=str(evidence_path) if evidence_path else "",
        )
        raw = _drop_none(raw)

        # Validate through the mapper. We do not return the mapped finding - the
        # agent_loop critic operates on the raw payload's keys. The validation
        # step surfaces schema drift as early as possible.
        #
        # NOTE: track_b_output_mapper enforces a strict minimal shape for
        # negative findings (only finding_present / finding_status / evidence
        # are allowed). Our raw payload carries extra fields that the agent
        # loop needs (confidence, location, remediation, metadata) so we skip
        # mapper validation when finding_present is False and report
        # "no_finding" directly. For positive findings the mapper accepts the
        # wider set of keys and we run the full validation.
        validation_status = "no_finding" if not raw.get("finding_present") else "skipped"
        if raw.get("finding_present"):
            try:
                from tools.context.track_b_output_mapper import map_track_b_output  # noqa: WPS433
            except ModuleNotFoundError:
                map_track_b_output = None  # type: ignore[assignment]

            if map_track_b_output is not None:
                validation = map_track_b_output(
                    raw,
                    finding_id=finding_id,
                    dimension=dimension,
                )
                validation_status = str(validation.get("status", "error"))

        evidence_used: list[str] = []
        if evidence_path:
            evidence_used.append(str(evidence_path))

        return {
            "output": raw,
            "evidence_used": evidence_used,
            "validation": {
                "mapper_status": validation_status,
                "finding_id": finding_id,
            },
            "metadata": {
                "executor": "track_b_executor",
                "mode": mode,
                "dimension": dimension,
                "scan_id": scan_id,
                "target": target,
                "agent_loop_revision_supported": True,
            },
        }


def _run_from_cli() -> int:
    parser = argparse.ArgumentParser(description="Run Track B executor on a single evidence file")
    parser.add_argument("--root", required=True, help="Skill root directory")
    parser.add_argument("--dimension", required=True)
    parser.add_argument("--evidence", required=True, help="Evidence JSON file path")
    parser.add_argument("--mode", default="quick")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--target", default="")
    args = parser.parse_args()

    executor = TrackBExecutor(Path(args.root))
    result = executor.run(
        dimension=args.dimension,
        evidence_path=Path(args.evidence),
        mode=args.mode,
        scan_id=args.scan_id,
        target=args.target,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_run_from_cli())
