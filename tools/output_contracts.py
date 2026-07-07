#!/usr/bin/env python3
"""Phase output contract validation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PHASE_CONTRACTS: dict[str, dict[str, Any]] = {
    "preflight": {
        "files": {"env_check.json": "env_check.json"},
    },
    "phase_0": {
        "files": {
            "target_profile.json": "target_profile.json",
            "scan_strategy.json": "scan_strategy.json",
            "coverage_plan.json": "coverage_plan.json",
            "sandbox_status.json": "sandbox_status.json",
        },
        "dirs": ["extracted"],
    },
    "track_a": {
        "files": {"track_a_findings.json": "track_findings.json"},
        "dirs": ["raw/track_a"],
    },
    "track_b": {
        "files": {"track_b_findings.json": "track_findings.json"},
    },
    "phase_2": {
        "files": {
            "merged_findings.json": "merged_findings.json",
            "coverage_report.json": "coverage_report.json",
        },
    },
    "phase_3": {
        "files": {"verified_findings.json": "verified_findings.json"},
        "dirs": ["poc_results"],
    },
    "phase_4": {
        "files": {
            "report/blackbox-security-report.md": None,
            "report/findings.json": "report_findings.json",
        },
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_json(schema_name: str, document: dict[str, Any], schemas_dir: Path) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
        try:
            from referencing import Registry, Resource
        except Exception:
            Registry = None
            Resource = None
    except Exception:
        return []

    schema_path = schemas_dir / schema_name
    if not schema_path.is_file():
        return [f"schema missing: {schema_name}"]
    schema = _load_json(schema_path)
    try:
        if Registry is not None:
            resources = []
            for candidate in schemas_dir.glob("*.json"):
                loaded = _load_json(candidate)
                schema_id = loaded.get("$id")
                if schema_id:
                    resources.append((schema_id, Resource.from_contents(loaded)))
                resources.append((candidate.as_uri(), Resource.from_contents(loaded)))
            Draft202012Validator(schema, registry=Registry().with_resources(resources)).validate(document)
        else:
            Draft202012Validator(schema).validate(document)
    except Exception as exc:
        return [f"schema validation failed: {exc.message if hasattr(exc, 'message') else exc}"]
    return []


def validate_phase_outputs(scan_root: Path, phase: str, schemas_dir: Path) -> list[str]:
    contract = PHASE_CONTRACTS.get(phase)
    if not contract:
        return [f"unknown phase contract: {phase}"]

    errors: list[str] = []
    for rel in contract.get("dirs", []):
        path = scan_root / rel
        if not path.is_dir():
            errors.append(f"{rel}: missing directory")

    for rel, schema_name in contract.get("files", {}).items():
        path = scan_root / rel
        if not path.is_file():
            errors.append(f"{rel}: missing file")
            continue
        if path.stat().st_size == 0:
            errors.append(f"{rel}: empty file")
            continue
        if schema_name:
            try:
                document = _load_json(path)
            except json.JSONDecodeError as exc:
                errors.append(f"{rel}: invalid json: {exc}")
                continue
            for schema_error in _validate_json(schema_name, document, schemas_dir):
                errors.append(f"{rel}: {schema_error}")

    return errors
