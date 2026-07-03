#!/usr/bin/env python3
"""Runtime context manifest helpers."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class ContextManifest:
    context_id: str
    phase: str
    loaded_files: list[str]
    excluded_files: list[str]
    untrusted_sources: list[str]
    token_budget: dict[str, int]
    dimension: str | None = None
    target: str | None = None
    function: str | None = None
    injection_findings: list[dict[str, Any]] = field(default_factory=list)
    context_profile: str = ""
    created_at: str = ""

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload["created_at"]:
            payload["created_at"] = now_iso()
        return payload


def write_context_manifest(path: Path, manifest: ContextManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.to_json(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_context_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_context_id(*, scan_id: str | None, phase: str, dimension: str | None, target: str | None, function: str | None) -> str:
    parts = [scan_id or "NO-SCAN", phase]
    if dimension:
        parts.append(dimension)
    if target:
        safe_target = target.strip("/").replace("/", "_").replace(" ", "_") or "target"
        parts.append(safe_target[:80])
    if function:
        parts.append(function.replace(" ", "_")[:80])
    return "CTX-" + "-".join(parts)
