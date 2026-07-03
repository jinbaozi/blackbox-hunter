#!/usr/bin/env python3
"""Base types and helpers for Track A tool adapters."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class ToolCommand:
    argv: list[str]
    timeout_sec: int
    output_path: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingSignal:
    signal_id: str
    source: dict[str, Any]
    signal_type: str
    location: dict[str, Any]
    evidence: dict[str, Any]
    promotion: dict[str, Any]
    severity_hint: str = "info"
    confidence: float = 0.0
    cwe_id: str | None = None
    cve_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        return {key: value for key, value in payload.items() if value not in (None, {}, [])}


@dataclass
class ToolResult:
    tool: str
    status: str
    raw_output: str
    signals: list[FindingSignal]
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "raw_output": self.raw_output,
            "signals": [signal.to_json() for signal in self.signals],
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class TrackAAdapter(Protocol):
    name: str

    def build_commands(self, target_profile: dict[str, Any], scan_root: Path) -> list[ToolCommand]:
        ...

    def parse_output(self, raw_path: Path) -> ToolResult:
        ...


def signal_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def make_signal(
    *,
    signal_id_value: str,
    tool: str,
    signal_type: str,
    description: str,
    supporting_file: str,
    location: dict[str, Any] | None = None,
    severity_hint: str = "info",
    confidence: float = 0.3,
    cwe_id: str | None = None,
    cve_id: str | None = None,
    promote_to_finding: bool = False,
    requires_track_b: bool = True,
    promotion_reason: str = "requires contextual confirmation before promotion",
    metadata: dict[str, Any] | None = None,
) -> FindingSignal:
    return FindingSignal(
        signal_id=signal_id_value,
        source={"track": "A", "tool": tool},
        signal_type=signal_type,
        location=location or {},
        evidence={
            "description": description,
            "supporting_files": [supporting_file],
        },
        promotion={
            "promote_to_finding": promote_to_finding,
            "requires_track_b": requires_track_b,
            "reason": promotion_reason,
        },
        severity_hint=severity_hint,
        confidence=confidence,
        cwe_id=cwe_id,
        cve_id=cve_id,
        metadata=metadata or {},
    )


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def read_json(path: Path) -> Any:
    return json.loads(read_text(path))
