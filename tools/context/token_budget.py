#!/usr/bin/env python3
"""Token budget helpers for BlackBox Hunter runtime context construction."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def estimate_tokens(text: str) -> int:
    """Conservative tokenizer-free approximation.

    This intentionally over-approximates for fail-closed budget checks until a
    model-specific tokenizer is available.
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


@dataclass
class TokenUsageRecord:
    scan_id: str
    phase: str
    dimension: str
    target: str
    function: str | None
    prompt_tokens_estimated: int
    prompt_tokens_actual: int | None = None
    cached_tokens: int | None = None
    completion_tokens: int | None = None
    truncated: bool = False
    context_profile: str = ""
    recorded_at: str = ""

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload["recorded_at"]:
            payload["recorded_at"] = now_iso()
        return payload


def append_token_usage(path: Path, record: TokenUsageRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_json(), ensure_ascii=False, sort_keys=True) + "\n")


def read_token_usage(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def ensure_within_budget(*, estimated_tokens: int, max_tokens: int, label: str) -> None:
    if max_tokens <= 0:
        raise ValueError(f"{label}: max_tokens must be positive")
    if estimated_tokens > max_tokens:
        raise ValueError(f"{label}: prompt budget exceeded: {estimated_tokens} > {max_tokens}")
