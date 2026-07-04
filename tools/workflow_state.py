#!/usr/bin/env python3
"""Workflow state helpers for resumable BlackBox Hunter phases."""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rerun_dir(scan_root: Path, phase: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = scan_root / "reruns" / f"{stamp}-{phase}"
    counter = 0
    while path.exists():
        counter += 1
        path = scan_root / "reruns" / f"{stamp}-{phase}-{counter}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def atomic_promote(candidate: Path, destination: Path, validator: Callable[[Path], None]) -> None:
    validator(candidate)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copy2(candidate, tmp)
    os.replace(tmp, destination)


def mark_phase(state: dict[str, Any], phase: str, status: str, message: str = "") -> dict[str, Any]:
    state.setdefault("phase_status", {})
    entry: dict[str, Any] = {"status": status, "retry_count": int((state["phase_status"].get(phase) or {}).get("retry_count", 0))}
    if status == "running":
        entry["started_at"] = now_iso()
    if status in {"done", "failed", "skipped"}:
        entry["completed_at"] = now_iso()
    if message or status == "failed":
        safe_message = message or "phase failed without exception message"
        entry["error_message"] = safe_message
        state.setdefault("error_log", []).append({"phase": phase, "status": status, "message": safe_message, "time": now_iso()})
    state["phase_status"][phase] = entry
    state["current_phase"] = "failed" if status == "failed" else phase
    state["updated_at"] = now_iso()
    return state


def required_output_missing(scan_root: Path, outputs: list[str]) -> list[str]:
    return [item for item in outputs if not (scan_root / item).exists()]


def promote_rerun_output(
    *,
    scan_root: Path,
    phase: str,
    output_name: str,
    writer: Callable[[Path], None],
    validator: Callable[[Path], None],
    state_path: Path | None = None,
) -> Path:
    state = read_json(state_path) if state_path and state_path.exists() else {"phase_status": {}, "error_log": []}
    run_dir = rerun_dir(scan_root, phase)
    candidate = run_dir / output_name
    destination = scan_root / output_name
    try:
        mark_phase(state, phase, "running")
        writer(candidate)
        atomic_promote(candidate, destination, validator)
        mark_phase(state, phase, "done")
    except Exception as exc:
        mark_phase(state, phase, "failed", str(exc) or exc.__class__.__name__)
        if state_path:
            write_json(state_path, state)
        raise
    if state_path:
        write_json(state_path, state)
    return destination
