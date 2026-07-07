#!/usr/bin/env python3
"""Shared output path resolution for BlackBox Hunter."""
from __future__ import annotations

from pathlib import Path

DEFAULT_OUTPUT_ROOT_NAME = "black-audit-output"


def default_output_root() -> Path:
    return (Path.cwd() / DEFAULT_OUTPUT_ROOT_NAME).resolve()


def resolve_workspace(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    return default_output_root()


def resolve_preflight_output(output: str | None, scan_root: str | Path | None) -> Path:
    if output:
        return Path(output).expanduser().resolve()
    if scan_root:
        return Path(scan_root).expanduser().resolve() / "env_check.json"
    return default_output_root() / "env_check.json"
