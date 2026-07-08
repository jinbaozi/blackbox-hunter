#!/usr/bin/env python3
"""Static-structure tests for B9 (ltrace/strace/gdb in PoC sandbox).

We can't always build the actual ``Dockerfile.poc`` in CI (no docker
daemon available), so this test asserts the *contract* instead:

1. ``sandbox/Dockerfile.poc`` references ltrace/strace/gdb in its install
   list, with a non-aborting fallback when a package isn't available.
2. ``tools/host_exemptions.json`` declares ``host-ltrace`` and
   ``host-strace-fork`` with the correct category and target_is_target_package
   flag.
3. ``tools/host_exemptions.json`` still carries the legacy IDs (regression).

The end-to-end ``docker run`` assertion lives in
``tests/e2e/full_workflow_dynamic.sh`` and runs only on hosts with a
reachable engine.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def test_dockerfile_poc_contains_dynamic_tools() -> None:
    dockerfile = (ROOT / "sandbox" / "Dockerfile.poc").read_text(encoding="utf-8")
    for tool in ("ltrace", "strace", "gdb"):
        assert tool in dockerfile, f"dynamic tool missing from Dockerfile.poc: {tool}"
    # Must wrap each install in `|| true` so missing packages don't abort
    # the build.
    for tool in ("ltrace", "strace", "gdb"):
        # crude regex: tool is mentioned AND a `|| true` is somewhere nearby
        # We just check that at least one "|| true" follows a tool install
        assert "|| true" in dockerfile, "Dockerfile must wrap optional installs with || true"


def test_host_exemptions_declare_dynamic_tracing() -> None:
    cfg = json.loads((ROOT / "tools" / "host_exemptions.json").read_text(encoding="utf-8"))
    by_id = {entry["id"]: entry for entry in cfg["exemptions"]}
    for required in ("host-ltrace", "host-strace-fork"):
        assert required in by_id, f"missing host exemption: {required}"
        entry = by_id[required]
        assert entry["category"] == "dynamic_tracing", entry
        assert "phase_3" in entry["applies_to"], entry
        # Critical: dynamic tracing must never widen to target-package code
        assert not entry.get("target_is_target_package"), entry
        assert entry["requires_reason_field"] is True, entry
        assert entry["requires_user_approval"] is True, entry


def test_host_exemptions_retain_legacy_ids() -> None:
    """Regression: previously-existing exemptions must not be dropped."""
    cfg = json.loads((ROOT / "tools" / "host_exemptions.json").read_text(encoding="utf-8"))
    ids = {entry["id"] for entry in cfg["exemptions"]}
    for legacy in ("host-kernel-probe", "host-perf-profiling", "host-debugger-syscalls"):
        assert legacy in ids, f"legacy exemption vanished: {legacy}"


def test_exemption_count_matches_documented_total() -> None:
    """Plan documented 5 exemptions after B9. We assert >=5 to avoid
    silently dropping IDs without updating the contract."""
    cfg = json.loads((ROOT / "tools" / "host_exemptions.json").read_text(encoding="utf-8"))
    assert len(cfg["exemptions"]) >= 5, cfg["exemptions"]


def run_all() -> None:
    test_dockerfile_poc_contains_dynamic_tools()
    test_host_exemptions_declare_dynamic_tracing()
    test_host_exemptions_retain_legacy_ids()
    test_exemption_count_matches_documented_total()
    print("B9 dynamic-tools tests OK (4/4)")


if __name__ == "__main__":
    run_all()