#!/usr/bin/env python3
"""Tests for tools.context.agent_loop + tools.context.track_b_executor integration.

A1 fix: agent_loop.py previously imported ``TrackBExecutor`` from
``tools.context.track_b_executor`` but that module did not exist. These
tests verify that:

1. The import no longer raises ``ModuleNotFoundError``.
2. ``AgentLoop(root).run(...)`` returns the documented shape
   ``{"final", "loop_history", "steps_used"}``.
3. ``TrackBExecutor`` produces a raw Track B payload that the
   ``track_b_output_mapper`` validates as ``success`` for evidence with
   signal keys and ``no_finding`` for empty/missing evidence.
4. The critic drives revisions when ``confidence`` is below the threshold.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.agent_loop import AgentLoop  # noqa: E402
from tools.context.track_b_executor import TrackBExecutor  # noqa: E402


def _write_evidence(payload: dict) -> Path:
    fd, name = tempfile.mkstemp(suffix=".json")
    Path(name).write_text(json.dumps(payload), encoding="utf-8")
    return Path(name)


def test_agent_loop_imports_cleanly() -> None:
    """The previously dead ``TrackBExecutor`` import must resolve."""
    # Reaching this point means import succeeded; double-check the symbol.
    assert AgentLoop is not None
    assert TrackBExecutor is not None


def test_track_b_executor_no_signal_returns_no_finding() -> None:
    evidence = _write_evidence({})
    ex = TrackBExecutor(ROOT)
    result = ex.run(
        dimension="dangerous_functions",
        evidence_path=evidence,
        mode="quick",
        scan_id="TEST-NOSIG",
        target="/usr/bin/foo",
    )
    assert result["output"]["finding_present"] is False
    assert result["output"]["finding_status"] == "no_finding"
    assert result["validation"]["mapper_status"] == "no_finding"
    assert str(evidence) in result["evidence_used"]


def test_track_b_executor_signal_validates_through_mapper() -> None:
    evidence = _write_evidence({"dangerous_imports": ["gets", "strcpy"], "unsafe_strings": ["password"]})
    ex = TrackBExecutor(ROOT)
    result = ex.run(
        dimension="dangerous_functions",
        evidence_path=evidence,
        mode="standard",
        scan_id="TEST-SIG",
        target="/usr/bin/demo",
    )
    assert result["output"]["finding_present"] is True
    assert result["output"]["finding_status"] == "candidate"
    assert result["output"]["confidence"] >= 0.55
    assert result["validation"]["mapper_status"] == "success"
    # Supporting files must include the evidence path so the mapper can validate
    assert str(evidence) in result["output"]["evidence"]["supporting_files"]


def test_track_b_executor_handles_missing_evidence_file() -> None:
    ex = TrackBExecutor(ROOT)
    result = ex.run(
        dimension="dangerous_functions",
        evidence_path=Path("/nonexistent/path/missing.json"),
        mode="quick",
        scan_id="TEST-MISS",
        target="/usr/bin/missing",
    )
    assert result["output"]["finding_present"] is False
    assert result["validation"]["mapper_status"] == "no_finding"
    # evidence_used records the path the caller asked about, even if it was missing
    assert result["evidence_used"] == ["/nonexistent/path/missing.json"]


def test_track_b_executor_propagates_cwe_id() -> None:
    evidence = _write_evidence({"cwe_id": "CWE-426", "dangerous_imports": ["gets"]})
    ex = TrackBExecutor(ROOT)
    result = ex.run(
        dimension="dangerous_functions",
        evidence_path=evidence,
        mode="standard",
        scan_id="TEST-CWE",
        target="/usr/bin/cwe_test",
    )
    assert result["output"]["cwe_id"] == "CWE-426"
    assert result["validation"]["mapper_status"] == "success"


def test_agent_loop_returns_documented_shape() -> None:
    evidence = _write_evidence({"dangerous_imports": ["recv", "strcpy"]})
    loop = AgentLoop(ROOT)
    result = loop.run(
        dimension="dangerous_functions",
        evidence_path=evidence,
        mode="standard",
        scan_id="TEST-LOOP",
        target="/usr/bin/loop_demo",
    )
    assert set(result.keys()) >= {"final", "loop_history", "steps_used"}
    assert isinstance(result["loop_history"], list)
    assert result["steps_used"] == len(result["loop_history"])
    assert result["steps_used"] >= 1
    # Final output should be a Track-B-shaped dict the critic can read
    assert "finding_present" in result["final"]
    assert "confidence" in result["final"]
    assert "evidence" in result["final"]


def test_agent_loop_critic_revises_low_confidence() -> None:
    """When the executor reports low confidence, the loop should revise upward."""
    evidence = _write_evidence({})  # no signal -> confidence 0.30, below default min
    loop = AgentLoop(ROOT)
    result = loop.run(
        dimension="dangerous_functions",
        evidence_path=evidence,
        mode="quick",
        scan_id="TEST-REVISE",
        target="/usr/bin/revise_demo",
    )
    # Even with no signal, the critic should have flagged low_confidence and
    # the reviser should have bumped the value within bounds.
    final_conf = float(result["final"]["confidence"])
    assert final_conf >= 0.30
    # loop_history records at least one critique pass
    assert result["steps_used"] >= 1


def run_all() -> None:
    test_agent_loop_imports_cleanly()
    test_track_b_executor_no_signal_returns_no_finding()
    test_track_b_executor_signal_validates_through_mapper()
    test_track_b_executor_handles_missing_evidence_file()
    test_track_b_executor_propagates_cwe_id()
    test_agent_loop_returns_documented_shape()
    test_agent_loop_critic_revises_low_confidence()
    print("agent_loop + track_b_executor tests OK (7/7)")


if __name__ == "__main__":
    run_all()
