#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.workflow_state import promote_rerun_output, required_output_missing  # noqa: E402


def valid_track_a(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["phase"] == "track_a"
    assert data["status"] == "success"


def test_promote_valid_rerun_without_overwriting_unrelated_outputs() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        scan_root = root / "BBH-20260704-rerun1"
        scan_root.mkdir()
        track_b = scan_root / "track_b_findings.json"
        track_b.write_text('{"phase":"track_b","sentinel":"keep"}\n', encoding="utf-8")
        state_path = scan_root / "scan_state.json"
        state_path.write_text('{"phase_status":{"track_a":{"status":"failed","retry_count":1}},"error_log":[],"updated_at":"2026-07-04T00:00:00Z"}\n', encoding="utf-8")

        def writer(path: Path) -> None:
            path.write_text(json.dumps({"phase": "track_a", "status": "success", "findings": [], "findings_count": 0}) + "\n", encoding="utf-8")

        destination = promote_rerun_output(scan_root=scan_root, phase="track_a", output_name="track_a_findings.json", writer=writer, validator=valid_track_a, state_path=state_path)
        assert destination.exists()
        assert json.loads(destination.read_text())["phase"] == "track_a"
        assert track_b.read_text(encoding="utf-8") == '{"phase":"track_b","sentinel":"keep"}\n'
        assert list((scan_root / "reruns").glob("*/track_a_findings.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["phase_status"]["track_a"]["status"] == "done"


def test_failed_rerun_does_not_promote() -> None:
    with tempfile.TemporaryDirectory() as td:
        scan_root = Path(td) / "scan"
        scan_root.mkdir()
        destination = scan_root / "track_a_findings.json"
        destination.write_text('{"phase":"track_a","status":"success","old":true}\n', encoding="utf-8")
        state_path = scan_root / "scan_state.json"
        state_path.write_text('{"phase_status":{},"error_log":[],"updated_at":"2026-07-04T00:00:00Z"}\n', encoding="utf-8")

        def writer(path: Path) -> None:
            path.write_text('{"phase":"wrong"}\n', encoding="utf-8")

        try:
            promote_rerun_output(scan_root=scan_root, phase="track_a", output_name="track_a_findings.json", writer=writer, validator=valid_track_a, state_path=state_path)
        except Exception:
            pass
        else:
            raise AssertionError("invalid rerun unexpectedly promoted")
        assert json.loads(destination.read_text(encoding="utf-8"))["old"] is True
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state["phase_status"]["track_a"]["status"] == "failed"
        assert state["error_log"]


def test_required_output_missing() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "present.json").write_text("{}", encoding="utf-8")
        assert required_output_missing(root, ["present.json", "missing.json"]) == ["missing.json"]


def run_all() -> None:
    test_promote_valid_rerun_without_overwriting_unrelated_outputs()
    test_failed_rerun_does_not_promote()
    test_required_output_missing()


if __name__ == "__main__":
    run_all()
    print("workflow resume/rerun tests OK")
