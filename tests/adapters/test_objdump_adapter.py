#!/usr/bin/env python3
"""Tests for B1: per-binary objdump timeout + size cap.

We exercise the ObjdumpAdapter end-to-end against real ELFs in /usr/bin and
against a synthetic oversized file. The size-cap path uses ``sh -c echo``
so we can test the ``binary_skipped_too_large`` branch without crafting a
50 MB file on disk.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.adapters.objdump_disasm import (  # noqa: E402
    MAX_BINARY_BYTES,
    ObjdumpAdapter,
    _compute_timeout,
)


def test_compute_timeout_lower_bound() -> None:
    """Tiny binaries (<=5 MB) should get the 5-second floor."""
    assert _compute_timeout(1024 * 1024) == 5  # 1 MB
    assert _compute_timeout(5 * 1024 * 1024) == 5  # 5 MB


def test_compute_timeout_proportional() -> None:
    """Mid-size binaries scale linearly (size_mb // 5), with a 5s floor."""
    # 10 MB: 10//5 = 2, but max(5, 2) = 5, so the floor wins.
    assert _compute_timeout(10 * 1024 * 1024) == 5  # 10 MB (floor applies)
    assert _compute_timeout(50 * 1024 * 1024) == 10  # 50 MB
    assert _compute_timeout(100 * 1024 * 1024) == 20  # 100 MB


def test_compute_timeout_upper_bound() -> None:
    """Very large binaries cap at 60s."""
    assert _compute_timeout(500 * 1024 * 1024) == 60


def test_adapter_missing_objdump_emits_warning() -> None:
    """When objdump is absent, build_commands returns a sentinel command."""
    from tools.track_a_runner import run_command
    with tempfile.TemporaryDirectory() as tmp:
        # Create a small fake "binary" file
        binary = Path(tmp) / "fakebin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)

        # Force objdump_bin to None
        adapter = ObjdumpAdapter()
        adapter.objdump_bin = None
        adapter.readelf_bin = None

        profile = {"binaries": [{"path": str(binary), "name": "fakebin"}]}
        commands = adapter.build_commands(profile, Path(tmp))
        assert len(commands) == 1, commands
        # Actually execute the sentinel command so the output file exists
        rc, _ = run_command(commands[0].argv, Path(commands[0].output_path), commands[0].timeout_sec)
        result = adapter.parse_output(Path(commands[0].output_path))
        assert any("missing_tool_objdump" in w for w in result.warnings), result.warnings
        assert result.status == "missing_tool", result.status


def test_adapter_oversized_binary_skipped() -> None:
    """A binary over MAX_BINARY_BYTES emits binary_skipped_too_large signal."""
    from tools.track_a_runner import run_command
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "huge"
        binary.write_bytes(b"")  # empty file is fine for the sentinel path

        adapter = ObjdumpAdapter()
        # Monkey-patch the stat lookup to report a >50 MB size
        original_stat = Path.stat

        def fake_stat(self, *a, **kw):
            if self.name == "huge":
                from types import SimpleNamespace
                return SimpleNamespace(st_size=MAX_BINARY_BYTES + 1)
            return original_stat(self, *a, **kw)

        try:
            Path.stat = fake_stat
            profile = {"binaries": [{"path": str(binary), "name": "huge"}]}
            commands = adapter.build_commands(profile, Path(tmp))
        finally:
            Path.stat = original_stat

        assert len(commands) == 1, commands
        # Execute the sentinel so parse_output can read it
        rc, _ = run_command(commands[0].argv, Path(commands[0].output_path), commands[0].timeout_sec)
        result = adapter.parse_output(Path(commands[0].output_path))
        assert result.status == "skipped_too_large", result.status
        assert any("binary_skipped_too_large" in w for w in result.warnings), result.warnings
        # The signal is emitted but should NOT be promoted to a finding.
        assert len(result.signals) == 1, result.signals
        assert result.signals[0].promotion["promote_to_finding"] is False, result.signals[0]


def test_adapter_real_objdump_smoke() -> None:
    """End-to-end smoke: run against /usr/bin/true (or /bin/true) if present."""
    objdump = shutil.which("objdump") or shutil.which("llvm-objdump")
    candidate = None
    for p in ("/usr/bin/true", "/bin/true", "/bin/echo", "/usr/bin/echo"):
        if Path(p).exists():
            candidate = p
            break
    if objdump is None or candidate is None:
        # Skip if we have neither objdump nor a candidate ELF.
        print("SKIP: no objdump/ELF available for live smoke")
        return

    with tempfile.TemporaryDirectory() as tmp:
        profile = {"binaries": [{"path": candidate, "name": Path(candidate).name}]}
        adapter = ObjdumpAdapter()
        commands = adapter.build_commands(profile, Path(tmp))
        assert commands, commands
        # Run the command via the existing Track A runner
        from tools.track_a_runner import run_command
        rc, _ = run_command(commands[0].argv, Path(commands[0].output_path), commands[0].timeout_sec)
        # /bin/true disassembles quickly; rc must be 0 or 1
        assert rc in (0, 1), rc
        result = adapter.parse_output(Path(commands[0].output_path))
        # The signal must always be emitted for a real binary.
        assert result.status == "success", result.status
        assert len(result.signals) >= 1, result.signals


def test_adapter_readelf_fallback_for_large_binaries() -> None:
    """A binary in (32 MB, 50 MB] should be handed to readelf, not objdump."""
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "medium"
        binary.write_bytes(b"")
        adapter = ObjdumpAdapter()
        adapter.objdump_bin = shutil.which("objdump") or shutil.which("llvm-objdump")
        adapter.readelf_bin = shutil.which("readelf")
        if adapter.readelf_bin is None:
            print("SKIP: no readelf available")
            return

        original_stat = Path.stat

        def fake_stat(self, *a, **kw):
            if self.name == "medium":
                from types import SimpleNamespace
                return SimpleNamespace(st_size=40 * 1024 * 1024)
            return original_stat(self, *a, **kw)

        try:
            Path.stat = fake_stat
            profile = {"binaries": [{"path": str(binary), "name": "medium"}]}
            commands = adapter.build_commands(profile, Path(tmp))
        finally:
            Path.stat = original_stat

        assert commands, commands
        assert "readelf" in commands[0].argv[0], commands[0].argv


def test_track_a_runner_routes_objdump() -> None:
    """The runner's ADAPTERS map must dispatch objdump to the new adapter."""
    from tools import track_a_runner
    assert "objdump" in track_a_runner.ADAPTERS
    assert track_a_runner.ADAPTERS["objdump"].endswith("ObjdumpAdapter")


def test_tool_registry_lists_objdump_with_readelf_fallback() -> None:
    """tool_registry.json must declare objdump with fallbacks=[readelf]."""
    data = json.loads((ROOT / "tools" / "tool_registry.json").read_text(encoding="utf-8"))
    objdump = next((t for t in data["tools"] if t["name"] == "objdump"), None)
    assert objdump is not None, "objdump entry missing from tool_registry.json"
    assert "readelf" in objdump.get("fallbacks", []), objdump


def run_all() -> None:
    test_compute_timeout_lower_bound()
    test_compute_timeout_proportional()
    test_compute_timeout_upper_bound()
    test_adapter_missing_objdump_emits_warning()
    test_adapter_oversized_binary_skipped()
    test_adapter_real_objdump_smoke()
    test_adapter_readelf_fallback_for_large_binaries()
    test_track_a_runner_routes_objdump()
    test_tool_registry_lists_objdump_with_readelf_fallback()
    print("B1 objdump adapter tests OK (9/9)")


if __name__ == "__main__":
    run_all()