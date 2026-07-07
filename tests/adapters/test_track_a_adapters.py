#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT))

from tools.adapters.checksec import ChecksecAdapter  # noqa: E402
from tools.adapters.cve_bin_tool import CveBinToolAdapter  # noqa: E402
from tools.adapters.cwe_checker import CweCheckerAdapter  # noqa: E402
from tools.adapters.dependency_parser import DependencyParserAdapter  # noqa: E402
from tools.adapters.lintian import LintianAdapter  # noqa: E402
from tools.adapters.rpmlint import RpmlintAdapter  # noqa: E402
from tools.adapters.yara_scan import YaraAdapter  # noqa: E402


def assert_signal_shape(signal: dict) -> None:
    assert signal["signal_id"].startswith("SIG-A-")
    assert signal["source"]["track"] == "A"
    assert signal["source"]["tool"]
    assert signal["signal_type"]
    assert signal["evidence"]["description"]
    assert signal["evidence"]["supporting_files"]
    assert signal["promotion"]["promote_to_finding"] is False
    assert isinstance(signal["promotion"]["requires_track_b"], bool)


def test_yara_adapter_outputs_signals_not_findings() -> None:
    result = YaraAdapter().parse_output(FIXTURES / "yara_output.txt").to_json()
    assert result["tool"] == "yara"
    assert len(result["signals"]) == 2
    assert any(signal["signal_type"] == "dangerous_command_execution_signal" for signal in result["signals"])
    for signal in result["signals"]:
        assert_signal_shape(signal)
        assert signal["promotion"]["requires_track_b"] is True


def test_checksec_adapter_outputs_hardening_signals() -> None:
    result = ChecksecAdapter().parse_output(FIXTURES / "checksec_output.txt").to_json()
    signal_types = {signal["signal_type"] for signal in result["signals"]}
    assert {"missing_stack_canary", "nx_disabled", "pie_disabled", "partial_or_no_relro"}.issubset(signal_types)
    for signal in result["signals"]:
        assert_signal_shape(signal)
        assert signal["promotion"]["requires_track_b"] is False


def test_checksec_adapter_dedupes_binaries_and_uses_single_file_arg(tmp_path: Path) -> None:
    binary = tmp_path / "usr" / "bin" / "demo"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELF")
    duplicate = str(binary)
    profile = {
        "binaries": [
            {"path": duplicate, "elf": True},
            {"path": duplicate, "elf": True},
            {"path": str(binary.parent / "script.sh"), "elf": False},
        ]
    }

    commands = ChecksecAdapter().build_commands(profile, tmp_path / "scan")

    assert len(commands) == 1
    assert commands[0].argv == ["checksec", "--file", str(binary.resolve(strict=False))]
    assert commands[0].argv.count("--file") == 1


def test_cve_bin_tool_adapter_keeps_cve_as_signal() -> None:
    result = CveBinToolAdapter().parse_output(FIXTURES / "cve_bin_tool.json").to_json()
    assert len(result["signals"]) == 1
    signal = result["signals"][0]
    assert_signal_shape(signal)
    assert signal["cve_id"] == "CVE-2024-12345"
    assert signal["promotion"]["promote_to_finding"] is False


def test_cwe_checker_adapter_requires_track_b() -> None:
    result = CweCheckerAdapter().parse_output(FIXTURES / "cwe_checker.json").to_json()
    assert len(result["signals"]) == 1
    signal = result["signals"][0]
    assert_signal_shape(signal)
    assert signal["cwe_id"] == "CWE-120"
    assert signal["location"]["address_offset"] == "0x4012ab"
    assert signal["promotion"]["requires_track_b"] is True


def test_lintian_adapter_outputs_package_signals() -> None:
    result = LintianAdapter().parse_output(FIXTURES / "lintian.txt").to_json()
    assert len(result["signals"]) == 2
    for signal in result["signals"]:
        assert_signal_shape(signal)
        assert signal["signal_type"].startswith("lintian:")


def test_rpmlint_adapter_outputs_package_signals() -> None:
    result = RpmlintAdapter().parse_output(FIXTURES / "rpmlint.txt").to_json()
    assert len(result["signals"]) == 2
    for signal in result["signals"]:
        assert_signal_shape(signal)
        assert signal["signal_type"].startswith("rpmlint:")


def test_dependency_parser_outputs_prioritization_signals() -> None:
    result = DependencyParserAdapter().parse_output(FIXTURES / "dependencies.json").to_json()
    assert len(result["signals"]) == 2
    assert {signal["signal_type"] for signal in result["signals"]} == {"crypto_dependency", "network_dependency"}
    for signal in result["signals"]:
        assert_signal_shape(signal)
        assert signal["promotion"]["requires_track_b"] is True


def run_all() -> None:
    test_yara_adapter_outputs_signals_not_findings()
    test_checksec_adapter_outputs_hardening_signals()
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        test_checksec_adapter_dedupes_binaries_and_uses_single_file_arg(Path(tmp))
    test_cve_bin_tool_adapter_keeps_cve_as_signal()
    test_cwe_checker_adapter_requires_track_b()
    test_lintian_adapter_outputs_package_signals()
    test_rpmlint_adapter_outputs_package_signals()
    test_dependency_parser_outputs_prioritization_signals()


if __name__ == "__main__":
    run_all()
    print("Track A adapter tests OK")
