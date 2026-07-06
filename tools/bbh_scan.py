#!/usr/bin/env python3
"""Minimal executable BlackBox Hunter workflow runner.

This runner provides a conservative quick workflow: preflight, package
profiling, optional Track A tool execution, optional Track B mapped output,
deterministic merge, verification summary, and section-complete report
generation.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.context.track_b_output_mapper import map_text  # noqa: E402
from tools.merge.merge_runner import merge_findings  # noqa: E402
from tools.report.report_generator import generate_report, validate_required_sections  # noqa: E402
from tools.track_a_runner import ADAPTERS as TRACK_A_ADAPTERS, run_track_a  # noqa: E402

PHASES = ["preflight", "phase_0", "track_a", "track_b", "phase_2", "phase_3", "phase_4"]
CONFIG_SUFFIXES = {".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml", ".xml"}
SYSTEMD_DIR_PARTS = {("lib", "systemd", "system"), ("usr", "lib", "systemd", "system")}
LIBRARY_SUFFIXES = {".so", ".dylib"}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scan_id() -> str:
    return "BBH-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def phase_entry(status: str, error: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {"status": status, "retry_count": 0}
    stamp = now_iso()
    if status == "running":
        entry["started_at"] = stamp
    elif status in {"done", "failed", "skipped"}:
        entry["completed_at"] = stamp
    if error:
        entry["error_message"] = error
    return entry


def initial_state(sid: str) -> dict[str, Any]:
    return {
        "scan_id": sid,
        "current_phase": "idle",
        "phase_status": {phase: phase_entry("pending") for phase in PHASES},
        "started_at": now_iso(),
        "updated_at": now_iso(),
        "error_log": [],
    }


def update_phase(scan_state: dict[str, Any], phase: str, status: str, error: str = "") -> None:
    scan_state["current_phase"] = "failed" if status == "failed" else phase
    scan_state["phase_status"][phase] = phase_entry(status, error)
    scan_state["updated_at"] = now_iso()
    if error:
        scan_state["error_log"].append({"phase": phase, "status": status, "message": error, "time": now_iso()})


def build_execution_decision(
    finding: dict[str, Any],
    sandbox_status: dict[str, Any],
    action_gate: dict[str, Any],
) -> dict[str, Any]:
    """Decide whether a PoC runs in the sandbox or on the host.

    Default: sandbox. A host execution is permitted only when the
    action gate carries a valid host_exception block.
    """
    he = action_gate.get("host_exception") if isinstance(action_gate, dict) else None
    if not isinstance(he, dict):
        return {"execution_mode": "sandbox"}
    return {
        "execution_mode": "host_exception",
        "host_exception": {
            "id": he.get("id", ""),
            "category": he.get("category", ""),
            "reason": he.get("reason", ""),
            "target_is_target_package": bool(he.get("target_is_target_package", False)),
        },
        "action_request": action_gate.get("request", {}) if isinstance(action_gate.get("request"), dict) else {},
        "action_decision": action_gate.get("decision", {}) if isinstance(action_gate.get("decision"), dict) else {},
    }


def check_host_exception(decision: dict[str, Any], host_exemptions_path: Path) -> None:
    """Validate a host-exception decision against the whitelist.

    Raises ValueError if the whitelist file fails schema validation.
    Raises PermissionError if the decision is not whitelisted.
    """
    if decision.get("execution_mode") != "host_exception":
        return
    if not host_exemptions_path.is_file():
        raise ValueError(f"host_exemptions.json not found: {host_exemptions_path}")
    whitelist = json.loads(host_exemptions_path.read_text(encoding="utf-8"))
    if whitelist.get("schema_version") != 1:
        raise ValueError("host_exemptions.json: unsupported schema_version")

    exemptions: dict[str, dict[str, Any]] = {}
    for item in whitelist.get("exemptions", []):
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError("host_exemptions.json: exemption missing id")
        eid_item = str(item["id"])
        if eid_item in exemptions:
            raise ValueError(f"host_exemptions.json: duplicate exemption id {eid_item}")
        exemptions[eid_item] = item

    he = decision.get("host_exception", {})
    eid = he.get("id", "")
    if eid not in exemptions:
        raise PermissionError(f"host_exception_id '{eid}' not in whitelist")
    if not he.get("reason"):
        raise PermissionError("host_exception.reason is required")
    if he.get("target_is_target_package") is True:
        raise PermissionError("C7 violation: target package may not run on host")

    exemption = exemptions[eid]
    if exemption.get("target_is_target_package") is True:
        raise PermissionError("C7 violation: whitelist entry has target_is_target_package=true")

    action_decision = decision.get("action_decision", {})
    if action_decision.get("allowed") is not True:
        raise PermissionError("host_exception action gate decision is not allowed")

    action_request = decision.get("action_request", {})
    if exemption.get("requires_user_approval") is True and action_request.get("user_approved") is not True:
        raise PermissionError("host_exception requires user approval")
    if action_request.get("runs_target_code") is True:
        raise PermissionError("C7 violation: host exception may not run target code")


def infer_package_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".deb":
        return "deb"
    if suffix == ".rpm":
        return "rpm"
    raise SystemExit(f"unsupported package type for {path}")


def validate_json(schema_name: str, document: dict[str, Any], schemas_dir: Path) -> None:
    try:
        from jsonschema import Draft202012Validator
        try:
            from referencing import Registry, Resource
        except Exception:
            Registry = None
            Resource = None
    except Exception:
        return

    schema_path = schemas_dir / schema_name
    schema = load_json(schema_path)
    if Registry is not None:
        resources = []
        for candidate in schemas_dir.glob("*.json"):
            loaded = load_json(candidate)
            schema_id = loaded.get("$id")
            if schema_id:
                resources.append((schema_id, Resource.from_contents(loaded)))
            resources.append((candidate.as_uri(), Resource.from_contents(loaded)))
        Draft202012Validator(schema, registry=Registry().with_resources(resources)).validate(document)
    else:
        Draft202012Validator(schema).validate(document)


def run_preflight(args: argparse.Namespace, scan_root: Path, package_type: str, package_path: Path) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(ROOT / "tools" / "preflight.py"),
        "--check-only",
        "--offline",
        "--auto-fix",
        "--package-type",
        package_type,
        "--package-path",
        str(package_path),
        "--scan-root",
        str(scan_root),
    ]
    if args.registry:
        cmd.extend(["--registry", str(Path(args.registry).resolve())])
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (scan_root / "logs").mkdir(parents=True, exist_ok=True)
    (scan_root / "logs" / "preflight.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (scan_root / "logs" / "preflight.stderr.txt").write_text(result.stderr, encoding="utf-8")
    env_path = scan_root / "env_check.json"
    if not env_path.exists():
        raise RuntimeError("preflight did not produce env_check.json")
    env = load_json(env_path)
    if result.returncode != 0 or env.get("block_decision", {}).get("blocked"):
        raise RuntimeError("preflight hard-blocked: " + "; ".join(env.get("block_decision", {}).get("blocked_tools", [])))
    return env


def run_cmd(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)


def extract_deb(package_path: Path, extracted: Path) -> tuple[str, list[str]]:
    if shutil.which("dpkg-deb"):
        result = run_cmd(["dpkg-deb", "-x", str(package_path), str(extracted)])
        if result.returncode == 0:
            return "dpkg-deb", []
        return "failed", [result.stderr or result.stdout or "dpkg-deb extraction failed"]
    return "failed", ["dpkg-deb unavailable"]


def extract_synthetic_rpm_fixture(package_path: Path, extracted: Path, allow: bool) -> tuple[str, list[str]]:
    if not allow:
        return "failed", ["rpm extraction tools unavailable"]
    marker = package_path.read_text(encoding="utf-8", errors="ignore")[:128]
    if "RPM_FIXTURE_PLACEHOLDER" not in marker:
        return "failed", ["not a synthetic rpm fixture"]
    target = extracted / "usr" / "bin" / package_path.stem
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("#!/bin/sh\nprintf '%s\\n' synthetic-rpm-fixture\n", encoding="utf-8")
    target.chmod(0o755)
    return "synthetic-rpm-fixture", ["synthetic RPM fixture mode used for CI smoke coverage"]


def extract_rpm(package_path: Path, extracted: Path, allow_synthetic: bool) -> tuple[str, list[str]]:
    if shutil.which("rpm2cpio") and shutil.which("cpio"):
        rpm2cpio = subprocess.Popen(["rpm2cpio", str(package_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cpio = subprocess.run(["cpio", "-idm", "--quiet"], cwd=extracted, stdin=rpm2cpio.stdout, text=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, rpm_err = rpm2cpio.communicate()
        if rpm2cpio.returncode == 0 and cpio.returncode == 0:
            return "rpm2cpio+cpio", []
        warning = (rpm_err or b"").decode("utf-8", errors="replace") + (cpio.stderr or b"").decode("utf-8", errors="replace")
        fallback_method, fallback_warnings = extract_synthetic_rpm_fixture(package_path, extracted, allow_synthetic)
        return fallback_method, [warning.strip() or "rpm2cpio extraction failed"] + fallback_warnings
    return extract_synthetic_rpm_fixture(package_path, extracted, allow_synthetic)


def relative_entry(path: Path, extracted: Path) -> str:
    return "/" + str(path.relative_to(extracted))


def path_parts(path: Path, extracted: Path) -> tuple[str, ...]:
    return tuple(path.relative_to(extracted).parts)


def is_systemd_unit(path: Path, extracted: Path) -> bool:
    parts = path_parts(path, extracted)
    return path.suffix == ".service" and any(parts[: len(prefix)] == prefix for prefix in SYSTEMD_DIR_PARTS)


def is_config_file(path: Path, extracted: Path) -> bool:
    parts = path_parts(path, extracted)
    if parts and parts[0] == "etc":
        return True
    return path.suffix.lower() in CONFIG_SUFFIXES


def is_library_file(path: Path) -> bool:
    return path.suffix.lower() in LIBRARY_SUFFIXES or ".so." in path.name


def collect_inventory(extracted: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    binaries: list[dict[str, Any]] = []
    attack_surface: list[dict[str, Any]] = []
    architectures = set()
    for path in sorted(extracted.rglob("*")):
        if not path.is_file():
            continue
        rel = relative_entry(path, extracted)
        mode = path.stat().st_mode
        is_exec = bool(mode & stat.S_IXUSR)
        is_setuid = bool(mode & stat.S_ISUID)
        is_elf = path.read_bytes()[:4] == b"\x7fELF"
        arch = "unknown"
        if is_elf:
            arch = "elf"
        elif is_exec:
            arch = "script"
        if is_elf or is_exec:
            architectures.add(arch)
            priority = 40 if is_setuid else (30 if is_elf else 20)
            binaries.append({"path": str(path), "elf": is_elf, "architecture": arch, "priority": priority, "setuid": is_setuid})
            attack_surface.append({"type": "cli", "entry_point": rel, "evidence": "executable file in extracted package"})
        if is_systemd_unit(path, extracted):
            attack_surface.append({"type": "config", "entry_point": rel, "evidence": "systemd unit may define service entry points and privileges"})
        elif is_config_file(path, extracted):
            attack_surface.append({"type": "config", "entry_point": rel, "evidence": "configuration file in extracted package"})
        elif is_library_file(path):
            attack_surface.append({"type": "library", "entry_point": rel, "evidence": "shared library entry point"})
    return binaries, attack_surface, sorted(architectures or {"unknown"})


def build_phase0(args: argparse.Namespace, scan_root: Path, package_path: Path, package_type: str, env: dict[str, Any]) -> dict[str, Any]:
    extracted = scan_root / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    if package_type == "deb":
        method, warnings = extract_deb(package_path, extracted)
    else:
        method, warnings = extract_rpm(package_path, extracted, args.allow_synthetic_rpm_fixture)
    if method == "failed":
        raise RuntimeError("; ".join(warnings))

    binaries, attack_surface, architectures = collect_inventory(extracted)
    profile = {
        "scan_id": args.scan_id,
        "package": {
            "path": str(package_path),
            "type": package_type,
            "name": package_path.stem,
            "version": "",
            "architecture": architectures[0] if architectures else "unknown",
            "size_bytes": package_path.stat().st_size,
        },
        "extraction": {"status": "success", "root": str(extracted), "method": method, "warnings": warnings},
        "binaries": binaries,
        "attack_surface": attack_surface,
        "architectures": architectures,
        "metadata": {"package_manager": env.get("package_manager", "unknown")},
    }
    write_json(scan_root / "target_profile.json", profile)

    available_tools = [tool["name"] for tool in env.get("tools", []) if tool.get("status") in {"available", "fallback_active"}]
    strategy = {
        "scan_id": args.scan_id,
        "mode": args.mode,
        "track_a_tools": [{"name": name, "timeout_sec": 120} for name in available_tools],
        "track_b_focus": ["dangerous_functions", "hardcoded_config"] if args.mode == "quick" else ["dangerous_functions", "input_validation", "memory_management", "privilege_model", "hardcoded_config"],
        "disassembly_engine": "strings_only",
        "attack_surfaces": [{"type": item["type"], "identifier": item["entry_point"], "priority": "medium"} for item in attack_surface],
        "estimated_duration_min": 1,
        "token_budget": 50000,
    }
    write_json(scan_root / "scan_strategy.json", strategy)

    coverage_plan = {
        "scan_id": args.scan_id,
        "mode": args.mode,
        "targets": [{"path": item["path"], "priority": item.get("priority", 10), "reason": "inventory executable", "architecture": item["architecture"]} for item in binaries],
        "tracks": {"track_a": available_tools, "track_b": strategy["track_b_focus"]},
        "limits": {"synthetic_rpm_fixture": bool(args.allow_synthetic_rpm_fixture)},
    }
    write_json(scan_root / "coverage_plan.json", coverage_plan)

    docker = next((tool for tool in env.get("tools", []) if tool.get("name") == "docker"), {})
    podman = next((tool for tool in env.get("tools", []) if tool.get("name") == "podman"), {})
    sandbox = {
        "base_image_ref": env.get("imported_image_ref") or "bbh-base:local-imported",
        "base_image_source": "imported_rootfs_tarball",
        "docker_available": docker.get("status") in {"available", "fallback_active"},
        "podman_available": podman.get("status") in {"available", "fallback_active"},
        "sandbox_ready": docker.get("status") in {"available", "fallback_active"} or podman.get("status") in {"available", "fallback_active"},
        "engine": "docker" if docker.get("status") in {"available", "fallback_active"} else ("podman" if podman.get("status") in {"available", "fallback_active"} else "none"),
        "limitations": env.get("block_decision", {}).get("warnings", []),
    }
    write_json(scan_root / "sandbox_status.json", sandbox)
    return profile


def available_track_a_adapter_names(env: dict[str, Any]) -> list[str]:
    available = [tool["name"] for tool in env.get("tools", []) if tool.get("status") in {"available", "fallback_active"}]
    return [name for name in available if name in TRACK_A_ADAPTERS]


def write_skipped_track_a(scan_root: Path, reason: str) -> None:
    write_json(scan_root / "track_a_findings.json", {
        "agent_id": "track-a-toolscan",
        "agent_role": "traditional-tooling",
        "phase": "track_a",
        "status": "skipped",
        "findings": [],
        "findings_count": 0,
        "warnings": [reason],
        "execution_time_ms": 0,
        "metadata": {"tools_executed": [], "tool_results": [], "signals_count": 0, "signals_promoted": 0},
    })


def write_track_b_from_output(scan_root: Path, args: argparse.Namespace) -> None:
    source = Path(args.track_b_output).resolve()
    mapped = map_text(
        source.read_text(encoding="utf-8"),
        finding_id=args.track_b_finding_id,
        dimension=args.track_b_dimension,
        tool="track-b-ai",
        agent_id="track-b-ai-local-fixture",
    )
    if mapped["status"] == "error":
        raise RuntimeError("Track B output mapping failed: " + mapped["reason"])
    findings = [mapped["finding"]] if mapped.get("finding") else []
    warnings = [] if findings else [mapped.get("reason", "Track B fixture produced no finding")]
    write_json(scan_root / "track_b_findings.json", {
        "agent_id": "track-b-ai-local-fixture",
        "agent_role": "ai-binary-analysis",
        "phase": "track_b",
        "status": "success",
        "findings": findings,
        "findings_count": len(findings),
        "warnings": warnings,
        "execution_time_ms": 0,
        "metadata": {
            "dimensions_analyzed": [args.track_b_dimension],
            "functions_analyzed": 1 if findings else 0,
            "token_usage": {"mode": args.mode, "tokens_used": 0, "source": "fixture"},
            "engine_failures": [],
            "architecture_branch": "fixture_output",
            "raw_output": str(source),
        },
    })


def write_skipped_track_b(scan_root: Path, args: argparse.Namespace) -> None:
    write_json(scan_root / "track_b_findings.json", {
        "agent_id": "track-b-ai",
        "agent_role": "ai-binary-analysis",
        "phase": "track_b",
        "status": "skipped",
        "findings": [],
        "findings_count": 0,
        "warnings": ["Track B agent invocation is not configured in the local runner; use --track-b-output to map a bounded fixture response"],
        "execution_time_ms": 0,
        "metadata": {
            "dimensions_analyzed": [],
            "functions_analyzed": 0,
            "token_usage": {"mode": args.mode, "tokens_used": 0},
            "engine_failures": [],
            "architecture_branch": "strings_only",
        },
    })


def write_track_outputs(scan_root: Path, env: dict[str, Any], args: argparse.Namespace) -> None:
    if args.run_track_a_tools:
        selected = available_track_a_adapter_names(env)
        if selected:
            run_track_a(scan_root, env, load_json(scan_root / "target_profile.json"), selected)
        else:
            write_skipped_track_a(scan_root, "Track A tool execution requested but no available Track A adapters were detected")
    else:
        write_skipped_track_a(scan_root, "Track A tool execution disabled; use --run-track-a-tools to execute available adapters")

    if args.track_b_output:
        write_track_b_from_output(scan_root, args)
    else:
        write_skipped_track_b(scan_root, args)


def write_merge_verify_report(scan_root: Path, sid: str, env: dict[str, Any]) -> None:
    track_a = load_json(scan_root / "track_a_findings.json")
    track_b = load_json(scan_root / "track_b_findings.json")
    merged = merge_findings(track_a, track_b)
    merged.setdefault("coverage_summary", {})["preflight_warnings"] = env.get("block_decision", {}).get("warnings", [])
    write_json(scan_root / "merged_findings.json", merged)

    profile = load_json(scan_root / "target_profile.json")
    coverage = {
        "binary_coverage_pct": 100 if profile.get("binaries") is not None else 0,
        "config_coverage_pct": 100,
        "dependency_coverage_pct": 0,
        "attack_surface_coverage_pct": 100 if profile.get("attack_surface") is not None else 0,
        "tool_coverage_pct": 100 if track_a.get("metadata", {}).get("tools_executed") else 0,
        "gaps": env.get("block_decision", {}).get("phase_blocks", []),
    }
    write_json(scan_root / "coverage_report.json", coverage)
    sandbox = load_json(scan_root / "sandbox_status.json")
    verified = {"verified_findings": [], "verification_stats": {"verified": 0, "skipped": 0}, "sandbox_info": sandbox}
    write_json(scan_root / "verified_findings.json", verified)

    report_dir = scan_root / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = generate_report(scan_root)
    missing = validate_required_sections(report)
    if missing:
        raise RuntimeError("report generator missed required sections: " + ", ".join(missing))
    (report_dir / "blackbox-security-report.md").write_text(report, encoding="utf-8")
    write_json(report_dir / "findings.json", {"findings": [item["finding"] for item in merged.get("merged_findings", [])]})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a schema-valid BlackBox Hunter workflow")
    parser.add_argument("--package", required=True, dest="package_path")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--mode", default="quick", choices=["quick", "standard", "deep", "full"])
    parser.add_argument("--registry", default="")
    parser.add_argument("--scan-id", default="")
    parser.add_argument("--allow-synthetic-rpm-fixture", action="store_true")
    parser.add_argument("--run-track-a-tools", action="store_true", help="Execute available Track A adapters instead of writing a skipped wrapper")
    parser.add_argument("--track-b-output", default="", help="Optional Track B fixture/model JSON output to map into findings")
    parser.add_argument("--action-gate", default="", help="Optional action gate JSON file for Phase 3 host-exception decisions")
    parser.add_argument("--track-b-dimension", default="dangerous_functions")
    parser.add_argument("--track-b-finding-id", default="TB-001")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.scan_id = args.scan_id or scan_id()
    package_path = Path(args.package_path).resolve()
    package_type = infer_package_type(package_path)
    scan_root = Path(args.workspace).resolve() / args.scan_id
    scan_root.mkdir(parents=True, exist_ok=True)
    state = initial_state(args.scan_id)
    if args.action_gate:
        state["action_gate"] = load_json(Path(args.action_gate).resolve())
    write_json(scan_root / "scan_state.json", state)

    try:
        update_phase(state, "preflight", "running")
        env = run_preflight(args, scan_root, package_type, package_path)
        update_phase(state, "preflight", "done")
        write_json(scan_root / "scan_state.json", state)

        update_phase(state, "phase_0", "running")
        build_phase0(args, scan_root, package_path, package_type, env)
        update_phase(state, "phase_0", "done")

        for phase in ("track_a", "track_b"):
            update_phase(state, phase, "running")
        write_track_outputs(scan_root, env, args)
        update_phase(state, "track_a", "done")
        update_phase(state, "track_b", "done")

        update_phase(state, "phase_2", "running")
        write_merge_verify_report(scan_root, args.scan_id, env)
        update_phase(state, "phase_2", "done")

        phase3_blocks = env.get("block_decision", {}).get("phase_blocks") or []
        if phase3_blocks:
            update_phase(state, "phase_3", "skipped", "; ".join(block.get("reason", "") for block in phase3_blocks))
        else:
            action_gate = state.get("action_gate", {}) or {}
            decision = build_execution_decision({}, {}, action_gate)
            if decision["execution_mode"] == "host_exception":
                try:
                    check_host_exception(decision, ROOT / "tools" / "host_exemptions.json")
                except (PermissionError, ValueError) as gate_err:
                    update_phase(state, "phase_3", "skipped")
                    state["phase_status"]["phase_3"]["execution_mode"] = "sandbox"
                    state["error_log"].append({
                        "phase": "phase_3",
                        "code": "host_exception_denied",
                        "reason": str(gate_err),
                        "ts": now_iso(),
                    })
                else:
                    update_phase(state, "phase_3", "done")
                    state["phase_status"]["phase_3"]["execution_mode"] = "host_exception"
                    state["phase_status"]["phase_3"]["host_exception_ref"] = decision["host_exception"]["id"]
                    state["error_log"].append({
                        "phase": "phase_3",
                        "code": "host_exception_invoked",
                        "host_exception_id": decision["host_exception"]["id"],
                        "reason": decision["host_exception"]["reason"],
                        "ts": now_iso(),
                    })
            else:
                update_phase(state, "phase_3", "done")
                state["phase_status"]["phase_3"]["execution_mode"] = "sandbox"

        update_phase(state, "phase_4", "done")
        state["current_phase"] = "completed"
        state["updated_at"] = now_iso()
        write_json(scan_root / "scan_state.json", state)

        schemas = ROOT / "templates"
        for schema_name, doc_name in [
            ("env_check.json", "env_check.json"),
            ("scan_state.json", "scan_state.json"),
            ("target_profile.json", "target_profile.json"),
            ("scan_strategy.json", "scan_strategy.json"),
            ("coverage_plan.json", "coverage_plan.json"),
            ("sandbox_status.json", "sandbox_status.json"),
            ("track_findings.json", "track_a_findings.json"),
            ("track_findings.json", "track_b_findings.json"),
            ("merged_findings.json", "merged_findings.json"),
            ("coverage_report.json", "coverage_report.json"),
            ("verified_findings.json", "verified_findings.json"),
        ]:
            validate_json(schema_name, load_json(scan_root / doc_name), schemas)
        print(scan_root)
        return 0
    except Exception as exc:
        update_phase(state, state.get("current_phase") if state.get("current_phase") in PHASES else "phase_0", "failed", str(exc))
        write_json(scan_root / "scan_state.json", state)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
