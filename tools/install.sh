#!/bin/bash
# BlackBox Hunter - Tool Environment Preflight and Installer
# Usage: ./install.sh [--check-only] [--force] [--offline] [--auto-fix]
#                    [--package-type deb|rpm] [--output file|--scan-root dir]
#                    [--registry file]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BBH_INSTALL_SCRIPT_DIR="$SCRIPT_DIR"

python3 - "$@" <<'PY'
import argparse
import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(os.environ["BBH_INSTALL_SCRIPT_DIR"]).resolve()
DEFAULT_REGISTRY = SCRIPT_DIR / "tool_registry.json"
EXTENDED_DIRS = [
    "~/.local/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/opt/homebrew/bin",
    "/snap/bin",
    "~/.cargo/bin",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="BlackBox Hunter environment preflight and tool installer"
    )
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--auto-fix", action="store_true")
    parser.add_argument("--package-type", choices=["deb", "rpm"], default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--scan-root", default="")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    return parser.parse_args()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_registry(path):
    registry_path = Path(path).expanduser().resolve()
    if not registry_path.exists():
        raise SystemExit(f"ERROR: tool registry not found: {registry_path}")
    try:
        with registry_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: malformed tool registry {registry_path}: {exc}") from exc
    if not isinstance(data.get("tools"), list):
        raise SystemExit(f"ERROR: registry {registry_path} must contain a tools array")
    return registry_path, data["tools"]


def output_path(args):
    if args.output:
        return Path(args.output).expanduser().resolve()
    if args.scan_root:
        return (Path(args.scan_root).expanduser().resolve() / "env_check.json")
    return (Path.cwd() / "env_check.json").resolve()


def detect_platform():
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    return "unknown"


def detect_pkg_manager():
    for name, binary in (("apt", "apt-get"), ("dnf", "dnf"), ("brew", "brew")):
        if shutil.which(binary):
            return name
    return "unknown"


def ensure_local_bin(path_warnings):
    path_patched = False
    local_bin = Path.home() / ".local" / "bin"
    try:
        local_bin.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        path_warnings.append(f"failed to create {local_bin}: {exc}")
        return path_patched

    local_bin_s = str(local_bin)
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if local_bin_s not in path_entries:
        os.environ["PATH"] = local_bin_s + os.pathsep + os.environ.get("PATH", "")
        shell_name = Path(os.environ.get("SHELL", "sh")).name
        profile = "~/.zshrc" if shell_name == "zsh" else "~/.bashrc"
        path_warnings.append(
            f"{local_bin_s} was not in PATH; added for this session. Persistent fix: "
            f"echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> {profile}"
        )
        path_patched = True
    return path_patched


def command_exists(binary):
    found = shutil.which(binary)
    if found:
        return Path(found).resolve()
    return None


def scan_extended_dirs(binary):
    for item in EXTENDED_DIRS:
        directory = Path(item).expanduser()
        candidate = directory / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            dir_s = str(directory.resolve())
            path_entries = os.environ.get("PATH", "").split(os.pathsep)
            patched = False
            if dir_s not in path_entries:
                os.environ["PATH"] = dir_s + os.pathsep + os.environ.get("PATH", "")
                patched = True
            return candidate.resolve(), patched
    return None, False


def run_command(command, timeout=20):
    try:
        return subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, exc.stdout or "", exc.stderr or "timeout")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def extract_version(text):
    match = re.search(r"([0-9]+(?:\.[0-9]+){0,3})", text or "")
    return match.group(1) if match else ""


def version_tuple(value):
    return tuple(int(part) for part in re.findall(r"\d+", value or ""))


def version_is_low(detected, required):
    if not detected or not required:
        return False
    left = version_tuple(detected)
    right = version_tuple(required)
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return left < right


def install_hints(tool):
    methods = tool.get("install_priority") or []
    cmds = tool.get("install_cmds") or {}
    hints = []
    for method in methods:
        if method == "pipx":
            hints.append(f"pipx install {tool['name']}")
        elif method == "pip":
            hints.append(f"pip install --user {tool['name']}")
        elif method == "npm" and tool.get("npm_package"):
            hints.append(f"npm install -g {tool['npm_package']}")
        elif method in cmds:
            hints.append(cmds[method])
        elif method == "manual" and cmds.get("manual"):
            hints.append(cmds["manual"])
    if not hints:
        hints.extend(str(value) for value in cmds.values())
    return hints


def install_command_for_method(method, tool):
    cmds = tool.get("install_cmds") or {}
    if method == "pipx":
        return ["pipx install " + shlex.quote(tool["name"])]
    if method == "pip":
        return ["pip install --user " + shlex.quote(tool["name"])]
    if method == "npm":
        package = tool.get("npm_package")
        return ["npm install -g " + shlex.quote(package)] if package else []
    if method == "manual":
        return [cmds["manual"]] if cmds.get("manual") else []
    if method in cmds:
        return [cmds[method]]
    return []


def confirm_install(tool_name, method, command):
    if not sys.stdin.isatty():
        return False, "install skipped: confirmation unavailable on non-interactive stdin"
    print(f"\nInstall missing tool '{tool_name}' via {method}?")
    print(f"Command: {command}")
    answer = input("Run this command? [y/N] ").strip().lower()
    if answer in {"y", "yes"}:
        return True, ""
    return False, "install skipped: user declined"


def confirm_fallback(tool_name, fallback_name):
    if not sys.stdin.isatty():
        return False, "non-interactive stdin: fallback not auto-activated"
    print(f"\nTool '{tool_name}' could not be installed/verified.")
    print(f"Fallback '{fallback_name}' is available but may produce lower-confidence results.")
    answer = input(f"Use fallback '{fallback_name}' instead? [y/N] ").strip().lower()
    if answer in {"y", "yes"}:
        return True, ""
    return False, "user declined fallback"


def maybe_install(tool, args):
    if args.check_only:
        return False, "", "check-only mode: install skipped"
    if args.offline:
        return False, "", "offline mode: install skipped"

    for method in tool.get("install_priority") or []:
        commands = install_command_for_method(method, tool)
        if not commands:
            continue
        if method == "pipx" and not shutil.which("pipx"):
            continue
        if method == "npm":
            if not shutil.which("npm"):
                continue
            prefix = run_command("npm config get prefix")
            expected = str(Path.home() / ".local")
            current = (prefix.stdout or "").strip()
            if current and current != expected:
                return False, "", (
                    f"npm prefix is {current}; configure npm prefix to {expected} before global installs"
                )
        command = commands[0]
        allowed, reason = confirm_install(tool["name"], method, command)
        if not allowed:
            return False, "", reason
        result = run_command(command, timeout=600)
        if result.returncode == 0:
            return True, method, ""
        message = (result.stderr or result.stdout or "").strip()
        return False, method, message or f"install command failed with exit {result.returncode}"
    return False, "", "no install method available"


def is_applicable(tool, package_type, platform):
    platforms = tool.get("platform") or []
    if platforms and platform not in platforms:
        return False, f"platform {platform} not in {platforms}"
    applies_to = tool.get("applies_to") or ""
    if applies_to and package_type and applies_to != package_type:
        return False, f"applies_to {applies_to}, package-type {package_type}"
    return True, ""


def detect_tool(tool, path_state):
    binary = tool.get("binary_name") or tool["name"]
    found = command_exists(binary)
    if not found:
        found, patched = scan_extended_dirs(binary)
        if patched:
            path_state["path_patched"] = True
    if not found:
        return {
            "available": False,
            "found_in": "",
            "detected_version": "",
            "error_message": "binary not found",
        }

    detected_version = ""
    error_message = ""
    detect_cmd = tool.get("detect_cmd") or f"{shlex.quote(binary)} --version"
    result = run_command(detect_cmd)
    if result.returncode == 0:
        detected_version = extract_version((result.stdout or "") + "\n" + (result.stderr or ""))
    else:
        error_message = ((result.stderr or result.stdout or "").strip() or f"detect command exited {result.returncode}")
    return {
        "available": True,
        "found_in": str(found),
        "detected_version": detected_version,
        "error_message": error_message,
    }


def detect_fallback(fallback, tools_by_name, path_state):
    fallback_tool = tools_by_name.get(fallback)
    if fallback_tool:
        result = detect_tool(fallback_tool, path_state)
        return result["available"], result.get("found_in", ""), fallback_tool.get("binary_name") or fallback
    found = command_exists(fallback)
    if not found:
        found, patched = scan_extended_dirs(fallback)
        if patched:
            path_state["path_patched"] = True
    return bool(found), str(found) if found else "", fallback


def make_tool_record(tool, args, platform, tools_by_name, path_state):
    priority = tool.get("priority", "optional")
    binary = tool.get("binary_name") or tool["name"]
    record = {
        "name": tool["name"],
        "binary_name": binary,
        "priority": priority,
        "status": "missing",
        "applicable": True,
    }

    applicable, reason = is_applicable(tool, args.package_type, platform)
    if not applicable:
        record["status"] = "skipped_not_applicable"
        record["applicable"] = False
        record["error_message"] = reason
        return record

    detection = detect_tool(tool, path_state)
    if detection["available"] and not args.force:
        record["status"] = "available"
        record["found_in"] = detection["found_in"]
        if detection["detected_version"]:
            record["detected_version"] = detection["detected_version"]
        if tool.get("version_min"):
            record["required_version"] = tool["version_min"]
            if version_is_low(detection["detected_version"], tool["version_min"]):
                record["status"] = "version_low"
                install_ok, method, error = maybe_install(tool, args)
                if install_ok:
                    after = detect_tool(tool, path_state)
                    if after["available"]:
                        record["status"] = "available"
                        record["found_in"] = after["found_in"]
                        record["install_method"] = method
                        if after["detected_version"]:
                            record["detected_version"] = after["detected_version"]
                        if version_is_low(after["detected_version"], tool["version_min"]):
                            record["status"] = "version_low"
                    else:
                        record["status"] = "install_failed"
                        record["install_method"] = method
                        record["error_message"] = after["error_message"] or "install verification failed"
                elif error:
                    record["error_message"] = error
        if detection["error_message"]:
            record["error_message"] = detection["error_message"]
    else:
        install_ok, method, error = maybe_install(tool, args)
        if install_ok:
            after = detect_tool(tool, path_state)
            if after["available"]:
                record["status"] = "available"
                record["found_in"] = after["found_in"]
                record["install_method"] = method
                if after["detected_version"]:
                    record["detected_version"] = after["detected_version"]
                if tool.get("version_min"):
                    record["required_version"] = tool["version_min"]
                    if version_is_low(after["detected_version"], tool["version_min"]):
                        record["status"] = "version_low"
            else:
                record["status"] = "install_failed"
                record["install_method"] = method
                record["error_message"] = after["error_message"] or "install verification failed"
        else:
            record["status"] = "missing"
            record["error_message"] = error or detection["error_message"]

    if record["status"] in {"missing", "version_low", "install_failed"}:
        for fallback in tool.get("fallbacks") or []:
            ok, found_in, binary_name = detect_fallback(fallback, tools_by_name, path_state)
            if ok:
                if args.auto_fix:
                    allowed = True
                else:
                    allowed, reason = confirm_fallback(tool["name"], fallback)
                if allowed:
                    record["status"] = "fallback_active"
                    record["fallback_used"] = fallback
                    record["found_in"] = found_in
                    record["error_message"] = f"primary unavailable; using fallback {fallback} ({binary_name})"
                    break
                else:
                    suffix = f"; fallback {fallback} declined ({reason})"
                    record["error_message"] = (record.get("error_message") or "") + suffix
                    break
    return record


def compute_decision(records):
    blocked_tools = []
    install_hints_out = []
    phase_blocks = []
    warnings = []
    confidence_ceiling = 0.95

    for record in records:
        if not record.get("applicable", True):
            continue
        priority = record["priority"]
        status = record["status"]
        if status == "available":
            continue
        if status == "fallback_active":
            if priority == "required":
                confidence_ceiling = min(confidence_ceiling, 0.80)
            warnings.append(f"{record['name']} using fallback {record.get('fallback_used', '')}".strip())
            continue
        if priority == "required":
            blocked_tools.append(record["name"])
            for hint in record.get("_install_hints", []):
                install_hints_out.append(f"{record['name']}: {hint}")
        elif priority == "required_verify":
            phase_blocks.append({
                "phase": "phase_3",
                "tool": record["name"],
                "reason": record.get("error_message", "verification runtime unavailable"),
            })
        elif priority == "high":
            confidence_ceiling -= 0.05
            warnings.append(f"{record['name']} unavailable: {status}")
        elif priority == "medium":
            confidence_ceiling -= 0.02
            warnings.append(f"{record['name']} unavailable: {status}")

    confidence_ceiling = max(0.0, min(1.0, round(confidence_ceiling, 2)))
    reason = ""
    if blocked_tools:
        reason = "required tools missing with no available fallback"
    elif phase_blocks:
        reason = "verification phase has unavailable runtime tools"
    elif warnings:
        reason = "scan can continue with degraded tool coverage"

    return {
        "block_decision": {
            "blocked": bool(blocked_tools),
            "reason": reason,
            "blocked_tools": blocked_tools,
            "install_hints": install_hints_out,
            "phase_blocks": phase_blocks,
            "warnings": warnings,
        },
        "confidence_ceiling": confidence_ceiling,
    }


def main():
    args = parse_args()
    registry_path, tools = load_registry(args.registry)
    out_path = output_path(args)
    print(f"env_check output: {out_path}")

    platform = detect_platform()
    package_manager = detect_pkg_manager()
    path_warnings = []
    path_state = {"path_patched": ensure_local_bin(path_warnings)}
    tools_by_name = {tool["name"]: tool for tool in tools if "name" in tool}

    print("=== BlackBox Hunter Environment Preflight ===")
    print(f"Platform: {platform} | Package manager: {package_manager}")
    if args.offline:
        print("Mode: offline (detect existing tools only; installs are skipped)")
    if args.check_only:
        print("Mode: check-only (installs are skipped)")
    if args.package_type:
        print(f"Package type filter: {args.package_type}")
    print(f"Registry: {registry_path}")

    records = []
    for index, tool in enumerate(tools, start=1):
        if "name" not in tool:
            continue
        print(f"[{index}/{len(tools)}] {tool['name']} ({tool.get('priority', 'optional')}) ... ", end="", flush=True)
        record = make_tool_record(tool, args, platform, tools_by_name, path_state)
        record["_install_hints"] = install_hints(tool)
        print(record["status"])
        records.append(record)

    decision = compute_decision(records)
    public_records = []
    for record in records:
        item = {key: value for key, value in record.items() if not key.startswith("_") and value not in ("", None, [])}
        public_records.append(item)

    report = {
        "checked_at": now_iso(),
        "path_patched": bool(path_state["path_patched"]),
        "path_warnings": path_warnings,
        "extended_dirs_scanned": EXTENDED_DIRS,
        "offline_mode": bool(args.offline),
        "check_only": bool(args.check_only),
        "registry_path": str(registry_path),
        "output_path": str(out_path),
        "package_type": args.package_type,
        "tools": public_records,
        "block_decision": decision["block_decision"],
        "confidence_ceiling": decision["confidence_ceiling"],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("")
    print("=== Preflight Summary ===")
    print(f"Tools checked: {len(public_records)}")
    print(f"Blocked: {str(report['block_decision']['blocked']).lower()}")
    print(f"Confidence ceiling: {report['confidence_ceiling']}")
    print(f"env_check written: {out_path}")

    return 1 if report["block_decision"]["blocked"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit("ERROR: interrupted")
PY
