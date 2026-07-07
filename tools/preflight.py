#!/usr/bin/env python3
"""BlackBox Hunter environment preflight."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(ROOT))

from tools.output_paths import resolve_preflight_output  # noqa: E402

TARBALL_PATH = "assets/rootfs/v11-2503-rootfs.tar"
LFS_POINTER_THRESHOLD_BYTES = 100 * 1024
DEFAULT_REGISTRY = SCRIPT_DIR / "tool_registry.json"
EXTENDED_DIRS = [
    "~/.local/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/opt/homebrew/bin",
    "/snap/bin",
    "~/.cargo/bin",
]
PKG_MANAGER_BINARIES = {
    "apt": "apt-get",
    "dnf": "dnf",
    "microdnf": "microdnf",
    "yum": "yum",
    "zypper": "zypper",
    "rpm-ostree": "rpm-ostree",
    "brew": "brew",
}
DEFAULT_MANAGER_PRIORITY = {
    "rpm": ["dnf", "microdnf", "yum", "zypper", "rpm-ostree", "apt", "brew"],
    "deb": ["apt", "dnf", "microdnf", "yum", "zypper", "rpm-ostree", "brew"],
    "": ["apt", "dnf", "microdnf", "yum", "zypper", "rpm-ostree", "brew"],
}
RPM_NATIVE_MANAGERS = {"dnf", "microdnf", "yum", "zypper", "rpm-ostree"}
PACKAGE_MANAGER_METHODS = set(PKG_MANAGER_BINARIES)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BlackBox Hunter environment preflight and tool installer")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--auto-fix", action="store_true")
    parser.add_argument("--package-type", choices=["deb", "rpm"], default="")
    parser.add_argument("--package-path", default="", help="Optional package path used to infer package type")
    parser.add_argument("--output", default="")
    parser.add_argument("--scan-root", default="")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    return parser.parse_args()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def infer_package_type(args: argparse.Namespace) -> str:
    if args.package_type:
        return args.package_type
    suffix = Path(args.package_path).suffix.lower()
    if suffix == ".rpm":
        return "rpm"
    if suffix == ".deb":
        return "deb"
    return ""


def load_registry(path: str) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    registry_path = Path(path).expanduser().resolve()
    if not registry_path.exists():
        raise SystemExit(f"ERROR: tool registry not found: {registry_path}")
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: malformed tool registry {registry_path}: {exc}") from exc
    if not isinstance(data.get("tools"), list):
        raise SystemExit(f"ERROR: registry {registry_path} must contain a tools array")
    return registry_path, data, data["tools"]


def output_path(args: argparse.Namespace) -> Path:
    return resolve_preflight_output(args.output, args.scan_root)


def detect_platform() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    return "unknown"


def manager_priority(registry: dict[str, Any], package_type: str) -> list[str]:
    configured = registry.get("package_manager_priority") or {}
    values = configured.get(package_type) or DEFAULT_MANAGER_PRIORITY.get(package_type) or DEFAULT_MANAGER_PRIORITY[""]
    return [str(item) for item in values]


def detect_pkg_manager(package_type: str, registry: dict[str, Any]) -> str:
    if sys.platform == "darwin":
        order = ["brew"]
    else:
        order = manager_priority(registry, package_type)
    for name in order:
        if shutil.which(PKG_MANAGER_BINARIES.get(name, name)):
            return name
    return "unknown"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def engine_for_status(engine_status: str) -> str | None:
    if engine_status == "ready":
        return "docker"
    if engine_status == "ready_podman":
        return "podman"
    return None


def image_exists(engine_status: str, image_ref: str | None) -> bool:
    engine = engine_for_status(engine_status)
    if not engine or not image_ref:
        return False
    result = run_argv([engine, "image", "inspect", image_ref], timeout=20)
    return result.returncode == 0


def detect_rootfs(repo_root: Path, engine_status: str = "unavailable") -> dict[str, str | None]:
    """Return rootfs_status and imported_image_ref.

    Statuses: imported, stale, not_imported, lfs_pointer, missing.
    """
    tarball = repo_root / TARBALL_PATH
    record = repo_root / "tools" / ".imported_rootfs.json"
    if not tarball.is_file():
        return {"rootfs_status": "missing", "imported_image_ref": None}
    if tarball.stat().st_size < LFS_POINTER_THRESHOLD_BYTES:
        return {"rootfs_status": "lfs_pointer", "imported_image_ref": None}
    if not record.is_file():
        return {"rootfs_status": "not_imported", "imported_image_ref": None}
    rec = json.loads(record.read_text(encoding="utf-8"))
    stable_ref = rec.get("stable_ref")
    actual_sha = sha256_file(tarball)
    if rec.get("tarball_sha256") != actual_sha:
        return {"rootfs_status": "stale", "imported_image_ref": stable_ref}
    if not image_exists(engine_status, stable_ref):
        return {"rootfs_status": "not_imported", "imported_image_ref": stable_ref}
    return {"rootfs_status": "imported", "imported_image_ref": stable_ref}


def detect_engine() -> str:
    for engine in ("docker", "podman"):
        path = shutil.which(engine)
        if path is None:
            continue
        result = run_argv([engine, "info"], timeout=20)
        if result.returncode == 0:
            return "ready" if engine == "docker" else "ready_podman"
    return "unavailable"


def reconcile_engine_phase_blocks(block_decision: dict[str, Any], engine: str) -> None:
    phase_blocks = block_decision.setdefault("phase_blocks", [])
    if engine in ("ready", "ready_podman"):
        phase_blocks[:] = [
            block for block in phase_blocks
            if not (block.get("phase") == "phase_3" and block.get("tool") in {"docker", "podman"})
        ]
        if not block_decision.get("blocked") and not phase_blocks:
            block_decision["reason"] = ""
        return

    if not any(block.get("phase") == "phase_3" and block.get("tool") == "docker" for block in phase_blocks):
        phase_blocks.append({
            "phase": "phase_3",
            "tool": "docker",
            "reason": "missing",
        })


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item and item not in seen:
            output.append(item)
            seen.add(item)
    return output


def resolve_install_priority(tool: dict[str, Any], package_type: str, package_manager: str, registry: dict[str, Any]) -> list[str]:
    methods = [str(item) for item in (tool.get("install_priority") or [])]
    if not methods:
        return []
    if package_type != "rpm":
        return methods

    cmds = tool.get("install_cmds") or {}
    system_packages = tool.get("system_packages") or {}
    rpm_first: list[str] = []
    if package_manager in RPM_NATIVE_MANAGERS:
        rpm_first.append(package_manager)
    rpm_first.extend(manager_priority(registry, "rpm"))
    rpm_first.extend(["docker", "snap", "script", "pipx", "npm", "pip", "manual"])

    ordered: list[str] = []
    for method in dedupe(rpm_first):
        if method in methods or method in cmds or method in system_packages:
            ordered.append(method)
    ordered.extend(method for method in methods if method not in ordered)
    return ordered


def ensure_local_bin(path_warnings: list[str]) -> bool:
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


def command_exists(binary: str) -> Path | None:
    found = shutil.which(binary) if binary else None
    return Path(found).resolve() if found else None


def scan_extended_dirs(binary: str) -> tuple[Path | None, bool]:
    if not binary:
        return None, False
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


def find_binary(binary: str, path_state: dict[str, bool]) -> Path | None:
    found = command_exists(binary)
    if not found:
        found, patched = scan_extended_dirs(binary)
        if patched:
            path_state["path_patched"] = True
    return found


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def run_argv(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    if not argv:
        return subprocess.CompletedProcess(argv, 127, "", "empty command")
    try:
        return subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, exc.stdout or "", exc.stderr or "timeout")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def run_command(command: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return run_argv(split_command(command), timeout=timeout)


def extract_version(text: str) -> str:
    match = re.search(r"([0-9]+(?:\.[0-9]+){0,3})", text or "")
    return match.group(1) if match else ""


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value or ""))


def version_is_low(detected: str, required: str) -> bool:
    if not detected or not required:
        return False
    left = version_tuple(detected)
    right = version_tuple(required)
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return left < right


def sudo_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo"] if shutil.which("sudo") else []


def system_install_argv(method: str, packages: list[str]) -> list[str]:
    if not packages:
        return []
    prefix = sudo_prefix()
    if method == "apt":
        return prefix + ["apt-get", "install", "-y"] + packages
    if method in {"dnf", "microdnf", "yum"}:
        return prefix + [method, "install", "-y"] + packages
    if method == "zypper":
        return prefix + ["zypper", "install", "-y"] + packages
    if method == "rpm-ostree":
        return prefix + ["rpm-ostree", "install"] + packages
    if method == "brew":
        return ["brew", "install"] + packages
    return []


def install_hints(tool: dict[str, Any], args: argparse.Namespace, package_type: str, package_manager: str, registry: dict[str, Any]) -> list[str]:
    methods = resolve_install_priority(tool, package_type, package_manager, registry)
    cmds = tool.get("install_cmds") or {}
    system_packages = tool.get("system_packages") or {}
    hints: list[str] = []
    for method in methods:
        if method == "pipx":
            hints.append(f"pipx install {tool['name']}")
        elif method == "pip":
            hints.append(f"pip install --user {tool['name']}")
        elif method == "npm" and tool.get("npm_package"):
            hints.append(f"npm install -g {tool['npm_package']}")
        elif method in system_packages:
            argv = system_install_argv(method, [str(item) for item in system_packages[method]])
            if argv:
                hints.append(shlex.join(argv))
        elif method in cmds:
            value = cmds[method]
            hints.append(shlex.join(value) if isinstance(value, list) else str(value))
        elif method == "manual" and cmds.get("manual"):
            hints.append(str(cmds["manual"]))
    if not hints:
        hints.extend(str(value) for value in cmds.values() if isinstance(value, str))
    return dedupe(hints)


def install_command_for_method(method: str, tool: dict[str, Any]) -> list[str]:
    cmds = tool.get("install_cmds") or {}
    system_packages = tool.get("system_packages") or {}
    if method == "pipx":
        return ["pipx", "install", tool["name"]]
    if method == "pip":
        return ["pip", "install", "--user", tool["name"]]
    if method == "npm":
        package = tool.get("npm_package")
        return ["npm", "install", "-g", package] if package else []
    if method in system_packages:
        return system_install_argv(method, [str(item) for item in system_packages[method]])
    if method == "docker" and tool.get("container_image"):
        return ["docker", "pull", str(tool["container_image"])]
    if method == "manual":
        return []
    if method in cmds:
        value = cmds[method]
        if isinstance(value, list):
            return [str(item) for item in value]
        return split_command(str(value))
    return []


def confirm_install(tool_name: str, method: str, argv: list[str]) -> tuple[bool, str]:
    if not sys.stdin.isatty():
        return False, "install skipped: confirmation unavailable on non-interactive stdin"
    print(f"\nInstall missing tool '{tool_name}' via {method}?")
    print(f"Command: {shlex.join(argv)}")
    answer = input("Run this command? [y/N] ").strip().lower()
    if answer in {"y", "yes"}:
        return True, ""
    return False, "install skipped: user declined"


def confirm_fallback(tool_name: str, fallback_name: str) -> tuple[bool, str]:
    if not sys.stdin.isatty():
        return False, "non-interactive stdin: fallback not auto-activated"
    print(f"\nTool '{tool_name}' could not be installed/verified.")
    print(f"Fallback '{fallback_name}' is available but may produce lower-confidence results.")
    answer = input(f"Use fallback '{fallback_name}' instead? [y/N] ").strip().lower()
    if answer in {"y", "yes"}:
        return True, ""
    return False, "user declined fallback"


def maybe_install(tool: dict[str, Any], args: argparse.Namespace, package_type: str, package_manager: str, registry: dict[str, Any]) -> tuple[bool, str, str]:
    if args.check_only:
        return False, "", "check-only mode: install skipped"
    if args.offline:
        return False, "", "offline mode: install skipped"

    for method in resolve_install_priority(tool, package_type, package_manager, registry):
        argv = install_command_for_method(method, tool)
        if not argv:
            continue
        if method == "pipx" and not shutil.which("pipx"):
            continue
        if method == "npm":
            if not shutil.which("npm"):
                continue
            prefix = run_argv(["npm", "config", "get", "prefix"])
            expected = str(Path.home() / ".local")
            current = (prefix.stdout or "").strip()
            if current and current != expected:
                return False, "", f"npm prefix is {current}; configure npm prefix to {expected} before global installs"
        allowed, reason = confirm_install(tool["name"], method, argv)
        if not allowed:
            return False, "", reason
        result = run_argv(argv, timeout=600)
        if result.returncode == 0:
            return True, method, ""
        message = (result.stderr or result.stdout or "").strip()
        return False, method, message or f"install command failed with exit {result.returncode}"
    return False, "", "no install method available"


def is_applicable(tool: dict[str, Any], package_type: str, platform: str) -> tuple[bool, str]:
    platforms = tool.get("platform") or []
    if platforms and platform not in platforms:
        return False, f"platform {platform} not in {platforms}"
    applies_to = tool.get("applies_to") or ""
    if applies_to:
        if not package_type:
            return False, f"applies_to {applies_to}, package-type unknown"
        if applies_to != package_type:
            return False, f"applies_to {applies_to}, package-type {package_type}"
    return True, ""


def detect_container_image_tool(tool: dict[str, Any], path_state: dict[str, bool]) -> dict[str, str | bool]:
    engine = tool.get("container_engine") or "docker"
    engine_found = find_binary(engine, path_state)
    if not engine_found:
        return {"available": False, "found_in": "", "detected_version": "", "error_message": f"container engine not found: {engine}"}

    image = tool.get("container_image") or tool.get("image") or tool["name"]
    detect_cmd = tool.get("detect_cmd") or f"{shlex.quote(engine)} image inspect {shlex.quote(image)}"
    result = run_command(detect_cmd, timeout=60)
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    if result.returncode == 0:
        return {"available": True, "found_in": str(engine_found), "detected_version": extract_version(output), "error_message": ""}

    message = (result.stderr or result.stdout or "").strip()
    return {
        "available": False,
        "found_in": str(engine_found),
        "detected_version": "",
        "error_message": message or f"container image unavailable or detect command exited {result.returncode}: {image}",
    }


def detect_host_binary_tool(tool: dict[str, Any], path_state: dict[str, bool]) -> dict[str, str | bool]:
    binary = tool.get("binary_name") or tool["name"]
    found = find_binary(binary, path_state)
    if not found:
        return {"available": False, "found_in": "", "detected_version": "", "error_message": "binary not found"}

    detect_cmd = tool.get("detect_cmd") or f"{shlex.quote(binary)} --version"
    result = run_command(detect_cmd)
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    if result.returncode != 0 and not tool.get("detect_nonzero_ok", False):
        message = (result.stderr or result.stdout or "").strip()
        return {
            "available": False,
            "found_in": str(found),
            "detected_version": "",
            "error_message": message or f"detect command exited {result.returncode}",
        }
    return {"available": True, "found_in": str(found), "detected_version": extract_version(output), "error_message": ""}


def detect_tool(tool: dict[str, Any], path_state: dict[str, bool]) -> dict[str, str | bool]:
    if (tool.get("execution_model") or "host_binary") == "container_image":
        return detect_container_image_tool(tool, path_state)
    return detect_host_binary_tool(tool, path_state)


def detect_fallback(fallback: str, tools_by_name: dict[str, dict[str, Any]], path_state: dict[str, bool]) -> tuple[bool, str, str]:
    fallback_tool = tools_by_name.get(fallback)
    if fallback_tool:
        result = detect_tool(fallback_tool, path_state)
        binary_name = fallback_tool.get("binary_name") or fallback_tool.get("container_image") or fallback
        return bool(result["available"]), str(result.get("found_in", "")), str(binary_name)
    found = find_binary(fallback, path_state)
    return bool(found), str(found) if found else "", fallback


def mark_after_install(tool: dict[str, Any], method: str, path_state: dict[str, bool], record: dict[str, Any]) -> None:
    after = detect_tool(tool, path_state)
    if not after["available"]:
        record["status"] = "install_failed"
        record["install_method"] = method
        record["error_message"] = after["error_message"] or "install verification failed"
        return
    record["status"] = "available"
    record["found_in"] = after["found_in"]
    record["install_method"] = method
    if after["detected_version"]:
        record["detected_version"] = after["detected_version"]
    if tool.get("version_min"):
        record["required_version"] = tool["version_min"]
        if version_is_low(str(after["detected_version"]), tool["version_min"]):
            record["status"] = "version_low"
            record["error_message"] = f"installed version below required minimum {tool['version_min']}"


def make_tool_record(
    tool: dict[str, Any],
    args: argparse.Namespace,
    package_type: str,
    platform: str,
    package_manager: str,
    registry: dict[str, Any],
    tools_by_name: dict[str, dict[str, Any]],
    path_state: dict[str, bool],
) -> dict[str, Any]:
    priority = tool.get("priority", "optional")
    binary = tool.get("binary_name") or tool["name"]
    execution_model = tool.get("execution_model") or "host_binary"
    record: dict[str, Any] = {
        "name": tool["name"],
        "binary_name": binary,
        "execution_model": execution_model,
        "priority": priority,
        "status": "missing",
        "applicable": True,
    }
    if tool.get("container_image"):
        record["container_image"] = tool["container_image"]
    if tool.get("container_engine"):
        record["container_engine"] = tool["container_engine"]

    applicable, reason = is_applicable(tool, package_type, platform)
    if not applicable:
        record.update({"status": "skipped_not_applicable", "applicable": False, "error_message": reason})
        return record

    detection = detect_tool(tool, path_state)
    if detection["available"] and not args.force:
        record["status"] = "available"
        record["found_in"] = detection["found_in"]
        if detection["detected_version"]:
            record["detected_version"] = detection["detected_version"]
        if tool.get("version_min"):
            record["required_version"] = tool["version_min"]
            if version_is_low(str(detection["detected_version"]), tool["version_min"]):
                record["status"] = "version_low"
                install_ok, method, error = maybe_install(tool, args, package_type, package_manager, registry)
                if install_ok:
                    mark_after_install(tool, method, path_state, record)
                elif error:
                    record["error_message"] = error
    else:
        install_ok, method, error = maybe_install(tool, args, package_type, package_manager, registry)
        if install_ok:
            mark_after_install(tool, method, path_state, record)
        else:
            record["status"] = "missing"
            record["error_message"] = error or str(detection["error_message"])
            if detection.get("found_in"):
                record["found_in"] = detection["found_in"]

    if record["status"] in {"missing", "version_low", "install_failed"}:
        for fallback in tool.get("fallbacks") or []:
            ok, found_in, binary_name = detect_fallback(str(fallback), tools_by_name, path_state)
            if ok:
                if args.auto_fix:
                    allowed, fallback_reason = True, ""
                else:
                    allowed, fallback_reason = confirm_fallback(tool["name"], str(fallback))
                if allowed:
                    record["status"] = "fallback_active"
                    record["fallback_used"] = str(fallback)
                    record["found_in"] = found_in
                    record["error_message"] = f"primary unavailable; using fallback {fallback} ({binary_name})"
                    break
                record["error_message"] = (record.get("error_message") or "") + f"; fallback {fallback} declined ({fallback_reason})"
                break
    return record


def compute_decision(records: list[dict[str, Any]]) -> dict[str, Any]:
    blocked_tools: list[str] = []
    install_hints_out: list[str] = []
    phase_blocks: list[dict[str, str]] = []
    warnings: list[str] = []
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


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    package_type = infer_package_type(args)
    registry_path, registry, tools = load_registry(args.registry)
    out_path = output_path(args)
    print(f"env_check output: {out_path}")

    platform = detect_platform()
    package_manager = detect_pkg_manager(package_type, registry)
    path_warnings: list[str] = []
    path_state = {"path_patched": ensure_local_bin(path_warnings)}
    tools_by_name = {tool["name"]: tool for tool in tools if "name" in tool}

    print("=== BlackBox Hunter Environment Preflight ===")
    print(f"Platform: {platform} | Package manager: {package_manager}")
    if args.offline:
        print("Mode: offline (detect existing tools only; installs are skipped)")
    if args.check_only:
        print("Mode: check-only (installs are skipped)")
    if package_type:
        print(f"Package type filter: {package_type}")
    print(f"Registry: {registry_path}")

    records: list[dict[str, Any]] = []
    for index, tool in enumerate(tools, start=1):
        if "name" not in tool:
            continue
        print(f"[{index}/{len(tools)}] {tool['name']} ({tool.get('priority', 'optional')}) ... ", end="", flush=True)
        record = make_tool_record(tool, args, package_type, platform, package_manager, registry, tools_by_name, path_state)
        record["_install_hints"] = install_hints(tool, args, package_type, package_manager, registry)
        print(record["status"])
        records.append(record)

    decision = compute_decision(records)
    engine = detect_engine()
    rootfs = detect_rootfs(repo_root, engine)
    public_records = [
        {key: value for key, value in record.items() if not key.startswith("_") and value not in ("", None, [])}
        for record in records
    ]

    report = {
        "checked_at": now_iso(),
        "path_patched": bool(path_state["path_patched"]),
        "path_warnings": path_warnings,
        "extended_dirs_scanned": EXTENDED_DIRS,
        "offline_mode": bool(args.offline),
        "check_only": bool(args.check_only),
        "package_manager": package_manager,
        "registry_path": str(registry_path),
        "output_path": str(out_path),
        "package_type": package_type,
        "tools": public_records,
        "block_decision": decision["block_decision"],
        "confidence_ceiling": decision["confidence_ceiling"],
    }
    report["rootfs_status"] = rootfs["rootfs_status"]
    report["imported_image_ref"] = rootfs["imported_image_ref"]
    report["engine_status"] = engine
    reconcile_engine_phase_blocks(report["block_decision"], engine)

    if rootfs["rootfs_status"] in ("missing", "lfs_pointer"):
        report["block_decision"]["blocked"] = True
        reason_msg = "rootfs tarball is missing or an LFS pointer. Run: git lfs pull"
        report["block_decision"]["reason"] = reason_msg
        report["block_decision"]["blocked_tools"] = list(
            set(report["block_decision"].get("blocked_tools", [])) | {TARBALL_PATH}
        )
        if not any("git lfs pull" in warning for warning in report["block_decision"].get("warnings", [])):
            report["block_decision"].setdefault("warnings", []).append(reason_msg)
        print(f"ERROR: {reason_msg}", file=sys.stderr)
    elif rootfs["rootfs_status"] in ("not_imported", "stale"):
        reason_msg = "rootfs image is not imported. Run: python3 tools/import_rootfs.py --tarball assets/rootfs/v11-2503-rootfs.tar"
        if not any("import_rootfs.py" in warning for warning in report["block_decision"].get("warnings", [])):
            report["block_decision"].setdefault("warnings", []).append(reason_msg)
        if not any(block.get("phase") == "phase_3" and block.get("tool") == "rootfs" for block in report["block_decision"].get("phase_blocks", [])):
            report["block_decision"].setdefault("phase_blocks", []).append({
                "phase": "phase_3",
                "tool": "rootfs",
                "reason": "not_imported",
            })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("")
    print("=== Preflight Summary ===")
    print(f"Tools checked: {len(public_records)}")
    print(f"Blocked: {str(report['block_decision']['blocked']).lower()}")
    print(f"Confidence ceiling: {report['confidence_ceiling']}")
    print(f"env_check written: {out_path}")

    return 1 if report["block_decision"]["blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
