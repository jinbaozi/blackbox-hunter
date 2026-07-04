#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pty
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def run_pty(cmd: list[str], *, env: dict[str, str], input_text: str, timeout: float = 8.0) -> tuple[int, str]:
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=ROOT, text=False, close_fds=True)
        os.close(slave)
        slave = -1
        data = bytearray()
        deadline = time.time() + timeout
        sent = False
        os.set_blocking(master, False)
        while True:
            if not sent:
                os.write(master, input_text.encode("utf-8"))
                sent = True
            if proc.poll() is not None:
                break
            if time.time() > deadline:
                proc.kill()
                raise TimeoutError("interactive preflight timed out")
            try:
                chunk = os.read(master, 4096)
                if chunk:
                    data.extend(chunk)
            except BlockingIOError:
                pass
            except OSError:
                pass
            time.sleep(0.05)
        while True:
            try:
                chunk = os.read(master, 4096)
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            data.extend(chunk)
        return int(proc.returncode or 0), data.decode("utf-8", errors="replace")
    finally:
        if slave != -1:
            os.close(slave)
        os.close(master)


def base_registry(tmp: Path, *, with_install: bool = False, fallback: bool = False) -> Path:
    tools = []
    if with_install:
        install_cmd = str(tmp / "fakebin" / "install-needtool")
        tools.append({
            "name": "needtool",
            "binary_name": "needtool",
            "execution_model": "host_binary",
            "install_priority": ["dnf", "manual"],
            "install_cmds": {"dnf": install_cmd, "manual": "manual needtool"},
            "detect_cmd": "needtool --version",
            "priority": "required",
            "fallbacks": [],
            "platform": ["linux", "darwin"],
        })
    else:
        tools.append({
            "name": "primary-missing",
            "binary_name": "primary-missing",
            "execution_model": "host_binary",
            "install_priority": ["manual"],
            "install_cmds": {"manual": "manual primary-missing"},
            "detect_cmd": "primary-missing --version",
            "priority": "required",
            "fallbacks": ["fallback-ok"] if fallback else [],
            "platform": ["linux", "darwin"],
        })
    path = tmp / "registry.json"
    path.write_text(json.dumps({"registry_version": 1, "package_manager_priority": {"rpm": ["dnf"], "deb": ["dnf"]}, "tools": tools}), encoding="utf-8")
    return path


def make_env(tmp: Path) -> dict[str, str]:
    home = tmp / "home"
    fakebin = tmp / "fakebin"
    home.mkdir()
    fakebin.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PATH"] = f"{fakebin}:/usr/bin:/bin"
    return env


def install_script() -> str:
    return '''#!/bin/sh
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/needtool" <<'EOS'
#!/bin/sh
echo needtool 2.0
EOS
chmod +x "$HOME/.local/bin/needtool"
exit 0
'''


def test_user_rejects_install_hard_blocks() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = make_env(tmp)
        write(tmp / "fakebin" / "dnf", "#!/bin/sh\nexit 0\n", 0o755)
        write(tmp / "fakebin" / "install-needtool", install_script(), 0o755)
        registry = base_registry(tmp, with_install=True)
        scan = tmp / "scan"
        rc, _ = run_pty([sys.executable, str(ROOT / "tools" / "preflight.py"), "--package-type", "rpm", "--registry", str(registry), "--scan-root", str(scan)], env=env, input_text="n\n")
        assert rc == 1
        data = json.loads((scan / "env_check.json").read_text(encoding="utf-8"))
        assert data["block_decision"]["blocked"] is True
        assert data["tools"][0]["status"] == "missing"


def test_user_approves_install_and_reverify() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = make_env(tmp)
        write(tmp / "fakebin" / "dnf", "#!/bin/sh\necho dnf fixture\n", 0o755)
        write(tmp / "fakebin" / "install-needtool", install_script(), 0o755)
        registry = base_registry(tmp, with_install=True)
        scan = tmp / "scan"
        rc, output = run_pty([sys.executable, str(ROOT / "tools" / "preflight.py"), "--package-type", "rpm", "--registry", str(registry), "--scan-root", str(scan)], env=env, input_text="y\n")
        assert rc == 0, output
        data = json.loads((scan / "env_check.json").read_text(encoding="utf-8"))
        tool = data["tools"][0]
        assert tool["status"] == "available", tool
        assert tool["install_method"] == "dnf"


def test_user_approves_fallback() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = make_env(tmp)
        write(tmp / "home" / ".local" / "bin" / "fallback-ok", "#!/bin/sh\necho fallback 1.0\n", 0o755)
        registry = base_registry(tmp, fallback=True)
        scan = tmp / "scan"
        rc, output = run_pty([sys.executable, str(ROOT / "tools" / "preflight.py"), "--package-type", "deb", "--registry", str(registry), "--scan-root", str(scan)], env=env, input_text="y\n")
        assert rc == 0, output
        data = json.loads((scan / "env_check.json").read_text(encoding="utf-8"))
        assert data["tools"][0]["status"] == "fallback_active"
        assert data["tools"][0]["fallback_used"] == "fallback-ok"


def test_user_declines_fallback_hard_blocks() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = make_env(tmp)
        write(tmp / "home" / ".local" / "bin" / "fallback-ok", "#!/bin/sh\necho fallback 1.0\n", 0o755)
        registry = base_registry(tmp, fallback=True)
        scan = tmp / "scan"
        rc, _ = run_pty([sys.executable, str(ROOT / "tools" / "preflight.py"), "--package-type", "deb", "--registry", str(registry), "--scan-root", str(scan)], env=env, input_text="n\n")
        assert rc == 1
        data = json.loads((scan / "env_check.json").read_text(encoding="utf-8"))
        assert data["block_decision"]["blocked"] is True
        assert data["tools"][0]["status"] == "missing"


def run_all() -> None:
    test_user_rejects_install_hard_blocks()
    test_user_approves_install_and_reverify()
    test_user_approves_fallback()
    test_user_declines_fallback_hard_blocks()


if __name__ == "__main__":
    run_all()
    print("interactive preflight approval tests OK")
