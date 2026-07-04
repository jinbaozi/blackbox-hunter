#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.bbh_scan import collect_inventory  # noqa: E402


def write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def test_complex_inventory_covers_exec_config_service_library() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cli = root / "usr" / "bin" / "cli-entry"
        write(cli, "#!/bin/sh\necho cli\n", 0o4755)
        config = root / "etc" / "example" / "config.conf"
        write(config, "listen=127.0.0.1\n")
        service = root / "lib" / "systemd" / "system" / "example.service"
        write(service, "[Service]\nExecStart=/usr/bin/cli-entry\n")
        library = root / "usr" / "lib" / "libdemo.so"
        write(library, "not-real-elf-but-library-surface\n")

        binaries, attack_surface, architectures = collect_inventory(root)

    assert architectures == ["script"]
    assert len(binaries) == 1
    assert binaries[0]["path"].endswith("/usr/bin/cli-entry")
    assert binaries[0]["setuid"] is True
    assert binaries[0]["priority"] == 40

    surfaces = {(item["type"], item["entry_point"]) for item in attack_surface}
    assert ("cli", "/usr/bin/cli-entry") in surfaces
    assert ("config", "/etc/example/config.conf") in surfaces
    assert ("config", "/lib/systemd/system/example.service") in surfaces
    assert ("library", "/usr/lib/libdemo.so") in surfaces


def run_all() -> None:
    test_complex_inventory_covers_exec_config_service_library()


if __name__ == "__main__":
    run_all()
    print("complex inventory tests OK")
