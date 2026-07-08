#!/usr/bin/env python3
"""B7: generate a libFuzzer-compatible C harness from a finding.

Given a finding with ``evidence.reproduction_hint`` and ``attack_surface``,
emit a self-contained C file that calls ``LLVMFuzzerTestOneInput`` and
forwards the fuzz payload to the target binary via ``execvp`` /
``popen`` / direct stdin. The harness is meant to compile with
``clang -fsanitize=fuzzer,address`` and run under afl-clang-fast via
``AFL_DRIVER_DSO_DEFER=1``.

We deliberately keep the harness trivial:

* Read N bytes from libFuzzer into a buffer.
* Pipe the buffer to the target binary's stdin.
* Invoke the binary with the documented entry_point as argv[1].
* Return 0 on clean exit, 1 on signal/timeout.

The harness never links against target code (we have no source); it
relies on the OS to dispatch stdin/argv, which is the documented pattern
for fuzzing file-consuming CLIs.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any


# Maximum fuzz payload size (libFuzzer default).
_MAX_LEN = 1 << 20  # 1 MiB


def _entry_point_args(finding: dict[str, Any]) -> list[str]:
    surface = finding.get("attack_surface") or {}
    entry = surface.get("entry_point")
    if not entry:
        return []
    try:
        return shlex.split(str(entry))
    except ValueError:
        return [str(entry)]


def _target_path(finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    return str(location.get("binary") or "/bin/cat")


def render_harness(finding: dict[str, Any]) -> str:
    """Return C source for a libFuzzer harness bound to ``finding``."""
    target = _target_path(finding)
    target_basename = Path(target).name
    args = _entry_point_args(finding)
    args_c_array = ",\n    ".join(f'"{a}"' for a in args) if args else ""
    args_joiner = ",\n    " + args_c_array if args_c_array else ""
    finding_id = finding.get('finding_id', 'unknown')
    compile_target = finding.get('finding_id', 'target')
    return f"""/* B7 fuzz harness: auto-generated for finding {finding_id}.
 * Compile with: clang -fsanitize=fuzzer,address -o fuzz_target {compile_target}.c
 * Run with:    ./fuzz_target corpus/ -max_total_time=30
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_LEN ({_MAX_LEN})

static const char *TARGET = "{target}";
static const char *TARGET_ARGS[] = {{
    "{target_basename}"{args_joiner}
}};
#define TARGET_ARGS_LEN (sizeof(TARGET_ARGS) / sizeof(TARGET_ARGS[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0 || size > MAX_LEN) return 0;
    int p[2];
    if (pipe(p) != 0) return 0;

    pid_t pid = fork();
    if (pid == 0) {{
        /* child: read payload from stdin, run target */
        close(p[1]);
        dup2(p[0], STDIN_FILENO);
        close(p[0]);
        char *argv[TARGET_ARGS_LEN + 1];
        for (size_t i = 0; i < TARGET_ARGS_LEN; i++) argv[i] = (char *)TARGET_ARGS[i];
        argv[TARGET_ARGS_LEN] = NULL;
        execvp(TARGET, argv);
        _exit(127);
    }}
    close(p[0]);
    /* parent: write fuzz payload to child's stdin */
    ssize_t off = 0;
    while (off < (ssize_t)size) {{
        ssize_t n = write(p[1], data + off, size - off);
        if (n <= 0) break;
        off += n;
    }}
    close(p[1]);
    int status = 0;
    waitpid(pid, &status, 0);
    /* libFuzzer treats any non-zero exit as a finding; we propagate signals */
    if (WIFSIGNALED(status)) return 1;
    return WEXITSTATUS(status);
}}
"""


def generate_harness(
    finding: dict[str, Any],
    output_path: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Write the harness for ``finding`` to ``output_path``.

    Returns the path + a sha256 of the rendered source for audit.
    """
    if output_path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite {output_path} (use --force)")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    src = render_harness(finding)
    output_path.write_text(src, encoding="utf-8")
    import hashlib
    sha = hashlib.sha256(src.encode("utf-8")).hexdigest()
    return {
        "finding_id": finding.get("finding_id"),
        "harness_path": str(output_path),
        "harness_sha256": sha,
        "compile_cmd": "clang -fsanitize=fuzzer,address -g -o " + str(output_path.with_suffix("")) + " " + str(output_path),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B7 fuzz harness generator")
    p.add_argument("--finding", required=True, help="Path to finding JSON")
    p.add_argument("--output", required=True, help="Where to write the .c harness")
    p.add_argument("--force", action="store_true", help="Overwrite existing harness")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    result = generate_harness(finding, Path(args.output), force=args.force)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())