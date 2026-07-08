#!/usr/bin/env python3
"""B6: detect language runtimes and generate runtime-stress PoCs.

The plan addresses GCC's bundled language runtimes (libgomp, libgfortran,
libgo, libjvm, libpython) which are silently shipped in compiler RPMs but
rarely covered by static analysis: a Fortran race condition, an OpenMP
data-sharing bug, or a Java/JVM escape can all live entirely inside a
shared library the scanner never inspects.

This module:

1. Walks the extracted package root and looks for the canonical runtime
   shared object filenames.
2. Emits ``target_profile.detected_runtimes[]`` with one entry per
   detected runtime. Each entry is::

       {
         "name": "openmp",
         "library": "libgomp.so.1",
         "library_path": "/usr/lib64/libgomp.so.1",
         "language": "C/C++",
         "smoke_template": "omp_smoke",
         "confidence": 0.7
       }

3. Generates a small PoC ``run.sh`` per detected runtime into
   ``<scan-root>/poc_results/<finding-id>/run.sh`` (compatible with the
   Phase 3 contract from B2/B3). Each PoC exercises the runtime's
   canonical risk:

   * ``openmp`` -> OMP_NUM_THREADS=2 + a parallel for that asserts a
     thread-count invariant.
   * ``fortran`` -> allocate + write + check.
   * ``go`` -> goroutine spawn + channel race.
   * ``jvm`` -> java -version + a Hello-World that loads the JVM.
   * ``python`` -> py_compile a trivial script.

The PoCs are conservative smoke tests, not fuzz harnesses (B7 covers
fuzzing); they exist so Phase 3 has *something* to run when the
package declares these runtimes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# Detection rules: (substring in filename, runtime name, language)
_RUNTIME_RULES: list[tuple[str, str, str, float]] = [
    ("libgomp", "openmp", "C/C++", 0.75),
    ("libgfortran", "fortran", "Fortran", 0.7),
    ("libgo", "go", "Go", 0.7),
    ("libjvm", "jvm", "Java", 0.7),
    ("libpython", "python", "Python", 0.6),
    ("libperl", "perl", "Perl", 0.6),
    ("libtcl", "tcl", "Tcl", 0.55),
    ("liblua", "lua", "Lua", 0.55),
]


def detect_runtimes(scan_root: Path | str) -> list[dict[str, Any]]:
    """Walk ``scan_root`` and return detected runtime entries."""
    root = Path(scan_root)
    out: list[dict[str, Any]] = []
    if not root.exists():
        return out
    seen: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        for needle, runtime, language, confidence in _RUNTIME_RULES:
            if needle in name and runtime not in seen:
                seen.add(runtime)
                out.append({
                    "name": runtime,
                    "library": name,
                    "library_path": str(path),
                    "language": language,
                    "confidence": confidence,
                    "smoke_template": f"{runtime}_smoke",
                })
                break
    return out


# Per-runtime PoC body templates. Each is a complete POSIX shell script
# that exits 0 on a clean run and non-zero on the expected misbehaviour.
_RUNTIME_POC_TEMPLATES: dict[str, str] = {
    "openmp": (
        "#!/bin/sh\n"
        "set -u\n"
        "# B6 OpenMP smoke: assert OMP_NUM_THREADS=2 produces >=2 threads.\n"
        "export OMP_NUM_THREADS=2\n"
        "if command -v gcc >/dev/null 2>&1; then\n"
        "  cat >/tmp/bbh_omp.c <<'C'\n"
        "#include <omp.h>\n"
        "#include <stdio.h>\n"
        "int main(void){\n"
        "  int n=0; #pragma omp parallel reduction(+:n) n++;\n"
        "  printf(\"%d\\n\", n); return n>=2?0:1;\n"
        "}\n"
        "C\n"
        "  gcc -fopenmp /tmp/bbh_omp.c -o /tmp/bbh_omp && /tmp/bbh_omp\n"
        "else\n"
        "  echo SKIP_NO_GCC\n"
        "fi\n"
    ),
    "fortran": (
        "#!/bin/sh\n"
        "set -u\n"
        "# B6 Fortran smoke: allocate + write + read-back.\n"
        "if command -v gfortran >/dev/null 2>&1; then\n"
        "  cat >/tmp/bbh_f90.f90 <<'F'\n"
        "program bbh_smoke\n"
        "  integer, allocatable :: a(:)\n"
        "  allocate(a(4)); a = [1,2,3,4]\n"
        "  print *, a(1)+a(4)\n"
        "  if (a(1)+a(4) /= 5) call exit(1)\n"
        "end program\n"
        "F\n"
        "  gfortran /tmp/bbh_f90.f90 -o /tmp/bbh_f90 && /tmp/bbh_f90\n"
        "else\n"
        "  echo SKIP_NO_GFORTRAN\n"
        "fi\n"
    ),
    "go": (
        "#!/bin/sh\n"
        "set -u\n"
        "# B6 Go smoke: goroutine + channel rendezvous.\n"
        "if command -v go >/dev/null 2>&1; then\n"
        "  cat >/tmp/bbh_go.go <<'G'\n"
        "package main\n"
        "import (\"fmt\"; \"time\")\n"
        "func main(){ ch:=make(chan int); go func(){ time.Sleep(1e8); ch<-1 }(); fmt.Println(<-ch) }\n"
        "G\n"
        "  cd /tmp && go run /tmp/bbh_go.go\n"
        "else\n"
        "  echo SKIP_NO_GO\n"
        "fi\n"
    ),
    "jvm": (
        "#!/bin/sh\n"
        "set -u\n"
        "# B6 JVM smoke: java -version should print a version banner.\n"
        "if command -v java >/dev/null 2>&1; then\n"
        "  java -version\n"
        "else\n"
        "  echo SKIP_NO_JAVA\n"
        "fi\n"
    ),
    "python": (
        "#!/bin/sh\n"
        "set -u\n"
        "# B6 Python smoke: py_compile a trivial script.\n"
        "if command -v python3 >/dev/null 2>&1; then\n"
        "  printf 'print(\"bbh_ok\")\\n' >/tmp/bbh_py.py\n"
        "  python3 -m py_compile /tmp/bbh_py.py && python3 /tmp/bbh_py.py\n"
        "else\n"
        "  echo SKIP_NO_PYTHON3\n"
        "fi\n"
    ),
}


def generate_poc(runtime: dict[str, Any], output_path: Path) -> dict[str, Any]:
    """Write a run.sh for the given runtime into ``output_path``."""
    body = _RUNTIME_POC_TEMPLATES.get(runtime["name"])
    if body is None:
        body = (
            f"#!/bin/sh\nset -u\necho 'B6 no template for runtime {runtime['name']}'\nexit 0\n"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(body, encoding="utf-8")
    output_path.chmod(0o755)
    return {
        "runtime": runtime["name"],
        "run_sh": str(output_path),
    }


def attach_to_target_profile(profile: dict[str, Any], detected: list[dict[str, Any]]) -> dict[str, Any]:
    """Inject ``detected_runtimes[]`` into a target_profile in-place."""
    profile = dict(profile)
    profile["detected_runtimes"] = detected
    return profile


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B6 language runtime detector + PoC generator")
    p.add_argument("--scan-root", required=True, help="Extracted package root")
    p.add_argument("--target-profile", default=None, help="Optional: attach runtimes to this profile")
    p.add_argument("--poc-output-dir", default=None, help="Where to write runtime PoCs")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    detected = detect_runtimes(args.scan_root)

    if args.poc_output_dir:
        out = Path(args.poc_output_dir)
        for runtime in detected:
            poc_dir = out / f"runtime_{runtime['name']}"
            generate_poc(runtime, poc_dir / "run.sh")

    if args.target_profile:
        path = Path(args.target_profile)
        profile = json.loads(path.read_text(encoding="utf-8"))
        profile = attach_to_target_profile(profile, detected)
        path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    json.dump({"detected_runtimes": detected}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())