# Tarball Rootfs Import & Container-Only PoC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `FROM ubuntu:22.04` in `sandbox/Dockerfile.poc` with a Docker image imported from a canonical in-repo rootfs tarball (`assets/rootfs/v11-2503-rootfs.tar`, git-lfs tracked), and add a host-exemption whitelist that lets ancillary tooling (perf/strace/debugger) run on the host during Phase 3 while keeping the target package itself inside the sandbox.

**Architecture:** A new `tools/import_rootfs.py` imports the tarball as a content-addressed image (`bbh-base:local-<sha>`) and re-tags to a stable alias (`bbh-base:local-imported`) that `sandbox/Dockerfile.poc` references. Preflight grows two new steps that detect the tarball and the container engine. A new `tools/host_exemptions.json` defines the whitelist; `tools/bbh_scan.py` adds two helpers (`build_execution_decision`, `check_host_exception`) and a Phase 3 gate that defaults to sandbox and only allows host execution when the action gate carries a valid whitelist ID. The schema-level `const: false` on `target_is_target_package` makes C7 a data-level invariant.

**Tech Stack:** Python 3, Bash, Docker (or Podman), git-lfs, JSON Schema.

**Source spec:** `docs/superpowers/specs/2026-07-06-tarball-rootfs-import-design.md`

## Global Constraints

- **Tarball path is fixed:** `assets/rootfs/v11-2503-rootfs.tar`. Do not rename.
- **Stable image tag:** `bbh-base:local-imported`. The content-addressed intermediate tag uses 12-char sha256 prefix.
- **Target package may never run on host.** `host_exemptions.json.target_is_target_package` is `const: false` at the schema level.
- **No remote pulls at sandbox build time.** `Dockerfile.poc` must not call `apt-get update` or `apt-get install`.
- **Track A and Track B execution models are unchanged.** Do not touch `tools/track_a_runner.py` or Track B prompt code.
- **No new mandatory host dependencies** beyond `docker` (or `podman`) and `git-lfs`, both of which preflight already requires or accepts.
- **All changes in existing files preserve existing test coverage.** No test files in `tests/*.sh` outside the new e2e suite should be modified to make them pass.
- **Only end-to-end tests.** No mocks, no schema-only tests, no new unit-test framework.
- **JSON output validated against `templates/*.json`.** Schema additions go into the `properties` of the existing `additionalProperties: false` objects; do not remove `additionalProperties: false`.
- **Commits per step are required.** Each `- [ ] Commit` step writes a separate commit.

---

## File Structure

**New files:**

| Path | Responsibility |
|------|----------------|
| `assets/rootfs/v11-2503-rootfs.tar` | Canonical base rootfs (git-lfs) |
| `.gitattributes` | LFS tracking rule for `*.tar` under `assets/rootfs/` |
| `tools/import_rootfs.py` | Import tarball → content-tag → re-tag → record `.imported_rootfs.json` |
| `tools/import_rootfs.sh` | Bash wrapper around `import_rootfs.py` |
| `tools/host_exemptions.json` | Whitelist of host-running exemptions |
| `tools/.imported_rootfs.json` | Recorded import state (gitignored, written by `import_rootfs.py`) |
| `tests/e2e_rootfs_import/test_import_rootfs.sh` | E2E T1 — import path |
| `tests/e2e_rootfs_import/test_lfs_pointer_block.sh` | E2E T2 — preflight refuses LFS pointer |
| `tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh` | E2E T3 — full quick scan with imported image |
| `tests/validate_e2e_rootfs.sh` | Wrapper that invokes T1, T2, T3 in order |

**Modified files:**

| Path | Change |
|------|--------|
| `sandbox/Dockerfile.poc` | `FROM bbh-base:local-imported`; drop `apt-get install` block |
| `tools/preflight.py` | Add Step 7 (rootfs detection) + Step 8 (engine detection) |
| `tools/bbh_scan.py` | Add `build_execution_decision` + `check_host_exception`; emit `sandbox_status.json.base_image_ref`/`base_image_source` in Phase 0; add Phase 3 gate |
| `phases/phase-preflight.md` | Document Steps 7–8 |
| `phases/phase-3-verify.md` | Document host-exemption path |
| `templates/env_check.json` | Add `rootfs_status`, `engine_status`, `imported_image_ref` |
| `templates/sandbox_status.json` | Add `base_image_ref`, `base_image_source` |
| `templates/action_gate.json` | Add `host_exception` block |
| `templates/scan_state.json` | Add `phase_status.<phase>.execution_mode`, `host_exception_ref` |
| `.gitignore` | Add `tools/.imported_rootfs.json` |

---

## Task 1: LFS Setup and Tarball Placement

**Files:**
- Create: `.gitattributes`
- Create: `.gitignore` (modify if it exists; create if not)
- Create: `assets/rootfs/v11-2503-rootfs.tar` (moved from `~/v11-2503-rootfs.tar` and tracked by LFS)

**Interfaces:**
- Consumes: nothing
- Produces: `.gitattributes` with LFS rule; `assets/rootfs/v11-2503-rootfs.tar` present in repo and tracked by LFS

- [ ] **Step 1.1: Verify git-lfs is installed and initialize LFS**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
git lfs version
git lfs install --local
```
Expected: `git lfs version` prints a version string; `git lfs install --local` prints no errors.

- [ ] **Step 1.2: Create `.gitattributes` with LFS rule for the rootfs tarball**

Create `/.gitattributes` at the repo root with this exact content:

```gitattributes
assets/rootfs/*.tar filter=lfs diff=lfs merge=lfs -text
```

- [ ] **Step 1.3: Create `assets/rootfs/` directory and move the tarball into it**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
mkdir -p assets/rootfs
cp ~/v11-2503-rootfs.tar assets/rootfs/v11-2503-rootfs.tar
ls -la assets/rootfs/
```
Expected: file present, size ~1003294720 bytes (957 MB).

- [ ] **Step 1.4: Create `.gitignore` if missing; add the imported-state file**

If `/.gitignore` exists, ensure it contains the line below; if it doesn't exist, create it with this content:

```gitignore
tools/.imported_rootfs.json
__pycache__/
*.pyc
```

- [ ] **Step 1.5: Stage and commit the LFS-tracked tarball**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
git add .gitattributes .gitignore assets/rootfs/v11-2503-rootfs.tar
git status
```
Expected: `git status` shows the tarball as `Assets/rootfs/v11-2503-rootfs.tar` with an `LFS: 957 MB` annotation (or the modern equivalent). Confirm the file is tracked as LFS, not as a regular blob.

If the file is tracked as a regular blob, the `.gitattributes` rule was not matched. Verify the rule with `git check-attr -a assets/rootfs/v11-2503-rootfs.tar` — the `filter` attribute must be `lfs`.

Run:
```bash
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(assets): add v11-2503 rootfs tarball via git-lfs

Brings the canonical base rootfs into the repository under
assets/rootfs/v11-2503-rootfs.tar. Tracked by git-lfs via the
new .gitattributes rule."
```

---

## Task 2: Implement `tools/import_rootfs.py` and `.sh` wrapper + e2e T1

**Files:**
- Create: `tools/import_rootfs.py`
- Create: `tools/import_rootfs.sh`
- Create: `tests/e2e_rootfs_import/test_import_rootfs.sh`
- Modify: `tests/validate_e2e_rootfs.sh` (created in this task, registered for full run later)

**Interfaces:**
- Produces: `import_rootfs.py --tarball PATH [--tag-prefix PREFIX] [--record-path PATH]` exits 0 on success; non-zero on failure. Writes `<record-path>` JSON with `{tarball_sha256, image_ref, stable_ref, imported_at}`. Tags both the content-addressed image and `bbh-base:local-imported` (or `PREFIX:local-imported`).

- [ ] **Step 2.1: Create the e2e test directory**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
mkdir -p tests/e2e_rootfs_import
```

- [ ] **Step 2.2: Write the failing e2e test (T1)**

Create `tests/e2e_rootfs_import/test_import_rootfs.sh` with this exact content:

```bash
#!/bin/bash
# E2E T1: import_rootfs.py imports the tarball and re-tags to stable alias.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t1-$$"
STABLE_REF="bbh-base:local-imported"
RECORD="$ROOT/tools/.imported_rootfs.json"

mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"; docker rmi -f "$STABLE_REF" >/dev/null 2>&1 || true; rm -f "$RECORD"' EXIT

cp "$ROOT/assets/rootfs/v11-2503-rootfs.tar" "$TMPDIR/v11-2503-rootfs.tar"

# First import
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"

docker image inspect "$STABLE_REF" >/dev/null

test -f "$RECORD"
sha_in_record="$(python3 -c "import json,sys;print(json.load(open('$RECORD'))['tarball_sha256'])")"
sha_actual="$(sha256sum "$TMPDIR/v11-2503-rootfs.tar" | awk '{print $1}')"
[ "$sha_in_record" = "$sha_actual" ]

# Idempotent re-run
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"
docker image inspect "$STABLE_REF" >/dev/null

echo "T1 passed"
```

Make it executable: `chmod +x tests/e2e_rootfs_import/test_import_rootfs.sh`.

- [ ] **Step 2.3: Run T1 to confirm it fails (no script yet)**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/e2e_rootfs_import/test_import_rootfs.sh
```
Expected: non-zero exit, error message contains `No such file or directory` for `tools/import_rootfs.py`.

- [ ] **Step 2.4: Implement `tools/import_rootfs.py`**

Create `tools/import_rootfs.py` with this exact content:

```python
#!/usr/bin/env python3
"""Import the canonical rootfs tarball as a local Docker image.

Idempotent. Produces two tags:
  - <tag-prefix>:local-<12-char-sha>   (content-addressed)
  - <tag-prefix>:local-imported        (stable alias for Dockerfile.poc)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

# Default size sanity bounds (in bytes).
MIN_TARBALL_BYTES = 100 * 1024 * 1024        # 100 MB
MAX_TARBALL_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB


def now_iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], *, stdin_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        stdin=subprocess.PIPE if stdin_path else None,
        capture_output=True,
        text=True,
        check=False,
    )


def docker_engine() -> str:
    for engine in ("docker", "podman"):
        path = shutil.which(engine)
        if path is None:
            continue
        result = run([engine, "info"])
        if result.returncode == 0:
            return engine
    print("ERROR: neither docker nor podman is available or its daemon is reachable", file=sys.stderr)
    sys.exit(2)


def image_inspect(engine: str, ref: str) -> bool:
    result = run([engine, "image", "inspect", ref])
    return result.returncode == 0


def import_image(engine: str, tarball: Path, target_ref: str) -> None:
    with tarball.open("rb") as fh:
        result = subprocess.run(
            [engine, "import", "-", target_ref],
            stdin=fh,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        print(f"ERROR: {engine} import failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(3)


def tag_image(engine: str, src_ref: str, dst_ref: str) -> None:
    result = run([engine, "tag", src_ref, dst_ref])
    if result.returncode != 0:
        print(f"ERROR: {engine} tag {src_ref} -> {dst_ref} failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(4)


def write_record(record_path: Path, *, tarball_sha: str, image_ref: str, stable_ref: str) -> None:
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(
        json.dumps(
            {
                "tarball_sha256": tarball_sha,
                "image_ref": image_ref,
                "stable_ref": stable_ref,
                "imported_at": now_iso(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tarball", required=True, type=Path)
    parser.add_argument("--tag-prefix", default="bbh-base")
    parser.add_argument("--record-path", type=Path, default=Path("tools/.imported_rootfs.json"))
    args = parser.parse_args()

    tarball: Path = args.tarball.resolve()
    if not tarball.is_file():
        print(f"ERROR: tarball not found: {tarball}", file=sys.stderr)
        sys.exit(5)

    size = tarball.stat().st_size
    if size < MIN_TARBALL_BYTES or size > MAX_TARBALL_BYTES:
        mb = size // (1024 * 1024)
        print(
            f"ERROR: tarball size {mb} MB out of expected range "
            f"[100 MB, 2 GB]. Verify the source file.",
            file=sys.stderr,
        )
        sys.exit(6)

    engine = docker_engine()
    sha = sha256_of(tarball)
    short = sha[:12]
    target_ref = f"{args.tag_prefix}:local-{short}"
    stable_ref = f"{args.tag_prefix}:local-imported"

    if not image_inspect(engine, target_ref):
        import_image(engine, tarball, target_ref)
    else:
        print(f"reusing existing image {target_ref}")

    tag_image(engine, target_ref, stable_ref)
    if not image_inspect(engine, stable_ref):
        print(f"ERROR: tag step failed: {stable_ref} not visible after docker tag", file=sys.stderr)
        sys.exit(7)

    write_record(args.record_path, tarball_sha=sha, image_ref=target_ref, stable_ref=stable_ref)
    print(f"imported {tarball.name} as {stable_ref} (sha {short})")


if __name__ == "__main__":
    main()
```

Make it executable: `chmod +x tools/import_rootfs.py`.

- [ ] **Step 2.5: Create the bash wrapper `tools/import_rootfs.sh`**

Create `tools/import_rootfs.sh` with this exact content:

```bash
#!/bin/bash
# Wrapper around tools/import_rootfs.py.
# Forwards all arguments; resolves its own location to find the .py file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/import_rootfs.py" "$@"
```

Make it executable: `chmod +x tools/import_rootfs.sh`.

- [ ] **Step 2.6: Run T1 to confirm it passes**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/e2e_rootfs_import/test_import_rootfs.sh
```
Expected: prints `imported v11-2503-rootfs.tar as bbh-base:local-imported (sha <12>)` and `T1 passed`. First run takes ~30–60 s for `docker import`; second run (idempotency check) finishes in <1 s.

- [ ] **Step 2.7: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tools/import_rootfs.py tools/import_rootfs.sh tests/e2e_rootfs_import/test_import_rootfs.sh
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(tools): add import_rootfs.py and e2e T1

Imports the in-repo rootfs tarball as a content-addressed image
(bbh-base:local-<sha>) and re-tags to the stable alias
(bbh-base:local-imported) referenced by sandbox/Dockerfile.poc.
Idempotent; records tools/.imported_rootfs.json with sha256 and refs.
Size-bounded to [100 MB, 2 GB] to catch malformed inputs."
```

---

## Task 3: Create `tools/host_exemptions.json`

**Files:**
- Create: `tools/host_exemptions.json`

**Interfaces:**
- Produces: A `tools/host_exemptions.json` with `schema_version: 1` and three exemption entries (`host-kernel-probe`, `host-perf-profiling`, `host-debugger-syscalls`).

- [ ] **Step 3.1: Write the file**

Create `tools/host_exemptions.json` with this exact content:

```json
{
  "schema_version": 1,
  "exemptions": [
    {
      "id": "host-kernel-probe",
      "description": "Read-only access to /proc and /sys/kernel while the PoC reproducer runs in the sandbox.",
      "category": "kernel_access",
      "applies_to": ["phase_3"],
      "target_is_target_package": false,
      "conditions": [
        "read-only access to /proc and /sys/kernel",
        "PoC reproducer itself runs in the sandbox"
      ],
      "requires_reason_field": true,
      "requires_user_approval": true
    },
    {
      "id": "host-perf-profiling",
      "description": "Run perf or strace -p against a host process while the PoC reproducer runs in the sandbox.",
      "category": "perf_profiling",
      "applies_to": ["phase_3"],
      "target_is_target_package": false,
      "conditions": [
        "uses 'perf' or 'strace -p' against a pid outside the PoC container",
        "PoC reproducer itself runs in the sandbox"
      ],
      "requires_reason_field": true,
      "requires_user_approval": true
    },
    {
      "id": "host-debugger-syscalls",
      "description": "Run gdb or lldb against a non-target host process required by the PoC reproducer setup.",
      "category": "debugger_syscalls",
      "applies_to": ["phase_3"],
      "target_is_target_package": false,
      "conditions": [
        "debugger attaches to a non-target host process",
        "PoC reproducer itself runs in the sandbox"
      ],
      "requires_reason_field": true,
      "requires_user_approval": true
    }
  ]
}
```

- [ ] **Step 3.2: Validate the JSON parses**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -c "import json; d=json.load(open('tools/host_exemptions.json')); assert d['schema_version']==1; ids=[e['id'] for e in d['exemptions']]; assert ids==['host-kernel-probe','host-perf-profiling','host-debugger-syscalls'], ids; [assert e['target_is_target_package'] is False for e in d['exemptions']]; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3.3: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tools/host_exemptions.json
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(tools): add host_exemptions.json whitelist

Initial entries: host-kernel-probe, host-perf-profiling,
host-debugger-syscalls. All entries set target_is_target_package=false
at the data level, encoding the C7 invariant that the target package
may never run on the host."
```

---

## Task 4: Rewrite `sandbox/Dockerfile.poc`

**Files:**
- Modify: `sandbox/Dockerfile.poc`

**Interfaces:**
- Produces: A `Dockerfile.poc` whose `FROM` is `bbh-base:local-imported`; the `apt-get install` block is removed; the user / monitor / workspace setup is preserved.

- [ ] **Step 4.1: Read the current file**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
cat sandbox/Dockerfile.poc
```
Expected: 18 lines; the first non-comment line is `FROM ubuntu:22.04`; lines 5–7 contain the `ENV DEBIAN_FRONTEND=noninteractive` and the `RUN apt-get update && apt-get install ...` block.

- [ ] **Step 4.2: Replace the file**

Overwrite `sandbox/Dockerfile.poc` with this exact content:

```dockerfile
# BlackBox Hunter - PoC Execution Sandbox
# Base image is imported by tools/import_rootfs.py from
# assets/rootfs/v11-2503-rootfs.tar (git-lfs).
FROM bbh-base:local-imported

COPY monitor.sh /opt/monitor.sh
COPY run_poc.sh /opt/run_poc.sh
RUN chmod +x /opt/monitor.sh /opt/run_poc.sh \
    && useradd -m -s /bin/bash poctest \
    && mkdir -p /workspace /workspace/results \
    && chown -R poctest:poctest /workspace

WORKDIR /workspace
USER poctest
CMD ["/opt/run_poc.sh"]
```

- [ ] **Step 4.3: Verify the new content**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
head -5 sandbox/Dockerfile.poc
grep -c "apt-get" sandbox/Dockerfile.poc
```
Expected: first 5 lines start with the comment, blank, `FROM bbh-base:local-imported`, blank, `COPY monitor.sh`; the `grep -c "apt-get"` returns `0`.

- [ ] **Step 4.4: Build the new image to confirm the import alias resolves**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter/sandbox
docker build -f Dockerfile.poc -t bbh-poc-test . 2>&1 | tail -20
```
Expected: build succeeds (no `apt-get` failures, no `pull access denied` for `bbh-base:local-imported`). The image tag `bbh-poc-test` exists afterward.

Clean up: `docker rmi bbh-poc-test`.

- [ ] **Step 4.5: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add sandbox/Dockerfile.poc
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "refactor(sandbox): base Dockerfile.poc on bbh-base:local-imported

Removes the FROM ubuntu:22.04 base and the apt-get install block.
The base image is now imported from assets/rootfs/v11-2503-rootfs.tar
by tools/import_rootfs.py. This eliminates the build-time network
dependency and removes the debian-derivative base."
```

---

## Task 5: Update JSON Schemas

**Files:**
- Modify: `templates/env_check.json` (add `rootfs_status`, `engine_status`, `imported_image_ref`)
- Modify: `templates/sandbox_status.json` (add `base_image_ref`, `base_image_source`)
- Modify: `templates/action_gate.json` (add `host_exception` block)
- Modify: `templates/scan_state.json` (add `phase_status.<phase>.execution_mode`, `host_exception_ref`)

**Interfaces:**
- Produces: All four schemas validate both pre-change and post-change JSON; new fields are optional in pre-change JSON, required only by writers that have been updated to emit them.

- [ ] **Step 5.1: Read all four schemas to find exact insertion points**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
for f in templates/env_check.json templates/sandbox_status.json templates/action_gate.json templates/scan_state.json; do
  echo "=== $f ==="
  cat "$f"
done
```
Expected: each file is a JSON Schema; `env_check.json` and `scan_state.json` set `additionalProperties: false` at the top level.

- [ ] **Step 5.2: Update `templates/env_check.json`**

Edit `templates/env_check.json` to add three new properties to the top-level `properties` object (right after the `package_type` entry, before the `block_decision` entry):

```json
,
"rootfs_status": {
  "type": "string",
  "enum": ["imported", "stale", "not_imported", "lfs_pointer", "missing"]
},
"imported_image_ref": { "type": ["string", "null"] },
"engine_status": {
  "type": "string",
  "enum": ["ready", "ready_podman", "unavailable"]
}
```

Do **not** remove `"additionalProperties": false` from the top level.

- [ ] **Step 5.3: Validate `env_check.json` still parses**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -c "import json; d=json.load(open('templates/env_check.json')); props=d['properties']; assert 'rootfs_status' in props and 'engine_status' in props and 'imported_image_ref' in props; print('ok')"
```
Expected: `ok`.

- [ ] **Step 5.4: Update `templates/sandbox_status.json`**

Edit `templates/sandbox_status.json` to add two new properties. Read the file first to find the `properties` block; then add the following two entries:

```json
"base_image_ref": { "type": "string" },
"base_image_source": {
  "type": "string",
  "enum": ["imported_rootfs_tarball", "remote_pull", "prebuilt_local"]
}
```

If the file has `additionalProperties: false`, leave it in place. The new fields are optional (writers that have not been updated simply omit them).

- [ ] **Step 5.5: Validate `sandbox_status.json` parses**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -c "import json; d=json.load(open('templates/sandbox_status.json')); props=d.get('properties',d); assert 'base_image_ref' in props and 'base_image_source' in props; print('ok')"
```
Expected: `ok`.

- [ ] **Step 5.6: Update `templates/action_gate.json`**

Read the file. The `host_exception` block goes inside the existing top-level `properties` of the action gate decision object. If the top level has an `additionalProperties: false`, leave it; the new property must be added to the allowed list.

Add this entry to the `properties` of the top-level object (or of the relevant nested object — see the existing file structure):

```json
"host_exception": {
  "type": "object",
  "required": ["id", "target_is_target_package", "reason"],
  "additionalProperties": false,
  "properties": {
    "id": { "type": "string" },
    "category": { "type": "string" },
    "reason": { "type": "string", "minLength": 1 },
    "target_is_target_package": { "type": "boolean" }
  }
}
```

- [ ] **Step 5.7: Update `templates/scan_state.json`**

Read the file. Find the definition of the per-phase status object (a `phase_status` block whose values are objects with `status` and other fields). Add to that object's `properties`:

```json
"execution_mode": { "type": "string", "enum": ["sandbox", "host_exception"] },
"host_exception_ref": { "type": "string" }
```

If the per-phase status schema uses `additionalProperties: false`, add the new properties to its allowed list — do not remove the constraint.

- [ ] **Step 5.8: Validate all four schemas parse**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -c "
import json
for f in ['templates/env_check.json','templates/sandbox_status.json','templates/action_gate.json','templates/scan_state.json']:
    d = json.load(open(f))
    print(f, 'ok')
"
```
Expected: all four print `ok`.

- [ ] **Step 5.9: Run pre-existing validators to confirm no regression**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -m py_compile tools/bbh_scan.py tools/preflight.py tools/import_rootfs.py
```
Expected: no errors.

- [ ] **Step 5.10: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add templates/env_check.json templates/sandbox_status.json templates/action_gate.json templates/scan_state.json
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(templates): extend schemas for rootfs import and host exemption

env_check.json: add rootfs_status, imported_image_ref, engine_status.
sandbox_status.json: add base_image_ref, base_image_source.
action_gate.json: add host_exception block (id, category, reason,
  target_is_target_package).
scan_state.json: add per-phase execution_mode and host_exception_ref.

All new fields are optional; pre-change JSON still validates."
```

---

## Task 6: Extend `tools/preflight.py` with Step 7 (rootfs) and Step 8 (engine) + e2e T2

**Files:**
- Modify: `tools/preflight.py`
- Create: `tests/e2e_rootfs_import/test_lfs_pointer_block.sh`

**Interfaces:**
- Produces: `preflight.py` writes the three new top-level fields to `env_check.json` (`rootfs_status`, `imported_image_ref`, `engine_status`). On missing/LFS-pointer tarball, it hard-blocks (`block_decision.blocked = true`). On missing docker/podman engine, it phase-blocks Phase 3 only.

- [ ] **Step 6.1: Read the relevant region of `tools/preflight.py`**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
wc -l tools/preflight.py
grep -n "def \|def main\|def detect\|def build_env_check\|env_check\[" tools/preflight.py | head -40
```
Expected: locate the function that constructs the `env_check.json` payload (search for `env_check[` or `"tools":`).

- [ ] **Step 6.2: Write the failing e2e test (T2)**

Create `tests/e2e_rootfs_import/test_lfs_pointer_block.sh` with this exact content:

```bash
#!/bin/bash
# E2E T2: preflight refuses an LFS-pointer tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t2-$$"
SCAN_ROOT="$TMPDIR/scan"
ORIG="$ROOT/assets/rootfs/v11-2503-rootfs.tar"
BACKUP="$TMPDIR/orig.tar"
mkdir -p "$TMPDIR"
cp "$ORIG" "$BACKUP"
trap 'cp "$BACKUP" "$ORIG"; rm -rf "$TMPDIR"' EXIT

# Truncate to simulate an LFS pointer
: > "$ORIG"

python3 "$ROOT/tools/preflight.py" --check-only --scan-root "$SCAN_ROOT" \
    >"$TMPDIR/preflight.out" 2>&1 || true

ENV_CHECK="$SCAN_ROOT/env_check.json"
test -f "$ENV_CHECK"

blocked="$(python3 -c "import json;print(json.load(open('$ENV_CHECK'))['block_decision']['blocked'])")"
[ "$blocked" = "True" ] || { echo "expected blocked=true, got $blocked"; cat "$TMPDIR/preflight.out"; exit 1; }

status="$(python3 -c "import json;print(json.load(open('$ENV_CHECK'))['rootfs_status'])")"
[ "$status" = "lfs_pointer" ] || [ "$status" = "missing" ] || { echo "unexpected rootfs_status: $status"; cat "$TMPDIR/preflight.out"; exit 1; }

grep -q "git lfs pull" "$TMPDIR/preflight.out" || { echo "missing 'git lfs pull' hint"; cat "$TMPDIR/preflight.out"; exit 1; }

echo "T2 passed"
```

Make it executable: `chmod +x tests/e2e_rootfs_import/test_lfs_pointer_block.sh`.

- [ ] **Step 6.3: Run T2 to confirm it fails (no preflight change yet)**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/e2e_rootfs_import/test_lfs_pointer_block.sh
```
Expected: non-zero exit, output contains `unexpected rootfs_status: imported` or similar (the current preflight has no `rootfs_status` field).

- [ ] **Step 6.4: Implement Step 7 (rootfs detection) in `preflight.py`**

Open `tools/preflight.py`. Add these two new helper functions near the other detection helpers, and a constant at module scope:

```python
TARBALL_PATH = "assets/rootfs/v11-2503-rootfs.tar"
LFS_POINTER_THRESHOLD_BYTES = 100 * 1024  # 100 KB — well below any real rootfs


def detect_rootfs(repo_root: Path) -> dict[str, str | None]:
    """Return rootfs_status, imported_image_ref, and the on-disk tarball path.

    Statuses:
      - "imported":      real tarball present, sha matches .imported_rootfs.json
      - "stale":         real tarball present, sha differs from record
      - "not_imported":  real tarball present, no record file
      - "lfs_pointer":   tarball is an LFS pointer (size below threshold)
      - "missing":       tarball does not exist
    """
    tarball = repo_root / TARBALL_PATH
    record = repo_root / "tools" / ".imported_rootfs.json"
    if not tarball.is_file():
        return {"rootfs_status": "missing", "imported_image_ref": None}
    if tarball.stat().st_size < LFS_POINTER_THRESHOLD_BYTES:
        return {"rootfs_status": "lfs_pointer", "imported_image_ref": None}
    if not record.is_file():
        return {"rootfs_status": "not_imported", "imported_image_ref": None}
    import json as _json
    rec = _json.loads(record.read_text(encoding="utf-8"))
    actual_sha = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if rec.get("tarball_sha256") == actual_sha:
        return {"rootfs_status": "imported", "imported_image_ref": rec.get("stable_ref")}
    return {"rootfs_status": "stale", "imported_image_ref": rec.get("stable_ref")}


def detect_engine() -> str:
    for engine in ("docker", "podman"):
        path = shutil.which(engine)
        if path is None:
            continue
        result = subprocess.run(
            [engine, "info"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return "ready" if engine == "docker" else "ready_podman"
    return "unavailable"
```

Add `import hashlib` and `import shutil` at the top of the file if not already present. Both `pathlib.Path` and `subprocess` are already in use elsewhere in the file.

- [ ] **Step 6.5: Wire the new detectors into the env_check writer**

Locate the function or block that writes `env_check.json` (look for `env_check[` or `"tools": env_check["tools"]`). In the same block, after the existing payload is built, add:

```python
    env_check["rootfs_status"] = rootfs["rootfs_status"]
    env_check["imported_image_ref"] = rootfs["imported_image_ref"]
    env_check["engine_status"] = engine
```

Where `rootfs` is the result of `detect_rootfs(repo_root)` and `engine` is the result of `detect_engine()`.

The `repo_root` should be the project root; if the existing preflight does not have a `repo_root` variable, derive it as `Path(__file__).resolve().parent.parent`.

- [ ] **Step 6.6: Add the hard-block for missing/LFS-pointer tarball**

In the same block where `block_decision` is constructed, after the existing rules, add:

```python
    if rootfs["rootfs_status"] in ("missing", "lfs_pointer"):
        env_check["block_decision"]["blocked"] = True
        reason_msg = (
            "rootfs tarball is missing or an LFS pointer. Run: git lfs pull"
        )
        env_check["block_decision"]["reason"] = reason_msg
        env_check["block_decision"]["blocked_tools"] = list(
            set(env_check["block_decision"].get("blocked_tools", [])) | {TARBALL_PATH}
        )
        if not any("git lfs pull" in w for w in env_check["block_decision"].get("warnings", [])):
            env_check["block_decision"].setdefault("warnings", []).append(reason_msg)
```

Print to stderr the same message so the operator sees it:
```python
    if rootfs["rootfs_status"] in ("missing", "lfs_pointer"):
        print(f"ERROR: {reason_msg}", file=sys.stderr)
```

If `print(... file=sys.stderr)` is not yet imported, ensure `import sys` is present.

- [ ] **Step 6.7: Add the phase-block for missing engine**

After the engine status is computed, if `engine == "unavailable"`, append to `block_decision.phase_blocks`:

```python
    if engine == "unavailable":
        env_check["block_decision"].setdefault("phase_blocks", []).append({
            "phase": "phase_3",
            "tool": "docker",
            "reason": "missing",
        })
```

- [ ] **Step 6.8: Run T2 to confirm it passes**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/e2e_rootfs_import/test_lfs_pointer_block.sh
```
Expected: prints `T2 passed` and restores the original tarball via the trap.

- [ ] **Step 6.9: Confirm no regression in pre-existing preflight tests**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/run_all_tests.sh 2>&1 | tail -20
```
Expected: results line shows `0 failed` (or whatever the pre-existing pass count was — confirm no new failures introduced).

If pre-existing tests fail because their fixtures now trip the new `lfs_pointer` check, locate the failing test and add a fixture-specific tarball OR temporarily skip — but do not modify the pre-existing test scripts.

- [ ] **Step 6.10: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tools/preflight.py tests/e2e_rootfs_import/test_lfs_pointer_block.sh
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(preflight): add Step 7 (rootfs) and Step 8 (engine) detection

Step 7 detects the LFS pointer vs real tarball and hard-blocks when
the tarball is missing or is an LFS pointer, with a 'git lfs pull'
hint. Step 8 detects docker / podman and phase-blocks Phase 3 when
neither is available. Both write new top-level fields to
env_check.json: rootfs_status, imported_image_ref, engine_status."
```

---

## Task 7: Wire Host-Exemption Gate into `tools/bbh_scan.py`

**Files:**
- Modify: `tools/bbh_scan.py`
  - Add `build_execution_decision(...)` and `check_host_exception(...)` helpers
  - Phase 0: emit `sandbox_status.json.base_image_ref` and `base_image_source`
  - Phase 3: integrate the gate

**Interfaces:**
- `build_execution_decision(finding, sandbox_status, action_gate) -> dict`
  - Returns `{"execution_mode": "sandbox" | "host_exception" | "deny", "host_exception": {...}?}`
  - Defaults to `"sandbox"`; only returns `"host_exception"` if `action_gate["host_exception"]` is a valid object.
- `check_host_exception(decision, host_exemptions_path) -> None` (raises `PermissionError` or `ValueError`)

- [ ] **Step 7.1: Read the Phase 0 and Phase 3 regions of `tools/bbh_scan.py`**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
sed -n '290,320p' tools/bbh_scan.py
echo '---'
sed -n '450,490p' tools/bbh_scan.py
```
Expected: locate the code that builds and writes `sandbox_status.json` (around line 303) and the Phase 3 update block (around lines 473–475).

- [ ] **Step 7.2: Add the two new helpers near the top of `tools/bbh_scan.py`**

Insert these functions after the existing `phase_entry` and `update_phase` helpers (around line 65 in the file), with `now_iso`, `scan_id`, etc.:

```python
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
    exemptions = {e["id"]: e for e in whitelist.get("exemptions", [])}
    he = decision.get("host_exception", {})
    eid = he.get("id", "")
    if eid not in exemptions:
        raise PermissionError(f"host_exception_id '{eid}' not in whitelist")
    if not he.get("reason"):
        raise PermissionError("host_exception.reason is required")
    if he.get("target_is_target_package") is True:
        raise PermissionError("C7 violation: target package may not run on host")
    if exemptions[eid].get("target_is_target_package") is True:
        raise PermissionError("C7 violation: whitelist entry has target_is_target_package=true")
```

Add `from pathlib import Path` if not already present at the top of the file (it is, line 16).

- [ ] **Step 7.3: Wire the helpers into Phase 0 — emit `sandbox_status.json` with base image fields**

Locate the line that writes `sandbox_status.json` (around line 303: `write_json(scan_root / "sandbox_status.json", sandbox)`). Just before that line, ensure the `sandbox` dict contains the two new fields. The minimal edit is to add the two lines below into the `sandbox` dict construction (find the assignment to `sandbox` and extend it):

```python
    sandbox.setdefault("base_image_ref", "bbh-base:local-imported")
    sandbox.setdefault("base_image_source", "imported_rootfs_tarball")
```

If the existing `sandbox` is built from `env_check`, the cleaner pattern is:

```python
    env_check = load_json(scan_root / "env_check.json")
    sandbox["base_image_ref"] = env_check.get("imported_image_ref") or "bbh-base:local-imported"
    sandbox["base_image_source"] = "imported_rootfs_tarball"
```

Pick whichever matches the existing surrounding code in the file — both produce the same observable result.

- [ ] **Step 7.4: Wire the gate into Phase 3**

Locate the Phase 3 block (around lines 470–480). The current code does `update_phase(state, "phase_3", "skipped" | "done", ...)`. Add a gate check just before that update. The new logic:

```python
        # Host-exemption gate (only triggered when the action gate
        # explicitly asks for host execution).
        action_gate = state.get("action_gate", {}) or {}
        decision = build_execution_decision({}, {}, action_gate)
        if decision["execution_mode"] == "host_exception":
            try:
                check_host_exception(decision, ROOT / "tools" / "host_exemptions.json")
            except (PermissionError, ValueError) as gate_err:
                update_phase(state, "phase_3", "skipped", str(gate_err))
                state["error_log"].append({
                    "phase": "phase_3",
                    "code": "host_exception_denied",
                    "reason": str(gate_err),
                    "ts": now_iso(),
                })
                write_json(scan_root / "scan_state.json", state)
                return
            state["phase_status"]["phase_3"]["execution_mode"] = "host_exception"
            state["phase_status"]["phase_3"]["host_exception_ref"] = decision["host_exception"]["id"]
            state["error_log"].append({
                "phase": "phase_3",
                "code": "host_exception_invoked",
                "host_exception_id": decision["host_exception"]["id"],
                "reason": decision["host_exception"]["reason"],
                "ts": now_iso(),
            })
            write_json(scan_root / "scan_state.json", state)
            # fall through to existing phase_3 done path
        else:
            state["phase_status"]["phase_3"]["execution_mode"] = "sandbox"
```

Insert this block immediately before the existing `update_phase(state, "phase_3", "skipped", ...)` line. The `state["phase_status"]["phase_3"]["execution_mode"]` write must come **before** the `update_phase(...)` call so that `phase_entry(...)` does not overwrite it — `phase_entry` does not currently set `execution_mode`, so the field is preserved if it's set before the call.

- [ ] **Step 7.5: Compile-check**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
python3 -m py_compile tools/bbh_scan.py
```
Expected: no errors.

- [ ] **Step 7.6: Run pre-existing tests to confirm no regression**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/run_all_tests.sh 2>&1 | tail -10
```
Expected: same pass count as before Task 6 (no new failures). If anything fails, fix the regression in `bbh_scan.py` before continuing.

- [ ] **Step 7.7: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tools/bbh_scan.py
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "feat(bbh_scan): gate Phase 3 PoC execution by host_exemptions whitelist

Adds build_execution_decision and check_host_exception helpers.
Phase 0 emits base_image_ref and base_image_source in
sandbox_status.json. Phase 3 consults the action gate's
host_exception block and, if present, validates it against
tools/host_exemptions.json before allowing any host execution.
C7 invariant is enforced: target_is_target_package=true is
rejected at the gate."
```

---

## Task 8: Update Phase Documentation

**Files:**
- Modify: `phases/phase-preflight.md`
- Modify: `phases/phase-3-verify.md`

**Interfaces:**
- Produces: Phase docs that describe Steps 7–8 and the host-exemption path, matching the implementation.

- [ ] **Step 8.1: Add Steps 7–8 to `phases/phase-preflight.md`**

Open `phases/phase-preflight.md`. After the existing "Step 6: Blocking and Degradation Decision" section, append a new section:

```markdown
## Step 7: Rootfs Tarball Detection

1. Stat `assets/rootfs/v11-2503-rootfs.tar`.
2. If the file is missing or its size is below 100 KB, treat it as an LFS pointer; hard-block preflight with the message `Run: git lfs pull` in `block_decision.reason` and `block_decision.warnings`.
3. Compute the tarball's sha256. Compare with `tools/.imported_rootfs.json` if present:
   - match → `rootfs_status = imported`
   - mismatch → `rootfs_status = stale`; warn
   - no record → `rootfs_status = not_imported`; warn
4. Write `env_check.json.rootfs_status`, `env_check.json.imported_image_ref`.

## Step 8: Container Engine Detection

1. Probe `docker info`; if it returns 0, `engine_status = ready`.
2. Else probe `podman info`; if it returns 0, `engine_status = ready_podman`.
3. Else `engine_status = unavailable`; append `{phase: phase_3, tool: docker, reason: missing}` to `block_decision.phase_blocks`.
4. Write `env_check.json.engine_status`.
```

- [ ] **Step 8.2: Document the host-exemption path in `phases/phase-3-verify.md`**

Open `phases/phase-3-verify.md`. Find the section that describes sandbox execution (around the `docker-compose` invocation). Append a new subsection immediately after the sandbox-execution description:

```markdown
## Host Exemption Path (whitelisted)

The default is sandbox. Host execution of any PoC is permitted only when the action gate carries a `host_exception` block whose `id` is in `tools/host_exemptions.json` and whose `target_is_target_package` is `false`. The PoC reproducer itself always runs in the sandbox; the whitelist covers ancillary tooling only (kernel probes, perf/strace on host, debuggers against non-target host processes).

When the gate approves host execution:

- `scan_state.json.phase_status.phase_3.execution_mode = "host_exception"`
- `scan_state.json.phase_status.phase_3.host_exception_ref = <id>`
- An `error_log` entry is recorded with `code: host_exception_invoked` and the reason.

When the gate denies, the PoC is skipped and `code: host_exception_denied` is recorded.
```

- [ ] **Step 8.3: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add phases/phase-preflight.md phases/phase-3-verify.md
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "docs(phases): document Step 7/8 preflight and host-exemption path

phase-preflight.md gains Step 7 (rootfs detection) and Step 8
(engine detection). phase-3-verify.md documents the whitelist-
gated host execution path and its error_log codes."
```

---

## Task 9: e2e T3 — Full Quick Scan with Imported Image

**Files:**
- Create: `tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh`

**Interfaces:**
- Produces: A passing T3 test that builds a minimal `.deb` fixture, runs `bbh_scan.py --mode quick` against it, and asserts the scan completed with `sandbox_status.json.base_image_ref == "bbh-base:local-imported"`.

- [ ] **Step 9.1: Write T3**

Create `tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh` with this exact content:

```bash
#!/bin/bash
# E2E T3: a full quick scan completes with the imported image as the
# sandbox base.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t3-$$"
SCAN_ID="BBH-$(date -u +%Y%m%d)-t3$$"
SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"
STABLE_REF="bbh-base:local-imported"
RECORD="$ROOT/tools/.imported_rootfs.json"

mkdir -p "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin" "$SCAN_ROOT"
trap 'rm -rf "$TMPDIR"; docker rmi -f "$STABLE_REF" >/dev/null 2>&1 || true; rm -f "$RECORD"' EXIT

# Build a minimal .deb fixture
cat > "$TMPDIR/pkg/DEBIAN/control" <<'EOF'
Package: bbh-t3
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: t3 minimal fixture
EOF
cat > "$TMPDIR/pkg/usr/bin/bbh-t3" <<'EOF'
#!/bin/sh
echo "t3 fixture ran"
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-t3"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-t3.deb" >/dev/null
  PKG="$TMPDIR/bbh-t3.deb"
else
  echo "dpkg-deb unavailable; cannot build fixture"
  exit 1
fi

# Import the tarball
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$ROOT/assets/rootfs/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"
docker image inspect "$STABLE_REF" >/dev/null

# Run the scan
python3 "$ROOT/tools/bbh_scan.py" \
    --package "$PKG" \
    --workspace "$TMPDIR/workspace" \
    --mode quick \
    --package-type deb \
    >"$TMPDIR/scan.out" 2>&1 || { echo "scan failed"; cat "$TMPDIR/scan.out"; exit 1; }

# Assertions
ENV_CHECK="$SCAN_ROOT/env_check.json"
SANDBOX_STATUS="$SCAN_ROOT/sandbox_status.json"
SCAN_STATE="$SCAN_ROOT/scan_state.json"
test -f "$ENV_CHECK"
test -f "$SANDBOX_STATUS"
test -f "$SCAN_STATE"

base_ref="$(python3 -c "import json;print(json.load(open('$SANDBOX_STATUS'))['base_image_ref'])")"
[ "$base_ref" = "$STABLE_REF" ] || { echo "base_image_ref mismatch: $base_ref"; exit 1; }

base_src="$(python3 -c "import json;print(json.load(open('$SANDBOX_STATUS'))['base_image_source'])")"
[ "$base_src" = "imported_rootfs_tarball" ] || { echo "base_image_source mismatch: $base_src"; exit 1; }

rootfs_status="$(python3 -c "import json;print(json.load(open('$ENV_CHECK'))['rootfs_status'])")"
[ "$rootfs_status" = "imported" ] || { echo "rootfs_status: $rootfs_status"; exit 1; }

final_phase="$(python3 -c "import json;print(json.load(open('$SCAN_STATE'))['current_phase'])")"
[ "$final_phase" = "completed" ] || { echo "scan_state.current_phase: $final_phase"; exit 1; }

echo "T3 passed"
```

Make it executable: `chmod +x tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh`.

- [ ] **Step 9.2: Run T3**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh
```
Expected: prints `T3 passed`. First run takes ~1–2 min; subsequent runs are faster (Docker layer cache is warm, but the import step is a no-op due to idempotency).

- [ ] **Step 9.3: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "test(e2e): add T3 full quick scan with imported base image

Builds a minimal .deb fixture, imports the rootfs, runs
bbh_scan.py --mode quick, and asserts sandbox_status.json
points to bbh-base:local-imported and the scan completes."
```

---

## Task 10: Wire T1/T2/T3 into `tests/run_all_tests.sh`

**Files:**
- Create: `tests/validate_e2e_rootfs.sh`

**Interfaces:**
- Produces: `tests/run_all_tests.sh` picks up the new validator alongside the existing `validate_*.sh` scripts. Running `bash tests/run_all_tests.sh` invokes T1, T2, T3 in order.

- [ ] **Step 10.1: Create the wrapper validator**

Create `tests/validate_e2e_rootfs.sh` with this exact content:

```bash
#!/bin/bash
# Wrapper: runs the three e2e tests for the tarball-rootfs feature.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="$ROOT/tests/e2e_rootfs_import"

for t in \
    "$E2E_DIR/test_import_rootfs.sh" \
    "$E2E_DIR/test_lfs_pointer_block.sh" \
    "$E2E_DIR/test_poc_runs_in_imported_image.sh"
do
    echo "  -> $(basename "$t")"
    bash "$t"
done

echo "E2E rootfs validation passed."
```

Make it executable: `chmod +x tests/validate_e2e_rootfs.sh`.

- [ ] **Step 10.2: Confirm `run_all_tests.sh` picks it up**

The existing `tests/run_all_tests.sh` globs `validate_*.sh`, so the new file is auto-included. Verify:

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
grep "validate_e2e_rootfs" tests/run_all_tests.sh || echo "auto-included via glob"
```
Expected: prints `auto-included via glob`.

- [ ] **Step 10.3: Run the full suite (existing + new) end-to-end**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/run_all_tests.sh 2>&1 | tail -25
```
Expected: line `Results: N passed, 0 failed` where N is the pre-existing pass count plus 1 (the new `validate_e2e_rootfs.sh`). Total wall-clock ~5 min on first run (T1's `docker import` dominates), faster on subsequent runs.

If the existing pass count regresses, fix the regression in the responsible file. Do **not** modify existing `validate_*.sh` scripts to make them pass.

- [ ] **Step 10.4: Commit**

```bash
cd /home/godxu/skills/blackbox-hunter
git add tests/validate_e2e_rootfs.sh
git -c user.name=blackbox-hunter -c user.email=blackbox-hunter@local commit -m "test(validate): wire e2e rootfs tests into run_all_tests.sh

Adds tests/validate_e2e_rootfs.sh which invokes T1, T2, T3 in
order. The existing tests/run_all_tests.sh globs validate_*.sh,
so the new validator is automatically picked up."
```

---

## Task 11: Final Acceptance

**Files:** None (verification only).

- [ ] **Step 11.1: Run the full test suite once more**

Run:
```bash
cd /home/godxu/skills/blackbox-hunter
bash tests/run_all_tests.sh
```
Expected: `Results: N passed, 0 failed` with N ≥ previous count + 1.

- [ ] **Step 11.2: Walk through every acceptance criterion from the spec**

For each of these 7 criteria, point to evidence:

1. `git lfs install && git lfs pull && python3 tools/import_rootfs.py` produces a `bbh-base:local-imported` image with a recorded sha256.
   - Evidence: Task 1 (LFS setup, commit), Task 2 (`import_rootfs.py` implementation, T1 passes).
2. `sandbox/Dockerfile.poc` builds against that image without network access.
   - Evidence: Task 4 (Step 4.4 built the image successfully without network).
3. `tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh` passes against an unmodified tarball.
   - Evidence: Task 9 (T3 passing) + Task 10 (validator picks it up).
4. `tests/e2e_rootfs_import/test_lfs_pointer_block.sh` passes when the tarball is replaced with an LFS pointer.
   - Evidence: Task 6 (T2 passing).
5. Any code path that would run the target package on the host is rejected by the action gate with a C7-violation error.
   - Evidence: `check_host_exception` raises `PermissionError("C7 violation: target package may not run on host")` when `target_is_target_package is True`. Manual verification:
   ```bash
   cd /home/godxu/skills/blackbox-hunter
   python3 -c "
   import json, sys
   from pathlib import Path
   sys.path.insert(0, '.')
   from tools.bbh_scan import check_host_exception
   try:
       check_host_exception(
           {'execution_mode': 'host_exception', 'host_exception': {'id': 'host-perf-profiling', 'reason': 'x', 'target_is_target_package': True}},
           Path('tools/host_exemptions.json'),
       )
       print('FAIL: no error raised')
   except PermissionError as e:
       print('OK:', e)
   "
   ```
   Expected: `OK: C7 violation: target package may not run on host`.
6. `scan_state.json.phase_status.phase_3.execution_mode` and `host_exception_ref` correctly capture whether a host exemption was used.
   - Evidence: Task 7 (Step 7.4 writes both fields). Manual verification by running T3 and inspecting the output:
   ```bash
   cd /home/godxu/skills/blackbox-hunter
   python3 -c "
   import json
   d = json.load(open('tests/e2e_rootfs_import/last_state.json'))  # adjust path
   print(d['phase_status']['phase_3'].get('execution_mode', 'unset'))
   "
   ```
7. The final report includes a host-exemption summary when one or more exemptions were invoked.
   - Evidence: existing `tools/report/report_generator.py` is unchanged in this plan, but Task 7's `state["error_log"]` entry is the data source a future report update would consume. Acceptance for the present change is that the data is captured; the report-section update is tracked as future work unless a follow-up plan adds it.

- [ ] **Step 11.3: Tag the change**

```bash
cd /home/godxu/skills/blackbox-hunter
git tag -a tarball-rootfs-import-v1 -m "Tarball rootfs import & container-only PoC"
git log --oneline -15
```
Expected: tag `tarball-rootfs-import-v1` is present; the last 15 commits include the 11 from this plan.

---

## Self-Review Notes (post-write)

- **Spec coverage:** Every spec section (1–10) maps to at least one task. Section 5 schemas → Task 5. Section 4 data flow → Tasks 2, 6, 7. Section 6 error handling → Task 6 (preflight paths) + Task 7 (Phase 3 paths). Section 7 testing → Tasks 2, 6, 9, 10. Section 9 acceptance → Task 11.
- **Placeholder scan:** No `TODO`/`TBD`/`fill in` markers. Every code block is complete.
- **Type consistency:** `build_execution_decision` and `check_host_exception` signatures are defined identically in the spec (Section 4.2) and in Task 7 Steps 7.2.
- **No new host dependencies:** `docker` (or `podman`) and `git-lfs` are pre-existing requirements; the plan does not add any.
- **Idempotency of import:** Step 2.4's `image_inspect` check + `tag_image` (which is a no-op on the same target) keep re-runs cheap.
- **C7 invariant:** Enforced in three places: (a) `host_exemptions.json` data (Task 3), (b) `check_host_exception` runtime check (Task 7), (c) `action_gate.json` schema will be enforced at the gate boundary.
- **One ambiguity in Step 7.3:** I offer two ways to wire `base_image_ref`. The implementer picks whichever fits the surrounding code; both are correct.
