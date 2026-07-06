# Tarball Rootfs Import & Container-Only PoC Verification

**Status:** draft
**Date:** 2026-07-06
**Owner:** blackbox-hunter
**Change ID (proposed):** `tarball-rootfs-import-v1`

## 1. Purpose

Replace `FROM ubuntu:22.04` and any other debian-derived base images with a single canonical rootfs tarball (`assets/rootfs/v11-2503-rootfs.tar`) imported as a local Docker image, and make PoC verification the only step that must run in a container. Track A scanning and Track B AI analysis continue to run on the host. A small, well-scoped whitelist lets ancillary tooling (perf, strace on host, debuggers) run on the host alongside the in-container PoC, but never lets the target package itself leave the sandbox.

## 2. Goals & Non-Goals

### Goals

1. The PoC sandbox image is fully derived from the in-repo tarball; no remote pull is required at sandbox build time.
2. The tarball is stored in the repository and distributed via git-lfs.
3. Track A and Track B execution models are unchanged.
4. A documented whitelist allows specific, non-target tooling to run on the host during Phase 3 while the PoC reproducer itself remains in the sandbox.
5. Constitution C7 is enforced by the schema: the target package may not run on the host under any exemption.

### Non-Goals

1. Migrating Track A or Track B into containers.
2. Supporting arbitrary user-supplied rootfs tarballs or remote image pulls at runtime.
3. Replacing the docker engine with runc, chroot, or any other runtime.
4. Renaming the tarball file in the repo.

## 3. Architecture

### 3.1 New and changed artifacts

| Path | Change | Purpose |
|------|--------|---------|
| `assets/rootfs/v11-2503-rootfs.tar` | new (LFS) | Canonical base rootfs |
| `.gitattributes` | new | LFS tracking rule for `*.tar` under `assets/rootfs/` |
| `tools/import_rootfs.py` | new | Import tarball → `bbh-base:local-<sha>` → re-tag → `bbh-base:local-imported`; records `.imported_rootfs.json` |
| `tools/import_rootfs.sh` | new | Bash wrapper delegating to `import_rootfs.py` |
| `tools/host_exemptions.json` | new | Whitelist of allowed host-running cases |
| `sandbox/Dockerfile.poc` | edit | `FROM bbh-base:local-imported`; drop the `apt-get install` block; keep `monitor.sh` / `run_poc.sh` / user setup |
| `tools/preflight.py` | edit | Step 7 (rootfs detection) + Step 8 (docker daemon detection); emit `env_check.json.rootfs_status` and `env_check.json.engine_status` |
| `tools/bbh_scan.py` | edit | In Phase 3, before any host PoC path, call `check_host_exception(...)`; record `phase_status.phase_3.execution_mode` and `phase_status.phase_3.host_exception_ref` |
| `phases/phase-preflight.md` | edit | Document Steps 7–8 |
| `phases/phase-3-verify.md` | edit | Document host-exemption path and the C7 invariant |
| `templates/env_check.json` | edit | Add `rootfs_status`, `engine_status`, `imported_image_ref` |
| `templates/sandbox_status.json` | edit | Add `base_image_ref`, `base_image_source` |
| `templates/action_gate.json` | edit | Add `host_exception` block |
| `templates/scan_state.json` | edit | Add `phase_status.phase_3.execution_mode` and `phase_status.phase_3.host_exception_ref` |
| `tests/e2e_rootfs_import/` | new | Three e2e shell scripts (T1, T2, T3) |

### 3.2 Image tag strategy

`import_rootfs.py` performs two tagged imports:

1. Content-addressed: `docker import - bbh-base:local-<short-sha-of-tar>` — used for cache-busting.
2. Stable alias: `docker tag bbh-base:local-<short-sha> bbh-base:local-imported` — referenced by `sandbox/Dockerfile.poc`.

This keeps `Dockerfile.poc` simple (`FROM bbh-base:local-imported`) while still invalidating downstream cache when the tarball changes (a new sha forces a new primary tag and a re-tag to the stable alias).

### 3.3 Component boundaries

- `tools/import_rootfs.py` — pure: depends only on `docker` CLI; no Phase 0–4 coupling.
- `tools/host_exemptions.json` — single source of truth for whitelist; consumed by both `tools/bbh_scan.py` and `templates/action_gate.json`.
- `tools/bbh_scan.py` — orchestrator; the only file that decides sandbox-vs-host execution for PoC.

## 4. Data Flow

### 4.1 One-time import (per environment, idempotent)

```text
git lfs install && git lfs pull
python3 tools/import_rootfs.py \
    --tarball assets/rootfs/v11-2503-rootfs.tar \
    --tag-prefix bbh-base

  1. Compute sha256 of tarball
  2. Compute short-sha = first-12-chars(sha256)
  3. target_ref = "bbh-base:local-<short-sha>"
  4. If "docker image inspect <target_ref>" succeeds → no-op, exit 0
  5. Else run "docker import - <target_ref>" < tarball
  6. "docker tag <target_ref> bbh-base:local-imported"
  7. Write tools/.imported_rootfs.json
     { "tarball_sha256", "image_ref", "stable_ref",
       "imported_at": "<ISO-8601 UTC>" }
```

### 4.2 Per-scan flow (only the changed parts)

**Preflight (Phase -1), new Steps 7–8:**

```text
Step 7: rootfs detection
  - stat assets/rootfs/v11-2503-rootfs.tar
  - if missing or size < 100 B (LFS pointer) → hard-block
  - compute sha256
  - read tools/.imported_rootfs.json
    - if present and sha matches → rootfs_status = "imported"
    - if present and sha differs → rootfs_status = "stale", warn
    - if missing → rootfs_status = "not_imported", warn
Step 8: docker engine detection
  - if "docker info" returns 0 → engine_status = "ready"
  - else if "podman info" returns 0 → engine_status = "ready_podman"
  - else → engine_status = "unavailable", phase-block phase_3

write env_check.json (additions):
  rootfs_status: "imported" | "stale" | "not_imported" | "lfs_pointer" | "missing"
  imported_image_ref: "bbh-base:local-imported" | null
  engine_status: "ready" | "ready_podman" | "unavailable"
```

**Phase 3 (PoC verification), the gate:**

```text
for each candidate finding:
  decision = build_execution_decision(finding, sandbox_status, action_gate)
  if decision.execution_mode == "sandbox":
      run sandbox with image = sandbox_status.base_image_ref
  elif decision.execution_mode == "host_exception":
      assert decision.host_exception.id ∈ host_exemptions.json.exemptions
      assert exemption.target_is_target_package == false   (schema-level)
      assert decision.host_exception.reason non-empty
      assert decision.host_exception.target_is_target_package == false
      run the same run_poc.sh wrapper, on the host
      record scan_state.phase_status.phase_3.execution_mode = "host_exception"
      record scan_state.phase_status.phase_3.host_exception_ref = id
      append scan_state.error_log entry { phase, code, host_exception_id, reason, ts }
  else:
      action gate returns "deny" → skip PoC + record error_log entry
```

**Phase 4 (report):** adds a section listing every `execution_mode == host_exception` invocation in this scan, with the exemption ID and reason.

### 4.3 Invariants

1. `env_check.json.imported_image_ref == "bbh-base:local-imported"` and that tag's underlying image must have been produced from a tarball whose sha256 is recorded in `tools/.imported_rootfs.json`. Mismatch → hard-block Phase 3.
2. The PoC reproducer itself always runs in the sandbox. Whitelist entries cover *ancillary* tooling only.
3. Schema rejects any `host_exemptions.json` entry where `target_is_target_package == true`.

## 5. Schemas (additions only)

### 5.1 `templates/env_check.json`

Add top-level properties:

```json
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

Remove `additionalProperties: false` on the top level OR add these to the allowed list. (Resolve during implementation.)

### 5.2 `templates/sandbox_status.json`

Add properties:

```json
"base_image_ref": { "type": "string" },
"base_image_source": {
  "type": "string",
  "enum": ["imported_rootfs_tarball", "remote_pull", "prebuilt_local"]
}
```

### 5.3 `templates/action_gate.json`

Add property to the gate decision:

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

### 5.4 `templates/scan_state.json`

`phase_status.<phase>` (where `<phase>` includes `phase_3`) gains:

```json
"execution_mode": { "type": "string", "enum": ["sandbox", "host_exception"] },
"host_exception_ref": { "type": "string" }
```

### 5.5 `tools/host_exemptions.json`

```json
{
  "type": "object",
  "required": ["schema_version", "exemptions"],
  "additionalProperties": false,
  "properties": {
    "schema_version": { "type": "integer", "const": 1 },
    "exemptions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "category", "applies_to",
                     "target_is_target_package", "conditions",
                     "requires_reason_field", "requires_user_approval"],
        "additionalProperties": false,
        "properties": {
          "id": { "type": "string" },
          "description": { "type": "string" },
          "category": {
            "type": "string",
            "enum": ["kernel_access", "perf_profiling", "debugger_syscalls"]
          },
          "applies_to": {
            "type": "array",
            "items": { "type": "string" }
          },
          "target_is_target_package": { "type": "boolean", "const": false },
          "conditions": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1
          },
          "requires_reason_field": { "type": "boolean" },
          "requires_user_approval": { "type": "boolean" }
        }
      }
    }
  }
}
```

Initial entries (matching what we agreed in Section 3 of brainstorming):

- `host-kernel-probe` (kernel_access): read-only `/proc` / `/sys/kernel` while PoC runs in sandbox.
- `host-perf-profiling` (perf_profiling): `perf` or `strace -p` against host process while PoC runs in sandbox.
- `host-debugger-syscalls` (debugger_syscalls): gdb/lldb against non-target host process while PoC runs in sandbox.

All three satisfy `target_is_target_package: false` and require a non-empty `reason` and explicit user approval.

## 6. Error Handling

| When | Condition | Behavior | User message |
|------|-----------|----------|--------------|
| Preflight Step 7 | tarball missing or is LFS pointer (size < 100 B) | hard-block preflight | `ERROR: rootfs tarball is missing or an LFS pointer. Run: git lfs pull` |
| Preflight Step 7 | sha mismatch with `.imported_rootfs.json` | warn + continue, Phase 3 will re-import on demand | `WARN: rootfs changed since last import. Phase 3 will re-import before use.` |
| Preflight Step 8 | docker & podman both unavailable | phase-block Phase 3 | `block_decision.phase_blocks += [{phase: phase_3, tool: docker, reason: missing}]` |
| Preflight Step 8 | docker present but daemon down | phase-block Phase 3 | `block_decision.phase_blocks += [{phase: phase_3, tool: docker, reason: daemon_unreachable}]` |
| `import_rootfs.py` | `docker import` non-zero exit | preflight failure | `ERROR: docker import failed: <stderr>` |
| `import_rootfs.py` | tarball size out of `[100 MB, 2 GB]` | refuse import | `ERROR: tarball size <N> MB out of expected range. Verify the source file.` |
| Phase 3 | host_exception.id not in whitelist | block + ask | `WARN: host_exception_id '<id>' not in whitelist` |
| Phase 3 | `target_is_target_package == true` requested | hard-deny (schema) | `ERROR: target package may not run on host. C7 violation.` |
| Phase 3 | action gate `decision == "deny"` | skip PoC, record in error_log | `WARN: phase_3 skipped: action gate denied` |
| Phase 3 | sandbox container fails to start | existing failure path | unchanged |

## 7. Testing

Three e2e tests under `tests/e2e_rootfs_import/`. No mocks, no schema-only tests.

### T1 — `test_import_rootfs.sh`

```text
setup:   cp assets/rootfs/v11-2503-rootfs.tar <tmp>/
run:     python3 tools/import_rootfs.py --tarball <tmp>/v11-2503-rootfs.tar
assert:
  - exit 0
  - `docker image inspect bbh-base:local-imported` succeeds
  - tools/.imported_rootfs.json exists and tarball_sha256 matches
  - re-run: still exit 0, no second image created
teardown: docker rmi bbh-base:local-imported; rm tools/.imported_rootfs.json
```

### T2 — `test_lfs_pointer_block.sh`

```text
setup:   truncate assets/rootfs/v11-2503-rootfs.tar to 100 bytes
run:     python3 tools/preflight.py --check-only --scan-root <tmp>
assert:
  - exit non-zero
  - env_check.json.block_decision.blocked == true
  - env_check.json.rootfs_status in ["lfs_pointer", "missing"]
teardown: git restore assets/rootfs/v11-2503-rootfs.tar
```

### T3 — `test_poc_runs_in_imported_image.sh`

```text
setup:   import tarball (skip if already imported)
         use existing tests/fixtures/debian/tiny.deb
run:     python3 tools/bbh_scan.py \
             --package tests/fixtures/debian/tiny.deb \
             --workspace <tmp> --mode quick
assert:
  - $SCAN_ROOT/scan_state.json.current_phase == "completed"
  - $SCAN_ROOT/sandbox_status.json.base_image_ref == "bbh-base:local-imported"
  - $SCAN_ROOT/sandbox_status.json.base_image_source == "imported_rootfs_tarball"
  - $SCAN_ROOT/env_check.json.rootfs_status == "imported"
teardown: docker rmi bbh-base:local-imported; rm -rf <tmp>; rm tools/.imported_rootfs.json
```

Total expected CI cost: ~3 minutes added.

## 8. Risks & Open Items

1. **First-time pull is heavy.** Cloning the repo with LFS pulls 957 MB. This is unavoidable given the chosen base; document it in the README and in the failure message.
2. **Docker daemon dependency.** Anyone running this needs a working docker (or podman) daemon. The Phase 3 phase-block handles this gracefully.
3. **`Dockerfile.poc` no longer runs `apt-get install`.** Anything the existing Dockerfile installed on top of `ubuntu:22.04` must already exist in the v11-2503 rootfs. If a needed tool is missing, the fix is to amend the v11-2503 rootfs upstream, not to add an `apt-get install` line back into `Dockerfile.poc`. (Otherwise we re-introduce network dependency at build time.)
4. **The whitelist may grow.** Adding a new exemption is a schema-validated edit to `tools/host_exemptions.json`. The schema-level `const: false` on `target_is_target_package` makes that the only safety-critical field; review should focus there.

## 9. Acceptance Criteria

1. `git lfs install && git lfs pull && python3 tools/import_rootfs.py` produces a `bbh-base:local-imported` image with a recorded sha256.
2. `sandbox/Dockerfile.poc` builds against that image without network access.
3. `tests/e2e_rootfs_import/test_poc_runs_in_imported_image.sh` passes against an unmodified tarball.
4. `tests/e2e_rootfs_import/test_lfs_pointer_block.sh` passes when the tarball is replaced with an LFS pointer.
5. Any code path that would run the target package on the host is rejected by the action gate with a C7-violation error.
6. `scan_state.json.phase_status.phase_3.execution_mode` and `host_exception_ref` correctly capture whether a host exemption was used.
7. The final report includes a host-exemption summary when one or more exemptions were invoked.

## 10. Mapping to Constitution

- **C1 (Context Minimality):** `import_rootfs.py` and the new preflight steps load only the tarball path, the registry, and `host_exemptions.json`. No raw artifacts.
- **C2 (Untrusted Evidence Isolation):** the tarball is treated as binary input to `docker import`; it never enters LLM context. `host_exemptions.json` is configuration, not target-derived.
- **C3 (Spec-Code Traceability):** this spec is the source of truth; tasks under `openspec/changes/tarball-rootfs-import-v1/tasks.md` will reference its sections.
- **C4 (Verification Required):** three e2e tests in `tests/e2e_rootfs_import/`.
- **C5 (Fail Closed):** missing tarball / missing docker / unknown exemption id all produce hard-block or skip-with-error, not silent success.
- **C6 (No Silent Degradation):** `rootfs_status`, `engine_status`, `execution_mode`, and `host_exception_ref` are all recorded.
- **C7 (Runtime Safety):** schema-level `const: false` on `target_is_target_package` makes C7 a property of the data, not a runtime check that could be missed.
- **C8 (Prompt Stability):** the change does not touch Track B prompts.
