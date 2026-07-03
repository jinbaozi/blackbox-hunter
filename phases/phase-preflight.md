# Phase -1: Environment Pre-flight Check

## Objective

Validate the runtime environment before scanning begins. Check tool availability, manage PATH, select package-type-aware package-manager priority, handle host-binary and container-image tools, and produce `env_check.json`. This phase determines whether the scan can proceed or must be blocked.

## Step 0: PATH Health Check

1. Ensure `$HOME/.local/bin` exists.
2. If it is absent from `$PATH`, prepend it for the current process, set `env_check.json.path_patched = true`, and record a persistent shell-profile hint in `path_warnings`.

## Step 1: Extended Directory Scan

Search normal PATH first, then:

```text
~/.local/bin
/usr/local/bin
/usr/bin
/opt/homebrew/bin
/snap/bin
~/.cargo/bin
```

If a binary is found in an extended directory that is not on PATH, prepend that directory and record the full path in `tools[].found_in`.

## Step 2: Package Manager Selection

The package manager order comes from `tools/tool_registry.json.package_manager_priority`.

Default RPM order:

```text
dnf -> microdnf -> yum -> zypper -> rpm-ostree -> apt -> brew
```

Default Debian order:

```text
apt -> dnf -> microdnf -> yum -> zypper -> rpm-ostree -> brew
```

The selected manager is written to `env_check.json.package_manager`. If `--package-type` is omitted, preflight may infer it from `--package-path` extension.

## Step 3: Tool Detection and Version Validation

For each applicable tool:

1. Locate the binary or required container engine.
2. Run the configured no-network `detect_cmd`.
3. If `detect_cmd` fails, mark the tool unavailable unless the registry explicitly sets `detect_nonzero_ok`.
4. Parse and compare `version_min` when present.
5. After an approved install action, re-run detection and version validation before marking the tool `available`.

## Step 4: Applicability Filter

For tools with `applies_to`:

- If package type is known and different, mark `skipped_not_applicable`.
- If package type is unknown, mark `skipped_not_applicable` with an unknown-type reason instead of executing a package-specific tool.

Examples: `lintian` applies to Debian packages; `rpmlint`, `rpm`, and `rpm2cpio` apply to RPM packages.

## Step 5: Missing Tool Handling

`tools/install.sh` delegates to `tools/preflight.py`.

Supported modes:

- Default: interactive and approval-gated.
- `--offline`: detect only; no network or host-changing action.
- `--check-only`: write `env_check.json` without host changes.
- `--auto-fix`: allow fallback activation in non-interactive tests and controlled fixtures.

Install hints are derived from registry `install_priority`, `system_packages`, and `install_cmds`. Host-changing package-manager, image-pull, and install actions must still require explicit user approval.

## Step 6: Blocking and Degradation Decision

| Priority | Status | Action |
|----------|--------|--------|
| `required` | missing, no fallback | Hard-block: `block_decision.blocked = true` |
| `required` | fallback available and approved | `fallback_active`, confidence ceiling at most `0.80` |
| `required_verify` | missing, no fallback | Phase-block Phase 3 only |
| `high` | missing | Warn and continue, lower confidence |
| `medium` | missing | Warn and continue, lower confidence |
| `optional` | missing | Skip |

For RPM packages, `rpm2cpio` is the primary extractor and may degrade to `7z` or `bsdtar`. If all required RPM extraction paths are unavailable, Phase 0 must stop before later phases.

## Outputs

- `$SCAN_ROOT/env_check.json`, validated against `templates/env_check.json`

## Error Handling

- Missing or malformed registry: abort with a clear error.
- PATH patching failure: record warning and continue.
- Container-image detection failure: record engine/image detail and apply the priority matrix.
- Missing package-manager command for a method: skip to the next method or produce an install hint; do not silently mark success.

## Integration with Other Phases

- Phase 0 reads `env_check.json` to choose extraction tools.
- Phase 1a reads `env_check.json.tools` and uses package applicability instead of re-detecting everything.
- Phase 1b uses `env_check.json` to select the binary-analysis engine chain.
- Phase 3 reads `block_decision.phase_blocks` before sandbox execution.
