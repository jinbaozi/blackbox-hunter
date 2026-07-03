# Phase -1: Environment Pre-flight Check

## Objective

Validate the runtime environment before scanning begins. Check tool availability, install missing dependencies, manage PATH, handle host-binary and container-image tools, and produce `env_check.json`. This phase determines whether the scan can proceed or must be blocked.

## Step 0: PATH Health Check

1. Verify that `$HOME/.local/bin` exists; create it with `mkdir -p` if absent.
2. Check whether `$HOME/.local/bin` is in `$PATH`. If not:
   - Append it to the current session: `export PATH="$HOME/.local/bin:$PATH"`
   - Record a warning in `env_check.json.path_warnings` with the persistent fix command:
     - bash: `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`
     - zsh: `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc`
   - Set `env_check.json.path_patched = true`

## Step 1: Extended Directory Scan

Define the extended directory list:

```text
~/.local/bin
/usr/local/bin
/usr/bin
/opt/homebrew/bin
/snap/bin
~/.cargo/bin
```

For each host-binary tool in `tools/tool_registry.json`:

1. Run `command -v <binary_name>` as primary detection.
2. If not found, scan each extended directory for the binary.
3. If found in an extended directory not already in PATH, append it and set `path_patched = true`.
4. Record `found_in` with the full path where the tool was located.

## Step 2: Container Image Tool Detection

Tools may declare `"execution_model": "container_image"` with `container_engine`, `container_image`, and `detect_cmd`.

1. Detect the container engine first, defaulting to Docker when `container_engine` is absent.
2. Do not require `binary_name` to exist on PATH for a container-image tool; `binary_name` is descriptive only in this mode.
3. Prefer a no-network detection command such as `docker run --rm --pull=never <image> --version` or `docker image inspect <image>`.
4. If the engine exists but the image is missing, mark the tool `missing` with the engine path in `found_in` and an image-specific `error_message`.
5. If the user approves installation, run the configured image pull command and re-run detection.
6. Record `execution_model`, `container_engine`, and `container_image` in `env_check.json.tools[]`.

## Step 3: Version Validation

For each detected tool with a `version_min` constraint:

1. Parse the version from `<binary_name> --version`, the tool-specific version command, or the container-image `detect_cmd`.
2. Compare against `version_min` using semver-like major.minor comparison.
3. If the detected version is below `version_min`, mark status as `version_low`.
4. If no parseable version is available but the detection command succeeded, treat the tool as available and record the empty version; downstream confidence should account for missing version evidence.

## Step 4: Applicability Filter

For tools with an `applies_to` field (e.g., `lintian` applies to `deb` only):

1. Compare against the target package type from user input.
2. If not applicable, mark status as `skipped_not_applicable` and exclude from blocking decisions.

## Step 5: Missing Tool Installation

Invoke `tools/install.sh` with the appropriate flags to install missing or version-low tools:

- Default mode: interactive (prompt user before each install).
- `--offline` mode: detect existing tools only and skip all installation/network update actions. This is a controlled-environment and reproducibility mode, not the default accuracy-first path.
- `--check-only` mode: detect and write `env_check.json` without installing.
- `--registry <file>`: use an alternate registry, primarily for tests and controlled fixtures.
- `--output <file>`: write `env_check.json` to an explicit path.
- `--scan-root <dir>`: write `<dir>/env_check.json` when `--output` is not provided.
- If neither `--output` nor `--scan-root` is provided, write `./env_check.json` in the current working directory and print the absolute output path before and after the run.
- Installation follows `install_priority` order per tool:
  1. `pipx install <tool>` (Python CLI tools preferred)
  2. `npm install -g <npm_package>` (if `npm_package` is defined)
  3. `pip install --user <tool>` (fallback when pipx unavailable)
  4. System package manager (`apt`, `dnf`, `brew`)
  5. Container image pull (`docker pull <image>` or equivalent) for container-image tools
  6. Manual binary download to `~/.local/bin`
- After each install attempt, re-run the tool-specific detection logic.
- Mark `install_failed` if verification fails.
- Never run a package-manager, image-pull, or host-install command without explicit user confirmation.

## Step 6: Blocking and Degradation Decision

Evaluate each tool based on its `priority` and availability:

| Priority | Status | Action |
|----------|--------|--------|
| `required` | missing, no fallback available | **Hard-block**: set `block_decision.blocked = true`, add to `blocked_tools`, generate `install_hints` |
| `required` | missing, fallback available | **Soft-warn**: set status to `fallback_active`, record `fallback_used` |
| `required_verify` | missing, no fallback | **Phase-block**: mark Phase 3 as blocked, allow Phases 0-2 and 4 to proceed |
| `high` | missing | **Warn-and-continue**: log warning, proceed |
| `medium` | missing | **Warn-and-continue**: log warning, proceed |
| `optional` | missing | **Silent-skip**: no warning needed |

Compute `confidence_ceiling` based on missing high-priority tools:
- All required + high tools available: ceiling = `0.95`
- Required tool using fallback: ceiling = `0.80`
- High tool missing: ceiling -= `0.05` per missing high tool
- Medium tool missing: ceiling -= `0.02` per missing medium tool

## Outputs

- `$SCAN_ROOT/env_check.json` — validated against `templates/env_check.json`

## Error Handling

- If `tool_registry.json` is missing or malformed, abort with a clear error message.
- If `install.sh` is not executable, attempt `chmod +x`; if that fails, abort.
- PATH patching failures are non-fatal; record in `path_warnings` and continue.
- Container-image detection failures are non-fatal unless the tool priority makes them blocking; record the engine/image and continue through the degradation matrix.

## Integration with Other Phases

- Phase 0 reads `env_check.json` to determine available extraction tools.
- Phase 1a reads `env_check.json.tools` instead of re-detecting each tool.
- Phase 1b reads `env_check.json` to select the disassembly engine chain.
- Phase 3 checks `env_check.json` for sandbox runtime availability (docker/podman).
- If `env_check.json` is missing (e.g., resume from a pre-preflight scan), each phase falls back to its own detection logic.
