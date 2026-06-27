# Phase 0: Package Profiling and Environment Preparation

## Objective

Extract, profile, and prepare the target package. Generate `scan_id`, `scan_state.json`, `target_profile.json`, `scan_strategy.json`, `coverage_plan.json`, and `sandbox_status.json`.

## Step 0: scan_id and Disk Preflight

Generate `scan_id` as `BBH-YYYYMMDD-<6 lowercase hex>`. Set `SCAN_ROOT=$WORKSPACE/$scan_id`.

Before extraction, require free disk space of `package_size * 5 + 1 GiB`. Abort with a `scan_state.json.error_log` entry if the preflight fails.

## Extraction

Use fallback order:

- deb: `dpkg-deb`, then `ar` plus `tar`, then `7z`.
- rpm: `rpm2cpio`, then `7z`, then `bsdtar`.

Write extracted contents to `$SCAN_ROOT/extracted/`.

## Inventory

Collect package metadata, ELF binaries, scripts, config files, systemd units, setuid/setgid files, network listeners, and command-line entry points. Record architecture per ELF binary.

## Architecture Branching

- `x86_64`: enable radare2, Ghidra, checksec, cwe_checker, and objdump fallback.
- `aarch64`: enable radare2, Ghidra, checksec, and objdump fallback; mark cwe_checker support as best effort.
- Other architectures: run metadata, strings, YARA, objdump, and dependency checks; cap Track B confidence at `0.70` unless decompiler output is available.

## Outputs

- `$SCAN_ROOT/scan_state.json`
- `$SCAN_ROOT/target_profile.json`
- `$SCAN_ROOT/scan_strategy.json`
- `$SCAN_ROOT/coverage_plan.json`
- `$SCAN_ROOT/sandbox_status.json`

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
