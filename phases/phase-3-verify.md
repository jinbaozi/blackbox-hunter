# Phase 3: PoC Verification

## Objective

Verify feasible findings inside the Docker sandbox and emit `verified_findings.json`.

## Sandbox Rules

Use `sandbox/docker-compose.sandbox.yml`. The container runs as user `poctest`, has `network_mode: none`, and uses the provided seccomp profile. The runner owns timeout enforcement through `sandbox/run_poc.sh`.

## Verification Flow

1. Select findings with enough reproduction detail and acceptable risk.
2. Create one PoC testcase from `templates/poc_testcase.md` per finding.
3. Mount the extracted package read-only.
4. Execute the testcase with bounded CPU, memory, process count, and timeout.
5. Record stdout, stderr, exit code, timeout status, crash signals, and evidence paths.

## Output

`verified_findings.json` wraps each finding with `poc_result` and a copy of `sandbox_status.json`.

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
