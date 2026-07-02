# Phase 3: PoC Verification

## Objective

Verify feasible findings inside the Docker or Podman sandbox and emit `verified_findings.json`. Phase 3 must distinguish a confirmed static finding from a runtime-verified finding, and must preserve enough evidence for audit and rerun.

## Inputs

- `$SCAN_ROOT/env_check.json`
- `$SCAN_ROOT/merged_findings.json`
- `$SCAN_ROOT/sandbox_status.json`
- Extracted package tree under `$SCAN_ROOT/extracted/`

## Sandbox Rules

Use `sandbox/docker-compose.sandbox.yml` for Docker-compatible runs. The container runs as user `poctest`, uses `network_mode: none`, drops all capabilities, runs with `no-new-privileges:true`, uses the provided seccomp profile, and mounts the extracted package read-only.

The runner owns timeout enforcement through `sandbox/run_poc.sh`. Results must be persisted by binding:

```text
RESULTS_DIR=$SCAN_ROOT/poc_results/<finding_id>
```

to `/workspace/results`. Do not rely on container tmpfs contents after container shutdown.

## PoC Eligibility

Construct a PoC only when all of the following are true:

1. The finding has a concrete target path and enough reproduction detail: affected binary/file, entry point, input shape, preconditions, and expected verification signal.
2. The test can run with no network, an unprivileged user, read-only package mounts, and bounded CPU, memory, process count, and timeout.
3. The test does not require destructive writes, persistence, external services, lateral movement, privileged host features, or credentials not present in the extracted package.
4. High or critical impact tests, and any potentially destructive test, have explicit user approval before execution.

Do not construct a runtime PoC for purely static findings such as hardening gaps, stale CVE matches, or hardcoded strings unless there is a safe local runtime signal to validate.

## Verification Flow

Before selecting findings, read `env_check.json.block_decision.phase_blocks`. If Phase 3 is blocked because Docker/Podman or another sandbox runtime is unavailable, mark Phase 3 as `skipped`, write the reason to `scan_state.json.error_log`, and continue to Phase 4 with unverified findings clearly labeled.

1. Select findings with enough reproduction detail and acceptable risk.
2. Create one PoC testcase from `templates/poc_testcase.md` per eligible finding.
3. Create `$SCAN_ROOT/poc_results/<finding_id>/` and bind it as `/workspace/results`.
4. Mount the extracted package read-only.
5. Execute the testcase with bounded CPU, memory, process count, and timeout.
6. Record stdout, stderr, exit code, timeout status, runner status, crash signals, monitor telemetry, pre/post state, and evidence paths.
7. Map the raw runner result into the finding verification state.

## Result Mapping

Use these `verification.poc_status` values:

| Runner / phase result | `poc_status` | Meaning |
|---|---|---|
| Expected crash, unsafe behavior, or deterministic vulnerability signal observed | `verified` | Runtime evidence confirms the finding. |
| Test executed cleanly and the expected signal was absent | `failed` | The PoC did not reproduce the issue under this sandbox. |
| PoC could not run because required local preconditions were absent | `inconclusive` | The finding remains statically supported but not runtime-confirmed. |
| PoC script missing, malformed, unreadable, or internally failed before exercising the target | `poc_error` | The PoC artifact failed; do not treat as a false positive. |
| Sandbox runtime, image build, mount, seccomp, or result collection failed | `sandbox_error` | Infrastructure failed; rerun after fixing the sandbox. |
| Finding was not eligible or user approval was not granted | `skipped` | No runtime validation attempted. |

## Output

`verified_findings.json` wraps each finding with `poc_result` and a copy of `sandbox_status.json`.

Each `poc_result` should include:

- `status`
- `exit_code`
- `timeout`
- `stdout_path`
- `stderr_path`
- `monitor_path`
- `pre_state_path`
- `post_state_path`
- `runner_status_path`
- `result_dir`
- `failure_reason` when applicable

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` and `$SCAN_ROOT/poc_results/<finding_id>/` for resume diagnostics. Infrastructure errors must not downgrade a statically supported finding to false positive; use `sandbox_error` or `inconclusive` instead.
