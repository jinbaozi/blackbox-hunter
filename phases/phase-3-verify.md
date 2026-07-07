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

## Action Gate

Before executing a PoC or setup command, build an action request and evaluate it with `tools/context/action_gate.py`.

The gate must block:

- PoC execution outside the configured sandbox.
- PoC execution that requires network access.
- Privileged execution or additional Linux capabilities.
- Writes outside the configured results directory.
- High or critical PoC execution without explicit user approval.
- Package-manager installs or image pulls without explicit user approval.

A blocked action must be recorded in `scan_state.json.error_log` and the affected finding should be marked `skipped`, `poc_error`, or `sandbox_error` depending on the failure type.

## Verification Flow

Before selecting findings, read `env_check.json.block_decision.phase_blocks`. If Phase 3 is blocked because Docker/Podman or another sandbox runtime is unavailable, mark Phase 3 as `skipped`, write the reason to `scan_state.json.error_log`, and continue to Phase 4 with unverified findings clearly labeled.

Even when Phase 3 is skipped or no eligible PoC exists, create `$SCAN_ROOT/poc_results/` and write `verified_findings.json`. Do not create per-finding runner files such as `stdout.txt`, `stderr.txt`, or `monitor.json` unless a PoC actually ran.

1. Select findings with enough reproduction detail and acceptable risk.
2. Create one PoC testcase from `templates/poc_testcase.md` per eligible finding.
3. Create `$SCAN_ROOT/poc_results/<finding_id>/` and bind it as `/workspace/results`.
4. Evaluate the planned execution with `tools/context/action_gate.py`.
5. Mount the extracted package read-only.
6. Execute the testcase with bounded CPU, memory, process count, and timeout.
7. Record stdout, stderr, exit code, timeout status, runner status, crash signals, monitor telemetry, pre/post state, and evidence paths.
8. Interpret the raw runner result with `sandbox/result_interpreter.py` and the expected verification signal before setting `verification.poc_status`.

## Host Exemption Path (whitelisted)

The default is sandbox. Host execution of any PoC is permitted only when the action gate carries a `host_exception` block whose `id` is in `tools/host_exemptions.json` and whose `target_is_target_package` is `false`. The PoC reproducer itself always runs in the sandbox; the whitelist covers ancillary tooling only (kernel probes, perf/strace on host, debuggers against non-target host processes).

Host exception also requires an allowed action-gate decision, explicit user approval when required by the whitelist, `request.runs_target_code = false`, and explicit `host_exception.target_is_target_package = false`.

When the gate approves host execution:

- `scan_state.json.phase_status.phase_3.execution_mode = "host_exception"`
- `scan_state.json.phase_status.phase_3.host_exception_ref = <id>`
- An `error_log` entry is recorded with `code: host_exception_invoked` and the reason.

When the gate denies, the PoC is skipped and `code: host_exception_denied` is recorded.

## Result Mapping

Use `sandbox/result_interpreter.py` to map runner results into `verification.poc_status`. A raw runner status is not itself a verification decision.

| Runner / phase result | `poc_status` | Meaning |
|---|---|---|
| Expected crash, unsafe behavior, timeout, exit code, or deterministic output pattern observed | `verified` | Runtime evidence confirms the expected signal. |
| Test executed cleanly and the expected signal was absent | `failed` | The PoC did not reproduce the issue under this sandbox. |
| Runner result did not prove or disprove the expected signal | `inconclusive` | The finding remains statically supported but not runtime-confirmed. |
| PoC script missing, malformed, unreadable, or internally failed before exercising the target | `poc_error` | The PoC artifact failed; do not treat as a false positive. |
| Sandbox runtime, image build, mount, seccomp, or result collection failed | `sandbox_error` | Infrastructure failed; rerun after fixing the sandbox. |
| Finding was not eligible or user approval was not granted | `skipped` | No runtime validation attempted. |

`completed` does not mean `verified`; it means the runner exited cleanly. `crash` does not mean `verified` unless the expected signal is a crash or the configured expected signal matches the observed output.

## Output

Required outputs:

- `$SCAN_ROOT/verified_findings.json`
- `$SCAN_ROOT/poc_results/`

`verified_findings.json` wraps each finding with `poc_result` and a copy of `sandbox_status.json`. Skipped or unverified findings must include a reason in `verification.failure_reason` and `poc_result.reason`.

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
- interpreted `poc_status`
- interpreted `finding_status`
- interpreter reason

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` and `$SCAN_ROOT/poc_results/<finding_id>/` for resume diagnostics. Infrastructure errors must not downgrade a statically supported finding to false positive; use `sandbox_error` or `inconclusive` instead.
