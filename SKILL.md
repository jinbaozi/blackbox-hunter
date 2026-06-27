---
name: blackbox-hunter
description: AI-assisted black-box vulnerability scanning for rpm/deb packages using Track A tools and Track B AI binary analysis.
---

# BlackBox Hunter

Use this skill when the user wants to scan an rpm or deb package for vulnerabilities without source code.

## Inputs

- Package path ending in `.rpm` or `.deb`.
- Optional scan mode: `quick`, `standard`, `deep`, or `full`.
- Optional resume path pointing to an existing `$WORKSPACE/<scan_id>/scan_state.json`.

## State Machine

```text
idle
  -> preflight_running
  -> preflight_done
  -> phase_0_running
  -> phase_0_done
  -> track_a_running + track_b_running
  -> track_a_done + track_b_done
  -> phase_2_running
  -> phase_2_done
  -> phase_3_running
  -> phase_3_done
  -> phase_4_running
  -> completed
```

Failure states are `failed` at the top level and `failed` or `skipped` per phase. A skipped optional phase must record a reason in `scan_state.json.error_log`.

Every phase entry in `scan_state.json.phase_status` has `status`, optional timestamps, `retry_count`, and optional `error_message`.

## Resume Logic

1. If the user provides a resume path, load `scan_state.json` and validate it against `templates/scan_state.json`.
2. Use `scan_id` to resolve `$SCAN_ROOT` and verify required outputs for every completed phase.
3. Re-run the first phase whose required output is missing, invalid, or marked `failed`.
4. Do not overwrite successful phase outputs. Write reruns to a timestamped `reruns/` subdirectory and atomically promote only valid outputs.
5. Track A and Track B may resume independently. Phase 2 starts only after both tracks are done, skipped, or failed with an explicit user-approved degradation.

## Orchestration

1. Run environment preflight from `phases/phase-preflight.md` to validate tool availability, install missing dependencies, and produce `env_check.json`. If hard-blocked, abort and present installation instructions to the user.
2. Load `phases/phase-0-profile.md` and produce `target_profile.json`, `scan_strategy.json`, `coverage_plan.json`, `sandbox_status.json`, and `scan_state.json`.
3. Run Track A from `phases/phase-1a-toolscan.md` for deterministic tooling.
4. Run Track B from `phases/phase-1b-ai-analysis.md` for prioritized AI binary analysis.
5. Merge and score with `phases/phase-2-merge.md`.
6. Verify feasible findings in the sandbox with `phases/phase-3-verify.md`.
7. Generate the final report with `phases/phase-4-report.md`.

## Phase Execution Contract

- Every JSON output must validate against a schema under `templates/`.
- Finding records must validate against `templates/finding.json` and use only `TA-NNN` or `TB-NNN` identifiers.
- All phase outputs are written under `$SCAN_ROOT`, where `$SCAN_ROOT=$WORKSPACE/<scan_id>`.
- Phase logs go under `$SCAN_ROOT/logs/`.
- Optional tools may degrade confidence but must not silently produce empty success output.

## User Checkpoints

- Ask before running package-manager commands that install host tools.
- Ask before running PoC verification against a finding marked high or critical impact.
- Ask before accepting degraded output when both Track A and Track B fail on the same binary.

## Error Escalation

Escalate to the user with concrete options when environment preflight hard-blocks on missing required tools, extraction fails, disk preflight fails, architecture support is missing for all binaries, sandbox startup fails, or schema validation fails after a rerun.
