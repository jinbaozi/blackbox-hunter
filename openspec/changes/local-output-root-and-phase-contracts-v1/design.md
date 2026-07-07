# Design: Local Output Root and Phase Contracts

## Path Resolution

`tools/output_paths.py` centralizes defaults:

- `DEFAULT_OUTPUT_ROOT_NAME = "black-audit-output"`
- `default_output_root()` returns `$PWD/black-audit-output`
- `resolve_workspace()` preserves explicit paths and otherwise returns the default root
- `resolve_preflight_output()` preserves explicit `--output` and `--scan-root`

## Phase Contracts

`tools/output_contracts.py` defines the required artifacts for each phase and validates JSON outputs against `templates/`.

The runner calls the validator after each phase. Any missing file, missing directory, empty artifact, malformed JSON, or schema failure is converted into a phase failure and recorded in `scan_state.json.error_log`.

## Phase 3

The local runner does not fabricate PoC evidence. If the sandbox is blocked or no executable PoC is configured, it creates only `$SCAN_ROOT/poc_results/` and `verified_findings.json` entries with skipped/unverified reasons.

## Report JSON

`report/findings.json` is now a versioned document containing:

- `schema_version`
- `scan_id`
- `findings`
- `summary`
- `generated_at`
