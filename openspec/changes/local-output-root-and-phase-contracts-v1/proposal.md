# Proposal: Local Output Root and Phase Contracts

## Problem

The workflow previously required callers to pass a workspace path and performed most artifact validation only near the end of the run. This allowed path drift and late discovery of missing phase outputs.

## Change

- Default workspace to `$PWD/black-audit-output`.
- Keep scan artifacts under `$WORKSPACE/<scan_id>`.
- Validate each phase's required files, directories, and schemas immediately after the phase.
- Require Phase 3 to emit skipped/unverified artifacts when PoC execution is unavailable.
- Version `report/findings.json` with `templates/report_findings.json`.

## Compatibility

Explicit `--workspace`, preflight `--output`, and preflight `--scan-root` continue to override defaults.
