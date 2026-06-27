# Phase 4: Report Generation

## Objective

Generate the final human-readable report from `verified_findings.json`, `coverage_report.json`, `scan_state.json`, and raw phase logs.

## Inputs

- `$SCAN_ROOT/env_check.json`
- `$SCAN_ROOT/target_profile.json`
- `$SCAN_ROOT/scan_strategy.json`
- `$SCAN_ROOT/coverage_plan.json`
- `$SCAN_ROOT/track_a_findings.json`
- `$SCAN_ROOT/track_b_findings.json`
- `$SCAN_ROOT/merged_findings.json`
- `$SCAN_ROOT/coverage_report.json`
- `$SCAN_ROOT/verified_findings.json`
- `$SCAN_ROOT/scan_state.json`
- Raw phase logs under `$SCAN_ROOT/logs/`

## Report Sections

Use `templates/report_summary.md` and include executive summary, environment, coverage, verified findings, unverified findings, limitations, remediation guidance, and appendix paths.

The final report must include conclusions from every previous phase:

- Phase -1: environment readiness, blocked tools, fallback decisions, confidence ceiling, and install hints.
- Phase 0: package profile, extracted target inventory, architecture coverage, and scan strategy.
- Phase 1a: deterministic tool coverage, warnings, and Track A finding summary.
- Phase 1b: AI analysis dimensions, selected binary-analysis engine, fallback mode, and Track B finding summary.
- Phase 2: deduplication result, merged finding counts, confidence adjustments, and coverage gaps.
- Phase 3: verification status, skipped verification reasons, sandbox status, and PoC evidence paths.

## Output

- `$SCAN_ROOT/report/blackbox-security-report.md`
- `$SCAN_ROOT/report/findings.json`
- Updated `$SCAN_ROOT/scan_state.json` marked `completed`

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
