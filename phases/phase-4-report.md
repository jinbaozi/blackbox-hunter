# Phase 4: Report Generation

## Objective

Generate the final human-readable report from `verified_findings.json`, `coverage_report.json`, `scan_state.json`, and raw phase logs.

## Report Sections

Use `templates/report_summary.md` and include executive summary, environment, coverage, verified findings, unverified findings, limitations, remediation guidance, and appendix paths.

## Output

- `$SCAN_ROOT/report/blackbox-security-report.md`
- `$SCAN_ROOT/report/findings.json`
- Updated `$SCAN_ROOT/scan_state.json` marked `completed`

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
