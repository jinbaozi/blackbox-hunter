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
- Phase 1a: deterministic tool coverage, Track A signal counts, warnings, and signal-to-finding promotion summary.
- Phase 1b: AI analysis dimensions, selected binary-analysis engine, fallback mode, and Track B finding summary.
- Phase 2: deduplication result, merged finding counts, lifecycle counts, confidence breakdowns, confidence adjustments, and coverage gaps.
- Phase 3: verification status, skipped verification reasons, sandbox status, PoC evidence paths, and distinction between runner status and vulnerability verdict.

## Finding Lifecycle Reporting

Reports must group findings by `finding_status` before severity:

1. `verified`
2. `confirmed_static`
3. `candidate`
4. `inconclusive`
5. `false_positive`

For each finding, show:

- `finding_status`
- `verification.poc_status`
- `confidence_breakdown.final`
- component confidence values: evidence, reachability, tool reliability, verification
- caps and adjustments from `confidence_breakdown.caps_applied` and `confidence_breakdown.adjustments`
- supporting signal references, if present

Do not describe `poc_error`, `sandbox_error`, or `inconclusive` as proof that a finding is false. These states must be reported as verification limitations.

## Output

- `$SCAN_ROOT/report/blackbox-security-report.md`
- `$SCAN_ROOT/report/findings.json`
- Updated `$SCAN_ROOT/scan_state.json` marked `completed`

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
