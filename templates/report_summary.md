# BlackBox Security Test Report

## 1. Executive Summary

Summarize package name, scan_id, scan mode, total findings, verified findings, and highest severity.

## 2. Preflight Environment Summary

Summarize env_check.json: checked_at, output path, offline/check-only mode, blocked tools, fallback decisions, phase blocks, install hints, path warnings, and confidence ceiling.

## 3. Target Profile Summary

Summarize target_profile.json: package path, package type, extracted inventory, binaries, scripts, configs, services, architectures, and attack-surface entry points.

## 4. Scan Strategy Summary

Summarize scan_strategy.json and coverage_plan.json: mode, selected Track A tools, Track B focus dimensions, target priorities, limits, and expected coverage.

## 5. Track A Summary

Summarize track_a_findings.json: deterministic tools executed, skipped tools, warnings, finding count, and strongest evidence classes.

## 6. Track B Summary

Summarize track_b_findings.json: binary-analysis engine, fallback mode, dimensions analyzed, functions/files reviewed, warnings, and finding count.

## 7. Merge and Confidence Summary

Summarize merged_findings.json: deduplication decisions, source IDs merged, confidence adjustments, and final finding count.

## 8. Verification Summary

Summarize verified_findings.json and sandbox_status.json: verified findings, unverified findings, skipped PoC reasons, sandbox runtime, and evidence paths.

## 9. Coverage Summary

Summarize coverage_report.json: binary, config, dependency, attack-surface, and tool coverage percentages plus gaps and degradation reasons.

## 10. Scope and Environment

Describe package path, package type, architecture coverage, extraction method, tool versions, sandbox status, and CVE database mode.

## 11. Findings

For each finding include severity, confidence, affected binary/function, evidence, verification status, remediation, and references.

## 12. Limitations and Next Steps

Document missing tools, unsupported architectures, offline database age, skipped PoC verification, unresolved coverage gaps, and recommended follow-up testing.

## 13. Appendix Artifact Paths

List env_check.json, target_profile.json, scan_strategy.json, coverage_plan.json, track_a_findings.json, track_b_findings.json, merged_findings.json, coverage_report.json, verified_findings.json, scan_state.json, raw logs, and PoC testcase paths.
