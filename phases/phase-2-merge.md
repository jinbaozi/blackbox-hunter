# Phase 2: Result Merge and Confidence Scoring

## Objective

Merge `track_a_findings.json` and `track_b_findings.json`, deduplicate equivalent findings, and emit `merged_findings.json` plus `coverage_report.json`.

## Deduplication Rules

Two findings are equivalent when they share the same binary and one of these keys matches: CVE ID, CWE plus function, address offset, or normalized title plus attack-surface entry point. Preserve all source IDs in `dedup_info.merged_from`.

## Confidence Scoring

Start from the finding confidence, then adjust:

- `+0.15` when both Track A and Track B agree.
- `+0.10` when evidence includes function or address-level location.
- `-0.15` for offline CVE database warnings.
- `-0.20` for architecture fallback without decompiler output.

Clamp final confidence to `[0, 1]`.

## Outputs

- `$SCAN_ROOT/merged_findings.json`
- `$SCAN_ROOT/coverage_report.json`
- Updated `$SCAN_ROOT/scan_state.json`

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
