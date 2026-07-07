# Phase 2: Result Merge and Confidence Scoring

## Objective

Merge `track_a_findings.json` and `track_b_findings.json`, deduplicate equivalent findings, attach normalized Track A `finding_signal` references, and emit `merged_findings.json` plus `coverage_report.json`.

Phase 2 must keep three concepts separate:

1. `finding_signal`: weak or intermediate tool evidence such as YARA hits, imported symbols, version matches, package-script warnings, or dependency context.
2. `finding_status`: lifecycle state of the finding itself.
3. `verification.poc_status`: result of runtime PoC verification, which must not be confused with the finding lifecycle.

## Finding Lifecycle

`finding_status` must use one of these values:

| Status | Meaning |
| --- | --- |
| `candidate` | A plausible issue exists, but evidence is incomplete or only signal-level. |
| `confirmed_static` | Static evidence is sufficient: affected location, source or trigger, sink or unsafe condition, and missing/insufficient guard are documented. |
| `verified` | Phase 3 or another safe verification path observed the expected signal. |
| `false_positive` | Evidence disproves the issue, such as an unaffected version, unreachable code, adequate guard, or wrong package mapping. |
| `inconclusive` | Evidence or environment is insufficient to confirm or reject. |

`verification.poc_status` remains a PoC-specific field. `poc_error` and `sandbox_error` are infrastructure states and must not become `false_positive`.

## Deduplication Rules

Two findings are equivalent when they share the same binary and one of these keys matches:

1. CVE ID.
2. CWE plus function.
3. Address offset.
4. Normalized title plus attack-surface entry point.

Preserve all source IDs in `dedup_info.merged_from`. Preserve Track A signal identifiers in `dedup_info.signal_refs` and in `finding.evidence.signal_refs` when those signals influenced the finding.

## Confidence Breakdown

Phase 2 must populate `finding.confidence_breakdown` and update the legacy scalar `finding.vulnerability.confidence` to match `confidence_breakdown.final`.

The breakdown fields are:

| Field | Meaning |
| --- | --- |
| `evidence` | Strength of concrete evidence, including function/address detail, source-to-sink evidence, and guard analysis. |
| `reachability` | Likelihood that the affected code/config is reachable from an attack surface. |
| `tool_reliability` | Reliability of the producing tool chain, including agreement across Track A and Track B and degradation warnings. |
| `verification` | Runtime verification confidence. Unknown infrastructure states should be neutral, not negative. |
| `final` | Weighted final score used for ordering and report severity confidence. |

Recommended weighting:

```text
final = 0.45 * evidence
      + 0.25 * reachability
      + 0.15 * tool_reliability
      + 0.15 * verification
```

Clamp each component and final confidence to `[0, 1]`.

## Required Caps and Adjustments

Apply these caps and adjustments after component scoring:

| Condition | Rule |
| --- | --- |
| Only imported symbol evidence | cap final at `0.45` |
| Only string/YARA hit evidence | cap final at `0.35` |
| Track A and Track B agree | increase tool reliability by `+0.15` |
| Function or address-level evidence | increase evidence and reachability |
| Source-to-sink path with missing guard | increase evidence and reachability |
| Offline/stale CVE database | reduce tool reliability by `-0.15` |
| Architecture fallback without decompiler output | reduce tool reliability by `-0.20` |
| CVE version or vendor backport unconfirmed | reduce evidence by `-0.10` |
| PoC verified | set verification to `1.0` and set finding_status to `verified` |
| PoC failed without expected signal | set verification to a low value but do not automatically mark false positive |
| `poc_error` or `sandbox_error` | treat verification as unknown/neutral and preserve static status |

Use `tools/merge/confidence_scoring.py` as the reference implementation for the above rules.

## Promotion Rules

Track A adapter output starts as `finding_signal`. Promote only when sufficient evidence exists:

- `finding_signal` only: keep `candidate` and require Track B or human review.
- Signal plus concrete location and static analysis: `confirmed_static`.
- Static evidence plus matching Phase 3 expected signal: `verified`.
- Disproven version, unreachable location, or adequate guard: `false_positive`.
- Missing evidence, environment mismatch, or ambiguous PoC: `inconclusive`.

## Outputs

- `$SCAN_ROOT/merged_findings.json`
- `$SCAN_ROOT/coverage_report.json`
- Updated `$SCAN_ROOT/scan_state.json`
- Optional `$SCAN_ROOT/logs/confidence_scoring.jsonl`

The phase is complete only after `merged_findings.json` and `coverage_report.json` validate against their schemas.

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.

If confidence scoring cannot be completed for one finding, mark that finding `inconclusive`, attach a reason in `confidence_breakdown.reason`, and continue scoring other findings.
