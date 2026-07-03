# Design: Finding Lifecycle and Confidence Breakdown

## Lifecycle

`finding_status` describes the vulnerability lifecycle and is separate from `verification.poc_status`:

- `candidate`: plausible but evidence is incomplete or signal-level.
- `confirmed_static`: static evidence is sufficient.
- `verified`: expected verification signal was observed.
- `false_positive`: evidence disproves the issue.
- `inconclusive`: evidence or environment is insufficient.

## Confidence Breakdown

`confidence_breakdown` contains:

- `evidence`
- `reachability`
- `tool_reliability`
- `verification`
- `final`
- `caps_applied`
- `adjustments`
- `reason`

The reference implementation uses:

```text
final = 0.45 * evidence
      + 0.25 * reachability
      + 0.15 * tool_reliability
      + 0.15 * verification
```

## Verification Handling

`poc_error` and `sandbox_error` are treated as verification unknown. They do not prove non-vulnerability and must not automatically become `false_positive`.

## Compatibility

`vulnerability.confidence` remains as a scalar field for downstream compatibility and should be synchronized with `confidence_breakdown.final` after Phase 2.
