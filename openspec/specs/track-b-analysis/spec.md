# Track B Analysis Specification

## Requirement TB-001: Prompt Manifest

WHEN Track B runs  
THE SYSTEM SHALL resolve prompt components from a manifest rather than embedding all prompt text in the phase document.

## Requirement TB-002: Dimension Lazy Loading

WHEN analyzing one dimension  
THE SYSTEM SHALL load only that dimension's prompt card and its declared dependencies.

## Requirement TB-003: Evidence Gate

WHEN Track B emits a finding  
THE SYSTEM SHALL include concrete evidence, affected location, confidence rationale, remediation, and supporting file paths.

## Requirement TB-004: High Confidence Gate

WHEN Track B assigns confidence above `0.80`  
THE SYSTEM SHALL have concrete source-to-sink, control-flow, version-range, or equivalent strong evidence.

## Requirement TB-005: Signal Rejection

WHEN evidence is only an imported symbol, YARA hit, or string match  
THE SYSTEM SHALL treat it as a signal and SHALL NOT emit a high-confidence finding.

## Requirement TB-006: Token Ledger

WHEN Track B calls an LLM  
THE SYSTEM SHALL record estimated prompt tokens, actual tokens when available, cached tokens when available, dimension, target, function, and context profile.
