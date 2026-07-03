# Dimension: protocol_parsing

## Goal

Analyze protocol handlers, file-format parsers, field-length handling, state machines, path construction, and parser error recovery.

## Sources

- network protocol fields
- file format headers
- archive metadata
- IPC message fields
- CLI-supplied file paths

## Review Targets

- length-field handling
- integer arithmetic for offsets and sizes
- parser loop bounds
- state transitions
- path normalization
- error recovery and cleanup

## Emit Finding Gate

Emit a finding only when a malformed or external input can reach an unsafe parser operation with missing validation, normalization, or state enforcement.

## Reject Conditions

- Do not report parser complexity alone.
- Do not report if length and state checks clearly dominate the operation.
- Do not report without an input format, field, or state precondition.
