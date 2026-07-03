# Dimension: input_validation

## Goal

Trace external input into parsers, length calculations, copies, allocations, index operations, and state transitions to find missing validation and boundary checks.

## Sources

- request fields
- file format fields
- CLI arguments
- config keys
- environment variables
- IPC payloads

## Sinks

- allocation sizes
- buffer copy lengths
- loop bounds
- array indexes
- pointer arithmetic
- parser state transitions

## Emit Finding Gate

Emit a finding only when the evidence identifies input origin, validation expectations, affected operation, missing or insufficient guard, and plausible impact.

## Reject Conditions

- Do not report merely because parsing code is complex.
- Do not report if the relevant length, range, type, or bounds check dominates the sink.
- Do not report when the input is internal and not attacker influenced.
