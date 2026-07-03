# Dimension: control_flow

## Goal

Inspect indirect calls, computed jumps, callback tables, error unwinding, and state-machine transitions for unsafe or externally influenced dispatch behavior.

## Sources

- parsed opcodes or message types
- config-driven callbacks
- plugin or handler names
- function pointer tables
- IPC command IDs

## Sinks

- indirect calls
- computed jumps
- virtual dispatch or callback invocation
- error cleanup paths
- state transitions that skip validation or authorization

## Emit Finding Gate

Emit a finding only when a control-flow target or transition is plausibly influenced by external input and missing validation, authorization, or bounds enforcement is shown.

## Reject Conditions

- Do not report indirect calls that are fully table-bounded or enum-validated.
- Do not report compiler-generated dispatch without external influence.
- Do not infer impact without concrete evidence and supporting artifact paths.
