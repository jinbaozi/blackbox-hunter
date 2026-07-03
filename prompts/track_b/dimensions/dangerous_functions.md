# Dimension: dangerous_functions

## Goal

Find unsafe libc, syscall, shell, or process-execution usage where attacker-controlled or externally influenced input reaches a dangerous sink without sufficient bounds, quoting, validation, or privilege separation.

## Sources

- network receive paths
- CLI arguments
- environment variables
- config values
- file/parser inputs
- IPC messages

## Sinks

- `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`
- `system`, `popen`, `exec*`
- `memcpy`, `memmove`, `strncpy` with attacker-controlled size or unterminated output
- `tmpnam`, `tempnam`, `mktemp`
- `rand`, `srand` when security-sensitive

## Emit Finding Gate

Emit a finding only when all are present:

1. affected binary and function or address
2. source of attacker-controlled or externally influenced input
3. dangerous sink
4. propagation path or control dependence
5. missing or insufficient guard
6. realistic preconditions
7. supporting artifact path

## Reject Conditions

- Imported symbol alone is a signal, not a finding.
- String-only evidence is a signal, not a finding.
- Do not report when bounds, quoting, or allowlist validation clearly protects the sink.
