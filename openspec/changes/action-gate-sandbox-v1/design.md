# Design: Action Gate and Sandbox Result Interpreter v1

## Overview

This change adds two deterministic runtime components:

```text
tools/context/action_gate.py
sandbox/result_interpreter.py
```

The action gate runs before an operation. The result interpreter runs after sandbox execution.

## Action Gate

The action gate evaluates an `ActionRequest` and emits a `GateDecision`. It is deterministic and does not execute commands.

Blocked conditions include:

- target code outside sandbox
- PoC network access
- privileged execution
- writes outside results directory
- high/critical PoC without user approval
- package-manager installs or image pulls without user approval

## Result Interpreter

The result interpreter receives an expected verification signal and raw runner result. It emits:

- `verification.poc_status`
- finding lifecycle status
- reason
- evidence paths

The interpreter makes these distinctions:

- `completed` is not automatically `verified`.
- `crash` is verified only when the expected signal matches.
- unexpected timeout is `inconclusive`.
- `poc_error` is not a false positive.
- `sandbox_error` is not a false positive.

## Schemas

- `templates/action_gate.json`
- `templates/poc_result.json`

## Validation

Unit tests cover allowed and blocked actions, expected signal matching, mismatch cases, timeout mapping, PoC artifact errors, sandbox errors, and fixture-based matrix evaluation.
