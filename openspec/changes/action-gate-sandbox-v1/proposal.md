# Proposal: Action Gate and Sandbox Result Interpreter v1

## Problem

BlackBox Hunter records sandbox runner output, but runner status alone is not a verification decision. A clean `completed` run does not prove a vulnerability, a `poc_error` does not prove a false positive, and sandbox failures must not downgrade statically supported findings. The project also needs a deterministic gate before risky operations such as PoC execution, image pulls, and package-manager installs.

## Goals

- Add deterministic action-gate evaluation before risky operations.
- Block PoC execution outside sandbox, networked PoCs, privileged PoCs, and writes outside result paths.
- Require explicit approval for high/critical PoC execution and install/image-pull actions.
- Add a sandbox result interpreter that maps runner output plus expected signal into `verification.poc_status`.
- Add schemas, fixtures, and tests for the gate and interpreter.
- Update Phase 3 documentation to require gate evaluation and result interpretation.

## Non-Goals

- This change does not execute Docker or Podman in tests.
- This change does not implement a full Track B executor.
- This change does not alter PoC generation logic.

## User Impact

Future Phase 3 execution becomes safer and less ambiguous. Existing reports should remain compatible, while future verification output can distinguish infrastructure failure, PoC artifact failure, inconclusive results, failed reproduction, and verified signals.
