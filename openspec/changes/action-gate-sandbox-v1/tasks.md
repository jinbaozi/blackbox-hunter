# Tasks: Action Gate and Sandbox Result Interpreter v1

## T1: Add Action Gate

- [x] Add `tools/context/action_gate.py`.
- [x] Block networked PoC execution.
- [x] Block privileged execution.
- [x] Block target code outside sandbox.
- [x] Require approval for high/critical PoCs.
- [x] Require approval for install/image-pull actions.

## T2: Add Result Interpreter

- [x] Add `sandbox/result_interpreter.py`.
- [x] Map expected crash signals.
- [x] Map expected timeout signals.
- [x] Map expected exit codes.
- [x] Map expected output patterns.
- [x] Keep `poc_error` and `sandbox_error` separate from false positives.

## T3: Add Schemas

- [x] Add `templates/action_gate.json`.
- [x] Add `templates/poc_result.json`.

## T4: Add Tests and Fixtures

- [x] Add `tests/context/test_action_gate.py`.
- [x] Add `tests/sandbox/test_result_interpreter.py`.
- [x] Add `tests/sandbox/run_poc_matrix.sh`.
- [x] Add fixture PoC result cases.
- [x] Add `tests/validate_action_gate_sandbox.sh`.

## T5: Update Phase Documentation

- [x] Update `phases/phase-3-verify.md` with action-gate and result-interpreter requirements.

## Deferred Tasks

- [ ] Integrate the gate into the future Phase 3 executor.
- [ ] Add Docker/Podman live integration tests where CI supports container execution.
