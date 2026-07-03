# Validation: Action Gate and Sandbox Result Interpreter v1

## Required Commands

```bash
python3 tests/context/test_action_gate.py
python3 tests/sandbox/test_result_interpreter.py
bash tests/sandbox/run_poc_matrix.sh
bash tests/validate_action_gate_sandbox.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- Low/medium PoC execution inside sandbox without network is allowed.
- High/critical PoC execution requires user approval.
- Target code execution outside sandbox is blocked.
- Networked PoC execution is blocked.
- Package-manager installs and image pulls require user approval.
- `completed` without the expected signal maps to `failed`, not `verified`.
- Matching crash, timeout, exit-code, or output-pattern signals map to `verified`.
- Unexpected timeout maps to `inconclusive`.
- `poc_error` maps to `poc_error`, not false positive.
- `sandbox_error` maps to `sandbox_error`, not false positive.

## Manual Review Checklist

- The action gate never executes commands.
- The result interpreter never treats raw runner status as the final verdict without expected-signal comparison.
- This change does not require Docker/Podman in CI.
