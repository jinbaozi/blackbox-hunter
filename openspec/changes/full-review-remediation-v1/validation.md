# Validation: full-review-remediation-v1

## Automated

- `bash tests/run_all_tests.sh`
- `bash tests/validate_python.sh`
- `bash tests/validate_preflight.sh`
- `bash tests/validate_preflight_contracts.sh`
- `bash tests/validate_full_workflow.sh`
- `bash tests/validate_security_regression.sh`
- `bash tests/validate_action_gate_sandbox.sh`

## Expected outcomes

- Preflight fails closed on failed detection commands.
- RPM package paths infer RPM package type without explicit `--package-type`.
- RPM install hints prefer RPM-native package-manager policy.
- Complete quick workflow writes every required phase artifact and ends with `scan_state.current_phase=completed`.
- Schema validation accepts generated workflow artifacts and fixtures.
- Sandbox result interpretation reads output with bounded truncation.
