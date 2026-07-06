# Validation: rpm-first-preflight-v1

## Automated Validation

- `python3 -m py_compile tools/preflight.py`
- `bash -n tools/install.sh`
- `bash -n tests/validate_preflight.sh`
- `bash -n tests/e2e/minimal_rpm_quick.sh`
- Local preflight fixture with `--package-type rpm`, fake `dnf`, missing primary, and available fallback.
- Local hard-block fixture with `--package-type rpm`, fake `dnf`, no fallback, and first-hint order assertion.

## Expected Outcomes

- RPM scans select `dnf` when fake `dnf` is first available.
- Required primary with fallback becomes `fallback_active`.
- Required primary without fallback exits `1` and reports `blocked=true`.
- First RPM hint uses the RPM-native method instead of apt or pip.
- Debian package-type tests continue to pass and preserve apt preference when apt is available.

## 2026-07-06 Follow-up Validation

- `TMPDIR=$PWD/.tmp bash tests/validate_preflight_contracts.sh` — passed; verifies default non-zero `detect_cmd` remains missing/hard-blocking and `detect_nonzero_ok: true` reports `nonzero-ok` as available with version `2.1`.
- `TMPDIR=$PWD/.tmp bash tests/validate_preflight.sh` — passed.
- `bash tests/validate_schemas.sh` — passed.
- `git diff --check` — passed.
- `TMPDIR=$PWD/.tmp bash tests/run_all_tests.sh` — passed; 26 passed, 0 failed.
