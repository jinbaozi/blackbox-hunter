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
