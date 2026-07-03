# Validation: Track A Adapter Framework v1

## Required Commands

```bash
python3 tests/adapters/test_track_a_adapters.py
bash tests/validate_adapters.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- YARA output becomes `finding_signal` records and is not promoted directly to findings.
- checksec hardening output becomes hardening signals.
- cve-bin-tool output becomes CVE version-match signals and is not promoted without version/backport confirmation.
- cwe_checker output becomes CWE pattern signals requiring Track B confirmation.
- lintian and rpmlint output becomes package metadata/script signals.
- dependency/import metadata becomes prioritization signals, not findings.
- Every signal includes raw supporting file paths and promotion metadata.
- Adapter tests use static fixtures and do not require external scanning tools.

## Manual Review Checklist

- This change does not run external scanners in tests.
- This change does not implement final Track A execution orchestration.
- This change does not promote weak signals to findings.
