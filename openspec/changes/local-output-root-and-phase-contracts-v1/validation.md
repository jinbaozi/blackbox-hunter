# Validation

Run:

```bash
python3 tests/test_output_contracts.py
bash tests/validate_preflight.sh
bash tests/validate_preflight_contracts.sh
bash tests/validate_schemas.sh
bash tests/validate_sandbox.sh
python3 -m py_compile tools/output_paths.py tools/output_contracts.py tools/preflight.py tools/bbh_scan.py
bash tests/e2e/full_workflow_quick.sh
bash tests/e2e/full_workflow_track_a_fixture.sh
bash tests/e2e/full_workflow_track_b_fixture.sh
```

Expected results:

- Standalone preflight defaults to `$PWD/black-audit-output/env_check.json`.
- Scans without `--workspace` write under `$PWD/black-audit-output/<scan_id>/`.
- Phase contract validation reports missing files, missing directories, and schema errors.
- Phase 3 creates `poc_results/` and `verified_findings.json` for skipped/unverified verification.
- `report/findings.json` validates against `templates/report_findings.json`.
