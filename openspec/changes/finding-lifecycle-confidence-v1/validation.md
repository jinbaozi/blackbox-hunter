# Validation

Run:

```bash
python3 tests/merge/test_confidence_scoring.py
bash tests/validate_confidence_scoring.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

Expected results:

- Confidence scoring tests pass.
- `confidence_breakdown.json` schema is well formed.
- `sample_finding.json`, `sample_merged_findings.json`, and `sample_verified_findings.json` validate against updated schemas.
- Phase 2 and Phase 4 documents reference lifecycle and component confidence.
