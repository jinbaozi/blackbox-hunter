# Traceability

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Finding lifecycle is explicit | `templates/finding.json`, `phases/phase-2-merge.md` | `tests/fixtures/sample_finding.json`, schema validation |
| Confidence uses components | `templates/confidence_breakdown.json`, `tools/merge/confidence_scoring.py` | `tests/merge/test_confidence_scoring.py` |
| PoC errors are not false positives | `tools/merge/confidence_scoring.py` | `test_sandbox_error_is_unknown_not_false_positive` |
| Reports show lifecycle and component confidence | `phases/phase-4-report.md` | documentation review |
| Merged output carries lifecycle stats | `templates/merged_findings.json` | `tests/fixtures/sample_merged_findings.json` |
