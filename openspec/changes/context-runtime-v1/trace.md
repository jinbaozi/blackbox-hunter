# Trace: Context Runtime v1

| Requirement | Implementation | Validation |
|---|---|---|
| RC-003 Raw Artifact Exclusion | `tools/context/evidence_trimmer.py` | `tests/context/test_evidence_trimmer.py` |
| RC-004 Track B Dimension Isolation | `tools/context/prompt_builder.py` | `tests/context/test_prompt_builder.py` |
| RC-005 Context Manifest | `tools/context/context_manifest.py`, `templates/context_manifest.json` | `tests/context/test_context_manifest.py` |
| RC-006 Budget Fail Closed | `tools/context/prompt_builder.py`, `tools/context/token_budget.py` | `tests/prompt_budget/test_track_b_budget.py` |
| RC-007 Artifact First | `tools/context/evidence_trimmer.py` | `tests/context/test_evidence_trimmer.py` |
| PH-001 Untrusted Evidence Wrapper | `tools/context/evidence_trimmer.py`, `tools/context/prompt_builder.py` | `tests/context/test_prompt_builder.py` |
| PH-005 Stable Prefix | `tools/context/prompt_builder.py` | `tests/context/test_prompt_builder.py` |
| TB-001 Prompt Manifest | `tools/context/prompt_builder.py` | `tests/context/test_prompt_builder.py` |
| TB-002 Dimension Lazy Loading | `tools/context/prompt_builder.py` | `tests/context/test_prompt_builder.py` |
| TB-006 Token Ledger | `tools/context/token_budget.py`, `templates/token_ledger.json` | `tests/prompt_budget/test_track_b_budget.py` |
