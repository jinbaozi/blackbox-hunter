# Validation: Context Runtime v1

## Required Commands

```bash
python3 tests/context/test_evidence_trimmer.py
python3 tests/context/test_context_manifest.py
python3 tests/context/test_prompt_builder.py
python3 tests/prompt_budget/test_track_b_budget.py
bash tests/validate_context_runtime.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- Evidence trimmer emits bounded excerpts and preserves full artifact paths.
- Evidence wrapper uses `UNTRUSTED_EVIDENCE`.
- Prompt builder loads base contract, evidence wrapper, output contract, and exactly one dimension card.
- Prompt builder excludes README, raw artifacts, logs, and unrelated dimension cards from loaded context.
- Prompt builder rejects dimensions not enabled for the selected mode.
- Prompt builder writes context manifest when requested.
- Quick-mode prompts for quick-mode dimensions stay within configured budget.
- Token ledger records estimated and cached token fields.

## Manual Review Checklist

- This change does not call an LLM.
- This change does not alter scan orchestration.
- This change creates runtime helpers for the future Track B executor.
