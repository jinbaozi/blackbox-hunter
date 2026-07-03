# Tasks: Context Runtime v1

## T1: Add Evidence Trimmer

- [x] Add `tools/context/evidence_trimmer.py`.
- [x] Preserve full raw artifact paths in evidence metadata.
- [x] Add bounded excerpt behavior and truncation markers.
- [x] Add untrusted evidence wrapping helper.

## T2: Add Prompt Builder

- [x] Add `tools/context/prompt_builder.py`.
- [x] Load stable prompt components from manifest.
- [x] Load exactly one selected dimension card.
- [x] Reject dimensions not enabled for the selected scan mode.
- [x] Wrap bounded evidence as untrusted evidence.
- [x] Fail closed on prompt budget overflow.

## T3: Add Token Budget Helpers

- [x] Add `tools/context/token_budget.py`.
- [x] Add conservative token estimator.
- [x] Add JSONL token usage ledger helpers.

## T4: Add Context Manifest Helpers

- [x] Add `tools/context/context_manifest.py`.
- [x] Add `templates/context_manifest.json`.
- [x] Add `templates/token_ledger.json`.

## T5: Add Validation

- [x] Add `tests/context/test_evidence_trimmer.py`.
- [x] Add `tests/context/test_context_manifest.py`.
- [x] Add `tests/context/test_prompt_builder.py`.
- [x] Add `tests/prompt_budget/test_track_b_budget.py`.
- [x] Add `tests/validate_context_runtime.sh`.

## Deferred Tasks

- [ ] Integrate prompt builder into a Track B executor.
- [ ] Add prompt-injection filter.
- [ ] Record actual API usage and cached tokens when an LLM call is made.
