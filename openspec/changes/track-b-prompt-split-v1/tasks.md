# Tasks: Track B Prompt Split v1

## T1: Reduce Phase 1b to Orchestration

- [x] Replace inline dimension prompt templates with a prompt loading contract.
- [x] Keep engine selection, architecture branch, scoring, mode limits, output contract, budget handling, and degradation rules.

## T2: Add Prompt Components

- [x] Add `prompts/track_b/base_contract.md`.
- [x] Add `prompts/track_b/evidence_wrapper.md`.
- [x] Add `prompts/track_b/output_contract.md`.

## T3: Add Dimension Cards

- [x] Add core dimension cards.
- [x] Add extended dimension cards for crypto/TLS/auth, filesystem/path handling, and IPC/local service boundaries.

## T4: Add Manifest and Schema

- [x] Add `prompts/track_b/manifest.json`.
- [x] Add `templates/prompt_manifest.json`.

## T5: Add Validation

- [x] Add `tests/context/test_prompt_manifest.py`.
- [x] Add `tests/validate_prompt_manifest.sh`.

## Deferred Tasks

- [ ] Implement `tools/context/prompt_builder.py`.
- [ ] Implement `tools/context/evidence_trimmer.py`.
- [ ] Implement token usage ledger and context manifest writer.
- [ ] Implement prompt injection filtering.
