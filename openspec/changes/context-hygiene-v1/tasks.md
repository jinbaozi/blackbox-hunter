# Tasks: Context Hygiene Foundation v1

## T1: Add Agent Runtime Rules

- [x] Add `AGENTS.md`.
- [x] Define context, tool, evidence, recovery, and review boundaries.

## T2: Add OpenSpec Project Foundation

- [x] Add `openspec/project.md`.
- [x] Add `openspec/constitution.md`.
- [x] Add stable specs for runtime context and prompt hygiene.
- [x] Add stable specs for Track B, sandbox verification, and finding lifecycle.

## T3: Add Runtime Context Policy

- [x] Add `tools/context/context_policy.json`.
- [x] Add `templates/context_policy.json`.
- [x] Add `tools/context/validate_context_policy.py`.

## T4: Add Validation Tests

- [x] Add `tests/context/test_context_policy.py`.
- [x] Add `tests/validate_context_policy.sh` so `tests/run_all_tests.sh` picks up the validation.

## T5: Wire Policy Into Skill Entry

- [x] Add Runtime Context Loading Policy to `SKILL.md`.

## Deferred Tasks

- [ ] Split Track B prompt cards.
- [ ] Implement prompt builder.
- [ ] Implement evidence trimmer.
- [ ] Implement injection filter.
- [ ] Implement token ledger.
- [ ] Implement action gate.
