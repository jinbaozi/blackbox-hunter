# Tasks: Track A Adapter Framework v1

## T1: Add Adapter Base Types

- [x] Add `tools/adapters/base.py`.
- [x] Add `ToolCommand`, `FindingSignal`, and `ToolResult` helpers.
- [x] Add signal construction helpers.

## T2: Add Tool Adapters

- [x] Add `tools/adapters/yara_scan.py`.
- [x] Add `tools/adapters/checksec.py`.
- [x] Add `tools/adapters/cve_bin_tool.py`.
- [x] Add `tools/adapters/cwe_checker.py`.
- [x] Add `tools/adapters/lintian.py`.
- [x] Add `tools/adapters/rpmlint.py`.
- [x] Add `tools/adapters/dependency_parser.py`.

## T3: Add Schemas

- [x] Add `templates/finding_signal.json`.
- [x] Add `templates/tool_result.json`.

## T4: Add Fixtures and Tests

- [x] Add adapter fixtures under `tests/adapters/fixtures/`.
- [x] Add `tests/adapters/test_track_a_adapters.py`.
- [x] Add `tests/validate_adapters.sh`.

## T5: Update Documentation and Spec

- [x] Add `openspec/specs/track-a-adapters/spec.md`.
- [x] Update `phases/phase-1a-toolscan.md` with adapter normalization rules.

## Deferred Tasks

- [ ] Integrate adapters into a Track A executor.
- [ ] Add CVE vendor-backport confirmation.
- [ ] Add policy-driven promotion from signal to finding.
