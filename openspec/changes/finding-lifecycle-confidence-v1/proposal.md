# Proposal: Finding Lifecycle and Confidence Breakdown

## Summary

Introduce an explicit finding lifecycle and structured confidence breakdown for merged findings.

## Motivation

Before this change, findings used a single scalar confidence and PoC status carried too much semantic weight. That made weak Track A signals, static findings, infrastructure verification errors, and verified vulnerabilities difficult to distinguish.

## Change

- Add `finding_status` to `templates/finding.json`.
- Add `confidence_breakdown` with evidence, reachability, tool reliability, verification, and final components.
- Add `tools/merge/confidence_scoring.py` as the Phase 2 reference implementation.
- Update Phase 2 and Phase 4 documentation to report lifecycle and confidence components.
- Update sample fixtures and tests.

## Non-goals

- This change does not implement full result deduplication.
- This change does not change Phase 3 sandbox execution behavior.
- This change does not promote Track A signals automatically.
