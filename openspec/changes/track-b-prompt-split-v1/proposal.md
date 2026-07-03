# Proposal: Track B Prompt Split v1

## Problem

`phases/phase-1b-ai-analysis.md` previously embedded prompt text and analysis guidance for every Track B dimension in one large phase document. That design violates runtime context minimality because an agent analyzing one dimension can accidentally load unrelated dimension prompts, repeated boilerplate, and placeholder checklist text.

## Goals

- Move Track B prompt text out of the phase document.
- Add a manifest-driven prompt structure.
- Add single-purpose dimension cards.
- Keep `phase-1b-ai-analysis.md` as an orchestration contract only.
- Add tests that prevent inline prompt templates from returning to Phase 1b.

## Non-Goals

- This change does not implement a prompt builder.
- This change does not implement evidence trimming.
- This change does not implement injection filtering.
- This change does not alter scanner execution behavior.

## User Impact

No scan-output behavior changes are expected. The change reduces future runtime context size and makes Track B prompt loading auditable.

## Follow-Up Changes

1. Implement prompt builder.
2. Implement evidence trimmer.
3. Implement token ledger and context manifest.
4. Implement prompt-injection filter.
