# Design: Track B Prompt Split v1

## Overview

Track B prompt material is split into stable prompt components and single-purpose dimension cards. The phase document remains the orchestration contract, while runtime prompt construction will later load components through `prompts/track_b/manifest.json`.

## Prompt Components

```text
prompts/track_b/base_contract.md
prompts/track_b/evidence_wrapper.md
prompts/track_b/output_contract.md
prompts/track_b/dimensions/*.md
```

## Stable Prefix Design

Future prompt builders should place stable prompt components before dynamic target evidence:

```text
base_contract.md
evidence_wrapper.md
output_contract.md
selected dimension card
bounded evidence slice
```

This structure supports cache-friendly prompt construction and prevents unrelated dimension text from entering context.

## Dimension Cards

Each dimension card must be single-purpose and include:

- `Goal`
- source or review target guidance
- `Emit Finding Gate`
- `Reject Conditions`

Cards must not include unrelated dimensions or raw output examples.

## Manifest

`prompts/track_b/manifest.json` declares:

- prompt component paths
- core dimensions
- extended dimensions
- mode defaults
- per-dimension required evidence fields
- per-dimension maximum context tokens

## Validation

`tests/context/test_prompt_manifest.py` validates paths, dimension declarations, mode defaults, and removal of inline prompt templates from Phase 1b.
