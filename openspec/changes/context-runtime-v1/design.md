# Design: Context Runtime v1

## Overview

This change implements runtime helpers that make Track B prompt construction progressive and auditable. It connects the context policy from `tools/context/context_policy.json` with the prompt manifest from `prompts/track_b/manifest.json`.

## Components

```text
tools/context/evidence_trimmer.py
tools/context/prompt_builder.py
tools/context/token_budget.py
tools/context/context_manifest.py
```

## Evidence Trimming

`evidence_trimmer.py` reads raw artifact paths and produces a bounded evidence slice. Full raw artifacts remain on disk and are referenced through `supporting_files` or `omitted` metadata.

## Prompt Building

`prompt_builder.py` loads:

1. `base_contract.md`
2. `evidence_wrapper.md`
3. `output_contract.md`
4. exactly one selected dimension card
5. one bounded evidence slice wrapped as `UNTRUSTED_EVIDENCE`

It rejects dimensions not enabled for the selected scan mode and fails closed when a prompt exceeds the configured budget.

## Token Budget

`token_budget.py` provides a conservative tokenizer-free token estimate and JSONL ledger helpers. The estimator is intentionally conservative until a model-specific tokenizer is introduced.

## Context Manifest

`context_manifest.py` writes a runtime manifest with:

- loaded files
- excluded files
- untrusted evidence sources
- token budget
- context profile
- target/function metadata

## Validation

Tests verify that prompts include only the selected dimension, exclude README/raw defaults, wrap evidence as untrusted data, write context manifests, and stay within quick-mode budgets.
