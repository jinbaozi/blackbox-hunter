# Design: Prompt Injection Defense v1

## Overview

This change adds a conservative prompt-injection detection layer for target-derived evidence. It is designed to mark suspicious evidence, not remove it. The evidence remains available for vulnerability analysis but is explicitly treated as untrusted data.

## Detection Layer

`tools/context/injection_filter.py` scans normalized text and decoded candidates for prompt-injection-like patterns.

Detection categories:

- direct instruction override attempts
- report suppression attempts
- prompt disclosure attempts
- tool-call or shell-execution instructions
- exfiltration instructions
- hidden Markdown/HTML instruction content
- base64 and hex encoded variants
- invisible Unicode/control-character normalization changes
- simple typoglycemia variants of high-risk keywords

## Evidence Integration

`tools/context/evidence_trimmer.py` now runs the injection filter on each raw artifact before trimming. If suspicious content is found, the evidence slice records:

- `suspicious: true`
- `injection_findings[]`
- source path
- matched patterns
- excerpts
- detection source such as normalized, base64, hex, or normalizer

## Prompt Builder Integration

`tools/context/prompt_builder.py` propagates evidence `injection_findings` into the context manifest and adds a `suspicious_evidence` runtime flag to the prompt. Evidence is still wrapped as `UNTRUSTED_EVIDENCE`.

## Preservation Policy

Suspicious evidence is not deleted, rewritten, or hidden. The filter policy is `wrapped_not_removed` because malicious strings may themselves be relevant evidence.

## Validation

Regression tests cover direct injection, indirect code comments, base64, hex, hidden Markdown, typoglycemia, invisible Unicode, benign output, and end-to-end propagation into context manifests.
