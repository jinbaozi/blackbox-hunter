# Proposal: Prompt Injection Defense v1

## Problem

BlackBox Hunter processes untrusted package-derived content such as ELF strings, configs, scripts, decompiler output, tool output, and PoC logs. Those artifacts can contain prompt-injection-like instructions. Without detection and explicit recording, suspicious content can silently enter LLM-visible evidence slices.

## Goals

- Detect direct and indirect prompt-injection-like content in untrusted evidence.
- Detect simple encoded payloads such as base64 and hex.
- Detect hidden Markdown/HTML and invisible Unicode control-character patterns.
- Detect simple typoglycemia variants of high-risk instruction words.
- Preserve suspicious evidence as data instead of deleting it.
- Propagate suspicious evidence findings into evidence slices and context manifests.
- Add regression fixtures and tests.

## Non-Goals

- This change does not block all possible prompt injection variants.
- This change does not remove suspicious evidence from reports.
- This change does not call an LLM.
- This change does not implement runtime tool-call action gating.

## User Impact

No scan-output behavior changes are expected until the Track B executor wires the runtime tools into live analysis. The change strengthens the evidence pipeline by marking suspicious target-derived content.

## Follow-Up Changes

1. Add action gate for PoC/tool execution.
2. Integrate injection findings into Track B executor metadata.
3. Add richer detectors for structured documents and binary encodings if needed.
