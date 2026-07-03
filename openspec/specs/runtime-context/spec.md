# Runtime Context Specification

## Requirement RC-001: Minimal Phase Loading

WHEN an agent starts a phase  
THE SYSTEM SHALL load only `SKILL.md`, `AGENTS.md`, the current phase document, and schemas required by that phase.

## Requirement RC-002: README Exclusion

WHEN an agent builds runtime context  
THE SYSTEM SHALL NOT include `README.md` unless the user explicitly requests human-facing documentation analysis.

## Requirement RC-003: Raw Artifact Exclusion

WHEN raw tool output, full disassembly, full strings output, or full decompiler output is available  
THE SYSTEM SHALL include only bounded excerpts and supporting file paths in LLM-visible context.

## Requirement RC-004: Track B Dimension Isolation

WHEN Track B analyzes a selected dimension  
THE SYSTEM SHALL load exactly the selected dimension card and SHALL NOT load unrelated dimension cards.

## Requirement RC-005: Context Manifest

WHEN an LLM-visible prompt is constructed  
THE SYSTEM SHALL write a context manifest containing loaded files, excluded files, untrusted evidence sources, token estimate, and injection-filter results.

## Requirement RC-006: Budget Fail Closed

WHEN context construction exceeds the configured prompt-token budget  
THE SYSTEM SHALL fail prompt construction or request a smaller evidence slice rather than silently exceeding the budget.

## Requirement RC-007: Artifact First

WHEN evidence exceeds the excerpt budget  
THE SYSTEM SHALL keep the full evidence on disk and include only a bounded excerpt plus supporting file path in LLM-visible context.
