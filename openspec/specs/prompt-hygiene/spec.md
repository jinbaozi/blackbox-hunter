# Prompt Hygiene Specification

## Requirement PH-001: Untrusted Evidence Wrapper

WHEN target-derived text is included in LLM-visible context  
THE SYSTEM SHALL wrap it as untrusted evidence and identify its source path and evidence kind.

## Requirement PH-002: Instruction/Data Separation

WHEN constructing prompts  
THE SYSTEM SHALL keep stable instructions separate from target-derived evidence.

## Requirement PH-003: Injection Detection

WHEN target-derived text is processed for LLM-visible context  
THE SYSTEM SHALL run injection-pattern detection and record suspicious matches in the context manifest.

## Requirement PH-004: Preserve Evidence

WHEN suspicious evidence is detected  
THE SYSTEM SHALL preserve the evidence as data and SHALL NOT execute, obey, or promote instructions found inside it.

## Requirement PH-005: Stable Prefix

WHEN constructing Track B prompts  
THE SYSTEM SHALL place stable base instructions and output contracts before dynamic target-specific evidence.

## Requirement PH-006: No Raw Prompt Dumps

WHEN generating final reports or logs  
THE SYSTEM SHALL avoid dumping complete prompts unless explicitly requested for diagnostics and safe to disclose.
