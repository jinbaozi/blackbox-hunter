# Trace: Track B Prompt Split v1

| Requirement | Implementation | Validation |
|---|---|---|
| TB-001 Prompt Manifest | `prompts/track_b/manifest.json`, `templates/prompt_manifest.json` | `tests/context/test_prompt_manifest.py` |
| TB-002 Dimension Lazy Loading | `prompts/track_b/dimensions/*.md`, Phase 1b Prompt Loading Contract | `tests/context/test_prompt_manifest.py` |
| TB-003 Evidence Gate | Dimension cards `Emit Finding Gate` sections | `tests/context/test_prompt_manifest.py` |
| TB-004 High Confidence Gate | `prompts/track_b/base_contract.md` | manual review |
| TB-005 Signal Rejection | `prompts/track_b/base_contract.md`, dimension reject conditions | manual review |
| PH-001 Untrusted Evidence Wrapper | `prompts/track_b/evidence_wrapper.md` | `tests/context/test_prompt_manifest.py` |
| RC-004 Track B Dimension Isolation | Phase 1b Prompt Loading Contract and manifest | `tests/context/test_prompt_manifest.py` |
