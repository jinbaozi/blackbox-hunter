# Validation: Prompt Injection Defense v1

## Required Commands

```bash
python3 tests/prompt_injection/test_injection_filter.py
python3 tests/prompt_injection/test_context_integration.py
bash tests/validate_prompt_injection.sh
bash tests/validate_context_runtime.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- Direct instruction override attempts are detected.
- Indirect prompt injection in code comments is detected.
- Base64 and hex encoded instruction payloads are detected.
- Hidden Markdown/HTML instruction payloads are detected.
- Invisible Unicode/control-character normalization changes are recorded.
- Simple typoglycemia variants are detected.
- Benign tool output does not produce suspicious matches.
- Suspicious evidence is preserved and marked with `policy: wrapped_not_removed`.
- Evidence slices include `suspicious` and `injection_findings` when matches are found.
- Prompt builder propagates `injection_findings` into context manifests.

## Manual Review Checklist

- The detector does not delete or rewrite suspicious evidence.
- The detector does not execute decoded payloads.
- Runtime prompt construction still wraps evidence as `UNTRUSTED_EVIDENCE`.
- This change does not call an LLM and does not alter scan orchestration.
