# Tasks: Prompt Injection Defense v1

## T1: Add Injection Filter

- [x] Add `tools/context/injection_filter.py`.
- [x] Detect direct instruction override patterns.
- [x] Detect report suppression, prompt disclosure, tool-call, shell, and exfiltration instructions.
- [x] Detect base64 and hex encoded candidates.
- [x] Detect invisible Unicode/control-character normalization changes.
- [x] Detect simple typoglycemia variants.

## T2: Integrate With Evidence Trimmer

- [x] Run injection detection for each raw artifact.
- [x] Preserve suspicious evidence as data.
- [x] Record `suspicious` and `injection_findings` in evidence slices.

## T3: Integrate With Prompt Builder

- [x] Propagate `injection_findings` into context manifests.
- [x] Add `suspicious_evidence` runtime flag to prompt construction.
- [x] Continue wrapping evidence as `UNTRUSTED_EVIDENCE`.

## T4: Add Schema

- [x] Add `templates/injection_filter_result.json`.

## T5: Add Regression Fixtures and Tests

- [x] Add prompt-injection fixtures.
- [x] Add benign fixture.
- [x] Add `tests/prompt_injection/test_injection_filter.py`.
- [x] Add `tests/prompt_injection/test_context_integration.py`.
- [x] Add `tests/validate_prompt_injection.sh`.

## Deferred Tasks

- [ ] Add action gate for tool/PoC execution.
- [ ] Add richer document parsers for HTML/PDF/Markdown if required.
- [ ] Integrate detector output into final report summaries.
