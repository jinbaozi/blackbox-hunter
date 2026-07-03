# Trace: Context Hygiene Foundation v1

| Requirement | Implementation | Validation |
|---|---|---|
| RC-001 Minimal phase loading | `SKILL.md`, `AGENTS.md`, `tools/context/context_policy.json` | `tests/context/test_context_policy.py` |
| RC-002 README exclusion | `tools/context/context_policy.json` | `tests/context/test_context_policy.py` |
| RC-003 Raw artifact exclusion | `tools/context/context_policy.json` | `tests/context/test_context_policy.py` |
| RC-004 Track B dimension isolation | `openspec/specs/track-b-analysis/spec.md` | deferred to Track B prompt split |
| RC-005 Context manifest | `openspec/specs/runtime-context/spec.md` | deferred to prompt builder |
| PH-001 Untrusted evidence wrapper | `AGENTS.md`, `tools/context/context_policy.json` | `tests/context/test_context_policy.py` |
| PH-002 Instruction/data separation | `AGENTS.md`, `openspec/specs/prompt-hygiene/spec.md` | deferred to prompt builder |
| SV-001 Sandbox only | `AGENTS.md`, `openspec/specs/sandbox-verification/spec.md` | existing sandbox validation |
| FL-001 Signal/finding separation | `openspec/specs/finding-lifecycle/spec.md` | deferred to Track A adapters |
