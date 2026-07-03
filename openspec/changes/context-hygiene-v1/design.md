# Design: Context Hygiene Foundation v1

## Overview

This change adds a spec-first foundation for progressive context disclosure. It establishes project-wide agent rules, runtime context requirements, and a machine-readable policy that future prompt builders and scanners must follow.

## Runtime Context Levels

```text
L0 Project Entry        SKILL.md + AGENTS.md constraints
L1 Phase Contract       current phase document only
L2 Dimension Card       selected Track B dimension only
L3 Evidence Slice       bounded excerpt + supporting file paths
L4 Raw Artifact         on-demand diagnostic read only
```

## Policy Files

- `AGENTS.md`: human-readable runtime rules for agents.
- `openspec/constitution.md`: project invariants.
- `openspec/specs/*/spec.md`: stable requirements.
- `tools/context/context_policy.json`: machine-readable context boundaries.
- `templates/context_policy.json`: schema for context policy validation.

## Validation Approach

The initial validator checks structural constraints that must stay true across future PRs:

- `README.md` is forbidden in default runtime context.
- raw artifacts are forbidden in default runtime context.
- untrusted evidence wrappers are required.
- Track B mode limits are present.
- allowed and forbidden context paths are disjoint.

## Future Extensions

Future changes will add:

- Prompt manifest validation.
- Prompt builder runtime context manifests.
- Evidence trimming.
- Injection filtering.
- Token usage ledger.
