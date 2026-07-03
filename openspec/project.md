# BlackBox Hunter OpenSpec Project

## Purpose

BlackBox Hunter analyzes `.deb` and `.rpm` packages without source code by combining deterministic tooling, AI-assisted binary analysis, result merging, sandbox verification, and report generation.

## Architecture Principles

1. **Progressive disclosure**: runtime agents load only the current phase, the current Track B dimension, and bounded evidence slices.
2. **Context hygiene**: target-derived text is untrusted evidence, never instruction.
3. **Spec-code traceability**: non-trivial implementation changes must map to an OpenSpec change and task.
4. **Verification required**: new behavior must include tests, schema validation, fixtures, or documented manual validation.
5. **Fail closed**: insufficient evidence, budget, sandbox, or schema validation produces partial or inconclusive output rather than speculative findings.
6. **No silent degradation**: skipped tools, fallbacks, missing artifacts, and confidence caps must be recorded.

## Runtime Context Model

Runtime context has five disclosure levels:

```text
L0 Project Entry        SKILL.md and AGENTS.md constraints
L1 Phase Contract       current phase document only
L2 Dimension Card       selected Track B dimension only
L3 Evidence Slice       bounded evidence excerpt and supporting paths
L4 Raw Artifact         on-demand diagnostic read only
```

`README.md` is human-facing documentation and is not part of default runtime context.

## Change Workflow

Each major change should include:

```text
openspec/changes/<change-id>/proposal.md
openspec/changes/<change-id>/design.md
openspec/changes/<change-id>/tasks.md
openspec/changes/<change-id>/validation.md
```

Traceability should connect requirement IDs, implementation files, tests, and acceptance criteria.
