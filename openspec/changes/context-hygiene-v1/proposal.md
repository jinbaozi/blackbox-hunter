# Proposal: Context Hygiene Foundation v1

## Problem

BlackBox Hunter already has phase-level orchestration, but runtime agents can still over-load context by reading human-facing documentation, unrelated phase documents, all Track B dimensions, or full raw tool output. This increases token cost and risks prompt contamination from target-derived content.

## Goals

- Establish project-level agent operating rules.
- Add OpenSpec-style requirements for runtime context and prompt hygiene.
- Add a machine-readable context policy.
- Add validation tests that prevent silent expansion of default runtime context.

## Non-Goals

- This change does not split Track B prompt cards yet.
- This change does not implement prompt construction yet.
- This change does not implement injection filtering yet.
- This change does not change scanner behavior.

## User Impact

Users should see no scan-output behavior change. Maintainers and agents gain explicit rules for future implementation PRs.

## Follow-up Changes

1. Track B prompt split.
2. Prompt builder and evidence trimmer.
3. Prompt injection filter.
4. Sandbox result interpreter.
5. Track A adapter framework.
