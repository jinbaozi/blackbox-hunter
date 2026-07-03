# Proposal: Context Runtime v1

## Problem

BlackBox Hunter now has a context policy and manifest-driven Track B prompt cards, but runtime prompt construction is not yet implemented. Without a prompt builder and evidence trimmer, agents can still accidentally include raw artifacts, unrelated dimension cards, or over-budget context.

## Goals

- Implement manifest-driven Track B prompt construction.
- Build bounded evidence slices from raw artifacts while keeping full artifacts on disk.
- Emit context manifests describing loaded files, excluded files, untrusted sources, and token budgets.
- Provide a token ledger helper for estimated and actual usage records.
- Add tests that enforce runtime context minimality and budget fail-closed behavior.

## Non-Goals

- This change does not call an LLM.
- This change does not implement prompt-injection filtering.
- This change does not implement Track A adapters.
- This change does not alter scan orchestration.

## User Impact

No scan-output behavior changes are expected until an executor wires these utilities into Track B. This change provides the runtime library and tests required for safe prompt construction.

## Follow-Up Changes

1. Prompt injection filter and suspicious evidence recording.
2. Track B executor integration.
3. Action gate and sandbox result interpreter.
4. Track A adapter framework.
