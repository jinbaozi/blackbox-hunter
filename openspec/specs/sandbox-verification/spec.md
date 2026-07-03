# Sandbox Verification Specification

## Requirement SV-001: Sandbox Only

WHEN a PoC is executed  
THE SYSTEM SHALL execute it only inside the configured sandbox.

## Requirement SV-002: No Network

WHEN PoC verification runs  
THE SYSTEM SHALL disable network access.

## Requirement SV-003: Result Persistence

WHEN PoC verification runs  
THE SYSTEM SHALL persist stdout, stderr, exit code, timeout status, runner status, pre/post state, monitor telemetry, and evidence paths under `$SCAN_ROOT/poc_results/<finding_id>/`.

## Requirement SV-004: Result Interpretation

WHEN a runner result is available  
THE SYSTEM SHALL interpret it against the expected verification signal before setting `verification.poc_status`.

## Requirement SV-005: Infrastructure Errors

WHEN sandbox startup, image build, mount, seccomp, or result collection fails  
THE SYSTEM SHALL mark the result `sandbox_error` and SHALL NOT downgrade a statically supported finding to false positive.

## Requirement SV-006: PoC Artifact Errors

WHEN a PoC script is missing, malformed, unreadable, or fails before exercising the target  
THE SYSTEM SHALL mark the result `poc_error`.

## Requirement SV-007: High Impact Approval

WHEN a finding has high or critical impact  
THE SYSTEM SHALL require explicit user approval before PoC execution.
