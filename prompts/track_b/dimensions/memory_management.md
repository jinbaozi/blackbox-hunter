# Dimension: memory_management

## Goal

Review allocation, lifetime, ownership, bounds, and cleanup behavior for reliability and security-relevant resource handling risks.

## Sources

- length fields
- parser-controlled sizes
- object ownership transfers
- error paths
- cleanup handlers

## Review Targets

- allocation and reallocation sites
- buffer access sites
- cleanup calls
- pointer reuse
- reference count changes
- integer arithmetic used for sizes or offsets

## Emit Finding Gate

Emit a finding only when evidence shows a concrete lifetime, bounds, allocation-size, or cleanup issue with an affected operation and realistic preconditions.

## Reject Conditions

- Do not report generic resource allocation or cleanup alone.
- Do not report a theoretical issue without a reachable input path.
- Do not report when ownership and bounds are clearly enforced.
