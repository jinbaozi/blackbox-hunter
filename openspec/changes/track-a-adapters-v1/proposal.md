# Proposal: Track A Adapter Framework v1

## Problem

Track A currently lists deterministic tools, but raw tool output is not normalized before downstream use. This can cause weak signals such as YARA hits, dangerous imports, strings matches, hardening gaps, and CVE version matches to be treated as findings too early.

## Goals

- Add a minimal Track A adapter framework.
- Normalize tool output into `finding_signal` records.
- Add schemas for `finding_signal` and `tool_result`.
- Add adapters for YARA, checksec, cve-bin-tool, cwe_checker, lintian, rpmlint, and dependency/import metadata.
- Add fixtures and tests proving weak signals are not promoted directly to findings.
- Update Phase 1a documentation with adapter normalization rules.

## Non-Goals

- This change does not implement a full Track A executor.
- This change does not run external tools in tests.
- This change does not implement CVE backport analysis.
- This change does not promote signals into final findings.

## User Impact

Future Track A output becomes more reliable and auditable. Weak tool hits become structured signals that can guide prioritization or Track B analysis without inflating finding counts.
