# Change: full-review-remediation-v1

## Summary

Repair the repository-level review findings after the RPM-first merge. The change closes contract gaps between documentation, schemas, preflight behavior, sandbox controls, and executable workflow coverage.

## Motivation

The project had strong phase contracts but several implementation gaps: `env_check.package_manager` was not schema-backed, detection failures could be reported as available, package-manager policy was duplicated, schema wrappers were loose, and no top-level workflow runner existed.

## Scope

- Make preflight package-manager policy registry-driven and package-path aware.
- Treat failed detection commands as unavailable unless explicitly allowed.
- Add structured package install metadata for install hints and approved actions.
- Tighten schemas and support file-only findings.
- Add stable scoped Track A signal IDs.
- Add an executable schema-valid workflow runner.
- Harden sandbox defaults and bounded PoC output interpretation.
- Add full workflow, preflight contract, and Python compile validations.
