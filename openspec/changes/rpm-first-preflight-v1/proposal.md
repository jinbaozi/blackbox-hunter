# Change: rpm-first-preflight-v1

## Summary

Prefer RPM-native package-management and extraction tooling when scanning `.rpm` packages, while preserving Debian behavior for `.deb` packages.

## Motivation

BlackBox Hunter already accepts both `.deb` and `.rpm` inputs, but preflight installation priority and regression coverage were biased toward Debian/apt paths. RPM scans need deterministic package-manager selection, native RPM install hints, and explicit validation of standard and degraded paths.

## Scope

- Make `tools/install.sh` choose RPM-native managers first for `--package-type rpm`.
- Record the selected `package_manager` in `env_check.json`.
- Expand `tools/tool_registry.json` with RPM extraction and package-audit tools.
- Add tests for RPM fallback activation, hard-block behavior, and install-hint ordering.
- Add a minimal RPM e2e prompt-build regression fixture.

## Non-Goals

- Running package-manager installs automatically without user approval.
- Replacing Track B analysis or sandbox policies.
- Requiring `rpmbuild` or host RPM tooling in CI for synthetic e2e coverage.
