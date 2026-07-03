# Tasks: full-review-remediation-v1

- [x] Back `env_check.package_manager` with schema validation.
- [x] Make preflight package manager priority registry-driven.
- [x] Infer package type from `--package-path` when needed.
- [x] Treat failed `detect_cmd` as unavailable by default.
- [x] Re-check version after approved install actions.
- [x] Add structured `system_packages` registry metadata.
- [x] Add stable scoped Track A signal IDs.
- [x] Support file-only findings in `finding.json`.
- [x] Tighten `track_findings` and `verified_findings` schemas.
- [x] Map Track B dimensions to allowed untrusted evidence kinds.
- [x] Bound PoC stdout/stderr reads in result interpretation.
- [x] Harden sandbox defaults for container naming and ptrace-class syscalls.
- [x] Add executable workflow runner and full workflow smoke validation.
- [x] Add preflight contract and Python compile validations.
