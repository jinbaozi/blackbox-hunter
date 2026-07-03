# Trace: full-review-remediation-v1

| Review finding | Remediation | Validation |
|---|---|---|
| `env_check.package_manager` not schema-backed | `templates/env_check.json` updated | `validate_schemas.sh`, workflow smoke |
| detection failure marked available | `tools/preflight.py` fail-closed detection | `validate_preflight_contracts.sh` |
| duplicated package-manager policy | registry-driven priority loading | `validate_preflight.sh` |
| missing executable workflow | `tools/bbh_scan.py` | `validate_full_workflow.sh` |
| weak signal IDs | scoped signal IDs in adapter base | adapter tests and schema validation |
| binary-only finding location | file-or-binary location schema | schema fixture validation |
| loose wrappers | strict track and verified wrappers | schema validation |
| unsafe output reading | bounded PoC output interpreter | sandbox tests |
| sandbox naming/syscall risk | scan-derived container name and ptrace-class deny | script validation |
| evidence kind mismatch | dimension-to-evidence-kind mapping | security and e2e prompt tests |
