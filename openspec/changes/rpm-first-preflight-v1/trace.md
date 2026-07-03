# Trace: rpm-first-preflight-v1

| Requirement | Implementation | Validation |
|---|---|---|
| Prefer RPM package managers | `tools/preflight.py` package-manager selection and method ordering | `tests/validate_preflight.sh` RPM fake-dnf case |
| Preserve standard/degraded behavior | existing status matrix plus package-type-aware hints | fallback and hard-block fixture assertions |
| Support RPM extraction path | `tools/tool_registry.json` entries for `rpm2cpio`, `7z`, `bsdtar` | registry JSON and preflight docs |
| Keep CI deterministic | synthetic RPM e2e fixture without host RPM build dependency | `tests/e2e/minimal_rpm_quick.sh` |
| Audit selected manager | `env_check.json.package_manager` | preflight fixture assertions |
