# Traceability

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Pull requests run automated validation | `.github/workflows/validate.yml` | GitHub Actions `validate` job |
| E2E prompt construction stays offline and minimal | `tests/e2e/minimal_deb_quick.sh`, `tests/e2e/track_b_prompt_build.sh` | `tests/validate_e2e_regression.sh` |
| Raw artifacts are not loaded into prompts | E2E sentinel checks, security regression test | `test_no_runtime_context_pollution.py` |
| Unrelated dimensions are not loaded | Prompt metadata checks | E2E and security regression tests |
| Runtime context fail-closed behavior remains enforced | quick-mode forbidden dimension check | `test_dimension_not_enabled_for_mode_fails_closed` |
