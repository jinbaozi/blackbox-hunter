# Validation

Run locally:

```bash
python3 -m pip install jsonschema
bash tests/run_all_tests.sh
bash tests/validate_e2e_regression.sh
bash tests/validate_security_regression.sh
```

Expected results:

- All existing `validate_*.sh` suites pass.
- Minimal deb quick E2E writes a prompt, metadata, and context manifest.
- Track B prompt-build E2E loads only the selected dimension card.
- Security regression confirms README, unrelated dimensions, and raw artifact contents are not included in runtime prompt context.
- GitHub Actions runs the same core validation on every PR and push to `main`.
