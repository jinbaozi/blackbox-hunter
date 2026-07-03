# Design: CI, E2E, and Regression Gate

## CI Workflow

The validation workflow runs on pull requests and pushes to `main`.

It installs only lightweight validation dependencies and then executes:

1. `bash tests/run_all_tests.sh`
2. `bash tests/validate_e2e_regression.sh`
3. `bash tests/validate_security_regression.sh`

`tests/run_all_tests.sh` already discovers `tests/validate_*.sh`, so the E2E and security wrappers also run in the unified test suite.

## E2E Scope

The E2E tests are intentionally minimal and offline:

- Build or emulate a tiny `.deb` fixture.
- Create a bounded evidence slice.
- Invoke `tools/context/prompt_builder.py`.
- Verify prompt, metadata, and context manifest outputs.
- Assert full raw artifacts are not read into the prompt.

## Security Regression Scope

The security regression test calls `build_track_b_prompt()` directly and verifies:

- README is excluded.
- Only the selected dimension card is loaded.
- Raw artifact contents are not copied into prompt text.
- `UNTRUSTED_EVIDENCE` remains present.
- disallowed dimension/mode combinations fail closed.

## Dependencies

The workflow installs `jsonschema` for schema validation. The E2E/security tests use only Python standard library and shell tools. If `dpkg-deb` is unavailable, the minimal package test emulates extraction and continues with prompt construction.
