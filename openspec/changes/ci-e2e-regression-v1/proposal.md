# Proposal: CI, E2E, and Regression Gate

## Summary

Add GitHub Actions validation and minimal E2E/security regression tests so future pull requests cannot silently regress context hygiene, prompt construction, adapter tests, sandbox tests, or schema validation.

## Motivation

The project now has multiple validation domains: schemas, scripts, prompt manifests, runtime context, prompt injection defense, action gates, sandbox interpretation, Track A adapters, and confidence scoring. These must run consistently in pull requests to prevent accidental reintroduction of raw-context leakage or unvalidated schema changes.

## Change

- Add `.github/workflows/validate.yml`.
- Add minimal deb quick E2E prompt-build test.
- Add Track B prompt-build E2E test.
- Add runtime context pollution security regression test.
- Add validation wrappers so existing `tests/run_all_tests.sh` discovers the new suites.

## Non-goals

- This change does not run a full real-world package scan.
- This change does not require Docker/Podman in CI.
- This change does not invoke external CVE databases or LLM APIs.
