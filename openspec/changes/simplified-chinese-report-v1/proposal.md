# Proposal: Simplified Chinese Final Report

## Summary

Require the final human-readable Markdown report to present all display text in Simplified Chinese.

## Motivation

`blackbox-security-report.md` is the final analyst-facing artifact. Mixed English headings, labels, and status descriptions make the report harder to consume for Chinese-language review workflows and weaken the report contract.

## Change

- Update Phase 4 documentation to require Simplified Chinese display text in the final Markdown report.
- Update the report summary template with Chinese headings and guidance.
- Localize the report generator headings, labels, lifecycle status display values, and common missing or unknown values.
- Keep machine-readable JSON schemas, JSON keys, artifact names, paths, package names, CVE/CWE IDs, commands, function names, enum raw values, and raw evidence excerpts unchanged.
- Add tests that reject the old English section headings and require Chinese report sections.

## Non-goals

- This change does not translate machine-readable JSON artifacts.
- This change does not translate target-derived raw evidence.
- This change does not alter finding lifecycle semantics or verification behavior.
