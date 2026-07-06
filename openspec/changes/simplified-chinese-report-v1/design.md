# Design: Simplified Chinese Final Report

## Language Contract

The final Markdown report `blackbox-security-report.md` uses Simplified Chinese for human-readable display text:

- report title and section headings
- explanatory prose
- field labels
- status and limitation descriptions
- remediation and recommendation text

Technical identifiers remain unchanged when translation would break traceability or machine compatibility.

## Generator Behavior

`tools/report/report_generator.py` reads the same JSON artifacts as before. It localizes only presentation strings and maps common lifecycle/status display values, including:

- `verified` -> `已验证`
- `confirmed_static` -> `静态确认`
- `candidate` -> `候选`
- `inconclusive` -> `结论不足`
- `false_positive` -> `误报`
- `unknown` -> `未知`
- `none` -> `无`

Structured technical summaries may continue to include original JSON keys inside serialized JSON snippets.

## Compatibility

`$SCAN_ROOT/report/findings.json` and all upstream phase artifacts keep their existing structure. Artifact filenames and paths in the appendix remain literal paths.
