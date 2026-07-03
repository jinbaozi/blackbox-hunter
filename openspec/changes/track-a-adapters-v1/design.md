# Design: Track A Adapter Framework v1

## Overview

Track A adapters convert deterministic tool output into normalized `finding_signal` records. A signal is an intermediate detection, not necessarily a vulnerability.

## Components

```text
tools/adapters/base.py
tools/adapters/yara_scan.py
tools/adapters/checksec.py
tools/adapters/cve_bin_tool.py
tools/adapters/cwe_checker.py
tools/adapters/lintian.py
tools/adapters/rpmlint.py
tools/adapters/dependency_parser.py
```

## Data Contracts

- `templates/finding_signal.json`: weak or intermediate detection signal.
- `templates/tool_result.json`: normalized output wrapper for one tool.

## Signal Rules

- YARA and strings hits are signals by default.
- Imported symbols are signals by default.
- CVE version matches are signals until vulnerable range and vendor backport state are confirmed.
- Hardening gaps are signals unless a policy explicitly promotes them.
- Static CWE patterns are signals until reachability and context are confirmed.

## Promotion

Each signal carries a `promotion` object:

```json
{
  "promote_to_finding": false,
  "requires_track_b": true,
  "reason": "requires contextual confirmation before promotion"
}
```

Downstream phases may promote signals only after evidence gates are satisfied.

## Validation

Tests use fixture outputs and do not require external tools. They verify that adapters return valid signal shapes and do not directly promote weak signals into findings.
