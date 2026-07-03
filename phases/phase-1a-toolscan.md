# Phase 1a: Track A - Traditional Tool Scanning

## Objective

Run deterministic tools against the extracted package and emit `track_a_findings.json` using `templates/track_findings.json`. Track A must also normalize weak or intermediate tool output into `finding_signal` records before any promotion to a finding.

## Inputs

- `$SCAN_ROOT/env_check.json`
- `$SCAN_ROOT/target_profile.json`
- `$SCAN_ROOT/scan_strategy.json`
- `$SCAN_ROOT/coverage_plan.json`

## CVE Database Mode

Use `cve-bin-tool --update now` only when network is available and the user has approved live updates. Otherwise use the local CVE cache. If the local cache is older than 14 days, continue in offline mode but add a warning and cap CVE-derived confidence at `0.75`.

## Tool Execution

Execute only tools whose preflight status is `available` or `fallback_active`. For tools marked `missing`, `version_low`, or `install_failed`, add a warning to the Track A output and lower confidence according to the degradation rules instead of emitting empty success output.

- `cve-bin-tool`: package and binary CVE hints.
- `checksec`: hardening flags for ELF binaries.
- `cwe_checker`: binary CWE patterns where architecture is supported.
- `strings` plus YARA: dangerous functions, secrets, and config pattern scans.
- `lintian` or `rpmlint`: package metadata and maintainer script issues.
- dependency checks: parse package metadata and shared library imports.

When `env_check.json` contains `block_decision.warnings`, propagate relevant tool degradation notes into `track_a_findings.json.warnings`.

## Adapter Normalization

Track A tool output must be normalized through adapters under `tools/adapters/` before findings are emitted.

Adapters produce `templates/tool_result.json` objects containing `templates/finding_signal.json` records. A finding signal is a weak or intermediate detection that may influence prioritization or later promotion, but is not automatically a vulnerability.

Signal handling rules:

1. YARA hits, strings hits, imported dangerous symbols, dependency presence, and generic CWE pattern matches are signals by default.
2. CVE version matches are signals until package versioning, vulnerable range, and vendor backport status are confirmed.
3. Hardening gaps are signals unless project policy explicitly promotes them into findings.
4. Signals requiring contextual source-to-sink or reachability evidence must set `promotion.requires_track_b = true`.
5. Adapters must preserve the raw output path in `evidence.supporting_files`.
6. Adapters must not silently emit empty success output when parsing fails; warnings should describe unparsed lines or degraded parsing.

Initial adapters:

- `tools/adapters/yara_scan.py`
- `tools/adapters/checksec.py`
- `tools/adapters/cve_bin_tool.py`
- `tools/adapters/cwe_checker.py`
- `tools/adapters/lintian.py`
- `tools/adapters/rpmlint.py`
- `tools/adapters/dependency_parser.py`

## Sandbox Boundary

Track A executes host-side static tools only. Phase 3 is the first phase that runs PoC logic inside Docker with `network_mode: none` and the unprivileged `poctest` user.

## Output

Wrap all Track A findings with:

```json
{
  "agent_id": "track-a-toolscan",
  "agent_role": "traditional-tooling",
  "phase": "track_a",
  "status": "success",
  "findings": [],
  "findings_count": 0,
  "warnings": [],
  "execution_time_ms": 0,
  "metadata": {
    "tools_executed": [],
    "tool_results": [],
    "signals_count": 0,
    "signals_promoted": 0
  }
}
```

`metadata.tool_results[]` should point to normalized adapter outputs. Final Track A findings must still validate against `templates/finding.json` and use `TA-NNN` identifiers.

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
