# Phase 1a: Track A - Traditional Tool Scanning

## Objective

Run deterministic tools against the extracted package and emit `track_a_findings.json` using `templates/track_findings.json`.

## CVE Database Mode

Use `cve-bin-tool --update now` only when network is available and the user has approved live updates. Otherwise use the local CVE cache. If the local cache is older than 14 days, continue in offline mode but add a warning and cap CVE-derived confidence at `0.75`.

## Tool Execution

- `cve-bin-tool`: package and binary CVE hints.
- `checksec`: hardening flags for ELF binaries.
- `cwe_checker`: binary CWE patterns where architecture is supported.
- `strings` plus YARA: dangerous functions, secrets, and config pattern scans.
- `lintian` or `rpmlint`: package metadata and maintainer script issues.
- dependency checks: parse package metadata and shared library imports.

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
  "metadata": { "tools_executed": [] }
}
```

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
