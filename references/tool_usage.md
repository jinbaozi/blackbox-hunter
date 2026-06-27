# Tool Usage Reference

## Required Baseline

Python 3 and POSIX shell are required for validation scripts. Docker, YARA, radare2, Ghidra, cve-bin-tool, checksec, cwe_checker, lintian, and rpmlint are optional scan accelerators.

## Preflight Phase

All tool detection, PATH management, installation prompts, and structured environment reporting are handled by the preflight phase (`phases/phase-preflight.md`) **before any scanning begins**. The preflight phase runs before Phase 0 and ensures the runtime environment is ready. It produces `env_check.json`, which records the status of every tool in the registry and any fallback decisions made.

Default preflight is accuracy-first: missing tools produce install hints and may be installed only after explicit user confirmation. `--offline` is an explicit controlled-environment mode for air-gapped hosts, CI, or historical reproduction; it detects existing tools only, skips installation/network actions, and records the resulting coverage and confidence degradation in `env_check.json`.

## 5-Tier Priority System and Degradation

Each tool in `tools/tool_registry.json` declares a `priority` field that determines how the system reacts when the tool is missing:

| Priority | Fallback | Behavior |
|---|---|---|
| `required` | none | **hard-block** — scan is aborted; user receives install hints with the recommended install method |
| `required` | fallback tool(s) | **soft-warn** — use fallback tool, record substitution in `env_check.json` |
| `required_verify` | none | **phase-block** — only Phase 3 (PoC verification) is blocked; other phases continue |
| `high` or `medium` | any | **warn-and-continue** — log a warning, proceed with available static evidence, lower confidence |
| `optional` | any | **silent-skip** — skip silently, no warning emitted |

Degradation entries are written to `env_check.json` (generated during preflight) and propagated to `scan_state.json.error_log` once scanning begins.

## Fallback Chains

When a tool with a fallback is missing, the preflight phase walks the chain in order until a working replacement is found:

| Primary Tool | Fallback Chain |
|---|---|
| `cve-bin-tool` | trivy → grype |
| `checksec` | hardening-check |
| `cwe_checker` | radare2 |
| `ghidra` | radare2 → objdump |
| `docker` | podman |
| `radare2` | objdump |

The resolved tool (or chain exhaustion) is recorded in `env_check.json` so downstream phases can inspect what is actually available.
