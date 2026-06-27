# Tool Usage Reference

## Required Baseline

Python 3 and POSIX shell are required for validation scripts. Docker, YARA, radare2, Ghidra, cve-bin-tool, checksec, cwe_checker, lintian, and rpmlint are optional scan accelerators.

## Degradation

When an optional tool is missing, record the missing tool in `scan_state.json.error_log`, continue with available static evidence, and lower confidence according to the phase playbook.
