# Phase 1b: Track B — AI Binary Analysis

## Objective
Perform structured AI-assisted binary analysis against prioritized functions and files.
The phase consumes target_profile.json and scan_strategy.json and emits track_b_findings.json.

## Required Inputs
- $SCAN_ROOT/target_profile.json
- $SCAN_ROOT/scan_strategy.json
- $SCAN_ROOT/scan_state.json
- Extracted package tree under $SCAN_ROOT/extracted

## Engine Commands

### radare2
```bash
r2 -q -c 'aaa; aflj' <binary>
r2 -q -c 'aaa; pdf @ <function_name>' <binary>
r2 -q -c 'aaa; pdc @ <function_name>' <binary>
r2 -q -c 'aaa; axtj @ <address>' <binary>
```

### Ghidra Headless
```bash
analyzeHeadless $SCAN_ROOT/ghidra project_$SCAN_ID -import <binary> -postScript DecompileFunction.java <function_address> -scriptPath tools/ghidra
```

### objdump Fallback
```bash
objdump -d -M intel <binary>
objdump -T <binary>
strings -n 8 <binary>
```

## Multi-Architecture Branch
- x86_64/amd64: use radare2 and Ghidra; prefer Ghidra pseudo-C for top functions.
- aarch64/arm64: use radare2 first; use Ghidra only when headless import succeeds.
- armv7/mips/riscv64: use objdump, readelf, strings, and YARA evidence; mark decompiler confidence lower.
- unknown: analyze strings/config/scripts only and set status partial.

## Function Priority Scoring

For each function calculate:
`priority = 0.25*symbol + 0.30*reachability + 0.20*density + 0.15*complexity + 0.10*privilege`

Weights:
- symbol: exported=1.0, dynamic=0.8, local named=0.5, anonymous=0.2
- reachability: network=1.0, file/parser=0.8, cli=0.6, config=0.5, internal=0.2
- density: min(unsafe_api_calls / max(instruction_count,1) * 20, 1.0)
- complexity: min(branch_count / 20, 1.0)
- privilege: setuid/capability/root service=1.0, daemon user=0.5, regular user=0.2

Mode limits:
| Mode | Token budget | Function limit | Dimensions |
|------|--------------|----------------|------------|
| quick | 50000 | Top 5 | dangerous_functions, hardcoded_config |
| standard | 200000 | Top 20 | five highest-value dimensions |
| deep | 500000 | Top 50 | all seven dimensions |
| full | 1000000 | all reachable functions | all seven dimensions plus cross-validation |

## Output Contract

Each AI finding must validate against finding.json and be wrapped in track_findings.json. Use TB-NNN IDs only.

## Dimension: dangerous_functions — 危险函数调用分析

### Analysis Goal
Find unsafe libc or syscall usage with missing bounds, quoting, or privilege checks.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `dangerous_functions` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Find unsafe libc or syscall usage with missing bounds, quoting, or privilege checks.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `dangerous_functions`.
- `vulnerability.cwe_id`: default `CWE-120` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `high` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `dangerous_functions`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: input_validation — 输入验证与边界检查

### Analysis Goal
Trace external input into parsers, length calculations, copy operations, and allocation sizes.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `input_validation` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Trace external input into parsers, length calculations, copy operations, and allocation sizes.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `input_validation`.
- `vulnerability.cwe_id`: default `CWE-20` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `high` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `input_validation`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: control_flow — 控制流异常检测

### Analysis Goal
Inspect indirect calls, computed jumps, error unwinding, and suspicious dispatch tables.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `control_flow` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Inspect indirect calls, computed jumps, error unwinding, and suspicious dispatch tables.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `control_flow`.
- `vulnerability.cwe_id`: default `CWE-119` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `medium` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `control_flow`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: memory_management — 内存管理缺陷

### Analysis Goal
Look for UAF, double-free, leaks, unchecked realloc, and lifetime confusion.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `memory_management` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Look for UAF, double-free, leaks, unchecked realloc, and lifetime confusion.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `memory_management`.
- `vulnerability.cwe_id`: default `CWE-416` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `high` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `memory_management`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: privilege_model — 权限模型分析

### Analysis Goal
Review setuid/capability/root-service flows and privilege drop failures.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `privilege_model` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Review setuid/capability/root-service flows and privilege drop failures.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `privilege_model`.
- `vulnerability.cwe_id`: default `CWE-250` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `high` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `privilege_model`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: protocol_parsing — 协议/解析攻击面

### Analysis Goal
Analyze protocol parsers, format strings, integer overflow, and state machines.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `protocol_parsing` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Analyze protocol parsers, format strings, integer overflow, and state machines.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `protocol_parsing`.
- `vulnerability.cwe_id`: default `CWE-190` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `high` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `protocol_parsing`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Dimension: hardcoded_config — 配置与硬编码风险

### Analysis Goal
Identify hardcoded secrets, weak crypto, insecure defaults, and debug behavior.

### Selection Criteria
- Prefer functions in exported symbols, init paths, parser loops, request handlers, or privileged code.
- Include any function with matching YARA evidence, suspicious strings, or dangerous imports.
- Include callers and callees within one hop when cross-reference output is available.

### Evidence to Collect
- Function name, address, binary path, architecture, import symbols, xrefs, and pseudo-C if available.
- Relevant raw command output path under `$SCAN_ROOT/raw/track_b/`.
- Attack-surface mapping from target_profile.json.

### Prompt Template
```text
You are Track B analyzing dimension `hardcoded_config` for BlackBox Hunter.
Inputs:
- target profile JSON: {{target_profile}}
- scan strategy JSON: {{scan_strategy}}
- function metadata: {{function_metadata}}
- disassembly or pseudo-C: {{function_body}}
- cross references: {{xrefs}}
Task:
1. Determine whether this function contains a vulnerability relevant to: Identify hardcoded secrets, weak crypto, insecure defaults, and debug behavior.
2. Trace attacker-controlled inputs to the vulnerable operation.
3. Identify required preconditions and why normal hardening does or does not mitigate it.
4. Return only JSON with keys: finding_present, title, cwe_id, severity, confidence, evidence, remediation, references.
5. If evidence is insufficient, set finding_present=false and explain the missing evidence in evidence.description.
Rules:
- Do not invent source code line numbers. Use line_offset only when provided by tooling.
- Use address_offset for binary offsets such as 0x401234.
- Keep raw_output short and point supporting_files to full command output.
- Confidence above 0.8 requires a concrete data/control flow, not just an imported symbol.
```

### Response to finding.json Mapping
- `finding_id`: next `TB-NNN`.
- `source.track`: `B`; `source.tool`: selected disassembly engine; `source.analysis_dimension`: `hardcoded_config`.
- `vulnerability.cwe_id`: default `CWE-798` unless the evidence supports a more precise CWE.
- `vulnerability.severity`: default `medium` and adjust by attack surface and exploitability.
- `verification.poc_status`: `untested`.
- `remediation.suggestion`: concrete code/config fix tied to the evidence.

### Error Handling
- If Ghidra fails, rerun with radare2 pseudo-C and lower maximum confidence to 0.75.
- If radare2 fails, use objdump and lower maximum confidence to 0.65.
- If output exceeds token budget, keep function signature, imports, xrefs, first 120 instructions, and branch/call sites.
- If token budget is exhausted, mark phase status `partial`, persist analyzed function IDs, and resume from the next function.

### Dimension-Specific Checks
1. Check item 1 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
2. Check item 2 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
3. Check item 3 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
4. Check item 4 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
5. Check item 5 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
6. Check item 6 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
7. Check item 7 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
8. Check item 8 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
9. Check item 9 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
10. Check item 10 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
11. Check item 11 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
12. Check item 12 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
13. Check item 13 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
14. Check item 14 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.
15. Check item 15 for `hardcoded_config`: confirm concrete evidence, affected input path, vulnerable operation, guard condition, and remediation impact before emitting a finding.

## Token Budget Enforcement

Maintain a ledger with fields: mode, tokens_budgeted, tokens_used, functions_completed, dimensions_completed, truncations. Stop before exceeding 95% of the mode budget and write partial output.

## Degradation Matrix
| Failure | Fallback | Confidence cap | State update |
|---------|----------|----------------|--------------|
| Ghidra import/decompile fails | radare2 `pdc` | 0.75 | warning |
| radare2 analysis fails | objdump + readelf + strings | 0.65 | warning |
| objdump fails | strings + YARA evidence only | 0.45 | partial |
| Token budget exhausted | persist checkpoint and stop | unchanged | partial resumable |

## Final Output
Write `$SCAN_ROOT/track_b_findings.json` using the `track_findings.json` wrapper. Include dimensions_analyzed, functions_analyzed, token_usage, engine_failures, and architecture_branch in metadata.

## Error Handling

Record phase failures in `scan_state.json.error_log`, mark the phase status as `failed` or `skipped`, and preserve partial artifacts under `$SCAN_ROOT/logs/` for resume diagnostics.
