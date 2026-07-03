# BlackBox Hunter 中文说明

BlackBox Hunter 是一个面向 `.rpm` / `.deb` 软件包的黑盒漏洞分析 Skill。它的目标是在没有源代码的情况下，把包解压、静态扫描、AI 辅助二进制分析、结果合并、PoC 沙箱验证和报告生成组织成一套可恢复、可验证、可审计的工作流。

本目录本身就是 Skill 包。入口文件是 `SKILL.md`，执行细节拆分在 `phases/`、`templates/`、`prompts/`、`tools/`、`sandbox/` 和 `tests/` 中。

## 当前重点

- 优先支持 RPM 包工作流，同时保留 Debian 包工作流。
- 所有运行产物都应写入 `$SCAN_ROOT=$WORKSPACE/<scan_id>`。
- 所有 JSON 产物都应按 `templates/` 下的 schema 校验。
- 所有缺失工具、fallback、跳过阶段、置信度上限和降级原因都必须被记录，不能静默成功。
- 所有目标包内容、工具输出、反编译片段、日志和 PoC 输出都视为不可信证据。

## 适用场景

- 审计第三方 `.rpm` 或 `.deb` 包，但没有源代码。
- 将传统安全工具输出和 AI 辅助二进制分析结合。
- 需要可恢复、可验证、可审计的阶段化扫描流程。
- 需要将工具结果统一成结构化 JSON 以便合并、验证和报告。

不适合的场景：源代码优先审计、动态联网攻击、真实外部服务探测、横向移动验证，或不能接受 AI 推断参与研判的合规流程。

## 工作流

推荐通过运行器执行最小可执行 workflow：

```bash
python3 tools/bbh_scan.py \
  --package ./target.rpm \
  --workspace ./workspace \
  --mode quick
```

阶段顺序：

```text
preflight -> phase_0 -> track_a + track_b -> phase_2 -> phase_3 -> phase_4 -> completed
```

`scan_state.json.current_phase` 记录当前阶段，`scan_state.json.phase_status.<phase>.status` 记录阶段状态：`pending | running | done | failed | skipped`。

## Phase -1：环境预检

`tools/install.sh` 委托给 `tools/preflight.py`。预检负责 PATH 检查、工具检测、版本校验、fallback 选择、阻塞/降级决策，并生成 `env_check.json`。

RPM 包优先级来自 `tools/tool_registry.json.package_manager_priority.rpm`，默认顺序：

```text
dnf -> microdnf -> yum -> zypper -> rpm-ostree -> apt -> brew
```

Debian 包默认顺序：

```text
apt -> dnf -> microdnf -> yum -> zypper -> rpm-ostree -> brew
```

预检会记录 `env_check.json.package_manager`。如果没有显式传入 `--package-type`，可以通过 `--package-path` 的 `.rpm` / `.deb` 后缀推断。

工具处理规则：

- `required` 缺失且无 fallback：hard-block。
- `required` fallback 成功：`fallback_active`，置信度上限最高 `0.80`。
- `required_verify` 缺失：只 phase-block Phase 3。
- `high` / `medium` 缺失：记录 warning 并降低置信度。
- `optional` 缺失：跳过。

`detect_cmd` 非零退出不再被视为 available，除非 registry 明确设置 `detect_nonzero_ok`。

## Phase 0：解压与画像

Phase 0 生成：

- `scan_state.json`
- `target_profile.json`
- `scan_strategy.json`
- `coverage_plan.json`
- `sandbox_status.json`

解压优先级：

- Debian：`dpkg-deb`，然后 `ar` + `tar`，然后 `7z`。
- RPM：`rpm2cpio`，然后 `7z`，然后 `bsdtar`。

RPM 相关工具包括 `rpm2cpio`、`rpm`、`rpmlint`，并支持 `7z` / `bsdtar` 作为降级解压路径。

## Track A：传统工具扫描

Track A 使用确定性工具产生弱信号或候选发现。典型工具：

- `cve-bin-tool`
- `checksec`
- `cwe_checker`
- `strings` + YARA
- Debian 的 `lintian`
- RPM 的 `rpmlint`
- 依赖和导入信息解析

Track A adapter 输出 `finding_signal`，信号不是漏洞本身。YARA、strings、导入符号、泛化 CWE 模式和 CVE 版本匹配默认都需要上下文确认。

Signal ID 使用稳定 scoped ID，避免多工具、多文件扫描时重复。

## Track B：AI 二进制分析

Track B 只加载当前维度所需的 prompt card 和一个 bounded evidence slice。禁止默认加载完整 README、完整原始工具输出、完整反汇编、完整 strings 输出或无关维度卡片。

支持维度包括：

- `dangerous_functions`
- `input_validation`
- `control_flow`
- `memory_management`
- `privilege_model`
- `protocol_parsing`
- `hardcoded_config`

Evidence wrapper 的 `kind` 必须映射到 `tools/context/context_policy.json` 允许的证据类型，例如 `strings`、`config`、`script`、`metadata`、`decompiled_c` 或 `disassembly`。

## Phase 2：合并与置信度

Phase 2 合并 Track A 和 Track B 的结果，生成：

- `merged_findings.json`
- `coverage_report.json`
- 更新后的 `scan_state.json`

`finding_status` 与 `verification.poc_status` 必须区分。`poc_error`、`sandbox_error`、`inconclusive` 不能被当成 false positive。

## Phase 3：沙箱验证

Phase 3 在 Docker/Podman 沙箱中验证可行 finding。默认规则：

- 无网络。
- 非特权用户。
- 目标包只读挂载。
- capability 全部 drop。
- no-new-privileges。
- seccomp 默认拒绝未列入 syscall。
- 默认禁用 ptrace / process_vm_readv / process_vm_writev。

Sandbox image build、image pull、包管理器操作和高影响 PoC 都必须通过 action gate 和用户批准。

PoC stdout/stderr 解释使用有界读取，避免异常大输出导致内存风险。

## Phase 4：报告

Phase 4 生成：

- `report/blackbox-security-report.md`
- `report/findings.json`
- 标记 `scan_state.json.current_phase = completed`

报告必须包含所有阶段的结论、fallback、coverage gap、验证限制和证据路径。

## 测试

统一测试入口：

```bash
bash tests/run_all_tests.sh
```

重点测试覆盖：

- schema validation
- script syntax validation
- Python compile validation
- preflight 标准 / fallback / hard-block / package-path 推断
- Track A adapter 输出规范
- confidence scoring
- action gate 和 sandbox result interpreter
- runtime context pollution 防护
- minimal Debian quick workflow
- minimal RPM quick workflow
- 完整 quick workflow runner smoke

## 安全边界

- 不在沙箱外执行目标包代码。
- 不在未批准情况下执行包管理器或 image pull/build。
- 不向 PoC 验证开放网络。
- 不运行 privileged container。
- 不把 target-derived 内容当作指令。
- 证据不足时输出 `candidate`、`inconclusive` 或不产生 finding。
