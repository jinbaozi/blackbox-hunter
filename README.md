# BlackBox Hunter 中文说明

BlackBox Hunter 是一个面向 `.deb` / `.rpm` 软件包的黑盒漏洞分析 Skill。它的目标是在没有源代码的情况下，把包解压、静态扫描、AI 辅助二进制分析、结果合并、PoC 沙箱验证和报告生成组织成一套可恢复、可验证、可审计的工作流。

这个目录本身就是 Skill 包。入口文件是 `SKILL.md`，执行细节拆分在 `phases/`、`templates/`、`tools/`、`sandbox/` 和 `tests/` 中。

## 适用场景

- 需要审计第三方 `.deb` 或 `.rpm` 包，但没有源代码。
- 需要同时利用传统安全工具和 AI 二进制分析来提高发现率。
- 需要把扫描过程拆成可恢复的阶段，避免一次失败导致全量重跑。
- 需要将不同工具、不同分析维度输出统一为结构化 JSON，便于后续合并、验证和报告生成。
- 需要在隔离 Docker 沙箱中对高价值发现做受控 PoC 验证。

不适合的场景：

- 源代码审计优先的项目。此 Skill 主要面向黑盒包扫描。
- 需要动态联网攻击、真实外部服务探测或横向移动验证的任务。
- 不能接受 AI 推断参与漏洞研判的合规流程。Track B 输出需要结合证据和置信度使用。

## 核心能力

### 1. 软件包画像

### Phase -1: 环境预检 (Preflight)

在任何扫描开始之前，环境预检阶段负责完成：

- 工具 PATH 检测和可用性验证。
- 按优先级分层（required / required_verify / high / medium / optional）处理缺失工具。
- 自动安装缺失工具，安装优先级：`pipx > npm > pip > apt/dnf/brew > manual`，默认安装路径 `~/.local/bin`。
- 生成 `env_check.json`，记录每个工具的状态和 fallback 决策。
- 对 `required` 且无 fallback 的工具执行 hard-block，中止扫描并给出安装提示。

详细逻辑见 `phases/phase-preflight.md`。

### Phase 0: 解压与画像

Phase 0 负责解压和画像生成：

- 生成唯一 `scan_id`，格式为 `BBH-YYYYMMDD-<6 hex>`。
- 做磁盘空间预检，按 `包大小 * 5 + 1 GiB` 估算工作目录需求。
- 识别包类型、架构、ELF 二进制、脚本、配置文件、systemd 单元和潜在入口点。
- 生成 `target_profile.json`、`scan_strategy.json`、`coverage_plan.json`、`sandbox_status.json` 和 `scan_state.json`。

### 2. Track A 传统工具扫描

Track A 使用确定性工具做静态分析，典型工具包括：

- `cve-bin-tool`：CVE 线索和依赖风险。
- `checksec`：ELF hardening 检查。
- `cwe_checker`：二进制 CWE 模式识别。
- `strings` + YARA：危险函数、硬编码密钥、可疑配置模式。
- `lintian` / `rpmlint`：Debian/RPM 包元数据与维护脚本检查。

Track A 输出统一封装为 `track_findings.json`，finding ID 使用 `TA-NNN`。

### 3. Track B AI 二进制分析

Track B 负责 AI 辅助研判，重点分析高风险函数和入口点。当前 Phase 1b 覆盖 7 个维度：

- `dangerous_functions`：危险函数调用。
- `input_validation`：输入验证与边界检查。
- `control_flow`：异常控制流和状态转换。
- `memory_management`：内存生命周期、越界和释放问题。
- `privilege_model`：权限边界、setuid、服务用户和敏感操作。
- `protocol_parsing`：协议解析、文件格式解析和长度字段处理。
- `hardcoded_config`：硬编码凭据、默认密钥和危险配置。

支持的分析引擎包括 Ghidra headless、radare2 和 objdump fallback。Track B 输出同样使用 `track_findings.json`，finding ID 使用 `TB-NNN`。

### 4. 结果合并和置信度评分

Phase 2 将 Track A 和 Track B 输出合并为 `merged_findings.json`，并生成 `coverage_report.json`。

合并逻辑关注：

- 同一二进制、同一 CVE/CWE、同一函数、同一地址偏移或等价标题的去重。
- 保留 `dedup_info.merged_from`，避免丢失原始来源。
- 按证据强度、跨 Track 一致性、架构 fallback、离线 CVE 数据库等因素调整置信度。

### 5. 沙箱 PoC 验证

Phase 3 在受限 Docker 环境中验证可复现发现：

- 容器内使用非特权用户 `poctest`。
- `network_mode: none` 禁用网络。
- 使用 seccomp profile 限制系统调用。
- `run_poc.sh` 负责 timeout、输出目录和退出码采集。
- 目标包以只读方式挂载，验证输出写入独立 scratch/output 目录。

验证结果写入 `verified_findings.json`。

### 6. 报告生成

Phase 4 从验证结果、覆盖率、状态文件和原始日志生成最终报告。报告模板位于 `templates/report_summary.md`，覆盖：

- 执行摘要。
- 范围和环境。
- 覆盖率。
- 漏洞发现。
- 限制条件和后续建议。

## 目录结构

```text
blackbox-hunter-skill/
├── SKILL.md                         # Skill 入口和总编排说明
├── README.md                        # 中文使用说明
├── phases/                          # 分阶段执行手册
│   ├── phase-preflight.md           # 环境预检（工具检测、安装、PATH 管理）
│   ├── phase-0-profile.md
│   ├── phase-1a-toolscan.md
│   ├── phase-1b-ai-analysis.md
│   ├── phase-2-merge.md
│   ├── phase-3-verify.md
│   └── phase-4-report.md
├── templates/                       # JSON Schema 与报告/PoC 模板
├── tools/
│   ├── tool_registry.json           # 工具注册表
│   ├── install.sh                   # 工具检测和安装辅助脚本
│   ├── ghidra/DecompileFunction.java
│   └── rules/                       # YARA 规则
├── sandbox/                         # PoC 沙箱配置
├── references/                      # CWE 和工具使用参考
└── tests/                           # schema、脚本、YARA 和 smoke 测试
```

## 数据流

```text
输入包
  -> Phase -1 (Preflight): env_check (工具检测、PATH 管理、自动安装)
  -> Phase 0: target_profile / scan_strategy / coverage_plan / scan_state
  -> Phase 1a: track_a_findings
  -> Phase 1b: track_b_findings
  -> Phase 2: merged_findings / coverage_report
  -> Phase 3: verified_findings
  -> Phase 4: final report
```

所有扫描产物默认写入：

```text
$WORKSPACE/<scan_id>/
```

`scan_state.json` 是断点续扫和状态恢复的核心文件。

## 关键 JSON 合同

`templates/` 中的 schema 是 Agent 间交换数据的正式合同：

- `finding.json`：统一漏洞发现格式，包含 `verification`、`remediation`、`references`。
- `target_profile.json`：包画像、二进制清单和攻击面。
- `scan_strategy.json`：扫描模式、工具计划、Track B 聚焦范围。
- `coverage_plan.json`：覆盖目标和 Track 分配。
- `scan_state.json`：阶段状态机、错误日志和断点续扫信息。
- `sandbox_status.json`：沙箱可用性和限制条件。
- `track_findings.json`：Track A / Track B 输出 wrapper。
- `merged_findings.json`：去重合并结果。
- `coverage_report.json`：覆盖率报告。
- `verified_findings.json`：PoC 验证后的发现。
- `env_check.json`：环境预检结果，记录工具检测状态、fallback 决策和安装记录。

所有 finding ID 只允许两类前缀：

- `TA-NNN`：Track A 传统工具扫描。
- `TB-NNN`：Track B AI 二进制分析。

## 状态机和断点续扫

Skill 使用 `scan_state.json` 追踪阶段状态：

```text
idle
  -> phase_0_running
  -> phase_0_done
  -> track_a_running + track_b_running
  -> track_a_done + track_b_done
  -> phase_2_running
  -> phase_2_done
  -> phase_3_running
  -> phase_3_done
  -> phase_4_running
  -> completed
```

恢复扫描时，应先验证 `scan_state.json`，然后检查每个已完成阶段的必需输出。若某个阶段状态为 `failed`，或输出缺失/无效，则从该阶段恢复。已成功阶段的输出不应被直接覆盖，重跑结果应先写入 `reruns/`，验证通过后再提升为正式输出。

## 工具依赖

基础验证只需要：

- `bash`
- `python3`

实际扫描使用的工具按优先级分为五个层级：

| 优先级 | 说明 | 缺失行为 |
|---|---|---|
| `required` | 核心扫描工具，无 fallback | hard-block：中止扫描，提示用户安装 |
| `required` (带 fallback) | 核心扫描工具，有替代链 | soft-warn：使用 fallback 工具继续 |
| `required_verify` | PoC 验证阶段必需 | phase-block：仅阻塞 Phase 3 |
| `high` / `medium` | 重要但非阻塞 | warn-and-continue：记录警告，继续扫描 |
| `optional` | 辅助加速工具 | silent-skip：静默跳过 |

典型工具包括：

- `cve-bin-tool`（fallback: trivy → grype）
- `checksec`（fallback: hardening-check）
- `cwe_checker`（fallback: radare2）
- `ghidra`（fallback: radare2 → objdump）
- `docker`（fallback: podman）
- `binwalk`、`yara`、`lintian`、`rpmlint`、`radare2`

**环境预检阶段**（`phase-preflight.md`）负责所有工具检测、PATH 管理和安装建议，在 Phase 0 之前完成。默认路径以准确率优先：尽可能发现缺失工具，给出安装命令，并在用户确认后执行安装。安装优先级为：

```text
pipx > npm > pip > apt/dnf/brew > manual
```

默认安装路径为 `~/.local/bin`。

工具注册和 fallback 链定义见 `tools/tool_registry.json` 与 `tools/install.sh`。缺失工具时，预检阶段会将检测结果写入 `env_check.json`，并在 `scan_state.json.error_log` 中记录降级原因。`install.sh` 支持 `--output <file>` 和 `--scan-root <dir>`；如果都不提供，默认写入当前目录的 `env_check.json` 并打印绝对路径。`--offline` 仅用于受控环境或复现历史扫描：只检测现有工具，不安装、不联网，并在报告中体现覆盖率和置信度降级。

## 快速验证

在仓库根目录运行：

```bash
bash blackbox-hunter-skill/tests/run_all_tests.sh
```

该脚本会执行：

- `validate_rules.sh`：YARA 规则 smoke 校验。
- `validate_schemas.sh`：JSON Schema 和 fixture 校验。
- `validate_scripts.sh`：shell 脚本语法和 phase 文档结构检查。
- `smoke_test.sh`：最小 smoke 测试；若本机没有 `dpkg-deb`，会跳过 fixture 包构建。

也可以单独运行：

```bash
bash blackbox-hunter-skill/tests/validate_schemas.sh
bash blackbox-hunter-skill/tests/validate_scripts.sh
bash blackbox-hunter-skill/tests/validate_rules.sh
bash blackbox-hunter-skill/tests/smoke_test.sh
```

## 使用方式

在支持 Codex Skill 的环境中，将 `blackbox-hunter-skill/` 作为 Skill 包使用。调用时给出目标包路径和扫描模式，例如：

```text
使用 blackbox-hunter 扫描 /path/to/package.deb，模式 standard。
```

恢复已有扫描时提供 `scan_state.json` 路径：

```text
使用 blackbox-hunter 从 /workspace/BBH-20260627-a1b2c3/scan_state.json 继续扫描。
```

执行代理应按 `SKILL.md` 的编排顺序加载 `phases/` 下的阶段文档，并在每个阶段结束后验证 JSON 输出。

## 安全边界

- Track A 和 Track B 以静态分析为主，不应执行目标包中的不可信逻辑。
- PoC 验证必须进入 `sandbox/` 定义的受限环境。
- 高危或破坏性 PoC 需要人工确认后再运行。
- 网络默认禁用，不把外部探测作为验证前提。
- 离线 CVE 数据库可用但会降低 CVE 相关发现置信度。

## 输出解读建议

- `severity` 表示潜在影响，不等于已验证可利用性。
- `confidence` 表示证据强度，受工具覆盖、架构支持和 Track 一致性影响。
- `verification.poc_status` 才是 PoC 验证状态，可能为 `untested`、`verified`、`failed` 或 `skipped`。
- Track B 的 AI 输出必须有函数、地址、反编译片段、字符串、配置或工具输出等证据支撑。

## 当前限制

- 多架构支持采用分支和降级策略；非 `x86_64` / `aarch64` 架构可能只能进行 strings、YARA、objdump 和元数据分析。
- Ghidra、radare2、Docker 等外部工具不随 Skill 自带，需要在运行环境中安装。
- `tests/` 主要验证 Skill 文件和数据合同，不代表对真实软件包完成了端到端漏洞扫描。
- PoC 沙箱用于降低风险，不应被视为强隔离安全边界。
