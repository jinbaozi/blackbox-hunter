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

## 扫描维度和具体方式

BlackBox Hunter 的扫描不是单一工具输出，而是按“包画像、确定性工具扫描、AI 二进制分析、合并评分、沙箱验证”分层推进。各维度的覆盖范围和执行方式如下。

| 扫描维度 | 关注目标 | 具体方式 | 主要证据或产物 |
|---|---|---|---|
| 包结构与攻击面画像 | 确认包类型、架构、入口点和可被攻击者触达的文件 | 解压 `.deb` / `.rpm`，遍历 ELF、脚本、配置文件、systemd 单元、setuid/setgid 文件、命令行入口、潜在网络监听点，并按架构决定后续工具链 | `target_profile.json`、`scan_strategy.json`、`coverage_plan.json` |
| 依赖与 CVE 线索 | 发现已知漏洞组件、共享库和包依赖风险 | 使用 `cve-bin-tool` 扫描包和二进制组件；不可用时按预检结果降级到 `trivy` 或 `grype`；离线 CVE 缓存超过 14 天时降低 CVE 发现置信度 | CVE ID、组件名、版本、数据库新鲜度、工具原始输出 |
| ELF 加固能力 | 判断二进制是否缺失常见安全缓解 | 使用 `checksec` 检查 NX、PIE、RELRO、Canary 等 hardening 标志；不可用时尝试 `hardening-check` fallback | hardening 标志、受影响 ELF 路径、置信度降级原因 |
| 二进制 CWE 模式 | 识别常见内存安全和二进制缺陷模式 | 使用 `cwe_checker` 对支持架构做静态模式分析；架构或工具不支持时降级到 `radare2`、`objdump`、`readelf`、`strings` 证据 | CWE 编号、函数或地址偏移、架构支持状态 |
| 危险函数与系统调用 | 发现不安全 libc/API、命令执行、临时文件、弱随机等高风险用法 | 使用 `strings`、导入表、YARA 规则和反汇编证据定位 `strcpy`、`sprintf`、`system`、`popen`、`mktemp`、`rand` 等调用，再由 Track B 做上下文确认 | YARA 命中、导入符号、函数名、地址、调用上下文 |
| 输入验证与边界检查 | 检查外部输入进入解析、长度计算、拷贝、分配前是否有边界约束 | 优先分析网络入口、文件/协议解析器、CLI 参数处理和配置加载函数；使用 Ghidra、radare2 或 objdump 追踪输入到危险操作的数据流 | 反编译片段、反汇编片段、xrefs、输入路径、缺失 guard |
| 控制流异常 | 发现可疑间接调用、computed jump、分发表、异常错误恢复路径 | Track B 对高优先级函数检查分支复杂度、间接跳转、函数指针调用和错误处理路径；结合 xref 和调用图判断是否可被输入影响 | 函数地址、调用图、跳转目标、可控条件说明 |
| 内存管理 | 检查越界读写、整数溢出后分配、use-after-free、double free 等风险 | 结合 `cwe_checker`、反编译输出、调用关系和危险内存 API，重点看长度字段、循环边界、分配大小、释放后访问 | CWE-119/CWE-120/CWE-125/CWE-190 等映射、函数片段、地址偏移 |
| 权限模型 | 检查 root 服务、setuid/setgid、Linux capability、特权文件操作和权限边界 | Phase 0 收集特权文件和服务用户；Track B 分析敏感操作是否受低权限输入影响；Track A 检查包脚本和服务配置 | setuid/setgid 清单、systemd `User=`、敏感路径、权限前置条件 |
| 协议和文件格式解析 | 检查协议字段、文件格式长度、归档路径和解析状态机 | 对 parser loop、请求处理函数、文件导入路径做优先级排序；分析长度字段、路径拼接、状态转换和错误恢复 | 解析函数、输入格式、长度字段、路径处理证据 |
| 硬编码配置与密钥 | 发现默认凭据、API token、私钥、证书、调试配置和危险默认值 | 使用 `strings` 和 YARA 规则扫描 credential 上下文、高熵字符串、私钥头、AWS key、debug/log level、`0.0.0.0` 绑定等模式；Track B 对可利用性做确认 | YARA 命中、字符串上下文、文件路径、配置键值 |
| 包元数据与维护脚本 | 检查安装/卸载脚本、包元数据、服务启动配置中的风险 | `.deb` 使用 `lintian`，`.rpm` 使用 `rpmlint`；同时人工/AI 关注 maintainer script、postinst、systemd unit、权限变更和 shell 执行 | lint 输出、脚本路径、配置片段、风险说明 |
| 嵌入内容与文件异常 | 发现包内嵌套固件、压缩内容、异常文件类型或隐藏载荷 | 使用文件遍历和 `binwalk` 做嵌入内容识别；对提取失败或不支持格式记录覆盖率限制 | 嵌入文件线索、文件类型、提取状态、覆盖率备注 |
| 去重、评分与覆盖率 | 合并多工具结果，避免重复报告并体现证据强弱 | Phase 2 按二进制、CVE/CWE、函数、地址偏移、等价标题去重；按证据强度、跨 Track 一致性、架构 fallback、CVE 数据库状态调整置信度 | `merged_findings.json`、`coverage_report.json`、`dedup_info.merged_from` |
| PoC 沙箱验证 | 对高价值发现做受控复现，区分“线索”和“已验证” | Phase 3 在 Docker/Podman 沙箱中运行 PoC；默认无网络、非特权用户、seccomp 限制、只读挂载目标包，采集退出码、stdout/stderr 和产物 | `verified_findings.json`、PoC 日志、`verification.poc_status` |

Track B 的 AI 二进制分析会按扫描模式控制深度：`quick` 只覆盖危险函数和硬编码配置；`standard` 覆盖五个最高价值维度；`deep` 覆盖七个核心维度；`full` 分析所有可达函数并做交叉验证。七个核心维度是：

- `dangerous_functions`：危险函数调用和不安全系统调用。
- `input_validation`：输入验证、边界检查、长度字段和分配大小。
- `control_flow`：异常控制流、间接调用、computed jump 和状态转换。
- `memory_management`：内存生命周期、越界访问、释放错误和整数溢出。
- `privilege_model`：权限边界、setuid/setgid、root 服务和敏感操作。
- `protocol_parsing`：协议解析、文件格式解析、路径和长度处理。
- `hardcoded_config`：硬编码凭据、默认密钥、调试配置和危险默认值。

所有维度都要求保留可审计证据。Track A 主要输出工具证据，Track B 必须绑定函数、地址、反编译/反汇编片段、字符串、配置或原始工具输出；证据不足时只能记录低置信度线索或不产生 finding。

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
