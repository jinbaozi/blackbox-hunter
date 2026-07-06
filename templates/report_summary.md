# BlackBox 安全测试报告

## 1. 执行摘要

汇总包名、scan_id、扫描模式、发现项总数、已验证发现项数量和最高严重级别。

## 2. 预检环境摘要

汇总 env_check.json：checked_at、输出路径、离线或仅检查模式、阻断工具、回退决策、阶段阻断、安装提示、路径告警和置信度上限。

## 3. 目标画像摘要

汇总 target_profile.json：包路径、包类型、提取清单、二进制文件、脚本、配置、服务、架构和攻击面入口。

## 4. 扫描策略摘要

汇总 scan_strategy.json 和 coverage_plan.json：模式、选定的 Track A 工具、Track B 重点维度、目标优先级、限制和预期覆盖。

## 5. Track A 汇总

汇总 track_a_findings.json：已执行的确定性工具、已跳过工具、告警、发现项数量和最强证据类型。

## 6. Track B 汇总

汇总 track_b_findings.json：二进制分析引擎、回退模式、已分析维度、已审查函数或文件、告警和发现项数量。

## 7. 合并与置信度摘要

汇总 merged_findings.json：去重决策、合并的来源 ID、置信度调整和最终发现项数量。

## 8. 验证摘要

汇总 verified_findings.json 和 sandbox_status.json：已验证发现项、未验证发现项、跳过 PoC 的原因、沙箱运行时和证据路径。

## 9. 覆盖摘要

汇总 coverage_report.json：二进制、配置、依赖、攻击面和工具覆盖比例，以及缺口和降级原因。

## 10. 范围与环境

说明包路径、包类型、架构覆盖、提取方法、工具版本、沙箱状态和 CVE 数据库模式。

## 11. 发现项

每个发现项包含严重级别、置信度、受影响二进制或函数、证据、验证状态、修复建议和参考资料。

## 12. 限制与后续步骤

记录缺失工具、不支持的架构、离线数据库时效、跳过的 PoC 验证、未解决覆盖缺口和建议的后续测试。

## 13. 附录 Artifact 路径

列出 env_check.json、target_profile.json、scan_strategy.json、coverage_plan.json、track_a_findings.json、track_b_findings.json、merged_findings.json、coverage_report.json、verified_findings.json、scan_state.json、raw logs 和 PoC testcase 路径。artifact 名称、文件路径和技术标识可保持原样。
