#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/templates/report_summary.md"
PHASE="$ROOT/phases/phase-4-report.md"

required_sections=(
  "## 2. 预检环境摘要"
  "## 3. 目标画像摘要"
  "## 4. 扫描策略摘要"
  "## 5. Track A 汇总"
  "## 6. Track B 汇总"
  "## 7. 合并与置信度摘要"
  "## 8. 验证摘要"
  "## 9. 覆盖摘要"
  "## 13. 附录 Artifact 路径"
)

for section in "${required_sections[@]}"; do
  grep -qF "$section" "$TEMPLATE" || {
    echo "FAIL: report template missing section: $section"
    exit 1
  }
done

required_inputs=(
  "env_check.json"
  "target_profile.json"
  "scan_strategy.json"
  "coverage_plan.json"
  "track_a_findings.json"
  "track_b_findings.json"
  "merged_findings.json"
  "coverage_report.json"
  "verified_findings.json"
  "scan_state.json"
)

for input in "${required_inputs[@]}"; do
  grep -qF "$input" "$PHASE" || {
    echo "FAIL: phase-4-report.md missing input: $input"
    exit 1
  }
  grep -qF "$input" "$TEMPLATE" || {
    echo "FAIL: report template missing artifact path mention: $input"
    exit 1
  }
done

echo "report template validation passed"
