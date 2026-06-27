#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/templates/report_summary.md"
PHASE="$ROOT/phases/phase-4-report.md"

required_sections=(
  "## 2. Preflight Environment Summary"
  "## 3. Target Profile Summary"
  "## 4. Scan Strategy Summary"
  "## 5. Track A Summary"
  "## 6. Track B Summary"
  "## 7. Merge and Confidence Summary"
  "## 8. Verification Summary"
  "## 9. Coverage Summary"
  "## 13. Appendix Artifact Paths"
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
