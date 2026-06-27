#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0

while IFS= read -r script; do
  name="${script#$PROJECT_DIR/}"
  printf '  script %-40s ' "$name"
  if bash -n "$script"; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi
done < <(find "$PROJECT_DIR" -name "*.sh" -type f | sort)

while IFS= read -r doc; do
  name="${doc#$PROJECT_DIR/}"
  printf '  markdown %-38s ' "$name"
  if grep -q "^# Phase" "$doc" && grep -q "^## Objective" "$doc" && grep -q "^## .*Error" "$doc"; then
    echo OK
  else
    echo "FAIL (missing required phase sections)"
    ERRORS=$((ERRORS + 1))
  fi
done < <(find "$PROJECT_DIR/phases" -name "*.md" -type f | sort)

SCHEMA_COUNT="$(find "$PROJECT_DIR/templates" -name "*.json" | wc -l | tr -d ' ')"
RULE_COUNT="$(find "$PROJECT_DIR/tools/rules" -name "*.yara" | wc -l | tr -d ' ')"
PHASE_COUNT="$(find "$PROJECT_DIR/phases" -name "*.md" | wc -l | tr -d ' ')"

[ "$SCHEMA_COUNT" -ge 10 ] || { echo "FAIL: expected >=10 schemas, found $SCHEMA_COUNT"; ERRORS=$((ERRORS + 1)); }
[ "$RULE_COUNT" -ge 3 ] || { echo "FAIL: expected >=3 YARA rules, found $RULE_COUNT"; ERRORS=$((ERRORS + 1)); }
[ "$PHASE_COUNT" -ge 6 ] || { echo "FAIL: expected >=6 phase docs, found $PHASE_COUNT"; ERRORS=$((ERRORS + 1)); }

[ "$ERRORS" -eq 0 ]
