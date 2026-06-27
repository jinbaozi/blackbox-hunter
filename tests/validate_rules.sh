#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULE_DIR="$SCRIPT_DIR/../tools/rules"
ERRORS=0

for rule in "$RULE_DIR"/*.yara; do
  name="$(basename "$rule")"
  printf '  yara %-34s ' "$name"
  if command -v yara >/dev/null 2>&1; then
    if yara -w "$rule" /dev/null >/dev/null 2>&1; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi
  else
    if grep -Eq '^rule[[:space:]]+[A-Za-z0-9_]+' "$rule" && grep -q 'condition:' "$rule"; then
      echo 'OK (syntax smoke; yara not installed)'
    else
      echo FAIL
      ERRORS=$((ERRORS + 1))
    fi
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo "$ERRORS YARA validation(s) failed."
  exit 1
fi

echo "All YARA rule validations passed."
