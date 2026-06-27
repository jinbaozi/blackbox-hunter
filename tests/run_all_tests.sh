#!/bin/bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

for test in "$TESTS_DIR"/validate_*.sh "$TESTS_DIR"/smoke_test.sh; do
  [ -f "$test" ] || continue
  name="$(basename "$test")"
  if bash "$test"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
