#!/bin/bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${TMPDIR:-/tmp}/bbh-test-logs-$$"
PASS=0
FAIL=0
trap 'rm -rf "$LOG_DIR"' EXIT
mkdir -p "$LOG_DIR"

for test in "$TESTS_DIR"/validate_*.sh "$TESTS_DIR"/smoke_test.sh; do
  [ -f "$test" ] || continue
  name="$(basename "$test")"
  log="$LOG_DIR/$name.log"
  printf '  test %-38s ' "$name"
  if bash "$test" >"$log" 2>&1; then
    echo OK
    PASS=$((PASS + 1))
  else
    echo FAIL
    FAIL=$((FAIL + 1))
    echo "--- $name output ---"
    cat "$log"
    echo "--- end $name output ---"
  fi
done

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
