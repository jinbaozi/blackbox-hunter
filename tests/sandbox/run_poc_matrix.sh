#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES_DIR="$PROJECT_DIR/tests/fixtures/poc_cases"
TMPDIR="${TMPDIR:-/tmp}/bbh-poc-matrix-$$"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

run_case() {
  local name="$1"
  local expected="$2"
  local input="$FIXTURES_DIR/$name.json"
  local output="$TMPDIR/$name.result.json"
  printf '  poc-matrix %-32s ' "$name"
  python3 "$PROJECT_DIR/sandbox/result_interpreter.py" "$input" --output "$output"
  if python3 - "$output" "$expected" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
actual = data["decision"]["poc_status"]
expected = sys.argv[2]
if actual != expected:
    raise SystemExit(f"expected {expected}, got {actual}")
PY
  then
    echo OK
  else
    echo FAIL
    return 1
  fi
}

run_case completed_absent_signal failed
run_case timeout_expected verified
run_case poc_error poc_error

python3 "$PROJECT_DIR/tests/sandbox/test_result_interpreter.py"
