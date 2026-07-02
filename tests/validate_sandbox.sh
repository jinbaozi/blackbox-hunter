#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SANDBOX_DIR="$PROJECT_DIR/sandbox"
ERRORS=0

check_contains() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  printf '  sandbox %-44s ' "$description"
  if grep -Eq -- "$pattern" "$file"; then
    echo OK
  else
    echo FAIL
    ERRORS=$((ERRORS + 1))
  fi
}

printf '  sandbox %-44s ' "run_poc.sh syntax"
if bash -n "$SANDBOX_DIR/run_poc.sh"; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi

printf '  sandbox %-44s ' "monitor.sh syntax"
if bash -n "$SANDBOX_DIR/monitor.sh"; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi

check_contains "$SANDBOX_DIR/run_poc.sh" '/opt/monitor\.sh[[:space:]]+--pid[[:space:]]+"\$POC_PID"' "monitor receives PoC PID"
check_contains "$SANDBOX_DIR/run_poc.sh" 'status\.txt' "runner writes status"
check_contains "$SANDBOX_DIR/run_poc.sh" 'timeout\.txt' "runner writes timeout state"
check_contains "$SANDBOX_DIR/run_poc.sh" 'exit_code\.txt' "runner writes exit code"
check_contains "$SANDBOX_DIR/run_poc.sh" 'poc_error' "runner classifies PoC errors"
check_contains "$SANDBOX_DIR/run_poc.sh" 'sandbox_error|timeout|inconclusive|crash|completed|failed' "runner exposes result classes"

check_contains "$SANDBOX_DIR/monitor.sh" '--pid' "monitor supports --pid"
check_contains "$SANDBOX_DIR/monitor.sh" 'PID must be numeric' "monitor validates PID"
check_contains "$SANDBOX_DIR/monitor.sh" 'VmPeak|VmRSS|Threads' "monitor records telemetry"

check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" 'network_mode:[[:space:]]*"none"' "network disabled"
check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" 'no-new-privileges:true' "no-new-privileges set"
check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" 'cap_drop:' "capabilities dropped"
check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" 'RESULTS_DIR' "results directory is bind-mounted"
check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" '/workspace/results' "results target is stable"
check_contains "$SANDBOX_DIR/docker-compose.sandbox.yml" 'read_only:[[:space:]]+false' "results mount is writable"

check_contains "$SANDBOX_DIR/seccomp-profile.json" '"defaultAction"[[:space:]]*:[[:space:]]*"SCMP_ACT_ERRNO"' "seccomp default deny"

if [ "$ERRORS" -ne 0 ]; then
  echo "$ERRORS sandbox validation(s) failed."
  exit 1
fi

echo "All sandbox validations passed."
