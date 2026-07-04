#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-sandbox-safe-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/pkg" "$TMPDIR/results" "$TMPDIR/poc"

if [ "${BBH_RUN_DOCKER_TESTS:-0}" != "1" ]; then
  echo "SKIP: set BBH_RUN_DOCKER_TESTS=1 to run Docker sandbox integration"
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed"
  exit 0
fi

cp "$ROOT/tests/fixtures/poc_safe/run.sh" "$TMPDIR/poc/run.sh"
chmod +x "$TMPDIR/poc/run.sh"
cat > "$TMPDIR/pkg/readme.txt" <<'EOF'
readonly package fixture
EOF

(
  cd "$ROOT/sandbox"
  SCAN_ID="BBH-20260704-sbx001" \
  CONTAINER_NAME="bbh-safe-$RANDOM" \
  POC_DIR="$TMPDIR/poc" \
  PACKAGE_DIR="$TMPDIR/pkg" \
  RESULTS_DIR="$TMPDIR/results" \
  POC_SCRIPT="/poc/run.sh" \
  TIMEOUT=30 \
  docker compose -f docker-compose.sandbox.yml up --build --abort-on-container-exit --exit-code-from poc-sandbox >/tmp/bbh-sandbox-safe.log 2>&1 || true
)

test -s "$TMPDIR/results/stdout.txt"
test -s "$TMPDIR/results/status.txt"
test -s "$TMPDIR/results/poc_output.txt"
grep -q "SAFE_POC_STARTED" "$TMPDIR/results/stdout.txt"
grep -q "PKG_WRITE_BLOCKED" "$TMPDIR/results/stdout.txt"

echo "sandbox safe integration OK"
