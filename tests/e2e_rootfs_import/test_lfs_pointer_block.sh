#!/bin/bash
# E2E T2: preflight refuses an LFS-pointer tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t2-$$"
SCAN_ROOT="$TMPDIR/scan"
ORIG="$ROOT/assets/rootfs/v11-2503-rootfs.tar"
BACKUP="$TMPDIR/orig.tar"
mkdir -p "$TMPDIR"
cp "$ORIG" "$BACKUP"
trap 'cp "$BACKUP" "$ORIG"; rm -rf "$TMPDIR"' EXIT

# Truncate to simulate an LFS pointer
: > "$ORIG"

python3 "$ROOT/tools/preflight.py" --check-only --scan-root "$SCAN_ROOT" \
    >"$TMPDIR/preflight.out" 2>&1 || true

ENV_CHECK="$SCAN_ROOT/env_check.json"
test -f "$ENV_CHECK"

blocked="$(python3 -c "import json;print(json.load(open('$ENV_CHECK'))['block_decision']['blocked'])")"
[ "$blocked" = "True" ] || { echo "expected blocked=true, got $blocked"; cat "$TMPDIR/preflight.out"; exit 1; }

status="$(python3 -c "import json;print(json.load(open('$ENV_CHECK'))['rootfs_status'])")"
[ "$status" = "lfs_pointer" ] || [ "$status" = "missing" ] || { echo "unexpected rootfs_status: $status"; cat "$TMPDIR/preflight.out"; exit 1; }

grep -q "git lfs pull" "$TMPDIR/preflight.out" || { echo "missing 'git lfs pull' hint"; cat "$TMPDIR/preflight.out"; exit 1; }

echo "T2 passed"
