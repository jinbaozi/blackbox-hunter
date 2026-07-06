#!/bin/bash
# E2E T1: import_rootfs.py imports the tarball and re-tags to stable alias.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t1-$$"
STABLE_REF="bbh-base:local-imported"
RECORD="$ROOT/tools/.imported_rootfs.json"

mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"; docker rmi -f "$STABLE_REF" >/dev/null 2>&1 || true; rm -f "$RECORD"' EXIT

cp "$ROOT/assets/rootfs/v11-2503-rootfs.tar" "$TMPDIR/v11-2503-rootfs.tar"

# First import
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"

docker image inspect "$STABLE_REF" >/dev/null

test -f "$RECORD"
sha_in_record="$(python3 -c "import json,sys;print(json.load(open('$RECORD'))['tarball_sha256'])")"
sha_actual="$(sha256sum "$TMPDIR/v11-2503-rootfs.tar" | awk '{print $1}')"
[ "$sha_in_record" = "$sha_actual" ]

# Idempotent re-run
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"
docker image inspect "$STABLE_REF" >/dev/null

echo "T1 passed"
