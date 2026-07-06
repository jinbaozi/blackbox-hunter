#!/bin/bash
# E2E T1: import_rootfs.py imports the tarball and re-tags to stable alias.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t1-$$"
STABLE_REF="bbh-base:local-imported"
RECORD="$TMPDIR/imported_rootfs.json"

mkdir -p "$TMPDIR"
cp "$ROOT/assets/rootfs/v11-2503-rootfs.tar" "$TMPDIR/v11-2503-rootfs.tar"
sha_actual="$(sha256sum "$TMPDIR/v11-2503-rootfs.tar" | awk '{print $1}')"
CONTENT_REF="bbh-base:local-${sha_actual:0:12}"

ENGINE=""
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
        ENGINE="$candidate"
        break
    fi
done
[ -n "$ENGINE" ] || { echo "no reachable docker or podman engine"; exit 1; }

trap 'rm -rf "$TMPDIR"; "$ENGINE" rmi -f "$STABLE_REF" "$CONTENT_REF" >/dev/null 2>&1 || true' EXIT

# First import
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"

"$ENGINE" image inspect "$STABLE_REF" >/dev/null

test -f "$RECORD"
sha_in_record="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['tarball_sha256'])" "$RECORD")"
[ "$sha_in_record" = "$sha_actual" ]

# Idempotent re-run
python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$TMPDIR/v11-2503-rootfs.tar" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"
"$ENGINE" image inspect "$STABLE_REF" >/dev/null

echo "T1 passed"
