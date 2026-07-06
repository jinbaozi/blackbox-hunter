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
HAD_STABLE_REF=0
HAD_CONTENT_REF=0
STABLE_IMAGE_ID=""

ENGINE=""
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
        ENGINE="$candidate"
        break
    fi
done
[ -n "$ENGINE" ] || { echo "BLOCKED: no reachable docker or podman engine"; exit 77; }

if "$ENGINE" image inspect "$STABLE_REF" >/dev/null 2>&1; then
    HAD_STABLE_REF=1
    STABLE_IMAGE_ID="$($ENGINE image inspect --format '{{.Id}}' "$STABLE_REF")"
fi
if "$ENGINE" image inspect "$CONTENT_REF" >/dev/null 2>&1; then
    HAD_CONTENT_REF=1
fi

restore() {
    rm -rf "$TMPDIR"
    if [ "$HAD_STABLE_REF" -eq 1 ] && [ -n "$STABLE_IMAGE_ID" ]; then
        "$ENGINE" tag "$STABLE_IMAGE_ID" "$STABLE_REF" >/dev/null 2>&1 || true
    else
        "$ENGINE" rmi -f "$STABLE_REF" >/dev/null 2>&1 || true
    fi
    if [ "$HAD_CONTENT_REF" -eq 0 ]; then
        "$ENGINE" rmi -f "$CONTENT_REF" >/dev/null 2>&1 || true
    fi
}
trap restore EXIT

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
