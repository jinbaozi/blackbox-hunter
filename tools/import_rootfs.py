#!/usr/bin/env python3
"""Import the canonical rootfs tarball as a local Docker image.

Idempotent. Produces two tags:
  - <tag-prefix>:local-<12-char-sha>   (content-addressed)
  - <tag-prefix>:local-imported        (stable alias for Dockerfile.poc)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

# Default size sanity bounds (in bytes).
MIN_TARBALL_BYTES = 100 * 1024 * 1024        # 100 MB
MAX_TARBALL_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB


def now_iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], *, stdin_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        stdin=subprocess.PIPE if stdin_path else None,
        capture_output=True,
        text=True,
        check=False,
    )


def docker_engine() -> str:
    for engine in ("docker", "podman"):
        path = shutil.which(engine)
        if path is None:
            continue
        result = run([engine, "info"])
        if result.returncode == 0:
            return engine
    print("ERROR: neither docker nor podman is available or its daemon is reachable", file=sys.stderr)
    sys.exit(2)


def image_inspect(engine: str, ref: str) -> bool:
    result = run([engine, "image", "inspect", ref])
    return result.returncode == 0


def import_image(engine: str, tarball: Path, target_ref: str) -> None:
    with tarball.open("rb") as fh:
        result = subprocess.run(
            [engine, "import", "-", target_ref],
            stdin=fh,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        print(f"ERROR: {engine} import failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(3)


def tag_image(engine: str, src_ref: str, dst_ref: str) -> None:
    result = run([engine, "tag", src_ref, dst_ref])
    if result.returncode != 0:
        print(f"ERROR: {engine} tag {src_ref} -> {dst_ref} failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(4)


def write_record(record_path: Path, *, tarball_sha: str, image_ref: str, stable_ref: str) -> None:
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(
        json.dumps(
            {
                "tarball_sha256": tarball_sha,
                "image_ref": image_ref,
                "stable_ref": stable_ref,
                "imported_at": now_iso(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tarball", required=True, type=Path)
    parser.add_argument("--tag-prefix", default="bbh-base")
    parser.add_argument("--record-path", type=Path, default=Path("tools/.imported_rootfs.json"))
    args = parser.parse_args()

    tarball: Path = args.tarball.resolve()
    if not tarball.is_file():
        print(f"ERROR: tarball not found: {tarball}", file=sys.stderr)
        sys.exit(5)

    size = tarball.stat().st_size
    if size < MIN_TARBALL_BYTES or size > MAX_TARBALL_BYTES:
        mb = size // (1024 * 1024)
        print(
            f"ERROR: tarball size {mb} MB out of expected range "
            f"[100 MB, 2 GB]. Verify the source file.",
            file=sys.stderr,
        )
        sys.exit(6)

    engine = docker_engine()
    sha = sha256_of(tarball)
    short = sha[:12]
    target_ref = f"{args.tag_prefix}:local-{short}"
    stable_ref = f"{args.tag_prefix}:local-imported"

    if not image_inspect(engine, target_ref):
        import_image(engine, tarball, target_ref)
    else:
        print(f"reusing existing image {target_ref}")

    tag_image(engine, target_ref, stable_ref)
    if not image_inspect(engine, stable_ref):
        print(f"ERROR: tag step failed: {stable_ref} not visible after docker tag", file=sys.stderr)
        sys.exit(7)

    write_record(args.record_path, tarball_sha=sha, image_ref=target_ref, stable_ref=stable_ref)
    print(f"imported {tarball.name} as {stable_ref} (sha {short})")


if __name__ == "__main__":
    main()
