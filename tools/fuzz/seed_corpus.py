#!/usr/bin/env python3
"""B7: emit a minimal seed corpus for each attack surface.

The plan calls for ``assets/seeds/<entry>/*.seed`` with 10 small (<4 KiB)
seeds per attack-surface entry. We deliberately keep the seeds
deterministic and minimal so the test can run offline:

* For ``network`` and ``ipc`` entries: 8-byte magic + 256-byte buffer.
* For ``cli`` entries: short argv-style strings.
* For ``file`` entries: a 512-byte blob with the magic + NUL-padded data.
* For ``config`` / ``env`` / ``library`` entries: key=value pairs.

Each seed is well under 4 KiB. The corpus is regeneratable from
``target_profile.attack_surface[]`` so we don't have to ship binary
blobs in git.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


_MAX_SEED_BYTES = 4 * 1024  # 4 KiB per plan

_MAGIC = b"BBHSEED\x00"


def _pad(buf: bytes, n: int) -> bytes:
    if len(buf) >= n:
        return buf[:n]
    return buf + b"\x00" * (n - len(buf))


def _seed_for(surface_type: str, index: int) -> bytes:
    if surface_type in ("network", "ipc"):
        # 8-byte magic + 256-byte buffer that's deterministic but
        # varies per index to give the fuzzer a non-trivial starting point.
        body = _MAGIC + _pad(f"addr={index}\ndata=00".encode("ascii"), 256)
    elif surface_type == "cli":
        body = _pad(f"--input payload-{index}\n".encode("ascii"), 256)
    elif surface_type == "file":
        body = _MAGIC + _pad(f"file-seed-{index}\n".encode("ascii"), 512)
    elif surface_type in ("config", "env"):
        body = _pad(f"key{index}=value{index}\n".encode("ascii"), 256)
    else:  # library or unknown
        body = _MAGIC + _pad(f"lib-seed-{index}\n".encode("ascii"), 512)
    return body[:_MAX_SEED_BYTES]


def generate_corpus(
    target_profile: dict[str, Any],
    output_root: Path,
    *,
    seeds_per_entry: int = 10,
) -> dict[str, Any]:
    """Write 10 seeds per attack-surface entry under ``output_root``.

    Returns a manifest ``{entry_id: [seed_paths...]}``.
    """
    output_root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, list[str]] = {}
    for index, surface in enumerate(target_profile.get("attack_surface") or []):
        if not isinstance(surface, dict):
            continue
        surface_type = str(surface.get("type") or "unknown")
        entry = str(surface.get("entry_point") or f"surface-{index}")
        # Sanitize the entry point so we can use it as a directory name.
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in entry)[:48] or f"surface-{index}"
        entry_dir = output_root / safe
        entry_dir.mkdir(parents=True, exist_ok=True)
        manifest[entry] = []
        for seed_index in range(seeds_per_entry):
            seed_path = entry_dir / f"seed-{seed_index:02d}.bin"
            seed_path.write_bytes(_seed_for(surface_type, seed_index))
            # Belt-and-braces: assert the size cap in case _seed_for changes.
            assert seed_path.stat().st_size <= _MAX_SEED_BYTES, seed_path
            manifest[entry].append(str(seed_path))
    return {
        "seeds_per_entry": seeds_per_entry,
        "max_seed_bytes": _MAX_SEED_BYTES,
        "entries": manifest,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="B7 seed corpus generator")
    p.add_argument("--target-profile", required=True, help="Path to target_profile.json")
    p.add_argument("--output-root", required=True, help="Where to write the corpus")
    p.add_argument("--seeds-per-entry", type=int, default=10)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    profile = json.loads(Path(args.target_profile).read_text(encoding="utf-8"))
    manifest = generate_corpus(profile, Path(args.output_root), seeds_per_entry=args.seeds_per_entry)
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())