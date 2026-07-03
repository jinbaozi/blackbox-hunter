#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.context.prompt_builder import build_track_b_prompt  # noqa: E402
from tools.context.token_budget import (  # noqa: E402
    TokenUsageRecord,
    append_token_usage,
    estimate_tokens,
    read_token_usage,
)


def evidence_for_dimension(dimension: str) -> dict:
    return {
        "binary": "/usr/bin/demo",
        "dimension": dimension,
        "function": "parse_request",
        "body_excerpt": "bounded excerpt only",
        "supporting_files": [f"raw/track_b/demo/{dimension}.json"],
        "omitted": {"raw/track_b/demo/full.txt": "full artifact retained on disk"},
        "truncated": True,
    }


def test_quick_mode_dimensions_stay_within_budget() -> None:
    for dimension in ["dangerous_functions", "hardcoded_config"]:
        built = build_track_b_prompt(
            root=ROOT,
            manifest_path=ROOT / "prompts/track_b/manifest.json",
            context_policy_path=ROOT / "tools/context/context_policy.json",
            dimension=dimension,
            evidence_json=evidence_for_dimension(dimension),
            mode="quick",
        )
        assert built.estimated_tokens <= built.max_prompt_tokens
        assert built.max_prompt_tokens <= 3000


def test_estimate_tokens_is_monotonic() -> None:
    assert estimate_tokens("abcd") <= estimate_tokens("abcd" * 100)


def test_token_ledger_jsonl_round_trip(tmp_path: Path | None = None) -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "token_usage.jsonl"
        append_token_usage(
            path,
            TokenUsageRecord(
                scan_id="BBH-20260703-a1b2c3",
                phase="track_b",
                dimension="dangerous_functions",
                target="/usr/bin/demo",
                function="parse_request",
                prompt_tokens_estimated=1200,
                cached_tokens=512,
                context_profile="track_b.v1.dangerous_functions",
            ),
        )
        records = read_token_usage(path)
        assert len(records) == 1
        assert records[0]["cached_tokens"] == 512
        assert records[0]["recorded_at"]


def run_all() -> None:
    test_quick_mode_dimensions_stay_within_budget()
    test_estimate_tokens_is_monotonic()
    test_token_ledger_jsonl_round_trip()


if __name__ == "__main__":
    run_all()
    print("Track B prompt budget tests OK")
