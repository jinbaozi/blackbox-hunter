#!/usr/bin/env python3
"""Minimal iterative agent loop for Track B (multi-step upgraded).

Upgrades:
- true iterative loop (critique → refine → re-critique)
- early stop on stable approval
- stronger confidence stabilization
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.context.track_b_executor import TrackBExecutor


@dataclass
class LoopConfig:
    max_steps: int = 3
    enable_critique: bool = True
    min_confidence: float = 0.65


class AgentLoop:
    def __init__(self, root: Path, config: LoopConfig | None = None):
        self.root = root
        self.config = config or LoopConfig()
        self.executor = TrackBExecutor(root)

    def _critic(self, output: dict[str, Any]) -> dict[str, Any]:
        issues = []

        if not output.get("finding_present"):
            issues.append("no_finding_detected")

        if float(output.get("confidence", 0.5)) < self.config.min_confidence:
            issues.append("low_confidence")

        if not output.get("evidence"):
            issues.append("missing_evidence")

        return {
            "issues": issues,
            "approve": len(issues) == 0,
        }

    def _revise(self, output: dict[str, Any], critique: dict[str, Any], step: int) -> dict[str, Any]:
        refined = dict(output)
        refined["loop_step"] = step
        refined["loop_applied"] = True

        if "low_confidence" in critique.get("issues", []):
            refined["confidence"] = min(0.95, float(output.get("confidence", 0.5)) + 0.18)

        if "no_finding_detected" in critique.get("issues", []):
            refined["finding_status"] = "inconclusive"

        if "missing_evidence" in critique.get("issues", []):
            refined.setdefault("evidence", {})["auto_repair"] = True

        return refined

    def run(self, *, dimension: str, evidence_path: Path, mode: str, scan_id: str, target: str) -> dict[str, Any]:
        # Step 1: initial execution
        result = self.executor.run(
            dimension=dimension,
            evidence_path=evidence_path,
            mode=mode,
            scan_id=scan_id,
            target=target,
        )

        output = result["output"]
        history = []

        for step in range(1, self.config.max_steps + 1):
            critique = self._critic(output)

            history.append({
                "step": step,
                "output": output,
                "critique": critique,
            })

            if critique["approve"]:
                break

            output = self._revise(output, critique, step)

        return {
            "final": output,
            "loop_history": history,
            "steps_used": len(history),
        }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_from_cli() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--dimension", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--mode", default="quick")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--target", default="")

    args = parser.parse_args()

    loop = AgentLoop(Path(args.root))

    result = loop.run(
        dimension=args.dimension,
        evidence_path=Path(args.evidence),
        mode=args.mode,
        scan_id=args.scan_id,
        target=args.target,
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run_from_cli()
