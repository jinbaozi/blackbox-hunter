#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$PROJECT_DIR/tests/context/test_evidence_trimmer.py"
python3 "$PROJECT_DIR/tests/context/test_context_manifest.py"
python3 "$PROJECT_DIR/tests/context/test_prompt_builder.py"
python3 "$PROJECT_DIR/tests/context/test_agent_loop.py"
python3 "$PROJECT_DIR/tests/prompt_budget/test_track_b_budget.py"
