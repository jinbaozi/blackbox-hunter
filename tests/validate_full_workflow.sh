#!/bin/bash
set -euo pipefail

python3 -m py_compile tools/bbh_scan.py tools/preflight.py
bash tests/e2e/full_workflow_quick.sh

echo "Full workflow validation passed."
