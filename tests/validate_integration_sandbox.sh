#!/bin/bash
set -euo pipefail

bash tests/integration/test_sandbox_run_safe.sh

echo "Sandbox integration validation completed."
