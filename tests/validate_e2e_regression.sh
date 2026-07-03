#!/bin/bash
set -euo pipefail

bash tests/e2e/minimal_deb_quick.sh
bash tests/e2e/track_b_prompt_build.sh

echo "E2E regression validation passed."
