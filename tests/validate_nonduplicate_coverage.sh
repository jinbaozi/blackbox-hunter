#!/bin/bash
set -euo pipefail

python3 tests/track_b/test_output_mapper.py
python3 tests/merge/test_merge_runner.py
python3 tests/workflow/test_resume_rerun.py
python3 tests/report/test_report_generator.py
python3 tests/sandbox/test_result_interpreter_large_output.py
python3 tests/preflight/test_interactive_approval.py
python3 tests/profile/test_complex_inventory.py

echo "Non-duplicative coverage validation passed."
