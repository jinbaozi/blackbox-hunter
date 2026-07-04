#!/bin/bash
set -euo pipefail

python3 -m py_compile \
  tools/preflight.py \
  tools/bbh_scan.py \
  tools/track_a_runner.py \
  tools/workflow_state.py \
  tools/adapters/base.py \
  tools/adapters/checksec.py \
  tools/adapters/cve_bin_tool.py \
  tools/adapters/cwe_checker.py \
  tools/adapters/dependency_parser.py \
  tools/adapters/lintian.py \
  tools/adapters/rpmlint.py \
  tools/adapters/yara_scan.py \
  tools/context/action_gate.py \
  tools/context/context_manifest.py \
  tools/context/evidence_trimmer.py \
  tools/context/injection_filter.py \
  tools/context/prompt_builder.py \
  tools/context/token_budget.py \
  tools/context/track_b_output_mapper.py \
  tools/merge/confidence_scoring.py \
  tools/merge/merge_runner.py \
  tools/report/report_generator.py \
  sandbox/result_interpreter.py

echo "Python compile validation passed."
