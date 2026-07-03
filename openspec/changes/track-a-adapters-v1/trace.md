# Trace: Track A Adapter Framework v1

| Requirement | Implementation | Validation |
|---|---|---|
| TA-001 Tool Output Normalization | `tools/adapters/*.py` | `tests/adapters/test_track_a_adapters.py` |
| TA-002 Signal Before Finding | `templates/finding_signal.json`, adapter promotion defaults | `tests/adapters/test_track_a_adapters.py` |
| TA-003 Raw Output Preservation | `tools/adapters/base.py` and adapters | `tests/adapters/test_track_a_adapters.py` |
| TA-004 Promotion Metadata | `templates/finding_signal.json` | `tests/adapters/test_track_a_adapters.py` |
| TA-005 No Silent Parse Success | adapter warnings | fixture parser tests |
| TA-006 External Tool Independence in Tests | static fixtures under `tests/adapters/fixtures/` | `tests/validate_adapters.sh` |
