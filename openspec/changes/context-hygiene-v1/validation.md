# Validation: Context Hygiene Foundation v1

## Required Commands

```bash
python3 tests/context/test_context_policy.py
bash tests/validate_context_policy.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- `tools/context/context_policy.json` is valid JSON.
- `templates/context_policy.json` is valid JSON Schema.
- `README.md` is forbidden from default runtime context.
- `raw/**` is forbidden from default runtime context.
- untrusted evidence wrapper is required.
- Track B mode limits exist for `quick`, `standard`, `deep`, and `full`.
- allowed and forbidden runtime context entries do not overlap exactly.
- `SKILL.md` references runtime context policy and `AGENTS.md`.

## Manual Review Checklist

- The change does not alter scanning behavior.
- The change does not expand default runtime context.
- The change establishes a foundation for Track B prompt split.
