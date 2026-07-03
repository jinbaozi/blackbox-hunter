# Validation: Track B Prompt Split v1

## Required Commands

```bash
python3 tests/context/test_prompt_manifest.py
bash tests/validate_prompt_manifest.sh
bash tests/validate_schemas.sh
bash tests/validate_scripts.sh
```

## Acceptance Criteria

- `prompts/track_b/manifest.json` is valid JSON.
- Base contract, evidence wrapper, output contract, and all dimension card paths exist.
- Core and extended dimensions are declared in the manifest.
- Mode defaults reference valid dimension names or manifest aliases.
- Phase 1b no longer contains inline `Prompt Template` sections.
- Phase 1b references `prompts/track_b/manifest.json` and the `Prompt Loading Contract`.
- Every dimension card is single-purpose and contains `Emit Finding Gate` and `Reject Conditions` sections.

## Manual Review Checklist

- No scan execution behavior changed.
- The phase document is shorter and orchestration-only.
- The change does not introduce runtime prompt construction yet.
- The next PR can implement prompt builder against the manifest.
