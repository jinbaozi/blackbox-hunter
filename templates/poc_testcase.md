# PoC Test Case

## Finding

- ID: `<finding_id>`
- Title: `<title>`
- Target binary: `<binary>`

## Preconditions

List files, environment variables, and command arguments required to exercise the finding.

## Execution

```bash
# Runs inside the PoC sandbox as user poctest.
<command>
```

## Expected Verification Signal

Describe the crash, error, unsafe behavior, or sanitized non-reproduction signal.

## Safety Notes

Do not enable network access. Do not write outside mounted scratch paths.
