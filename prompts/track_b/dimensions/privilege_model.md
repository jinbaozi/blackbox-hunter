# Dimension: privilege_model

## Goal

Review setuid/setgid binaries, Linux capabilities, root services, privileged file operations, and privilege drop behavior for boundary mistakes.

## Sources

- CLI arguments
- config files
- service units
- environment variables
- local IPC messages
- package maintainer scripts

## Review Targets

- setuid/setgid execution paths
- service startup users and permissions
- capability use
- sensitive path reads or writes
- privilege drop and regain logic
- authorization checks before privileged operations

## Emit Finding Gate

Emit a finding only when low-privilege or external input can influence a privileged operation without adequate authorization, path control, or privilege separation.

## Reject Conditions

- Do not report privileged execution alone.
- Do not report when the path is administrative-only and not externally influenced.
- Do not report when privilege drop and authorization checks clearly dominate the operation.
