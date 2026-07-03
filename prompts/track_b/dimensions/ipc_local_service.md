# Dimension: ipc_local_service

## Goal

Review local service and IPC boundaries including Unix sockets, DBus, shared memory, localhost services, systemd activation, and local management interfaces.

## Sources

- Unix socket messages
- DBus methods
- local HTTP requests
- shared memory fields
- systemd socket activation
- CLI tools that talk to local daemons

## Review Targets

- authentication and authorization checks
- socket filesystem permissions
- message parsing
- method dispatch
- localhost-only assumptions
- service user and privilege boundaries

## Emit Finding Gate

Emit a finding only when a local or lower-privilege actor can influence an IPC operation without adequate authentication, authorization, parsing, or permission controls.

## Reject Conditions

- Do not report local IPC existence alone.
- Do not report when socket or method access is restricted to the intended trust boundary.
- Do not report localhost binding without a concrete cross-boundary impact.
