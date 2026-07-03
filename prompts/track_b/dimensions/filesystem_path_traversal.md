# Dimension: filesystem_path_traversal

## Goal

Review path construction, archive extraction paths, temporary files, symlinks, file permissions, and path normalization for unsafe filesystem behavior.

## Sources

- CLI file paths
- config paths
- archive entry names
- protocol path fields
- environment variables
- package scripts

## Review Targets

- path joins and normalization
- relative path segments
- symlink-sensitive operations
- temporary file creation
- permission changes
- file writes under privileged services

## Emit Finding Gate

Emit a finding only when external or low-privilege input can influence a sensitive path operation without adequate normalization, allowlisting, or permission control.

## Reject Conditions

- Do not report path manipulation without a sensitive operation.
- Do not report when paths are fixed, internal, or administrative-only.
- Do not report if canonicalization and allowlisting clearly protect the operation.
