# Dimension: crypto_tls_auth

## Goal

Review cryptographic, TLS, certificate, session, token, and authentication behavior for unsafe defaults or missing verification.

## Sources

- config files
- command-line flags
- environment variables
- embedded strings
- TLS setup functions
- authentication handlers

## Review Targets

- disabled certificate verification
- weak protocol or cipher configuration
- hardcoded trust anchors or shared secrets
- token creation and validation
- session lifetime and randomness
- authentication bypass logic

## Emit Finding Gate

Emit a finding only when evidence ties the behavior to an active runtime path, default setting, or reachable authentication flow.

## Reject Conditions

- Do not report algorithm names without usage context.
- Do not report test certificates unless installed as active trust material.
- Do not report debug-only branches unless they are reachable in production configuration.
