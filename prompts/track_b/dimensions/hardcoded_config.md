# Dimension: hardcoded_config

## Goal

Identify hardcoded credentials, weak secrets, insecure defaults, debug behavior, exposed management endpoints, and dangerous configuration choices.

## Sources

- strings output
- config files
- scripts
- service units
- embedded certificates or keys
- default account names

## Review Targets

- private keys or API tokens
- default passwords or shared secrets
- debug flags
- bind-all interfaces
- disabled verification flags
- insecure default file permissions

## Emit Finding Gate

Emit a finding only when the value or setting is security-relevant, likely active, and tied to a component or entry point.

## Reject Conditions

- Do not report placeholder examples, test data, or documentation-only strings unless they are installed as active defaults.
- Do not report high-entropy strings without context.
- Do not report public certificates as secrets.
