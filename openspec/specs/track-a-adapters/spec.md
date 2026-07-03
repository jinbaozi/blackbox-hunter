# Track A Adapter Specification

## Requirement TA-001: Tool Output Normalization

WHEN Track A tool output is parsed  
THE SYSTEM SHALL normalize it through a tool adapter before downstream use.

## Requirement TA-002: Signal Before Finding

WHEN output is a weak indicator such as a YARA hit, strings hit, imported symbol, generic CWE pattern, hardening gap, dependency presence, or unconfirmed CVE version match  
THE SYSTEM SHALL represent it as a `finding_signal` rather than a final finding.

## Requirement TA-003: Raw Output Preservation

WHEN an adapter emits a signal  
THE SYSTEM SHALL include the raw output path in `evidence.supporting_files`.

## Requirement TA-004: Promotion Metadata

WHEN an adapter emits a signal  
THE SYSTEM SHALL include promotion metadata describing whether Track B is required and why the signal is or is not promoted.

## Requirement TA-005: No Silent Parse Success

WHEN an adapter cannot parse a line or section  
THE SYSTEM SHALL record a warning rather than silently dropping diagnostic context.

## Requirement TA-006: External Tool Independence in Tests

WHEN adapter tests run  
THE SYSTEM SHALL use static fixtures and SHALL NOT require external scanners to be installed.
