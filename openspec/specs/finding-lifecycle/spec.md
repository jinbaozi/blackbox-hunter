# Finding Lifecycle Specification

## Requirement FL-001: Signal/Finding Separation

WHEN a tool reports a weak indicator such as an imported symbol, YARA hit, or string match  
THE SYSTEM SHALL represent it as a finding signal unless additional evidence promotes it.

## Requirement FL-002: Finding Status

WHEN a finding is emitted  
THE SYSTEM SHOULD include a lifecycle status such as `candidate`, `confirmed_static`, `verified`, `false_positive`, or `inconclusive`.

## Requirement FL-003: PoC Status Separation

WHEN PoC verification is performed  
THE SYSTEM SHALL use `verification.poc_status` only for the PoC state and SHALL NOT use it as the complete finding lifecycle.

## Requirement FL-004: Inconclusive Handling

WHEN evidence or environment is insufficient to prove or disprove a finding  
THE SYSTEM SHALL mark the result inconclusive rather than speculative verified or false positive.

## Requirement FL-005: Confidence Breakdown

WHEN findings are merged  
THE SYSTEM SHOULD score evidence, reachability, tool reliability, verification, and final confidence separately.
