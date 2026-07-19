# Rule Engine Internals

This document describes the high-level rule execution model for maintainers.

## Pipeline

```text
raw event -> normalized event -> provenance edge -> policy match -> correlation -> alert workflow
```

## Rule Inputs

Rules can use:

- process metadata
- file paths and operations
- network endpoints
- container context
- provenance relationships
- taint labels
- whitelist state

## Matching

Simple matches evaluate the current event or graph relation. Correlation rules evaluate related activity within a configured time window.

Example:

```text
curl writes /tmp/file
  -> bash reads /tmp/file within 5m
  -> alert
```

## Severity and Scoring

Severity is assigned by the rule, analyzer, or incident scoring layer. Downstream delivery may filter on minimum severity.

## Whitelists

Whitelists should be applied narrowly:

- process name
- path prefix
- host group
- maintenance window

Every whitelist entry should include a reason and owner.

## Rollout

Policy publish creates a versioned bundle. Agents acknowledge the desired policy version through telemetry, allowing operators to identify drift before relying on the new rule set.
