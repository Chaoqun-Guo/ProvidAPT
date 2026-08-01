# Bug Tracker

This document tracks notable repository bugs and their current status.

## Status Legend

| Status | Meaning |
| --- | --- |
| Open | Confirmed and not fixed yet |
| In Progress | Fix is underway |
| Fixed | Resolved and validated |
| Needs Triage | Requires more investigation |

## Recently Fixed

### BUG-001: Persistent HMAC key handling

- **Status**: Fixed
- **Component**: `pkg/secure/merkle.go`
- **Severity**: High
- **Summary**: HMAC keys were not persisted across restarts

### BUG-002: Credential tracker deadlock

- **Status**: Fixed
- **Component**: `internal/engine/provenance/credential.go`
- **Severity**: Critical
- **Summary**: Recursive graph locking could block `AddEvent` execution

### BUG-003: Windows path normalization in supply-chain detection

- **Status**: Fixed
- **Component**: `internal/policy/supplychain/monitor.go`
- **Severity**: Medium
- **Summary**: Windows path separators caused inconsistent matching

### BUG-004: SPDX import guardrails

- **Status**: Fixed
- **Component**: `internal/policy/supplychain/sbom.go`
- **Severity**: High
- **Summary**: Empty SPDX records could trigger downstream failures

### BUG-005: Supply-chain severity calibration

- **Status**: Fixed
- **Component**: `internal/policy/supplychain/detector.go`
- **Severity**: Medium
- **Summary**: Untrusted write severity did not reflect actual risk

## Known Follow-Ups

| ID | Area | Status | Note |
| --- | --- | --- | --- |
| FOLLOWUP-001 | historical test scripts | In Progress | legacy validation scripts are being normalized to the current binary and command names |
| FOLLOWUP-002 | older benchmark/editorial pages | Fixed | obsolete root progress logs removed and documentation indexes refreshed |

## Last Updated

- 2026-08-01
