# Network Enforcement Test Matrix

## Overview
This document provides a comprehensive matrix of behavioral tests that verify the authorization gate actually prevents network calls when authorization is missing or invalid. These tests go beyond static source code analysis to verify runtime behavior with mocked network functions.

## Test Philosophy
Behavioral tests verify that the authorization gate functions correctly at runtime by:
1. Mocking network functions to detect actual calls
2. Testing various authorization states (valid, missing, invalid)
3. Verifying that network calls are prevented when authorization fails
4. Ensuring network calls proceed only when proper authorization is present

## Test Matrix

### Test Categories
1. **Authorization Gate Unit Tests** - Test the gate in isolation
2. **Assessment Script Integration Tests** - Test network prevention in each script
3. **Scope Checker Integration Tests** - Test authorization integration with scope validation
4. **Edge Case and Failure Mode Tests** - Test boundary conditions and error handling

## Detailed Test Cases

### 1. Authorization Gate Unit Tests
*Tests the AuthorizationGate class directly with mocked network detection*

| Test ID | Description | Setup | Expected Behavior | Verification Method |
|---------|-------------|-------|-------------------|---------------------|
| NET-UNIT-001 | Default deny with no authorizations | No external auth, no human approval | `check_authorization()` returns `DENY` with `REQUIRE_EXTERNAL_AUTHORIZATION` | Mock network function - should not be called |
| NET-UNIT-002 | Missing external authorization | Valid human approval, no external auth | `check_authorization()` returns `DENY` with `REQUIRE_EXTERNAL_AUTHORIZATION` | Mock network function - should not be called |
| NET-UNIT-003 | Missing human approval | Valid external auth, no human approval | `check_authorization()` returns `DENY` with `REQUIRE_HUMAN_APPROVAL` | Mock network function - should not be called |
| NET-UNIT-004 | Valid authorization | Valid external auth + valid human approval (matching) | `check_authorization()` returns `APPROVE` | Mock network function - should be allowed to proceed |
| NET-UNIT-005 | Asset mismatch | Valid auths but asset doesn't match | `check_authorization()` returns `DENY` with "Asset mismatch" | Mock network function - should not be called |
| NET-UNIT-006 | Technique mismatch | Valid auths but technique not permitted | `check_authorization()` returns `DENY` with "Technique not permitted" | Mock network function - should not be called |
| NET-UNIT-007 | Environment mismatch | Valid auths but environment doesn't match | `check_authorization()` returns `DENY` with "Environment mismatch" | Mock network function - should not be called |
| NET-UNIT-008 | Expired human approval | Valid external auth + expired human approval | `check_authorization()` returns `DENY` (during loading) | Mock network function - should not be called |
| NET-UNIT-009 | Wrong activity in human approval | Valid external auth + human approval with wrong activity | `check_authorization()` returns `DENY` with "Human approval activity mismatch" | Mock network function - should not be called |
| NET-UNIT-010 | Malformed gate file | Corrupted JSON in gate file | System exits with error message | No network functions should be called |
| NET-UNIT-011 | Missing gate file | No authorization-gate.json file | System exits with error message | No network functions should be called |

### 2. Assessment Script Integration Tests
*Tests each assessment script to verify network calls are prevented*

| Test ID | Script | Description | Setup | Expected Behavior | Verification Method |
|---------|--------|-------------|-------|-------------------|---------------------|
| NET-INT-001 | authz-audit-assessment.py | Test method call with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-002 | authz-audit-assessment.py | Test method call with missing external auth | Valid human approval, no external auth | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-003 | authz-audit-assessment.py | Test method call with missing human approval | Valid external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-004 | authz-audit-assessment.py | Test method call with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `_make_request()` - should be called |
| NET-INT-005 | authz-audit-assessment.py | Test method call with asset mismatch | Valid auths but wrong asset | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-006 | api-security-assessment.py | Test endpoint call with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-007 | api-security-assessment.py | Test endpoint call with missing external auth | Valid human approval, no external auth | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-008 | api-security-assessment.py | Test endpoint call with missing human approval | Valid external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-009 | api-security-assessment.py | Test endpoint call with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `_make_request()` - should be called |
| NET-INT-010 | api-security-assessment.py | Test endpoint call with technique mismatch | Valid auths but wrong technique | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-011 | auth-audit-assessment.py | Test login endpoint with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-012 | auth-audit-assessment.py | Test login endpoint with missing external auth | Valid human approval, no external auth | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-013 | auth-audit-assessment.py | Test login endpoint with missing human approval | Valid external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-014 | auth-audit-assessment.py | Test login endpoint with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `_make_request()` - should be called |
| NET-INT-015 | auth-audit-assessment.py | Test login endpoint with environment mismatch | Valid auths but wrong environment | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-016 | payment-security-assessment.py | Test payment endpoint with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-017 | payment-security-assessment.py | Test payment endpoint with missing external auth | Valid human approval, no external auth | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-018 | payment-security-assessment.py | Test payment endpoint with missing human approval | Valid external auth, no human approval | `_respectful_request()` returns `None` | Mock `_make_request()` - should not be called |
| NET-INT-019 | payment-security-assessment.py | Test payment endpoint with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `_make_request()` - should be called |
| NET-INT-020 | payment-security-assessment.py | Test payment endpoint with production testing disabled | Valid auths but `production_testing_enabled: false` | `_respectful_request()` returns `None` for production env | Mock `_make_request()` - should not be called |
| NET-INT-021 | passive-reconnaissance.py | Test certificate transparency check with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `urllib.request.urlopen` - should not be called |
| NET-INT-022 | passive-reconnaissance.py | Test web archives check with no authorizations | No external auth, no human approval | `_respectful_request()` returns `None` | Mock `urllib.request.urlopen` - should not be called |
| NET-INT-023 | passive-reconnaissance.py | Test certificate transparency check with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `urllib.request.urlopen` - should be called |
| NET-INT-024 | passive-reconnaissance.py | Test web archives check with valid authorization | Valid external auth + valid human approval | `_respectful_request()` proceeds normally | Mock `urllib.request.urlopen` - should be called |

### 3. Scope Checker Integration Tests
*Tests scope checker authorization integration*

| Test ID | Description | Setup | Expected Behavior | Verification Method |
|---------|-------------|-------|-------------------|---------------------|
| NET-SCOPE-001 | Legacy check_target with no authorizations | No external auth, no human approval | Returns `False` (deny) | No network calls in assessment scripts |
| NET-SCOPE-002 | Legacy check_target with missing external auth | Valid human approval, no external auth | Returns `False` (deny) | No network calls in assessment scripts |
| NET-SCOPE-003 | Legacy check_target with missing human approval | Valid external auth, no human approval | Returns `False` (deny) | No network calls in assessment scripts |
| NET-SCOPE-004 | Legacy check_target with valid authorization | Valid external auth + valid human approval | Returns `True` (allow) | Network calls proceed in assessment scripts |
| NET-SCOPE-005 | New check_target_authorization with asset mismatch | Valid auths but wrong asset | Returns `AuthorizationDecision.DENIED` | Assessment scripts receive deny and don't call network |
| NET-SCOPE-006 | New check_target_authorization with technique mismatch | Valid auths but wrong technique | Returns `AuthorizationDecision.DENIED` | Assessment scripts receive deny and don't call network |
| NET-SCOPE-007 | New check_target_authorization with environment mismatch | Valid auths but wrong environment | Returns `AuthorizationDecision.DENIED` | Assessment scripts receive deny and don't call network |
| NET-SCOPE-008 | New check_target_authorization with valid authorization | Valid external auth + valid human approval (matching) | Returns `AuthorizationDecision.APPROVED` | Assessment scripts proceed with network calls |
| NET-SCOPE-009 | Automatic method selection - passes activity/technique/environment | Valid auths + matching parameters | Returns `AuthorizationDecision.APPROVED` | Network calls proceed |
| NET-SCOPE-010 | Automatic method selection - fails activity/technique/environment | Valid auths + mismatched parameters | Returns `AuthorizationDecision.DENIED` | Network calls blocked |

### 4. Edge Case and Failure Mode Tests
*Tests boundary conditions and error handling*

| Test ID | Description | Setup | Expected Behavior | Verification Method |
|---------|-------------|-------|-------------------|---------------------|
| NET-EDGE-001 | Concurrent authorization checks | Multiple threads checking auth simultaneously | Thread-safe behavior, consistent results | No race conditions in network call prevention |
| NET-EDGE-002 | Malformed JSON in gate file | Invalid JSON syntax | System exits with clear error | No partial network calls before exit |
| NET-EDGE-003 | Missing required fields in gate | Missing policy_version, approved_asset, etc. | System exits with validation error | No network calls attempted |
| NET-EDGE-004 | Network timeout simulation | Slow network response simulation | Authorization checked before timeout | No network calls made if auth fails |
| NET-EDGE-005 | Large payload handling | Large JSON in gate file | Proper parsing and validation | Network calls prevented if validation fails |
| NET-EDGE-006 | Unicode and special characters | Unicode in asset names, special chars in rationale | Proper handling and validation | Network calls blocked on validation failure |
| NET-EDGE-007 | Clock skew handling | Timestamps with reasonable clock skew | Proper expiration validation | Expired approvals blocked despite clock skew |
| NET-EDGE-008 | Empty restrictions array | Valid auths with empty restrictions | Should work normally (no restrictions) | Network calls proceed with valid auths |
| NET-EDGE-009 | Wildcard asset matching | Exact matching only (no wildcards) | Subdomain mismatch should be denied | Network calls blocked for subdomain mismatch |
| NET-EDGE-010 | Case sensitivity testing | Case-sensitive matching for asset/technique | "Example.COM" != "example.com" | Network calls blocked on case mismatch |

## Test Implementation Approach

### Mocking Strategy
For all behavioral tests, we will mock network functions at the appropriate level:

1. **urllib.request.urlopen** - Mocked in assessment scripts and passive reconnaissance
2. **Internal request functions** - Mocked `_make_request()` and `_respectful_request()` methods
3. **Authorization gate functions** - Mocked `check_authorization()` for testing integration points

### Test Framework
Using Python's unittest.mock framework:
- `patch()` decorator/context manager for mocking
- `Mock` and `MagicMock` objects for simulating network responses
- `call_count` and `call_args_list` for verifying mock invocation
- `side_effect` for simulating exceptions and delays

### Verification Metrics
Each test will verify:
1. **Authorization Decision** - Correct deny/approve decision returned
2. **Network Call Prevention** - Mocked network functions not called when authorization fails
3. **Network Call Permission** - Mocked network functions called when authorization succeeds
4. **Error Handling** - Proper exceptions or return values on failure
5. **Logging Integrity** - Appropriate authorization decisions logged

## Test Data Samples

### Valid External Authorization Sample
```json
{
  "policy_source": "https://hackerone.com/mercadolibre",
  "policy_version": "1.0.0",
  "policy_last_updated": "2026-10-01T00:00:00Z",
  "approved_asset": "api.mercadolibre.com",
  "permitted_technique": "GET",
  "environment": "sandbox",
  "restrictions": ["rate_limit:10/r/min"],
  "verification_date": "2026-10-01T00:00:00Z",
  "policy_reference": "https://hackerone.com/mercadolibre/program"
}
```

### Valid Human Approval Sample
```json
{
  "approver_id": "security-researcher-001",
  "approval_timestamp": "2026-10-01T10:00:00Z",
  "expiration_timestamp": "2026-10-02T10:00:00Z",
  "asset": "api.mercadolibre.com",
  "activity": "api-security-testing",
  "technique": "GET",
  "environment": "sandbox",
  "rationale": "Testing API endpoint for IDOR vulnerability as part of authorized bug bounty research",
  "external_authorization_reference": "policy_v1.0.0_api_mercadolibre_com"
}
```

## Pass/Fail Criteria

### Pass Conditions
1. When authorization is **DENIED**: Network mock functions must have `call_count == 0`
2. When authorization is **APPROVED**: Network mock functions must be called as expected
3. Error conditions must produce appropriate return values or exceptions
4. Logging must record the correct authorization decision and reason

### Fail Conditions
1. When authorization is **DENIED** but network mock functions are called (`call_count > 0`)
2. When authorization is **APPROVED** but network mock functions are not called when expected
3. System crashes or unhandled exceptions during testing
4. Incorrect authorization decisions returned
5. Missing or incorrect audit log entries

## Implementation Notes

These tests will be implemented in the test suite to provide concrete evidence that:
1. The authorization gate actually prevents network calls when it should
2. Network calls are only permitted when proper authorization is present
3. All assessment scripts properly integrate with the authorization gate
4. The scope checker correctly enforces authorization constraints

The tests will use clearly mocked network functions to ensure no actual network calls are made during testing, maintaining compliance with the passive reconnaissance only requirement.