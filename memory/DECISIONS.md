# Mercado Libre Bug Bounty Research Agent - Key Decisions

## Architectural and Implementation Decisions

### Decision: Fail-Closed Authorization Design
**Date**: 2026-10-13 (Phase 2.6 implementation)
**Decision**: Implement authorization gate that defaults to DENY, requiring explicit external program authorization AND human approval
**Reason**: 
- Addresses critical flaw where authorization gate was documented but not technically enforced
- Prevents unauthorized security testing by default
- Aligns with security best practices of default deny
- Ensures no network requests or active testing occurs without proper authorization
**Verification**: All assessment scripts check authorization before HTTP requests; 31/31 tests passing

### Decision: Dual Authorization Requirement
**Date**: 2026-10-13 (Phase 2.6 implementation)
**Decision**: Require BOTH external program authorization from Mercado Libre AND human approval from security researcher
**Reason**: 
- Provides defense-in-depth authorization control
- External authorization ensures program-level approval
- Human approval ensures researcher-level accountability
- Prevents single point of failure in authorization process
**Verification**: Gate returns REQUIRE_EXTERNAL_AUTHORIZATION or REQUIRE_HUMAN_APPROVAL when either is missing

### Decision: Production Testing Protection
**Date**: 2026-10-13 (Phase 2.6 implementation)
**Decision**: Explicitly disable production testing by default with strict validation requirements
**Reason**: 
- Prevents accidental testing against production systems
- Aligns with bug bounty program safety requirements
- Requires explicit policy authorization for any production testing
**Verification**: production_testing_enabled: false in gate; _validate_production_testing() enforces restrictions

### Decision: Append-Only JSONL Decision Logging
**Date**: 2026-10-13 (Phase 2.6 implementation)
**Decision**: Use JSONL (JSON Lines) format for authorization decision logs in daily files
**Reason**: 
- Append-only format prevents modification of existing entries
- JSONL is parseable by standard tools and allows structured querying
- Daily files prevent excessive file size and enable easy archival
- Logs non-sensitive data for audit trail without compromising privacy
**Verification**: Logs written to logs/authorization-decisions/auth_decisions_YYYY-MM-DD.jsonl; verified append-only behavior

### Decision: Cryptographic Authorization Provenance Framework
**Date**: 2026-10-13 (Phase 2.8 remediation)
**Decision**: Design framework for cryptographic signature verification rather than implementing unverifiable claims
**Reason**: 
- Cannot include private keys in repository for security reasons
- Cannot generate realistic approval signatures without access to private keys
- Framework provides clear path to implementation when trusted keys are available
- Maintains fail-closed behavior: if verification fails or keys missing, authorization denied
**Verification**: Design documented in reports/authorization-provenance-design.md with clear trust model and verification process

### Decision: Behavioral Testing with Mocked Network Functions
**Date**: 2026-10-13 (Phase 2.8 remediation)
**Decision**: Create test matrix using mocked network functions to verify actual runtime behavior
**Reason**: 
- Static source code inspection does not verify runtime behavior
- Behavioral tests with mocks prove authorization gate actually prevents network calls
- Maintains passive reconnaissance only requirement (no actual network calls during testing)
- Provides concrete evidence of authorization enforcement effectiveness
**Verification**: Test matrix in reports/network-enforcement-test-matrix.md with detailed test cases and verification methods

### Decision: Honest Documentation of Security Properties
**Date**: 2026-10-13 (Phase 2.8 remediation)
**Decision**: Remove overstated claims and accurately document actual security properties and limitations
**Reason**: 
- Previous claims of "tamper-resistant" logging were misleading without cryptographic guarantees
- Transparency about limitations builds trust and enables proper risk assessment
- Users can make informed decisions based on actual capabilities
- Aligns with security best practices of honest security documentation
**Verification**: Updated documentation in phase-2.8-remediation-report.md accurately describes logging integrity as append-only with file-system-dependent integrity

## Security Rule Decisions

### Rule: No Testing Without Explicit Authorization
**Date**: Ongoing (foundational principle)
**Rule**: All security testing requires explicit authorization via scope validation
**Reason**: 
- Fundamental requirement of ethical security research and bug bounty programs
- Prevents legal and ethical violations
- Core to the agent's purpose as an authorized security research assistant
**Enforcement**: Authorization gate blocks all network requests without proper authorization

### Rule: Passive Reconnaissance Only for Initial Information Gathering
**Date**: Ongoing (foundational principle)
**Rule**: Initial information gathering must be purely passive
**Reason**: 
- Prevents accidental or premature active testing
- Allows scope validation before any potentially disruptive activities
- Aligns with responsible security research methodologies
**Enforcement**: Assessment scripts check authorization before any network requests; passive reconnaissance functions respect authorization decisions

### Rule: Sandbox/Test Environments Only for Payment Testing
**Date**: Ongoing (foundational principle)
**Rule**: Payment testing must be in sandbox/test environments only
**Reason**: 
- Prevents disruption of real payment systems
- Protects against financial liability
- Aligns with standard bug bounty program restrictions
**Enforcement**: Payment security assessment script validates environment and requires explicit authorization

### Rule: Rate Limit Compliance
**Date**: Ongoing (foundational principle)
**Rule**: Adhere to all program-specified rate limits and restrictions
**Reason**: 
- Prevents denial of service conditions
- Shows respect for target systems
- Required by most bug bounty programs
**Enforcement**: Assessment scripts include rate limiting in _respectful_request() wrappers

### Rule: Data Privacy and Minimization
**Date**: Ongoing (foundational principle)
**Rule**: Do not collect, retain, or transmit sensitive data unnecessarily
**Reason**: 
- Protects user privacy and reduces attack surface
- Aligns with data protection principles and regulations
- Minimizes potential impact of any security issues
**Enforcement**: Authorization logging intentionally omits sensitive data like IPs, user agents unless explicitly needed and sanitized

---
*This document will be updated with new decisions as they are made throughout the project lifecycle*