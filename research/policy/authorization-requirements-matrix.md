# Mercado Libre Bug Bounty Program - Authorization Requirements Matrix

## Purpose
This document maps the current state of authorization requirements and permissions by comparing:
1. Available information from verified-scope.json (CSV export)
2. Current configuration in authorization-gate.json
3. Missing information requiring official policy retrieval
4. Authorization status and next steps

## Matrix Legend
- ✅ **EXPLICITLY PERMITTED**: Clearly authorized in available sources
- ❌ **EXPLICITLY PROHIBITED**: Clearly forbidden in available sources
- ⚠️ **CONDITIONAL UPON APPROVAL**: Requires explicit authorization
- ❓ **NOT SPECIFIED / UNKNOWN**: Information not available in current sources
- ℹ️ **INFORMATIONAL**: Context or metadata, not an authorization requirement

## Authorization Requirements Matrix

| Requirement Category | Specific Item | Status in verified-scope.json | Status in authorization-gate.json | Authorization Status | Source/Notes |
|----------------------|---------------|-------------------------------|-----------------------------------|----------------------|--------------|
| **Program Identification** | Program Name | ✅ Available | ✅ Configured | AUTHORIZED BASELINE | Scope files |
| | Platform | ✅ Available | ✅ Configured | AUTHORIZED BASELINE | Scope files |
| | Program Description | ✅ Available | ❓ Not referenced | INFORMATIONAL | Scope files |
| **Scope Definition** | In-Scope Assets | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | 85 total records |
| | Out-of-Scope Assets | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | Exclusions listed |
| | Wildcard Domains | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | Pattern matching |
| | Mobile Applications | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | Platform-specific |
| | API Endpoints | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | Endpoint listing |
| | Other Assets (Hardware, etc.) | ✅ Complete (CSV export) | ✅ Integrated | SCOPE DEFINED | Categorized assets |
| **Eligibility Status** | Submission Eligible Assets | ✅ Complete (76/85) | ✅ Integrated | ELIGIBILITY DEFINED | Submission eligibility |
| | Bounty Eligible Assets | ✅ Complete (71/85) | ✅ Integrated | BOUNTY ELIGIBILITY DEFINED | Bounty eligibility |
| | Non-Bounty Eligible Assets | ✅ Complete (9/85) | ✅ Integrated | NON-BOUNTY DEFINED | Scope restricted |
| | Non-Submission Eligible Assets | ✅ Complete (5/85) | ✅ Integrated | NOT ELIGIBLE | Outside program |
| **Vulnerability Policy** | Accepted Categories | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Excluded Categories | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Special Consideration | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Out-of-Scope Categories | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| **Testing Authorization** | Permitted Techniques | ❓ NOT AVAILABLE | ❓ ["UNKNOWN"] | ❓ POLICY REQUIRED | Requires explicit list |
| | Prohibited Techniques | ❓ NOT AVAILABLE | ❓ ["UNKNOWN"] | ❓ POLICY REQUIRED | Requires explicit list |
| | Permitted Testing Types | ℹ️ Passive Only | ✅ ["PASSIVE_RECONNAISSANCE", "DOCUMENTATION_REVIEW", "PUBLIC_SOURCE_ANALYSIS"] | ✅ CURRENTLY PERMITTED | Conservative default |
| | Production Testing | ℹ️ Not Specified | ❌ ["STRICTLY_PROHIBITED"] | ❌ EXPLICITLY PROHIBITED | Gate default |
| | Sandbox Testing | ❓ NOT AVAILABLE | ❌ [false] | ❓ POLICY REQUIRED | Requires explicit auth |
| | API Abuse Testing | ❓ NOT AVAILABLE | ❌ (in prohibited list) | ❓ POLICY REQUIRED | Requires explicit auth |
| | IDOR Testing | ❓ NOT AVAILABLE | ❌ (in prohibited list) | ❓ POLICY REQUIRED | Requires explicit auth |
| | Authentication Testing | ❓ NOT AVAILABLE | ❌ (in prohibited list) | ❓ POLICY REQUIRED | Requires explicit auth |
| | Payment Testing | ❓ NOT AVAILABLE | ❌ (in prohibited list) | ❓ POLICY REQUIRED | Requires explicit auth |
| **Rate Limits & Automation** | Rate Limits | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Automation Restrictions | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Approved Tools | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Requests/Minute | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Concurrent Connections | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| **Account & Credentials** | Test Accounts Required | ℹ️ Not Specified | ✅ [true] | ⚠️ CONDITIONAL | Gate requires if provided |
| | Provided Test Accounts | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Must be explicitly provided |
| | Test Credit Cards | ℹ️ Not Specified | ✅ [true] | ⚠️ CONDITIONAL | Gate requires if provided |
| | Provided Test Instruments | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Must be explicitly provided |
| | Authentication Testing | ❓ NOT AVAILABLE | ❌ [false] | ❓ POLICY REQUIRED | Requires explicit auth |
| | Credential Testing | ❓ NOT AVAILABLE | ❌ [false] | ❓ POLICY REQUIRED | Requires explicit auth |
| | MFA Testing | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Password Testing | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Session Testing | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| **Payment & Financial** | Production Payment Testing | ℹ️ Not Specified | ❌ ["STRICTLY_PROHIBITED"] | ❌ EXPLICITLY PROHIBITED | Gate default |
| | Sandbox Payment Testing | ❓ NOT AVAILABLE | ❌ [false] | ❓ POLICY REQUIRED | Requires explicit auth |
| | Real Financial Transactions | ℹ️ Not Specified | ❌ ["STRICTLY_PROHIBITED"] | ❌ EXPLICITLY PROHIBITED | Gate default |
| | Test Instrument Requirements | ❓ NOT AVAILABLE | ❓ ["EXPLICITLY_PROVIDED_ONLY"] | ❓ POLICY REQUIRED | Must be provided |
| | Transaction Amount Limits | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Currency Testing Restrictions | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Refund Testing | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Webhook Testing | ❓ NOT AVAILABLE | ❓ ["EXPLICIT_AUTHORIZATION_REQUIRED"] | ❓ POLICY REQUIRED | Requires explicit auth |
| **Data Handling & Privacy** | Sensitive Data Collection | ℹ️ Not Specified | ✅ ["PROHIBITED"] | ✅ EXPLICITLY PROHIBITED | Gate default |
| | Personal Data Retention | ℹ️ Not Specified | ✅ ["PROHIBITED"] | ✅ EXPLICITLY PROHIBITED | Gate default |
| | Credential Storage | ℹ️ Not Specified | ✅ ["PROHIBITED"] | ✅ EXPLICITLY PROHIBITED | Gate default |
| | Payment Data Handling | ℹ️ Not Specified | ✅ ["PROHIBITED_IN_PRODUCTION"] | ✅ CONDITIONAL | Sandbox only with auth |
| | Data Transmission | ℹ️ Not Specified | ✅ ["ENCRYPTED_ONLY"] | ✅ EXPLICITLY PROHIBITED (plaintext) | Gate default |
| | Logs/Evidence Retention | ℹ️ Not Specified | ✅ ["TEMPORARY_ONLY"] | ✅ EXPLICITLY PROHIBITED (persistent) | Gate default |
| | Third-Party Sharing | ℹ️ Not Specified | ✅ ["PROHIBITED_WITHOUT_APPROVAL"] | ⚠️ CONDITIONAL | Requires approval |
| | Public Disclosure | ℹ️ Not Specified | ✅ ["COORDINATED_ONLY"] | ✅ EXPLICITLY PROHIBITED (uncoordinated) | Gate default |
| **Environment Controls** | Sandbox Testing Allowed | ❓ NOT AVAILABLE | ❌ [false] | ❓ POLICY REQUIRED | Requires explicit auth |
| | Sandbox Environments Authorized | ❓ NOT AVAILABLE | ❌ [] | ❓ POLICY REQUIRED | Must be specified |
| | Test Environment Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Isolation Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Data Reset Procedures | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Environment-Specific Credentials | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Sandbox Indicators Required | ℹ️ Not Specified | ✅ [true] | ⚠️ CONDITIONAL | Current gate setting |
| | Production Impact Prohibited | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY PROHIBITED | Gate default |
| **Vulnerability-Specific Rules** | Accepted Categories | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Excluded Categories | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Special Consideration | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Bounty Eligibility Criteria | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Severity Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | CVSS Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Duplicate Report Policy | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Reward Structure | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Payout Conditions | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| **Disclosure & Reporting** | Disclosure Timelines | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Coordinated Disclosure Required | ℹ️ Not Specified | ✅ [true] | ⚠️ CONDITIONAL | Current gate setting |
| | Initial Report Window | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Extension Request Process | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Rejection Appeal Process | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Bounty Claim Procedures | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Public Disclosure Permissions | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Legal Notice Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Safe Harbor Provisions | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Confidentiality Requirements | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| **Authorization Mechanics** | External Auth Required | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Human Approval Required | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Scope Validation Required | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Default Deny Position | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Reauthorization Period | ❓ NOT AVAILABLE | ❓ UNKNOWN | ❓ POLICY REQUIRED | Missing from CSV |
| | Policy Update Monitoring | ℹ️ Not Specified | ✅ ["MONTHLY"] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Evidence Requirements | ℹ️ Not Specified | ✅ ["COMPREHENSIVE"] | ✅ EXPLICITLY REQUIRED | Gate default |
| | False Positive Assessment | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Reproducibility Required | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Impact Assessment | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Remediation Recommendations | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| | Human Review Before Submission | ℹ️ Not Specified | ✅ [true] | ✅ EXPLICITLY REQUIRED | Gate default |
| **Keys & Cryptography** | Trusted Public Keys | ❓ NOT AVAILABLE | ✅ [Test keys only] | ⚠️ CONDITIONAL | Prod keys required |
| | Trusted Checkpoint Keys | ❓ NOT AVAILABLE | ✅ [Test keys only] | ⚠️ CONDITIONAL | Prod keys required |
| | Cryptographic Verification | ❓ NOT AVAILABLE | ℹ️ [Framework only] | ❓ POLICY REQUIRED | Requires prod keys |

## Summary of Authorization Status

### ✅ Currently Authorized/Permitted Activities
1. Passive reconnaissance (documentation review, public source analysis)
2. Scope validation and authorization checking
3. Security rule enforcement (data protection, non-production testing defaults)
4. Audit trail maintenance (temporary logging only)
5. Vulnerability validation framework (requires authorization to activate)
6. Report generation (requires human approval for submission)

### ❌ Currently Prohibited/Blocked Activities
1. All active network-based security testing (scanning, probing, etc.)
2. Production environment testing of any kind
3. Payment system testing in production
4. Credential testing/authentication bypass attempts
5. Injection testing, fuzzing, exploitation attempts
6. Denial-of-service activities
7. Social engineering
8. Privilege escalation attempts
9. Data persistence/collection beyond temporary needs
10. Uncoordinated public disclosure
11. Third-party sharing without approval
12. All vulnerability-specific testing without explicit policy authorization

### ❓ Requiring External Authorization (Policy-Dependent)
All of the following require explicit authorization from the Mercado Libre HackerOne program before they can be permitted:

1. **Vulnerability Category Authorization**: Which vulnerability types are accepted for testing and bounty
2. **Testing Technique Authorization**: Specific HTTP methods, tools, and techniques permitted
3. **Rate Limit Authorization**: Request frequency, concurrent connections, burst allowances
4. **Account Authorization**: Explicitly provided test accounts and credentials
5. **Payment Testing Authorization**: Sandbox/test environment payment testing
6. **Environment Authorization**: Specific sandbox/staging environment approvals
7. **Disclosure Authorization**: Coordinated disclosure timelines and procedures
8. **Reward Authorization**: Bounty amounts, payout conditions, severity requirements
9. **Cryptographic Authorization**: Trusted public keys for authorization verification
10. **Special Conditions**: Any program-specific requirements or safe harbor provisions

### 🔄 Authorization Gate Current State
- **Gate Status**: DISABLED (fail-closed: DENY by default)
- **Production Testing**: Explicitly disabled (`production_testing_enabled: false`)
- **Human Approval**: Required but currently PENDING
- **External Authorization**: Required but currently NOT OBTAINED (policy incomplete)
- **Scope Validation**: Active and integrated with gate
- **Default Position**: DENY all unless explicitly permitted

## Discrepancy Analysis

### Compared to Official Policy Requirements
All "UNKNOWN" and "NOT AVAILABLE" entries represent discrepancies between what is required for complete authorization and what is currently available from the CSV export.

### Critical Missing Information for Authorization Decisions
The following must be obtained from the official HackerOne policy before any authorization can be granted:

1. **Vulnerability Categories**: What is accepted vs excluded for bounty
2. **Testing Permissions**: What techniques and tools are explicitly permitted
3. **Rate Limits**: What request frequencies are allowed
4. **Account Provisions**: What test accounts/credentials are explicitly provided
5. **Payment Policy**: What payment testing is allowed in sandbox
6. **Disclosure Rules**: What disclosure timelines and procedures apply
7. **Reward Structure**: What bounties are paid and under what conditions
8. **Special Conditions**: Any program-specific requirements

## Recommendations for Policy Completion

1. **Manual Policy Retrieval**: Access https://hackerone.com/mercadolibre and https://hackerone.com/mercadolibre/policy_scopes via JavaScript-enabled browser to obtain complete policy
2. **Policy Documentation**: Copy exact policy text into project documentation
3. **Gate Configuration Update**: Once policy is obtained, update authorization-gate.json with explicit values
4. **Authorization Request**: Submit formal authorization request to Mercado Libre program with complete policy understanding
5. **Human Approval Process**: Establish clear human approval workflow for authorized activities
6. **Regular Policy Review**: Implement monthly policy change monitoring per gate configuration

## Verification and Audit Trail
- **Retrieval Date**: 2026-10-15
- **Sources Consulted**: 
  - scopes/verified-scope.json (CSV export)
  - scopes/authorization-gate.json (current gate configuration)
  - PROJECT_STATE.md (project status and limitations)
  - WebFetch attempts (confirming inaccessibility of dynamic content)
- **Limitations Documented**: Automatic retrieval blocked by JavaScript-dependent content
- **No Inference Made**: All missing sections explicitly marked as UNKNOWN/NOT AVAILABLE
- **Exact Meaning Preserved**: Available information quoted directly from sources

## Next Status Update
Upon obtaining complete official policy, this matrix should be updated to reflect:
- Conversion of "UNKNOWN"/"NOT AVAILABLE" to explicit permissions/prohibitions
- Authorization gate configuration updates
- External authorization request status
- Human approval status for specific activities