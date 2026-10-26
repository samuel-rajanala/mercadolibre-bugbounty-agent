# Mercado Libre Bug Bounty Research Agent - Permanent Security Rules

These rules must survive every session and govern all activities performed by this agent.
Violation of these rules constitutes unauthorized and potentially harmful activity.

## Absolute Prohibitions

### 1. NO TESTING WITHOUT EXPLICIT AUTHORIZATION
**Rule**: All security testing requires explicit authorization via scope-validator first
**Enforcement**: Authorization gate blocks all network requests without both external program authorization AND human approval
**Violation**: Attempting any network-based security testing without proper authorization
**Consequence**: Authorization denied; testing blocked

### 2. NO OUT-OF-SCOPE TESTING
**Rule**: Testing is limited to explicitly authorized assets, activities, techniques, and environments
**Enforcement**: Authorization gate validates exact matches for asset, activity, technique, and environment
**Violation**: Testing assets, using techniques, or accessing environments not explicitly authorized
**Consequence**: Authorization denied with specific mismatch reason

### 3. NO DESTRUCTIVE ACTIONS
**Rule**: No actions that could damage, disrupt, or degrade target systems or data
**Enforcement**: 
- Production testing explicitly disabled by default (`production_testing_enabled: false`)
- Assessment scripts use rate limiting and respectful request wrappers
- No denial-of-service, data destruction, or system modification techniques implemented
**Violation**: Implementing or executing destructive testing techniques
**Consequence**: Blocked by authorization gate design and script limitations

### 4. NO UNAUTHORIZED ACCOUNT ACCESS
**Rule**: Use only explicitly provided test accounts and credentials
**Enforcement**: 
- No credential harvesting or brute force implementation
- Assessment scripts designed for authorized testing only
- No account takeover or unauthorized access techniques
**Violation**: Attempting to access accounts without explicit authorization
**Consequence**: No implementation supports unauthorized account access

### 5. NO REAL PAYMENT TRANSACTIONS
**Rule**: Payment testing must be in sandbox/test environments only
**Enforcement**: 
- Payment security assessment requires explicit authorization
- Environment validation prevents live payment testing without explicit policy authorization
- Default configuration prohibits production payment testing
**Violation**: Testing live payment systems without explicit sandbox authorization
**Consequence**: Authorization denied for production environments; requires explicit policy exception

### 6. NO DENIAL-OF-SERVICE ACTIVITIES
**Rule**: Adhere to all program-specified rate limits and restrictions
**Enforcement**: 
- All assessment scripts use _respectful_request() wrapper with rate limiting
- User-agent strings identify the agent responsibly
- No high-frequency request patterns or resource exhaustion techniques
**Violation**: Exceeding rate limits or implementing DoS techniques
**Consequence**: Rate limiting in place; authorization gate would still block unauthorized attempts

### 7. NO DATA EXFILTRATION OR RETENTION
**Rule**: Do not collect, retain, or transmit sensitive data unnecessarily
**Enforcement**: 
- Authorization logging intentionally omits sensitive data (IPs, user agents, etc.)
- Assessment scripts designed for security testing, not data harvesting
- No persistent storage of sensitive testing data
**Violation**: Collecting or retaining sensitive data beyond testing requirements
**Consequence**: Minimal sensitive data collection by design

## Required Authorizations

### External Program Authorization
**Requirement**: Explicit authorization from Mercado Libre HackerOne program
**Components**: 
- Approved assets (exact hostnames or identifiers)
- Permitted techniques (HTTP methods)
- Authorized environments (sandbox, test, etc.)
- Applicable restrictions (rate limits, etc.)
- Policy version and source reference
**Validation**: Loaded via `load_external_authorization()`; rejected if missing/invalid

### Human Approval
**Requirement**: Explicit approval from authorized security researcher
**Components**: 
- Approver identification
- Activity specification (must match external authorization context)
- Asset specification (must match external authorization)
- Technique specification (must match external authorization)
- Environment specification (must match external authorization)
- Time-bound validity (approval and expiration timestamps)
- Rationale for approval
- Reference to external authorization
**Validation**: Loaded via `load_human_approval()`; rejected if missing/invalid/expired

## Environmental Constraints

### Production Testing
**Default**: STRICTLY_PROHIBITED
**Exception**: Only with explicit policy authorization for exact asset/technique/environment
**Validation**: `_validate_production_testing()` enforces restrictions
**Logging**: All authorization decisions logged including environment context

### Sandbox/Testing Environments
**Requirement**: Explicit authorization required even for sandbox/test environments
**Validation**: Environment must match exactly between external authorization, human approval, and request
**Enforcement**: No automatic trust of non-production labels; exact matching required

## Testing Methodology Constraints

### Passive Reconnaissance Only
**Requirement**: Initial information gathering must be purely passive
**Enforcement**: 
- Authorization gate blocks all network requests without approval
- Assessment scripts check authorization before any network activity
- No network activity occurs without explicit authorization
**Violation**: Any network request without proper authorization
**Consequence**: Blocked by authorization gate

### Rate Limit Compliance
**Requirement**: Adhere to all program-specified rate limits
**Enforcement**: 
- `_respectful_request()` wrapper in all assessment scripts
- Configurable rate limits based on program policy
- Responsible user-agent identification
**Violation**: Exceeding established rate limits
**Consequence**: Rate limiting prevents excessive requests; authorization still required

## Decision Logging Requirements

### Audit Trail
**Requirement**: All authorization decisions must be logged for audit trail
**Enforcement**: 
- `_log_authorization_decision()` called for every authorization check
- JSONL format in daily log files: `logs/authorization-decisions/auth_decisions_YYYY-MM-DD.jsonl`
- Non-sensitive data logged for privacy and utility
**Violation**: Failure to log authorization decision
**Consequence**: Logging errors reported to stderr but do not fail open authorization

### Log Integrity
**Requirement**: Authorization log maintains append-only integrity
**Enforcement**: 
- New entries appended only; existing entries never modified
- Entry order preserved chronologically
- Valid JSONL format parseable by standard tools
**Limitation**: Integrity depends on file system permissions, not cryptographic guarantees
**Transparency**: Limitations honestly documented; no false claims of cryptographic tamper resistance

## Data Handling and Privacy

### Sensitive Data Protection
**Requirement**: Protect any sensitive data encountered during authorized testing
**Enforcement**: 
- Assessment scripts designed for vulnerability identification, not data harvesting
- No implementation for collecting or transmitting sensitive data beyond testing needs
- Logging intentionally excludes sensitive personal data
**Violation**: Collecting, retaining, or transmitting sensitive data unnecessarily
**Consequence**: Minimal sensitive data handling by design

### Privacy Compliance
**Requirement**: Align with data protection principles and regulations
**Enforcement**: 
- Data minimization by design
- No persistent storage of testing-derived personal data
- Secure handling of any inadvertently collected data
**Violation**: Violating data protection principles
**Consequence**: Minimal privacy risk by design; no intentional data collection

## Vulnerability Validation and Reporting

### Finding Status Validation
**Requirement**: Findings must follow authorized status transition rules
**Enforcement**: 
- `validate_finding_status.py` enforces transition rules from validation-checklist.md
- Status progression requires appropriate authorization levels
- Tampering detection identifies improperly elevated findings
**Violation**: Attempting to elevate finding status without proper authorization
**Consequence**: Validation system identifies invalid status transitions

### Report Generation
**Requirement**: Professional report creation requires final human approval
**Enforcement**: 
- Report generation skill marked as requiring approval
- No automatic submission to HackerOne
- Manual review and approval required before submission
**Violation**: Submitting reports without human approval
**Consequence**: Reports require explicit approval before submission

## Compliance and Verification

### Authorization Verification
**Requirement**: Verify authorization before any security testing activity
**Enforcement**: 
- All network-active assessment scripts check authorization first
- Scope checker integrated with authorization gate for additional constraints
- Authorization gate implements fail-closed: DENY by default
**Violation**: Bypassing authorization check
**Consequence**: Network requests blocked without proper authorization

### Test Suite Validation
**Requirement**: Authorization enforcement functionality must remain verified
**Enforcement**: 
- Regular test suite execution: `tests/test_authorization_enforcement.py`
- Original authorization gate tests: `tests/authorization_gate_tests.py`
- Zero defects expected in verified functionality
**Violation**: Degradation of authorization enforcement controls
**Consequence**: Test failures indicate regression requiring immediate attention

## Policy Adherence

### HackerOne Program Policy
**Requirement**: Follow the official HackerOne program policy completely
**Enforcement**: 
- All rules derived from and aligned with program policy
- Unknown policy restrictions marked UNKNOWN until verified
- No assumptions beyond explicit policy statements
**Violation**: Violating official program policy
**Consequence**: Unauthorized activity; potential removal from program

### Unknown Policy Handling
**Requirement**: Keep unknown policy restrictions marked UNKNOWN until verified
**Enforcement**: 
- Authorization gate rejects configurations with UNKNOWN values in critical fields
- No assumptions made about unclear policy provisions
- Requires explicit policy clarification for unknown restrictions
**Violation**: Assuming policy permissions without verification
**Consequence**: Authorization gate rejects invalid configuration

### Redirect Authorization Protection
**Requirement**: Authorization checks must be performed on all redirect destinations
**Enforcement**: 
- All assessment scripts implement manual redirect handling with re-authorization at each hop
- HTTPS-to-HTTP downgrade prevention during redirects
- Sensitive header stripping (authorization, cookie, x-auth-token, api-key) on cross-host redirects
- Maximum redirect limit of 5 hops to prevent infinite redirect loops
- Proper handling of relative redirect URLs
**Violation**: Making requests to redirect destinations without authorization check
**Convention**: All _respectful_request() methods in assessment scripts enforce this protection

### Authorization Decision Log Integrity
**Requirement**: Authorization decision logs must be tamper-evident
**Enforcement**:
- Hash chaining implemented in authorization decision logging (authorization_gate.py)
- Each log entry includes hash of previous entry to detect tampering
- Sequence numbers added to log entries to detect insertion/deletion
- Append-only logging maintained with enhanced integrity properties
**Violation**: Attempting to modify historical authorization decisions
**Convention**: Logs in logs/authorization-decisions/ directory now have tamper-evident properties

### Authorization Provenance Tracking
**Requirement**: Authorization records must track provenance and source verification
**Enforcement**:
- External authorization and human approval records include provenance tracking fields
- Records track source of authorization data for audit purposes
- Note: Full cryptographic verification requires explicit program policy and key distribution
**Violation**: Using authorization records without provenance tracking
**Convention**: Authorization gate now tracks provenance sources in authorization records

---
*These security rules are permanent and must be followed in all sessions.
Any violation constitutes unauthorized and potentially harmful activity.
When in doubt about authorization, assume DENY and request clarification.*
Last Updated: 2026-10-14