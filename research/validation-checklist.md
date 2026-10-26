# Mercado Libre Bug Bounty Research - Offline Validation Checklist

This checklist must be completed and approved before progressing any finding beyond the RESEARCH_LEAD status. All items must be verified offline without making network requests or performing active testing.

## Validation Checklist

### 1. Asset-to-Scope Mapping Verification
- [ ] Finding's affected asset is explicitly identified
- [ ] Affected asset maps to an exact record in `scopes/verified-scope.json` or `scopes/mercadolibre-scope.json`
- [ ] Scope record ID documented and verified
- [ ] Asset type matching performed (URL, WILDCARD, MOBILE_APP, etc.)
- [ ] Wildcard interpretation follows exact program policy (no assumptions beyond explicit listings)
- [ ] Submission eligibility confirmed from scope data
- [ ] Bounty eligibility confirmed from scope data
- [ ] Asset not found in out-of-scope or exclusion lists

### 2. Authorization Verification
- [ ] Current authorization-gate status checked (`scopes/authorization-gate.json`)
- [ ] Human approval status verified as "APPROVED" for active testing
- [ ] Production testing status confirmed as disabled (must remain disabled)
- [ ] Specific testing technique authorization verified
- [ ] Rate limits and automation restrictions reviewed (if known)
- [ ] Account requirements verified (test accounts only, explicitly provided)
- [ ] Sandbox/testing requirements confirmed (if applicable)
- [ ] No authorization inferred - explicit validation required

### 3. Evidence Requirements
- [ ] Evidence collected is purely passive (no active testing, scanning, probing)
- [ ] Evidence sources documented (public sources, documentation, passive observation)
- [ ] No sensitive data collected, retained, or transmitted
- [ ] Evidence minimizes personal and payment data exposure
- [ ] Evidence collection methods documented and compliant
- [ ] Timestamps and provenance preserved for all evidence
- [ ] Evidence does not require authentication to access
- [ ] Evidence does not trigger security controls or rate limits

### 4. Observed Behavior Documentation
- [ ] Observed behavior clearly described and reproducible
- [ ] Behavior separated from interpretation/hypothesis
- [ ] HTTP status codes, headers, and response content documented (if applicable)
- [ ] Timing information and request/response details preserved
- [ ] Environmental factors noted (time of day, regional variations, etc.)
- [ ] Comparison to expected/normal behavior documented
- [ ] No claims of vulnerability based solely on HTTP 200, 403, or 404 responses

### 5. Security Impact Analysis
- [ ] Security impact hypothesis clearly articulated
- [ ] Impact based on observed behavior, not speculation
- [ ] Affected user population or data types identified
- [ ] Potential exploitation scenarios documented (hypothetical only)
- [ ] Business logic impact considered (if applicable)
- [ ] Privilege escalation paths mapped (if applicable and authorized)
- [ ] Data exposure pathways identified (if applicable)
- [ ] Impact severity rationale provided (without claiming specific severity)

### 6. False Positive Assessment
- [ ] Alternative explanations for observed behavior considered
- [ ] Common misconfigurations ruled out (where possible through passive observation)
- [ ] Documentation reviewed to confirm expected behavior
- [ ] Regional variations or feature flags considered
- [ ] Testing artifacts or monitoring ruled out (via passive observation)
- [ ] Rate limiting or security controls considered as alternative explanations
- [ ] Caching or CDN effects considered
- [ ] Third-party service behavior considered

### 7. Validation Requirements (for Future Active Testing - Authorization Required)
- [ ] Specific validation requirements documented for when authorization is obtained
- [ ] Preconditions for active testing clearly defined
- [ ] Required test accounts/credentials specified (must be explicitly provided)
- [ ] Specific test endpoints or parameters identified
- [ ] Expected results for both vulnerable and patched states documented
- [ ] Validation methodology described (must comply with rate limits and restrictions)
- [ ] Cleanup and restoration procedures documented
- [ ] Data minimization plan for validation activities
- [ ] Rollback procedures in case of unexpected impact

### 8. Remediation Planning
- [ ] Potential remediation strategies identified (generic, not specific to internal systems)
- [ ] Fix validation approach described
- [ ] Testing considerations for remediation noted
- [ ] Regression prevention strategies considered
- [ ] Documentation update requirements identified
- [ ] Monitoring or detection suggestions provided

### 9. Compliance and Risk Assessment
- [ ] Data privacy implications assessed and minimized
- [ ] Legal compliance verified (no laws violated in evidence collection)
- [ ] Program policy compliance confirmed
- [ ] Risk of disruption or damage assessed as minimal for proposed validation
- [ ] Confidentiality requirements understood
- [ ] Coordinated disclosure requirements acknowledged
- [ ] Public disclosure permissions verified (none assumed)

### 10. Approval and Sign-off
- [ ] All checklist items completed and verified
- [ ] Evidence properly labeled and stored
- [ ] Finding status justified based on completed validation
- [ ] Human reviewer identified and contacted for approval
- [ ] Approval documentation prepared (separate from this checklist)
- [ ] No network requests made during validation process
- [ ] No active testing performed during validation process
- [ ] Production systems not impacted during validation
- [ ] All activities remain in preparation/validation mode only

## Status Progression Rules

### From INFORMATIONAL to RESEARCH_LEAD:
- Asset-to-scope mapping verified
- Basic observational evidence collected
- No authorization required beyond passive reconnaissance

### From RESEARCH_LEAD to POTENTIAL_SECURITY_ISSUE:
- All items in sections 1-6 completed
- Authorization-gate human approval status: "APPROVED" for research progression
- No active testing performed
- Evidence supports security impact hypothesis (not proof)
- False positive assessment completed

### From POTENTIAL_SECURITY_ISSUE to CONFIRMED_VULNERABILITY:
- **EXPLICIT AUTHORIZATION REQUIRED** from Mercado Libre program
- All items in sections 1-8 completed
- Active testing performed within authorized boundaries
- Reproducible evidence obtained
- Security impact verified
- False positives ruled out through testing
- Human approval obtained for specific validation activity
- Rate limits and restrictions complied with during testing
- Evidence properly sanitized (no sensitive data)
- Restoration/cleanup completed

### Rejection Criteria (Any Status to REJECTED):
- Asset not in scope (verified)
- Authorization cannot be obtained or verified
- Evidence insufficient to support security impact hypothesis
- False positive confirmed through analysis
- Testing would violate program policy or legal restrictions
- Evidence collection compromised privacy or safety
- Duplicate of existing validated finding
- Vulnerability already known and disclosed
- Authorization-gate not in APPROVED state for requested activity

## Important Notes
- This checklist applies to offline validation only
- Active testing requires explicit authorization and a separate validation process
- Production testing remains disabled at all times
- All validation must respect rate limits and automation restrictions (when known)
- Evidence must not contain sensitive personal or financial data
- When in doubt, assume DENY and seek clarification
- This checklist does not authorize any activity - it validates readiness for authorization requests