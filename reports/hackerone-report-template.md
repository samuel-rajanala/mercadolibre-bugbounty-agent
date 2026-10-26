# HackerOne Report Template - Mercado Libre Bug Bounty Program

## Report Information
- **Report ID:** [To be assigned by HackerOne]
- **Program:** Mercado Libre Bug Bounty Program
- **Reporter:** [Security Researcher Handle/Name]
- **Report Date:** [Date of Submission]
- **Status:** [New, Triaged, Resolved, etc.]
- **Vulnerability Type:** [Selected from HackerOne taxonomy]
- **Severity:** [None, Low, Medium, High, Critical]
- **CVSS Score:** [If applicable]
- **Bounty Awarded:** [Amount, if any]
- **Disclosure Date:** [Date of public disclosure, if applicable]

---

## Summary
[Provide a concise summary of the vulnerability in 2-3 sentences. What is the issue, where is it located, and what is the potential impact? Do not include sensitive details or reproduction steps in this section.]

---

## Affected Asset
- **Asset:** [Specific asset affected - URL, endpoint, parameter, etc.]
- **Asset Type:** [URL, API endpoint, parameter, etc.]
- **Scope Eligibility:** [Submission Eligible / Bounty Eligible / Not Eligible]
- **Scope Record ID:** [Reference to exact record in scopes/verified-scope.json]
- **Environment:** [Production / Staging / Development / Test - ONLY if explicitly authorized]

---

## Scope Eligibility Verification
- [ ] Asset confirmed in scope via `scopes/verified-scope.json`
- [ ] Asset confirmed in scope via `scopes/mercadolibre-scope.json`
- [ ] Submission eligibility confirmed
- [ ] Bounty eligibility confirmed
- [ ] Asset not in out-of-scope or exclusion lists
- [ ] Wildcard interpretation validated (no assumptions beyond explicit listings)
- [ ] Scope validation performed using authorized tools
- [ ] Validation timestamp recorded

**Note:** Attach or reference scope validation evidence if required by program.

---

## Vulnerability Category
- **Primary Category:** [Select from: Cross-Site Scripting (XSS), SQL Injection, Authentication Bypass, Insecure Direct Object Reference (IDOR), Server-Side Request Forgery (SSRF), etc.]
- **Secondary Categories:** [If applicable]
- **CWE Reference:** [CWE-ID if applicable, e.g., CWE-79 for XSS]
- **OWASP Mapping:** [OWASP Top 10 category if applicable]
- **Special Considerations:** [Any program-specific categorization notes]

---

## Preconditions
[List any conditions that must be met for the vulnerability to be exploitable. Examples:
- User must be authenticated
- Specific headers must be present
- Certain cookies must be set
- User must have specific role/permissions
- Specific HTTP method must be used
- Specific parameters must be present
- Certain state must be established
- Network position requirements
- Time-based conditions
- Feature flags or A/B test variations]

*If no preconditions beyond normal access, state: "No special preconditions required."*

---

## Reproduction Steps
[Provide clear, concise, numbered steps to reproduce the vulnerability. Each step should be actionable and reproducible. Do not include actual exploit payloads or sensitive data in this section - those go in Evidence or separate secure communication if required.]

1. [First step - e.g., "Navigate to https://www.mercadolibre.com/"]
2. [Second step - e.g., "Click on the login button"]
3. [Third step - e.g., "Enter test credentials in username field"]
4. [Continue with specific steps...]
5. [Final step - e.g., "Observe the behavior described in Actual Behavior"]

**Important:** 
- Steps must be reproducible by the triage team
- Use only explicitly provided test credentials if authentication is required
- Do not include steps that would violate rate limits or program restrictions
- If active testing was performed, confirm it was within explicitly authorized boundaries
- Steps should not cause disruption, data corruption, or denial of service
- If reproduction requires specific state, explain how to achieve it

---

## Expected Behavior
[What should happen when the steps are followed correctly? This is the secure, intended behavior of the application.]

[Example: "The application should validate the input and return an error message indicating invalid format without processing the request further."]

[Example: "The user should be redirected to the login page with an appropriate error message."]

[Example: "The request should be rejected with an HTTP 403 Forbidden response."]

---

## Actual Behavior
[What actually happens when the steps are followed? Describe the observable difference from expected behavior.]

[Example: "The application processes the input without validation and returns a successful response containing sensitive data in the response body."]

[Example: "The application allows access to the resource without proper authentication checks."]

[Example: "The application returns HTTP 200 OK with debugging information that should not be exposed in production."]

[Example: "The application sets a cookie that can be manipulated to gain unauthorized access."]

---

## Security Impact
[Describe the potential security impact if this vulnerability were exploited. Be specific about what an attacker could achieve.]

### Potential Impact:
- [ ] Authentication bypass
- [ ] Authorization bypass / Privilege escalation
- [ ] Data exposure (PII, credentials, financial data, etc.)
- [ ] Data modification or destruction
- [ ] Account takeover
- [ ] Financial fraud
- [ ] Reputational damage
- [ ] Compliance violations
- [ ] Further attack chain enablement
- [ ] Malware distribution
- [ ] Phishing facilitation
- [ ] Session hijacking
- [ ] Man-in-the-middle possibilities
- [ ] Denial of service
- [ ] Log tampering or evasion
- [ ] Other: [specify]

### Affected Data Types:
- [ ] Personal Identifiable Information (PII)
- [ ] Payment Card Information
- [ ] Authentication Credentials
- [ ] Session Tokens
- [ ] Financial Transaction Data
- [ ] Health Information (PHI)
- [ ] Proprietary Business Data
- [ ] User-Generated Content
- [ ] Administrative Access
- [ ] Other: [specify]

### User Impact:
- [ ] Individual users affected
- [ ] Specific user roles affected
- [ ] All users potentially affected
- [ ] Geographic or regional impact
- [ ] Temporal or time-based impact

### Business Impact:
- [ ] Financial loss potential
- [ ] Regulatory fines potential
- [ ] Legal liability potential
- [ ] Customer trust erosion
- [ ] Brand reputation damage
- [ ] Operational disruption potential
- [ ] Intellectual property exposure

### Technical Details:
[Provide technical details about the vulnerability mechanism without revealing exploit code. Examples:
- "The parameter 'user_id' is not properly validated for type and bounds before database query"
- "The response includes debugging information when a specific header is present"
- "The application uses predictable values for security tokens"
- "The implementation does not implement proper output encoding for user-controlled data"
- "The access control check occurs after the data retrieval operation"]
- [Technical detail 1]
- [Technical detail 2]
- [Technical detail 3]

---

## Evidence
[Attach or reference all evidence supporting this report. Evidence must be:
- Collected passively or within explicitly authorized boundaries
- Properly sanitized (no sensitive data)
- Clearly labeled and organized
- Timestamps preserved
- Does not violate any laws or program policies]

### Evidence Inventory:
1. **[Evidence Type]** - [Brief description]
   - File: [filename or reference]
   - Description: [What this evidence shows]
   - Relevance: [How this evidence supports the report]
   - Collection Method: [Passive observation, documentation review, etc.]
   - Timestamp: [When collected]
   - Validation: [How this evidence was validated]

2. **[Evidence Type]** - [Brief description]
   - File: [filename or reference]
   - Description: [What this evidence shows]
   - Relevance: [How this evidence supports the report]
   - Collection Method: [Passive observation, documentation review, etc.]
   - Timestamp: [When collected]
   - Validation: [How this evidence was validated]

### Evidence Types May Include:
- Screenshots (with sensitive data redacted)
- Network traffic captures (sanitized)
- Log files (sanitized)
- Code snippets (from public sources)
- Documentation references
- Error messages
- Header information
- Response samples (sanitized)
- Timeline analyses
- Comparative studies
- Tool output (from authorized scanners)
- Manual test results (within authorization)

### Important Evidence Guidelines:
- [ ] No sensitive data (PII, credentials, payment data) included in evidence
- [ ] All evidence collected via passive means OR within explicit authorization
- [ ] Evidence does not violate rate limits or automation restrictions
- [ ] Evidence collection did not trigger security controls inappropriately
- [ ] Evidence does not require circumvention of security controls to obtain
- [ ] Timestamps and provenance preserved
- [ ] Evidence properly labeled and organized
- [ ] Chain of custody maintained for collected evidence
- [ ] No evidence obtained through unauthorized access
- [ ] All evidence legally obtained and compliant with program policy

---

## Remediation Recommendations
[Provide specific, actionable recommendations for fixing the vulnerability. Base recommendations on security best practices and the specific nature of the vulnerability. Do not presume knowledge of internal systems.]

### Immediate Actions:
- [ ] [Specific action to mitigate risk immediately]
- [ ] [Specific action to mitigate risk immediately]
- [ ] [Specific action to mitigate risk immediately]

### Short-Term Fixes:
- [ ] [Specific fix to address root cause]
- [ ] [Specific fix to address root cause]
- [ ] [Specific fix to address root cause]

### Long-Term Improvements:
- [ ] [Specific improvement for defense-in-depth]
- [ ] [Specific improvement for defense-in-depth]
- [ ] [Specific improvement for defense-in-depth]

### Validation Steps:
[How to verify the fix works - ONLY if authorization is obtained for testing]
- [ ] [Specific validation step]
- [ ] [Specific validation step]
- [ ] [Specific validation step]

### Testing Considerations:
[If applicable and authorization obtained]
- [ ] [Specific testing consideration]
- [ ] [Specific testing consideration]
- [ ] [Specific testing consideration]

### References:
- [ ] [Relevant security standard or guideline]
- [ ] [Relevant security standard or guideline]
- [ ] [Relevant security standard or guideline]
- [ ] [OWASP ASVS control reference]
- [ ] [CWE prevention recommendations]
- [ ] [Vendor-specific guidance if applicable]

---

## Additional Context
[Any additional information that would help the triage team understand and validate the report.]

### Research Methodology:
- [ ] Passive reconnaissance only
- [ ] Documentation review
- [ ] Public source analysis
- [ ] Authorized active testing (specify boundaries)
- [ ] Manual analysis
- [ ] Automated scanning (specify tool and authorization)
- [ ] Third-party service analysis
- [ ] Configuration review
- [ ] Other: [specify]

### Limitations:
- [ ] Any limitations in testing or evidence collection
- [ ] Factors that may affect reproducibility
- [ ] Environmental considerations
- [ ] Time-based variations considered
- [ ] Regional variations considered
- [ ] Feature flag or A/B test considerations
- [ ] Authorization boundaries respected
- [ ] Rate limits respected (if known)
- [ ] Data minimization applied

### Assumptions Made:
[List any assumptions made in the analysis - should be minimal and justified]
- [ ] Assumption 1 with justification
- [ ] Assumption 2 with justification
- [ ] Assumption 3 with justification
- [ ] No assumptions made beyond observable evidence

### Related Reports:
[If this report is related to other reports or findings]
- [ ] Related to Report #[number] - [brief description]
- [ ] Similar to publicly disclosed vulnerability [CVE-ID or reference]
- [ ] Part of potential vulnerability chain
- [ ] Duplicate check performed against known issues

### Communication Preferences:
- [ ] Preferred method for follow-up questions
- [ ] Timezone for communication
- [ ] Language preference
- [ ] Availability for clarification
- [ ] Public disclosure coordination preferences

---

## Attachments and References
[List all attached files or provide references to external materials]

### Attached Files:
1. [filename.ext] - [description]
2. [filename.ext] - [description]
3. [filename.ext] - [description]

### External References:
1. [URL] - [description of what it shows]
2. [URL] - [description of what it shows]
3. [URL] - [description of what it shows]

### Internal References:
1. scopes/verified-scope.json - [specific records referenced]
2. scopes/mercadolibre-scope.json - [specific records referenced]
3. research/findings.json - [related finding IDs if applicable]
4. research/validation-checklist.md - [if validation performed]
5. scope-validation logs - [if applicable]

---

## Reporter Notes
[Any additional notes from the reporter that don't fit elsewhere in the report]

### Conflicts of Interest:
[ ] None declared
[ ] [Describe any potential conflicts of interest]

### Legal Compliance:
[ ] All activities conducted in compliance with applicable laws
[ ] No unauthorized access performed
[ ] No laws violated during research
[ ] Evidence legally obtained
[ ] Program policy compliance maintained

### Good Faith Statement:
[ ] This report is submitted in good faith to improve security
[ ] No intent to cause harm, damage, or disruption
[ ] Desire to work collaboratively with the security team
[ ] Willingness to assist with validation and remediation
[ ] Understanding of responsible disclosure principles

---

## Terms and Conditions Acknowledgment
[By submitting this report, you acknowledge and agree to:]

- [ ] I have read and understood the Mercado Libre Bug Bounty Program policy
- [ ] I will comply with all program rules, restrictions, and requirements
- [ ] I will not engage in any prohibited activities
- [ ] I will respect rate limits and automation restrictions
- [ ] I will use only explicitly provided test credentials
- [ ] I will not test or access out-of-scope assets
- [ ] I will minimize collection and transmission of sensitive data
- [ ] I will follow coordinated disclosure procedures
- [ ] I will not publicly disclose vulnerabilities without authorization
- [ ] I recognize that the program may modify terms and conditions
- [ ] I understand that bounty awards are at the program's discretion
- [ ] I accept the program's decision regarding report validity and severity
- [ ] I will not engage in extortion or threaten public disclosure for payment
- [ ] I will interact with the program in a professional and respectful manner

---

*Report Generated Using Mercado Libre Bug Bounty Research Agent*
*For Authorized Security Research Only*
*Do not submit without explicit authorization for the reported activity*
*Active testing requires explicit program authorization*