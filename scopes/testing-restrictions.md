# Mercado Libre Testing Restrictions and Requirements

## Important Notice
**TESTING RESTRICTIONS INFORMATION IS NOT AVAILABLE IN PROVIDED CSV**

The official Mercado Libre HackerOne scope CSV export does not contain information about:
- Testing restrictions and limitations
- Rate limits and automation restrictions
- Account requirements and test credentials
- Prohibited testing techniques
- Disclosure requirements and timelines
- Payment testing environment requirements (sandbox vs production)

## Authorization Requirements (Based on Available Information)

Despite the lack of specific testing restrictions in the CSV export, the following authorization requirements MUST be followed:

1. **EXPLICIT AUTHORIZATION REQUIRED**: All security testing requires explicit scope validation
2. **PASSIVE RECONNAISSANCE ONLY**: Initial information gathering must be purely passive until authorization is confirmed
3. **DEFAULT DENY POSITION**: When in doubt about authorization, assume DENY and request clarification
4. **ASSET TYPE AWARE MATCHING**: Matching must consider asset types (URL, WILDCARD, MOBILE APP, etc.)
5. **NO WILDCARD ASSUMPTIONS**: Do not infer coverage beyond explicitly listed wildcard patterns
6. **TEST ACCOONTS ONLY**: Use only explicitly provided test credentials (obtain from program directly)
7. **SANDBOX ENVIRONMENTS**: Payment-related testing must occur in sandbox/test environments only
8. **DATA PROTECTION**: Do not unnecessarily collect, retain, or transmit sensitive data

## Required Actions Before Testing

Before conducting ANY security testing:

1. **Scope Validation**: Use the scope validation tools to confirm target authorization
2. **Eligibility Check**: Confirm whether target is submission eligible and bounty eligible
3. **Program Contact**: For missing policy information, contact the Mercado Libre HackerOne program directly
4. **Documentation**: Maintain records of all authorization checks and testing activities

## Missing Information

The following critical information is **NOT AVAILABLE IN PROVIDED CSV** and must be obtained separately:

- Specific testing timeframes or windows
- Rate limits requests per minute/hour/day
- Approved testing tools and techniques
- Prohibited attack vectors (DoS, social engineering, etc.)
- Authentication bypass testing restrictions
- Payment transaction limits and test card information
- Communication channels for program interaction
- Expected response times for triage and resolution
- Legal safe harbor provisions and confidentiality requirements

## Continuous Compliance

Security researchers should:
- Regularly re-fetch the official scope CSV for updates
- Maintain awareness of changing program policies
- Document all authorization validations
- Escalate policy questions to the program directly when uncertain
- Err on the side of caution when policy information is unavailable
