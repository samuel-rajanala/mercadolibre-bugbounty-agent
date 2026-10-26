# Scope Validator Skill

## Purpose
Authorize or deny security testing targets based on verified bug bounty program policy to ensure all activities remain within explicitly authorized boundaries.

## When to Use
- Before ANY security testing, scanning, or interaction with a target
- When discovering new subdomains or assets during reconnaissance
- When testing third-party integrations or dependencies
- When considering automation or tool usage that might affect scope
- Prior to each individual test request or payload delivery

## Inputs
- Target hostname, IP address, URL, or asset identifier
- Normalized target format (scheme://host:port/path)
- Testing method (GET, POST, PUT, DELETE, etc.)
- Test type (reconnaissance, scanning, exploitation, etc.)
- Infrastructure involvement (third-party, cloud service, etc.)
- Verified policy data from program-intelligence skill

## Outputs
- Authorization decision: AUTHORIZED, DENIED, or REQUIRES_MANUAL_VERIFICATION
- Detailed reasoning for the decision
- Scope eligibility status (in-scope, out-of-scope, bounty-eligible)
- Testing method authorization (if different rules apply)
- Infrastructure authorization status
- Recommended next steps or alternative approaches

## Workflow

### 1. Target Normalization
```
- Strip credentials, fragments, and unnecessary components
- Convert to lowercase for case-insensitive matching
- Expand wildcard patterns if explicitly authorized
- Resolve aliases and CNAME records (when authorized)
- Standardize port notation (exclude :80 and :443 when implied)
```

### 2. Scope Matching
```
- Check exact match against in-scope assets list
- Check wildcard domain matches (only if explicitly authorized in policy)
- Check IP range and CIDR block inclusions
- Check application-specific paths and endpoints
- Verify mobile app package names and bundle IDs
- Confirm API endpoint and version specificity
```

### 3. Authorization Validation
```
- Confirm bounty eligibility for vulnerability submission
- Verify testing method is permitted for this asset type
- Check if third-party infrastructure involvement is authorized
- Validate automation and rate limit compliance
- Ensure testing does not affect excluded assets or services
```

### 4. Decision Synthesis
```
- Apply deny-by-default principle for uncertain cases
- Provide specific policy references for authorization decisions
- Distinguish between scope eligibility and testing authorization
- Note any special conditions or restrictions that apply
- Suggest scoping clarification needed for ambiguous cases
```

## Safety Requirements
- **DENY BY DEFAULT**: When scope cannot be conclusively determined, DENY access
- **NEVER ASSUME**: Do not assume wildcard authorization without explicit policy statement
- **THIRD-PARTY CHECK**: Always verify if testing involves third-party services before proceeding
- **METHOD SPECIFIC**: Different testing methods (recon vs exploitation) may have different rules
- **NO EXPANSION**: Never automatically expand scope based on similar naming or ownership
- **DOCUMENT REASONING**: Always provide clear policy references for authorization decisions

## Required Files
- Input: `scopes/verified-scope.json` (from program-intelligence skill)
- Internal: `scripts/scope-checker.py` (executable validation script)
- Output: `logs/validation.log` (all authorization decisions with timestamps)
- Optional: `scopes/pending-verification.txt` (targets requiring manual review)

## Integration Points
- Called automatically by reconnaissance skill before host discovery
- Integrated into all specialized research skills (api-security, authentication-audit, etc.)
- Used by vulnerability validation to confirm test authorization
- References remediation skill to ensure fixes stay within scope
- Feeds program dashboard with scope compliance metrics

## Example Usage
```
/scope-validator check_target --host api.mercadolibre.com --method GET
/scope-validator validate_scope --target img.mercadolibre.com --type reconnaissance
/scope-validator test_authorization --url https://api.mercadolibre.com/payments/v1 --method POST
```

## Error Conditions
- Target not found in policy: RETURN DENIED with suggestion to check spelling
- Ambiguous wildcard matches: RETURN REQUIRES_MANUAL_VERIFICATION
- Third-party service detection: RETURN DENIED unless explicitly authorized
- Testing method not permitted: RETURN DENIED with allowed methods list
- Policy data missing or corrupted: RETURN ERROR and halt processing