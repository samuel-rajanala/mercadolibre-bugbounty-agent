# API Security Skill

## Purpose
Conduct authorized security testing of APIs to identify authorization flaws, data exposure, input validation issues, and other API-specific vulnerabilities within explicitly authorized boundaries.

## When to Use
- After reconnaissance identifies API endpoints and specifications
- When testing authentication and authorization mechanisms in APIs
- To investigate data exposure, mass assignment, and input validation flaws
- For testing API version inconsistencies and improper error handling
- When evaluating API authentication tokens and credential management

## Inputs
- Authorized API endpoints and specifications (from reconnaissance and scope validation)
- HTTP methods and parameters to test (GET, POST, PUT, DELETE, PATCH, etc.)
- Authentication tokens and credentials (only explicitly authorized test accounts)
- Request headers and content types to evaluate
- Expected response schemas and data structures
- Rate limiting and concurrency constraints from program policy
- Test data that does not affect production systems or user accounts

## Outputs
- Authorization bypass vulnerabilities (vertical/horizontal privilege escalation)
- Excessive data exposure (sensitive fields in responses)
- Improper input validation (injection flaws, XSS in API responses)
- Mass assignment vulnerabilities (unauthorized field modification)
- Insecure object references (IDOR in API parameters)
- Authentication weaknesses (token validation flaws, credential issues)
- Inconsistent authorization between API versions or environments
- Improper error handling (information leakage through stack traces)
- Rate limiting and bypass vulnerabilities
- Content type confusion and deserialization issues
- Webhook and callback security issues
- GraphQL-specific vulnerabilities (if applicable)
- All findings with reproduction steps and impact assessment

## Workflow

### Phase 1: API Inventory and Documentation Review
```
- Catalog all discovered API endpoints and versions
- Collect public API documentation, SDKs, and developer portals
- Identify authentication mechanisms (API keys, JWT, OAuth, Basic Auth)
- Map HTTP methods, parameters, and expected responses for each endpoint
- Document rate limiting, authentication requirements, and permissions
- Identify deprecated or undocumented endpoints (if publicly available)
```

### Phase 2: Authentication Testing (Authorized Accounts Only)
```
- Test API key validation and rotation procedures
- Evaluate JWT token signing, expiration, and algorithm confusion
- Test OAuth token validation and scope enforcement
- Check for credential leakage in logs, headers, or error messages
- Verify proper token invalidation on logout or password change
- Test brute force protections on authentication endpoints
- Evaluate multi-factor authentication implementation (if applicable)
```

### Phase 3: Authorization Testing
```
- Test vertical privilege escalation (user -> admin)
- Test horizontal privilege escalation (user A -> user B resources)
- Check for missing authorization on sensitive endpoints
- Test parameter-based access control (user_id, object_id, etc.)
- Evaluate object-level authorization checks (BOLA)
- Test function-level authorization for administrative functions
- Check for authorization bypass via HTTP method manipulation
- Evaluate authorization headers and token validation logic
```

### Phase 4: Input Validation and Data Exposure Testing
```
- Test for injection flaws (SQL, NoSQL, Command Injection) in parameters
- Evaluate for cross-site scripting in API responses (JSONP, callbacks)
- Test for XML external entity (XXE) processing in XML endpoints
- Check for insecure deserialization in request/response bodies
- Test for mass assignment via unexpected parameter injection
- Evaluate for excessive data exposure in responses (PII, credentials)
- Check for sensitive data in URLs, headers, or error messages
- Test for content type confusion and misuse
- Evaluate for path traversal in file-related endpoints
```

### Phase 5: Business Logic and State Testing
```
- Test for improper state transitions in API workflows
- Evaluate for race conditions in state-changing operations
- Check for authorization bypass via state manipulation
- Test for input validation bypass via encoding or obfuscation
- Evaluate for business logic flaws in payment or transaction APIs
- Check for inconsistent data validation between API versions
```

### Phase 6: Version and Environment Comparison
```
- Test differences between API versions (v1, v2, v3, etc.)
- Compare authorization mechanisms between environments (if authorized)
- Test for information disclosure in beta or deprecated endpoints
- Evaluate for inconsistent security controls across versions
```

## Safety Requirements
- **USE ONLY AUTHORIZED TEST ACCOUNTS**: Never test against real user accounts without explicit permission
- **NO PRODUCTION DATA IMPACT**: Use test data that does not affect real transactions or user data
- **RESPECT RATE LIMITS**: Adhere to program-specified rate limits and concurrency limits
- **NO DESTRUCTIVE TESTING**: Do not test for data destruction or service disruption
- **FINANCIAL TESTING RESTRICTIONS**: Never test payment workflows with real funds (use sandbox only)
- **DATA PRIVACY**: Do not collect or retain sensitive data from API responses
- **ERROR HANDLING**: Do not intentionally cause errors that might affect service stability
- **THIRD-PARTY APIS**: Verify authorization before testing third-party service integrations
- **WEBHOOK SECURITY**: Only test webhooks with explicit authorization and safe payloads
- **NO CREDENTIAL STUFFING**: Use only explicitly provided test credentials

## Required Tools
- HTTP clients: curl, HTTPie, Postman (authorized use only)
- API testing frameworks: OWASP ZAP (authorized scope only), Burp Suite (authorized scope)
- JSON/JWT analysis tools: jwt.io, jq, jsonwebtoken libraries
- Parameter discovery tools: Arjun, ParamSpider (scope-limited use)
- API specification tools: Swagger UI, Postman collections (publicly available)
- Proxy tools: Only with explicit authorization and within scope
- Network tools: Only for authorized API endpoint testing

## Output Files
- `api/authentication-testing.json` - authentication test results and findings
- `api/authorization-testing.json` - authorization bypass test results
- `api/input-validation.json` - input validation and injection test results
- `api/data-exposure.json` - excessive data exposure findings
- `api/business-logic.json` - business logic and state testing results
- `api/version-comparison.json` - API version inconsistencies
- `api/reproduction-steps.md` - detailed reproduction instructions for each finding
- `api/impact-assessment.json` - business and technical impact analysis
- `logs/api-security.log` - detailed audit trail of all API testing

## Integration Points
- Receives authorized API endpoints from reconnaissance and scope validation
- Provides findings to vulnerability validation for confirmation
- Feeds remediation skill with specific code fix recommendations
- Updates program dashboard with API security testing progress
- References authentication-audit skill for credential and session testing
- Works with payment-security skill for financial API testing

## Example Usage
```
/api-security test_endpoint --url https://api.mercadolibre.com/users/{id} --method GET
/api-security test_auth --endpoint https://api.mercadolibre.com/oauth/token
/api-security mass_assignment --endpoint https://api.mercadolibre.com/users/me --method PATCH
/api-security idor_test --resource users --id_param user_id --start 1 --end 100
/api-security version_diff --endpoint /v1/users vs /v2/users
```

## Error Conditions
- Unauthorized endpoint detected: HALT and request scope clarification
- Production data affected: IMMEDIATELY STOP and initiate incident response
- Rate limit exceeded: BACK OFF and respect program restrictions
- Authentication failure with test accounts: VERIFY credentials and permissions
- Unexpected response codes: INVESTIGATE but do not exploit without authorization