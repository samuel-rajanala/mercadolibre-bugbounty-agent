# Authorization Audit Skill

## Purpose
Conduct authorized security testing of authorization mechanisms to identify instances of broken object-level authorization (BOLA), broken function-level authorization, privilege escalation, and other authorization flaws within explicitly authorized boundaries.

## When to Use
- After authentication mechanisms have been mapped and tested
- When testing access controls on resources, functions, and data
- To investigate authorization bypass techniques and inconsistent access controls
- For evaluating administrative functionality and sensitive operation permissions
- When testing cross-account data isolation and tenant separation in multi-tenant systems
- To assess authorization logic in APIs, web applications, and mobile applications

## Inputs
- Authorized endpoints and resources requiring authentication (from previous testing)
- Only explicitly authorized test accounts with different privilege levels
- Resource identifiers, object IDs, and parameter names to test for authorization
- Test data that does not affect real user accounts, production data, or other users' information
- Rate limiting and concurrency constraints from program policy
- Different user roles, groups, and permission levels (only authorized test accounts)
- Context about business logic and expected authorization behavior

## Outputs
- Broken Object Level Authorization (BOLA) - unauthorized access to other users' resources
- Broken Function Level Authorization (BFUA) - unauthorized access to administrative functions
- Vertical privilege escalation (low privilege user -> high privilege operations)
- Horizontal privilege escalation (user A -> user B resources of same privilege level)
- Insecure direct object references (IDOR) in parameters and APIs
- Missing authorization checks on sensitive endpoints and functions
- Authorization bypass via parameter manipulation, encoding, or obfuscation
- Inconsistent authorization between web, mobile, and API interfaces
- Cross-account data isolation failures in multi-tenant systems
- Unauthorized access to administrative consoles, dashboards, or management interfaces
- Privilege escalation via parameter tampering or state manipulation
- All findings with reproduction steps and impact assessment

## Workflow

### Phase 1: Authorization Mapping and Role Definition
```
- Map all protected resources, functions, and endpoints requiring authorization
- Identify different user roles, permission levels, and access tiers
- Document resource ownership models and access control logic
- Map API endpoints to business functions and required permission levels
- Identify administrative functions, management consoles, and sensitive operations
- Note resource identifiers, object IDs, and parameter naming conventions
- Document expected authorization behavior for each resource type
```

### Phase 2: Object-Level Authorization Testing (BOLA/IDOR)
```
- Test access to other users' resources by modifying object IDs in parameters
- Evaluate resource identifiers for predictability and enumeration vulnerability
- Test for UUID vs sequential ID usage and corresponding attack vectors
- Check for proper authorization checks on read, update, and delete operations
- Test for resource access via alternative endpoints or parameter names
- Evaluate for reference disclosure in logs, error messages, or headers
- Test for secondary authorization context validation (user + resource ownership)
```

### Phase 3: Function-Level Authorization Testing
```
- Test access to administrative functions with non-administrative user accounts
- Evaluate function name obfuscation and discovery via brute force or wordlists
- Check for proper authorization decorators, middleware, or controllers
- Test for HTTP method manipulation to bypass function-level restrictions
- Evaluate for missing authorization on POST, PUT, DELETE, and PATCH operations
- Test for authorization bypass via header manipulation or parameter injection
- Check for proper separation of concerns between user and admin functions
```

### Phase 4: Privilege Escalation Testing
```
- Test vertical privilege escalation paths (guest -> user -> admin -> superadmin)
- Evaluate for privilege chaining via intermediate privilege levels
- Test for privilege escalation via parameter tampering (role=admin, access_level=high)
- Check for session manipulation to elevate privileges (cookie modification)
- Test for direct object references in administrative contexts
- Evaluate for insufficient re-authentication on privilege elevation
- Test for race conditions in privilege validation and assignment
```

### Phase 5: Context and State-Based Authorization Testing
```
- Test authorization bypass via state manipulation or parameter ordering
- Evaluate for timezone, locale, or context-based authorization flaws
- Check for proper validation of business logic constraints and state transitions
- Test for authorization bypass via race conditions in state-changing operations
- Evaluate for proper authorization in callback and webhook processing
- Test for authorization consistency across different access methods (web, mobile, API)
```

### Phase 6: Multi-Tenant and Cross-Account Testing
```
- Test cross-account data isolation in multi-tenant applications
- Evaluate for tenant identifier leakage or prediction
- Test for unauthorized access to other tenants' data or resources
- Check for proper namespace isolation and access controls
- Evaluate for shared resource vulnerabilities (caches, sessions, temporary files)
- Test for data leakage via shared infrastructure or third-party services
```

### Phase 7: Authorization Logic and Bypass Testing
```
- Test for authorization bypass via encoding, alternates, or polluting parameters
- Evaluate for case sensitivity, whitespace, or special character bypass
- Check for proper validation of authorization tokens and signatures
- Test for authorization header manipulation and injection
- Evaluate for JSON property pollution and prototype poisoning effects
- Test for authorization bypass via content type confusion or manipulation
- Check for proper validation of referrer origin and same-origin policies
```

## Safety Requirements
- **USE ONLY EXPLICITLY AUTHORIZED TEST ACCOUNTS**: Never test against real user accounts without explicit permission
- **NO REAL USER DATA ACCESS**: Never access, modify, or delete real user data or resources
- **NO PRODUCTION DATA IMPACT**: Use only test data that does not affect real transactions or user information
- **RESPECT RATE LIMITS**: Adhere to program-specified rate limits for authorization testing
- **NO DESTRUCTIVE TESTING**: Do not test for data destruction, account deletion, or service disruption
- **DATA PRIVACY**: Do not collect, retain, or transmit real user data from authorization tests
- **TEST ACCOUNT ISOLATION**: Ensure test accounts cannot affect real user accounts or data
- **CONSISTENT TESTING**: Use the same test accounts throughout to minimize confusion
- **NO CREDENTIAL THEFT**: Never attempt to steal credentials from authorization testing
- **SESSION INTEGRITY**: Be careful not to disrupt legitimate user sessions during testing
- **THIRD-PARTY SERVICE AUTHORIZATION**: Verify explicit authorization before testing third-party service integrations

## Required Tools
- HTTP clients: curl, HTTPie, browsers (for manual testing within scope)
- Session manipulation tools: browser developer tools, cookie editors (for authorized test accounts only)
- Parameter manipulation tools: Burp Suite Intruder, OWASP ZAP fuzzers (scope-limited use)
- JWT/oauth analysis tools: jwt.io, OAuth debugging tools (for authorized tokens only)
- API testing frameworks: Postman, Insomnia (authorized scope only)
- Proxy tools: Burp Suite, OWASP ZAP (only within explicitly authorized scope)
- Comparison tools: diff, vimdiff, graphical diff tools (for response comparison)
- Logging tools: Only for authorized test account activity

## Output Files
- `authz/bola-testing.json` - broken object level authorization test results
- `authz/bfua-testing.json` - broken function level authorization test results
- `authz/privilege-escalation.json` - vertical and horizontal privilege escalation results
- `authz/idore-testing.json` - insecure direct object reference test results
- `authz/missing-auth.json` - missing authorization check test results
- `authz/bypass-techniques.json` - authorization bypass technique test results
- `authz/cross-account.json` - multi-tenant and cross-account isolation test results
- `authz/reproduction-steps.md` - detailed reproduction instructions for each finding
- `authz/impact-assessment.json` - business and technical impact analysis
- `logs/authorization-audit.log` - detailed audit trail of all authorization testing

## Integration Points
- Receives authorized endpoints from reconnaissance, api-security, and authentication-audit skills
- Provides findings to vulnerability validation for confirmation
- Feeds remediation skill with specific code fix recommendations (access control fixes)
- Updates program dashboard with authorization security testing progress
- Works with api-security skill for API authorization testing
- References authentication-audit skill for pre-authorization authentication state
- Informs payment-security skill about payment authorization logic and controls

## Example Usage
```
/authorization-audit test_bola --endpoint /api/users/{id}/profile --param id --start 1 --end 100
/authorization-audit test_bfua --endpoint /admin/users --method GET --role user
/authorization-audit test_privilege_esc --endpoint /api/upgrade-role --param role --value admin
/authorization-audit test_idor --resource orders --param order_id --start 1000 --end 1100
/authorization-audit test_bypass --header X-Role --value admin --endpoint /api/sensitive
/authorization-audit test_context --param state=approved --value pending --endpoint /api/order/{id}
```

## Error Conditions
- Unauthorized endpoint detected: HALT and request scope clarification
- Real user data accessed: IMMEDIATELY STOP and initiate incident response
- Rate limit exceeded: BACK OFF and respect program restrictions
- Test account permissions insufficient: VERIFY with program administrator or adjust
- Unexpected authorization behavior: INVESTIGATE but do not exploit without authorization
- Test account lockout: STOP immediately and use only authorized test credentials