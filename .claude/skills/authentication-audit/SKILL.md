# Authentication Audit Skill

## Purpose
Conduct authorized security testing of authentication mechanisms to identify weaknesses in login, session management, password recovery, multi-factor authentication, and related authentication flows within explicitly authorized boundaries.

## When to Use
- After reconnaissance identifies authentication endpoints and portals
- When testing login mechanisms, credential validation, and session handling
- To investigate password reset, account recovery, and authentication bypass flaws
- For evaluating multi-factor authentication implementation and strength
- When testing single sign-on (SSO), OAuth, and federated identity implementations
- To assess credential storage, transmission, and protection mechanisms

## Inputs
- Authorized authentication endpoints and flows (login, logout, password reset, MFA, SSO, etc.)
- Only explicitly authorized test accounts and credentials
- Session tokens, cookies, and authentication artifacts from authorized testing
- Password dictionaries and wordlists (only for authorized brute force testing if permitted)
- Multi-factor authentication devices and methods (only authorized test factors)
- Rate limiting and concurrency constraints from program policy
- Test data that does not affect real user accounts or production systems

## Outputs
- Authentication bypass vulnerabilities (login without valid credentials)
- Weak credential validation (insufficient password complexity, weak hashing)
- Session management flaws (session fixation, prediction, insufficient expiration)
- Password reset and account recovery vulnerabilities (token leakage, brute force)
- Multi-factor authentication weaknesses (bypass, cloning, insufficient verification)
- Credential transmission issues (HTTP instead of HTTPS, tokens in URLs)
- Credential storage vulnerabilities (plaintext, weak encryption, insecure storage)
- Single sign-on and federated identity misconfigurations
- OAuth and OpenID Connect implementation flaws
- Brute force and credential stuffing vulnerabilities (if authorized and controlled)
- Session replay and token manipulation vulnerabilities
- All findings with reproduction steps and impact assessment

## Workflow

### Phase 1: Authentication Endpoint Mapping
```
- Identify all authentication-related endpoints (login, logout, register, etc.)
- Map authentication flows (web forms, API endpoints, mobile deep links)
- Document authentication methods (form-based, token-based, certificate-based)
- Identify third-party authentication services (Google, Facebook, Apple SSO)
- Catalog password reset, account recovery, and email verification flows
- Note multi-factor authentication implementation points and methods
```

### Phase 2: Credential Validation Testing
```
- Test password complexity requirements and enforcement
- Evaluate password hashing algorithms (bcrypt, scrypt, Argon2 vs weak MD5/SHA1)
- Test for weak or default credentials in administrative interfaces
- Check for credential leakage in autocomplete, logs, or error messages
- Evaluate remember-me functionality and persistent cookie security
- Test for username enumeration via timing differences or error messages
- Check for password strength meter bypass or client-side only validation
```

### Phase 3: Session Management Testing
```
- Test session ID generation for randomness and unpredictability
- Evaluate session expiration on logout, timeout, and inactivity
- Check for session fixation vulnerabilities
- Test for predictable or sequential session identifiers
- Evaluate secure cookie attributes (HttpOnly, Secure, SameSite)
- Test for session disclosure in URLs, logs, or error messages
- Check for concurrent session limitations and proper invalidation
```

### Phase 4: Password Reset and Account Recovery Testing
```
- Test password reset token generation for randomness and entropy
- Evaluate password reset token expiration and length requirements
- Check for password reset token leakage via Referer or logging
- Test for brute force protection on password reset endpoints
- Evaluate for account enumeration via password reset timing differences
- Test for password reset token reuse or insufficient invalidation
- Check for outdated password reset links and proper expiration
- Test for cross-user password reset (token validity across accounts)
```

### Phase 5: Multi-Factor Authentication Testing
```
- Test MFA enforcement for sensitive operations and administrative access
- Evaluate MFA method security (SMS, TOTP, push notification, hardware keys)
- Test for MFA bypass via session manipulation or credential replay
- Check for proper MFA initiation and validation steps
- Evaluate backup code generation, storage, and validation
- Test for MFA recovery process and account takeover resistance
- Check for phishing resistance in MFA implementations
```

### Phase 6: Single Sign-On and Federated Identity Testing
```
- Test SAML implementation for XML external entity and signature wrapping
- Evaluate OAuth implementation for state parameter and redirect URI validation
- Check for OpenID Connect nonce and token validation
- Test for token theft via cross-site scripting or token leakage
- Evaluate single logout (SLO) implementation and session invalidation
- Check for identity provider impersonation and assertion tampering
- Test for attribute injection and privilege escalation via SAML/OIDC
```

### Phase 7: Credential Storage and Transmission Testing
```
- Test for credential transmission over HTTP instead of HTTPS
- Check for sensitive data in URLs (session IDs, passwords, tokens)
- Evaluate for credential storage in local storage, cookies, or HTML5 storage
- Test for credential leakage via autocomplete, browser history, or caching
- Check for password storage in plaintext or reversible encryption
- Evaluate for secure transmission of credentials in API requests and responses
- Test for credential hashing salt uniqueness and storage protection
```

## Safety Requirements
- **USE ONLY EXPLICITLY AUTHORIZED TEST ACCOUNTS**: Never test against real user accounts
- **NO REAL CREDENTIAL THEFT**: Do not attempt to steal or use real user credentials
- **NO ACCOUNT TAKEOVER ATTEMPTS**: Never attempt to take over real user accounts
- **RESPECT RATE LIMITS**: Adhere to program-specified rate limits for authentication endpoints
- **NO DESTRUCTIVE TESTING**: Do not test for account deletion or service disruption
- **FINANCIAL AUTHENTICATION TESTING**: Never test payment authentication with real funds
- **DATA PRIVACY**: Do not collect or retain real user credentials or session data
- **PASSWORD TESTING LIMITS**: If authorized, use only provided wordlists with strict limits
- **MFA TESTING CONSTRAINTS**: Only test with explicitly authorized test factors and devices
- **SSO TESTING AUTHORIZATION**: Verify explicit authorization before testing SSO integrations
- **NO CREDENTIAL STUFFING**: Use only explicitly provided test credentials if authorized
- **SESSION TESTING CAUTION**: Be careful not to disrupt legitimate user sessions

## Required Tools
- HTTP clients: curl, HTTPie, browsers (for manual testing within scope)
- Password testing tools: hashcat, John the Ripper (only with explicit authorization and authorized wordlists)
- Session analysis tools: browser developer tools, cookie inspectors
- JWT/OAuth analysis tools: jwt.io, OAuth debugging tools
- SSL/TLS analysis: SSL Labs, curl for certificate validation
- Proxy tools: Burp Suite, OWASP ZAP (only within explicitly authorized scope)
- Network analysis: Wireshark, tcpdump (only for authorized traffic analysis)
- Forensic tools: Only for authorized test account analysis

## Output Files
- `auth/login-testing.json` - login mechanism test results and findings
- `auth/session-management.json` - session handling test results and findings
- `auth/password-reset.json` - password reset and account recovery test results
- `auth/mfa-testing.json` - multi-factor authentication test results
- `auth/sso-federated.json` - single sign-on and federated identity test results
- `auth/credential-storage.json` - credential transmission and storage test results
- `auth/brute-force.json` - brute force and credential stuffing test results (if authorized)
- `auth/reproduction-steps.md` - detailed reproduction instructions for each finding
- `auth/impact-assessment.json` - business and technical impact analysis
- `logs/authentication-audit.log` - detailed audit trail of all authentication testing

## Integration Points
- Receives authorized authentication endpoints from reconnaissance and scope validation
- Provides findings to vulnerability validation for confirmation
- Feeds remediation skill with specific code fix recommendations
- Updates program dashboard with authentication security testing progress
- Works with api-security skill for API authentication testing
- References authorization-audit skill for post-authentication authorization testing
- Informs payment-security skill about payment authentication mechanisms

## Example Usage
```
/authentication-audit test_login --endpoint https://www.mercadolibre.com/login
/authentication-audit test_session --cookie JSESSIONID --token XYZ
/authentication-audit test_password_reset --endpoint https://www.mercadolibre.com/reset
/authentication-audit test_mfa --endpoint https://www.mercadolibre.com/mfa/validate
/authentication-audit test_sso --endpoint https://www.mercadolibre.com/sso/saml
/authentication-audit test_credential_storage --checkout-flow
```

## Error Conditions
- Unauthorized authentication endpoint detected: HALT and request scope clarification
- Real user account affected: IMMEDIATELY STOP and initiate incident response
- Rate limit exceeded: BACK OFF and respect program restrictions
- Test account credentials invalid: VERIFY with program administrator or reset
- Unexpected authentication behavior: INVESTIGATE but do not exploit without authorization
- MFA device lockout: STOP immediately and use only authorized test devices