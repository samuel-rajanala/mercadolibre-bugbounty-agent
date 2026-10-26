# Remediation Skill

## Purpose
Develop and recommend practical fixes for confirmed vulnerabilities, including secure code examples, configuration changes, and validation tests to prevent recurrence.

## When to Use
- After a vulnerability has been CONFIRMED via the vulnerability-validation skill
- Before providing remediation advice to the development team
- When creating regression tests to prevent vulnerability reintroduction
- To develop defense-in-depth recommendations beyond immediate fixes
- For creating educational materials about the vulnerability and prevention

## Inputs
- Confirmed vulnerability details from vulnerability-validation skill
- Root cause analysis and technical explanation
- Reproduction steps and proof of concept
- Technology stack and implementation details (language, framework, version)
- Available source code or configuration samples (if authorized)
- Existing security controls and mitigation measures in place
- Program-specific constraints and deployment considerations
- Testing environment details for validation of fixes

## Outputs
- Root cause explanation with technical details
- Specific code fixes with secure implementation examples
- Configuration changes and security hardening recommendations
- Input validation and sanitization guidelines
- Authentication and authorization improvements
- Defense-in-depth recommendations and additional controls
- Regression tests to prevent vulnerability reintroduction
- Validation steps to confirm fix effectiveness
- Deployment considerations and rollback procedures
- Educational summary for development team awareness
- References to security standards and best practices (OWASP, CWE, etc.)

## Workflow

### Phase 1: Root Cause Analysis Review
```
- Review confirmed vulnerability details and reproduction steps
- Analyze root cause analysis from validation phase
- Identify specific file, function, or component where vulnerability exists
- Determine technology stack, framework version, and implementation details
- Evaluate existing security controls that failed or were bypassed
- Understand business logic flow and data flow at point of vulnerability
```

### Phase 2: Fix Development and Secure Alternatives
```
- Develop minimal necessary fix to address root cause
- Ensure fix does not break legitimate functionality
- Consider alternative secure implementations if applicable
- Evaluate fix for potential bypass vectors or new weaknesses
- Check for consistency with existing code patterns and conventions
- Validate fix against OWASP ASVS and applicable security standards
- Consider performance impact and scalability of the fix
```

### Phase 3: Code Example Generation
```
- Provide secure code examples in the relevant programming language
- Show before/after comparison highlighting the security improvement
- Include proper error handling and edge case consideration
- Demonstrate proper input validation, output encoding, or authorization checks
- Show secure use of APIs, libraries, and framework features
- Provide configuration examples for security hardening
- Include comments explaining the security rationale for changes
```

### Phase 4: Validation and Testing Recommendations
```
- Create regression tests to verify fix effectiveness
- Develop test cases for both positive and negative scenarios
- Include tests for bypass attempts and edge cases
- Recommend specific testing procedures for QA and development
- Suggest automated testing integration points (CI/CD pipelines)
- Provide validation steps to confirm vulnerability is resolved
- Recommend manual testing procedures for complex logic
```

### Phase 5: Defense-in-Depth Recommendations
```
- Suggest additional security controls beyond immediate fix
- Recommend monitoring and logging improvements for detection
- Propose input validation at multiple layers (client, API, database)
- Suggest authorization re-verification for sensitive operations
- Recommend security headers and CSP where applicable
- Propose regular security testing and code review schedules
- Recommend dependency management and vulnerability scanning
```

### Phase 6: Deployment and Rollback Planning
```
- Create deployment plan for fix implementation
- Develop rollback procedure in case of unexpected issues
- Recommend testing in staging environment before production
- Suggest feature flags or gradual rollout where applicable
- Provide backup and recovery procedures
- Recommend communication plan for stakeholders
```

## Safety Requirements
- **ONLY PROVIDE FIXES FOR CONFIRMED VULNERABILITIES**: Never speculate or provide fixes for unconfirmed findings
- **RESPECT INTELLECTUAL PROPERTY**: Do not disclose proprietary code or algorithms without authorization
- **NO DESTRUCTIVE RECOMMENDATIONS**: Never suggest changes that could cause system instability or data loss
- **MAINTAIN FUNCTIONALITY**: Ensure fixes preserve legitimate business functionality
- **CONSIDER COMPATIBILITY**: Ensure fixes work with existing systems, plugins, and integrations
- **RESPECT DEPLOYMENT CONSTRAINTS**: Consider release cycles, maintenance windows, and deployment procedures
- **DATA PRIVACY**: Do not suggest changes that would compromise data protection requirements
- **THIRD-PARTY CONSIDERATIONS**: Account for impact on third-party integrations and services
- **NO GUARANTEES**: Clearly state that fixes should be tested in appropriate environments before deployment
- **ENVIRONMENT-SPECIFIC**: Tailor recommendations to the specific technology stack and deployment environment

## Required Information
- Confirmed vulnerability report from validation phase
- Technology stack details (language, framework, version, server)
- Available code snippets or configuration samples (only if authorized)
- Existing security controls and mitigation measures
- Deployment environment details (cloud, on-premise, containerized)
- Performance requirements and scalability considerations
- Maintenance window and release process information
- Team expertise and familiarity with suggested fixes

## Output Files
- `remediation/root-cause-analysis.md` - detailed root cause explanation
- `remediation/secure-code-examples/` - directory with language-specific secure examples
- `remediation/configuration-fixes/` - directory with configuration change recommendations
- `remediation/regression-tests/` - directory with test cases to prevent reintroduction
- `remediation/defense-in-depth.md` - additional security control recommendations
- `remediation/deployment-guide.md` - deployment and rollback procedures
- `remediation/validation-steps.md` - steps to confirm fix effectiveness
- `remediation/educational-summary.md` - summary for development team awareness
- `logs/remediation.log` - detailed audit trail of all remediation activities
- `remediation/summary.json` - structured summary of remediation recommendations

## Integration Points
- Receives confirmed vulnerabilities from vulnerability-validation skill
- Works with scope-validator to ensure fix development remains within scope
- Feeds report-generator skill with fix details for vulnerability reports
- Updates program dashboard with remediation progress and status
- References all specialized skills for context-specific fix recommendations
- Provides input to program dashboard about remediation tracking

## Example Usage
```
/remediation generate_fix --vuln IDOR --endpoint /api/users/{id} --language Java --framework Spring
/remediation analyze_rootcause --vuln XSS --endpoint /search --parameter q
/remediation create_regression_test --vuln SQLi --endpoint /login --method POST
/remediation recommend_defense_indepth --vuln CSRF --technology-stack "React/Node.js"
/remediation create_deployment_plan --vuln PaymentState --service microservice-payments
```

## Error Conditions
- Unconfirmed vulnerability provided: HALT and require validation confirmation
- Insufficient technical details: REQUEST additional information from validation phase
- Proprietary code requested without authorization: REFUSE and suggest alternatives
- Fix would break functionality: FLAG POTENTIAL ISSUES and suggest alternatives
- Deployment environment unknown: REQUEST clarification for appropriate recommendations
- Security standard conflict: HIGHLIGHT and suggest compliant alternatives