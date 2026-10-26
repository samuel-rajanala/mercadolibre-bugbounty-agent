# Mercado Libre Bug Bounty Research Agent

This AI-assisted security research agent is designed for authorized security testing of the Mercado Libre HackerOne bug bounty program.

## Usage

### Initial Setup
1. Provide the Mercado Libre HackerOne program policy information
2. The agent will create scoped skills and workflows based on authorized assets
3. All security testing must be explicitly authorized before execution

### Core Workflow
Follow these phases for authorized security research:

1. **Program Intelligence** - Analyze and understand program policy
   ```
   /program-intelligence analyze_policy --source [policy_file_or_url]
   ```

2. **Scope Validation** - Verify targets are authorized before testing
   ```
   /scope-validator check_target --host example.com --method GET
   ```

3. **Reconnaissance** - Gather passive intelligence on authorized assets
   ```
   /reconnaissance run_passive --scope-file scopes/verified-scope.json
   ```

4. **Specialized Testing** - Conduct authorized vulnerability research
   ```
   /api-security test_endpoint --url https://api.mercadolibre.com/endpoint
   /authentication-audit test_login --endpoint https://www.mercadolibre.com/login
   /authorization-audit test_bola --endpoint /api/users/{id} --param id
   /payment-security test_state --endpoint https://api.sandbox.mercadolibre.com/payments/{id}
   ```

5. **Vulnerability Validation** - Confirm findings and eliminate false positives
   ```
   /vulnerability-validation validate_finding --type IDOR --evidence initial-testing.json
   ```

6. **Remediation** - Develop fixes for confirmed vulnerabilities
   ```
   /remediation generate_fix --vuln IDOR --language Java --framework Spring
   ```

7. **Report Generation** - Create submission-ready reports (requires approval)
   ```
   /report-generator create_report --vuln IDOR --endpoint /api/users/{id}
   ```

## Authorization Requirements
- **NO TESTING WITHOUT EXPLICIT AUTHORIZATION**: All targets must be validated via scope-validator first
- **PASSIVE RECONNAISSANCE ONLY**: Initial information gathering must be purely passive
- **TEST ACCOUNTS ONLY**: Use only explicitly provided test accounts and credentials
- **SANDBOX/TEST ENVIRONMENTS**: Payment testing must be in sandbox/test environments only
- **RATE LIMIT COMPLIANCE**: Adhere to all program-specified rate limits and restrictions
- **DATA PRIVACY**: Do not collect, retain, or transmit sensitive data unnecessarily

## Skill Categories
- `program-intelligence` - Policy analysis and scope understanding
- `scope-validator` - Authorization checking before any testing
- `reconnaissance` - Passive information gathering
- `api-security` - API-specific vulnerability testing
- `authentication-audit` - Authentication mechanism testing
- `authorization-audit` - Authorization and access control testing
- `payment-security` - Payment processing system testing (sandbox only)
- `vulnerability-validation` - False positive elimination and confirmation
- `remediation` - Fix development and secure code examples
- `report-generator` - Professional report creation (requires approval)

## Project Structure
```
mercadolibre-bugbounty-agent/
├── CLAUDE.md
├── README.md
├── scopes/
│   ├── mercadolibre-scope.json (to be filled with policy)
│   └── program-policy.md (to be filled with policy)
├── scripts/
├── evidence/
├── reports/
├── findings/
├── logs/
└── .claude/
    └── skills/
        ├── program-intelligence/
        │   └── SKILL.md
        ├── scope-validator/
        │   └── SKILL.md
        ├── reconnaissance/
        │   └── SKILL.md
        ├── api-security/
        │   └── SKILL.md
        ├── authentication-audit/
        │   └── SKILL.md
        ├── authorization-audit/
        │   └── SKILL.md
        ├── payment-security/
        │   └── SKILL.md
        ├── vulnerability-validation/
        │   └── SKILL.md
        ├── remediation/
        │   └── SKILL.md
        └── report-generator/
            └── SKILL.md
```

## Important Notes
- This agent is designed to assist with authorized security research only
- All security testing requires explicit authorization via the scope validation skill
- The agent will not perform any testing without proper scope confirmation
- Reports generated require final human approval before submission to HackerOne
- When in doubt about authorization, assume DENY and request clarification
- The agent respects all stated program restrictions and limitations