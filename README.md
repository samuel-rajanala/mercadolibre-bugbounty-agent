# Mercado Libre Bug Bounty Research Agent

## Project Status: Initial Setup

This is an AI-assisted security research environment for the Mercado Libre HackerOne bug bounty program.

## Current Status

### Policy Information Retrieval
I attempted to retrieve the official Mercado Libre HackerOne program policy from:
- https://hackerone.com/mercadolibre
- https://hackerone.com/mercadolibre/policy_scopes

**What I was able to retrieve:**
- Basic program identification: "MercadoLibre Bug Bounty Program | HackerOne"
- Program description: "The MercadoLibre Bug Bounty Program enlists the help of the hacker community at HackerOne to make MercadoLibre more secure. HackerOne is the #1 hacker-powered security platform, helping organizations find and fix critical vulnerabilities before they can be criminally exploited."

**What I could not retrieve:**
- Detailed scope information (in-scope/out-of-scope assets)
- Bounty-eligible vs non-bounty-eligible assets
- Explicitly excluded assets
- Wildcard domain rules
- Mobile application scope
- Vulnerability categories accepted/excluded
- Testing restrictions
- Rate limits and automation restrictions
- Account requirements
- Disclosure requirements
- Reward structure
- Duplicate-report policy
- Special conditions and program-specific requirements

**Reason:** The HackerOne platform loads its policy content dynamically via JavaScript, which cannot be executed in this environment to extract the detailed policy information.

### What I Need From You
To proceed with building a proper security research agent, I need you to provide the Mercado Libre HackerOne program policy information. Please share:

1. The complete scope information from the policy page
2. Any additional program rules, reward structures, or testing restrictions
3. Or alternatively, you can guide me on how to proceed with the information I have

Once you provide the policy information, I will:
- Save it to `scopes/mercadolibre-scope.json` and `scopes/program-policy.md`
- Continue building the security environment as specified
- Create all the specialized skills and workflows
- Set up the scope validation component
- Begin reconnaissance on authorized assets

## Project Structure Created
```
mercadolibre-bugbounty-agent/
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
        │   └── SKILL.md (template)
        ├── scope-validator/
        │   └── SKILL.md (template)
        ├── reconnaissance/
        │   └── SKILL.md (template)
        ├── api-security/
        │   └── SKILL.md (template)
        ├── authentication-audit/
        │   └── SKILL.md (template)
        ├── authorization-audit/
        │   └── SKILL.md (template)
        ├── payment-security/
        │   └── SKILL.md (template)
        ├── vulnerability-validation/
        │   └── SKILL.md (template)
        ├── remediation/
        │   └── SKILL.md (template)
        └── report-generator/
            └── SKILL.md (template)
```

## Next Steps
Once you provide the policy information, I will:
1. Save the verified policy to the scopes/ directory
2. Begin populating each skill with practical instructions, workflows, and safety requirements
3. Create the scope validation script
4. Set up passive reconnaissance workflows
5. Create specialized research workflows for authentication, authorization, API security, payment security, injection vulnerabilities, and business logic
6. Implement vulnerability validation and severity assessment components
7. Set up automated report generation (requiring your approval before submission)
8. Build the remediation engine
9. Create the final dashboard

Please provide the Mercado Libre HackerOne program policy information so I can proceed with building a complete, authorized security research agent.