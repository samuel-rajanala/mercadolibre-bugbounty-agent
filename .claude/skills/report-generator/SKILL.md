# Report Generator Skill

## Purpose
Generate professional, submission-ready bug bounty reports following HackerOne best practices and program-specific requirements.

## When to Use
- After a vulnerability has been CONFIRMED via vulnerability-validation skill
- After remediation recommendations have been generated
- Before seeking final approval for submission to the bug bounty program
- To create consistent, high-quality reports that maximize chances of approval and reward
- For creating documentation of security findings for internal tracking

## Inputs
- Confirmed vulnerability details from vulnerability-validation skill
- Root cause analysis and impact assessment
- Reproduction steps and proof of concept
- Remediation recommendations and secure code examples
- CVSS score and severity justification (from severity-assessment if available)
- Program-specific bounty structure and reward information
- Disclosure requirements and timelines from program policy
- Reporter information and authentication details
- Submission format requirements (HackerOne, Bugcrowd, etc.)

## Outputs
- Professional bug bounty report in HackerOne format
- Executive summary with impact-first narrative
- Detailed reproduction steps with minimal proof of concept
- Clear vulnerability classification and technical description
- Accurate CVSS score with vector string and justification
- Detailed security and business impact assessment
- Root cause analysis and technical explanation
- Practical remediation recommendations
- References to security standards (CWE, OWASP, etc.)
- All required fields for submission to the bug bounty program
- Report ready for final human approval before submission

## Workflow

### Phase 1: Information Collection and Validation
```
- Gather all confirmed vulnerability details from validation phase
- Collect reproduction steps, proof of concept, and evidence
- Retrieve root cause analysis and impact assessment
- Obtain remediation recommendations and secure code examples
- Verify CVSS score and severity justification
- Confirm all information meets validation standards
- Ensure no speculative or unconfirmed information is included
```

### Phase 2: Report Structure and Formatting
```
- Create impact-first executive summary (what attacker can do)
- Structure report according to HackerOne best practices
- Format for clear readability and professional presentation
- Include all required sections: Summary, Vulnerability Details, Steps to Reproduce, Impact, etc.
- Ensure proper markdown formatting for HackerOne platform
- Validate report length and conciseness guidelines
```

### Phase 3: Content Development
```
- Write clear vulnerability title following naming conventions
- Develop executive summary that leads with impact
- Detail vulnerability classification (CWE, OWASP, vulnerability type)
- Provide step-by-step reproduction instructions with minimal poc
- Include all necessary requests, headers, payloads, and environmental factors
- Describe security impact with concrete examples of potential harm
- Explain business impact in terms relevant to the organization
- Provide root cause analysis with technical details
- Offer practical remediation recommendations with code examples
- Include CVSS score with detailed justification matching actual impact
- Add references to relevant security standards and best practices
```

### Phase 4: Quality Assurance and Review
```
- Verify all claims are supported by evidence and reproduction steps
- Check for clarity, conciseness, and professional tone
- Ensure no exaggerated or speculative statements
- Confirm CVSS score accurately reflects demonstrated impact
- Validate that reproduction steps are minimal and reproducible
- Check that remediation is practical and addresses root cause
- Ensure report complies with program-specific requirements
- Prepare for final human approval before submission
```

## Safety Requirements
- **ONLY REPORT CONFIRMED VULNERABILITIES**: Never report findings that are not validated
- **NO SPECULATION OR EXAGGERATION**: Stick to what is proven and reproducible
- **RESPECT PROGRAM REQUIREMENTS**: Follow all submission guidelines and format requirements
- **DATA PRIVACY**: Do not include sensitive data from proof of concept in reports
- **REPRODUCIBLE ONLY**: Include only steps that can be reproduced by others
- **MINIMUM NECESSARY INFORMATION**: Include only what's needed to understand and fix the vulnerability
- **NO FALSE CLAIMS**: Never claim impact that has not been demonstrated
- **RESPECT DISCOVERY TIMEFRAMES**: Do not report vulnerabilities outside allowed windows
- **THIRD-PARTY CONSIDERATIONS**: Do not implicate third parties without evidence and authorization
- **PROFESSIONAL TONE**: Maintain respectful, professional communication throughout
- **APPROVAL REQUIRED**: Reports must receive final human approval before submission

## Required Information
- Confirmed vulnerability report from validation phase
- Reproduction steps and proof of concept
- Root cause analysis and technical explanation
- CVSS score and severity justification
- Remediation recommendations and secure code examples
- Program bounty structure and reward information
- Disclosure requirements and timelines
- Reporter information (handle, credentials, etc.)
- Submission deadline considerations

## Output Files
- `reports/[timestamp]-[vuln-type]-[endpoint].md` - completed bug bounty report
- `reports/template.md` - reusable report template for future use
- `reports/checklist.md` - submission checklist based on program requirements
- `reports/summary.json` - structured data for tracking and metrics
- `logs/report-generation.log` - detailed audit trail of all report generation
- `reports/pending-approval/` - directory for reports awaiting final approval

## Integration Points
- Receives confirmed vulnerabilities from vulnerability-validation skill
- Receives remediation recommendations from remediation skill
- Receives CVSS scores from severity-assessment skill (when implemented)
- Works with scope-validator to confirm all testing was authorized
- Updates program dashboard with report generation statistics
- Provides final output for human approval before submission to HackerOne
- All reports clearly indicate they require final approval before submission

## Example Usage
```
/report-generator create_report --vuln IDOR --endpoint /api/users/{id} --confirmed-file validation/results.json
/report-generator use_template --template reports/template.md --output reports/2026-10-12-IDOR-users.md
/report-generator checklist --report reports/2026-10-12-IDOR-users.md
/report-generator validate_format --report reports/2026-10-12-IDOR-users.md --platform hackerone
```

## Error Conditions
- Unconfirmed vulnerability provided: HALT and require validation confirmation
- Missing critical information: REQUEST additional details from validation/remediation phases
- CVSS score missing or unjustified: GENERATE preliminary score but flag for review
- Report exceeds length limits: SUGGEST condensation and prioritization
- Format incompatible with platform: PROVIDE alternative formats and conversion help
- Authorization issues discovered: HALT and reconfirm scope before proceeding