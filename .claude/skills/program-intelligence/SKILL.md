# Program Intelligence Skill

## Purpose
Analyze and extract actionable information from bug bounty program policies to guide authorized security research.

## When to Use
- At the start of a new engagement
- When reviewing program policy updates
- Before conducting reconnaissance to understand scope boundaries
- When determining if a target is authorized for testing

## Inputs
- Program policy document (URL, file path, or pasted content)
- Specific questions about scope, rules, or requirements
- Target assets to validate against policy

## Outputs
- Structured scope information (JSON format)
- Human-readable policy summary
- Authorization decisions for specific targets
- List of in-scope and out-of-scope assets
- Vulnerability categories and testing restrictions
- Reward structures and disclosure requirements

## Workflow

### 1. Policy Ingestion
```
- Accept policy via URL, file upload, or direct text input
- Extract text content from HTML/PDF/markdown sources
- Identify key sections: scope, rules, rewards, restrictions
```

### 2. Scope Analysis
```
- Parse in-scope assets (domains, subdomains, IPs, applications)
- Identify out-of-scope assets and explicit exclusions
- Process wildcard domain rules
- Note mobile application scope and API endpoints
- Distinguish between bounty-eligible and non-bounty-eligible assets
```

### 3. Rule Extraction
```
- Identify vulnerability categories accepted for bounty
- Extract excluded vulnerability types
- Document testing restrictions (rate limits, automation bans)
- Record account requirements and credential usage rules
- Capture disclosure timelines and requirements
- Note special conditions and program-specific requirements
```

### 4. Intelligence Synthesis
```
- Generate structured scope validation rules
- Create human-readable policy summary
- Identify potential testing vectors within scope
- Highlight high-value targets based on program focus
- Note any recent policy changes or updates
```

## Safety Requirements
- Never infer scope - when uncertain, mark as requiring manual verification
- Default to deny for ambiguous targets
- Clearly separate factual policy information from interpretation
- Do not attempt to access or test assets without explicit policy authorization
- Respect all stated testing restrictions and limitations

## Expected Files
- Input: policy documents in various formats (URL, .txt, .md, .json, .pdf)
- Output: 
  - `scopes/verified-scope.json` - structured scope data
  - `scopes/policy-summary.md` - human-readable summary
  - `logs/policy-analysis.log` - analysis process log

## Example Usage
```
/program-intelligence analyze_policy --url https://hackerone.com/example/program
/program-intelligence validate_scope --target api.example.com
/program-intelligence get_vuln_categories --format json
```

## Integration Points
- Feeds data to scope-validator skill for authorization checks
- Informs reconnaissance skill about authorized targets
- Provides context for all specialized research skills
- Updates program dashboard with policy status

## Error Handling
- If policy cannot be retrieved: request manual input from user
- If policy is ambiguous: flag for manual verification and default to deny
- If format is unsupported: suggest alternative formats or manual copy-paste
- If network fails: offer cached version or local file input options