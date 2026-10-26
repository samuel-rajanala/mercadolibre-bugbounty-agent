# Reconnaissance Skill

## Purpose
Conduct passive reconnaissance on authorized assets to gather intelligence without triggering security alerts or violating testing restrictions.

## When to Use
- At the beginning of a security assessment
- After scope validation confirms targets are authorized
- Before active testing to understand the attack surface
- When identifying potential entry points and technology stacks
- To gather publicly available information about the target

## Inputs
- Authorized target list (from scope-validator skill)
- Reconnaissance scope boundaries (network ranges, subdomain limits)
- Passive-only constraint flag (to ensure no active probing)
- Available API keys for passive sources (Shodan, Censys, SecurityTrails, etc.)
- Timeboxing constraints for reconnaissance phases

## Outputs
- Authorized subdomain inventory (with scope validation)
- Passive DNS records and historical resolutions
- Technology stack fingerprints (web server, frameworks, languages)
- Publicly documented APIs and endpoints
- Public JavaScript library and framework usage
- Certificate transparency logs and SSL/TLS configurations
- Public repository references and code snippets
- Historical data from web archives and search engines
- Metadata from public job postings, press releases, and social media
- Third-party service integrations and dependencies
- Organization structure and personnel information (from public sources)
- All findings clearly marked with scope authorization status

## Workflow

### Phase 1: Passive Information Gathering (NO ACTIVE PROBING)
```
- Check certificate transparency logs for subdomains
- Query public DNS databases and historical records
- Search web archives (Wayback Machine, archive.today)
- Check search engine caches and public indexes
- Review public job postings, LinkedIn, and social media
- Examine public code repositories (GitHub, GitLab, Bitbucket)
- Analyze public job descriptions for technology insights
- Review press releases, blog posts, and technical articles
- Check third-party service listings and partnerships
- Examine public SSL/TLS certificate details
```

### Phase 2: Public Resource Enumeration
```
- Query public API documentation sites and developer portals
- Check public SDK releases and library distributions
- Review public conference presentations and talks
- Examine public bug bounty write-ups (from other programs)
- Check public vulnerability databases for historical issues
- Review open-source projects associated with the organization
- Check public compliance reports and certifications
- Examine public documentation and user guides
```

### Phase 3: Technology Fingerprinting (Passive Methods Only)
```
- Analyze HTTP headers from historical requests (via archives)
- Identify JavaScript libraries from public code samples
- Detect frameworks from URL patterns and file structures
- Recognize server technologies from error message patterns
- Identify CDN and WAF usage from request/response patterns
- Detect load balancers and proxy configurations
- Identify database technologies from connection string patterns
- Recognize authentication systems from token formats
```

### Phase 4: Asset Organization and Validation
```
- Organize all findings by domain, application, and technology
- Cross-reference each asset with scope validation
- Mark clearly authorized vs requiring manual verification
- Identify high-value targets based on technology and exposure
- Create visual attack surface maps (when authorized)
- Generate passive reconnaissance summary report
```

## Safety Requirements
- **STRICTLY PASSIVE ONLY**: No active probing, scanning, or interaction
- **NO HIGH-VOLUME REQUESTS**: Respect rate limits of passive sources
- **NO BRUTE FORCE OR FUZZING**: Prohibited without explicit authorization
- **NO CRAWLING WITHOUT PERMISSION**: Only passive observation of public data
- **RESPECT ROBOTS.TOS AND TERMS OF SERVICE**: Of all passive sources
- **NO AUTOMATED SUBDOMAIN BRUTE FORCE**: Use only public data sources
- **THIRD-PARTY SERVICE CHECK**: Verify if passive sources involve unauthorized third parties
- **DATA MINIMIZATION**: Collect only what's necessary for security research
- **NO PERSONAL DATA COLLECTION**: Avoid PII unless directly relevant to security scope

## Required Tools (Check Availability)
- Passive DNS services (SecurityTrails, PassiveTotal, VirusTotal historical)
- Certificate transparency monitors (crt.sh, Google CT logs)
- Web archive services (Wayback Machine, archive.today)
- Search engines (via official APIs where available)
- Public code repository search (GitHub API, GitLab API)
- Job site APIs (LinkedIn, Indeed, Glassdoor - where permitted)
- Social media APIs (Twitter/X, LinkedIn - where permitted and authorized)
- Public API directories (Postman Public Hub, API List)
- Technology stack analyzers (Wappalyzer, BuiltWith - via public data)
- SSL/TLS analysis tools (SSL Labs public API where available)

## Output Files
- `recon/authorized-subdomains.txt` - scope-validated subdomains
- `recon/passive-dns-records.txt` - historical DNS resolutions
- `recon/technology-stack.json` - fingerprinted technologies per asset
- `recon/public-endpoints.txt` - publicly documented APIs and endpoints
- `recon/js-libraries.txt` - identified JavaScript frameworks and libraries
- `recon/ssl-certificates.txt` - certificate transparency findings
- `recon/public-repos.txt` - discovered public code repositories
- `recon/technology-metadata.txt` - additional context and version info
- `recon/reconnaissance-summary.md` - executive summary of findings
- `logs/reconnaissance.log` - detailed audit trail of all passive queries

## Integration Points
- Receives authorized targets from scope-validator skill
- Provides target list to api-security and authentication-audit skills
- Feeds asset inventory to vulnerability validation skill
- Updates program dashboard with reconnaissance progress
- Informs remediation effort about discovered technologies
- All outputs clearly marked with scope authorization status

## Example Usage
```
/reconnaissance run_passive --scope-file scopes/verified-scope.json
/reconnaissance check_subdomain --host api.mercadolibre.com
/reconnaissance get_technology --target mercadolibre.com --passive-only
/reconnaissance list_public_apis --scope mercadolibre
```

## Error Handling
- If passive source unavailable: skip and log, continue with other sources
- If rate limited: implement exponential backoff and continue later
- If ambiguous results: flag for manual verification, don't assume authorization
- If third-party service detected in passive source: verify authorization before use
- If scope validation fails for discovered asset: exclude from further processing