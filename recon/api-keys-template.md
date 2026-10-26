# API Keys Configuration for Enhanced Reconnaissance

To enhance the passive reconnaissance capabilities, you can configure API keys for various passive data sources. Below is a template for configuring these keys.

## Environment Variables
Copy this template to `.env` or set these as environment variables:

```bash
# Passive DNS & Certificate Transparency
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret

# Code Repositories
GITHUB_API_KEY=your_github_api_key_here
GITLAB_API_KEY=your_gitlab_api_key_here

# Search Engines (if available via API)
GOOGLE_CUSTOM_SEARCH_API_KEY=your_google_api_key_here
GOOGLE_CUSTOM_SEARCH_ENGINE_ID=your_search_engine_id_here

# Technology Stack & Job Sites
BUILTWITH_API_KEY=your_builtwith_api_key_here
WAPPALYZER_API_KEY=your_wappalyzers_api_key_here
```

## Configuration File (JSON)
Alternatively, create `recon/api-keys.json`:

```json
{
  "securitytrails": {
    "api_key": "your_securitytrails_api_key_here"
  },
  "virustotal": {
    "api_key": "your_virustotal_api_key_here"
  },
  "shodan": {
    "api_key": "your_shodan_api_key_here"
  },
  "censys": {
    "api_id": "your_censys_api_id",
    "api_secret": "your_censys_api_secret"
  },
  "github": {
    "api_key": "your_github_api_key_here"
  },
  "gitlab": {
    "api_key": "your_gitlab_api_key_here"
  },
  "google_search": {
    "api_key": "your_google_api_key_here",
    "engine_id": "your_search_engine_id_here"
  },
  "builtwith": {
    "api_key": "your_builtwith_api_key_here"
  }
}
```

## Enhanced Reconnaissance Capabilities

With API keys configured, the reconnaissance script could be enhanced to:

### 1. SecurityTrails / PassiveTotal
- DNS enumeration (historical and current records)
- SSL/TLS certificate information
- Subdomain discovery
- WHOIS records
- IP address details

### 2. VirusTotal
- URL and domain scanning history
- SSL certificate analysis
- Passive DNS
- Related domains and IPs
- File analysis (if any samples uploaded)

### 3. Shodan / Censys
- Internet-wide scan results
- Open port discovery
- Service and version detection
- SSL/TLS certificate analysis
- Technology fingerprinting

### 4. GitHub / GitLab API
- Code repository search
- Organization member enumeration
- Public repository analysis
- Commit history review
- Issue and pull request examination

### 5. BuiltWith / Wappalyzer
- Technology stack detection
- Framework identification
- CMS and e-commerce platform detection
- Analytics and tracking tool identification

### 6. Search Engines & Web Archives
- Google Custom Search (for site-specific searches)
- Bing API
- Wayback Machine enhanced access
- Archive.today
- Search engine cache inspection

## Example Enhancement to Passive Reconnaissance Script

Here's how the certificate transparency check could be enhanced with SecurityTrails:

```python
def check_certificate_transparency_enhanced(self) -> List[Dict]:
    """Enhanced CT logging check using SecurityTrails API."""
    if not self.api_keys.get('securitytrails'):
        print("  SecurityTrails API key not configured - skipping enhanced CT check")
        return self.check_certificate_transparency()  # Fallback to basic
    
    # Enhanced implementation using SecurityTrails API
    # ... API call implementation ...
```

## Recommendations

1. **Start with free tier API keys** - Many services offer free tiers suitable for initial reconnaissance
2. **Focus on high-value targets** - Prioritize checking critical domains first
3. **Respect rate limits** - Implement proper backoff and retry logic
4. **Audit your findings** - Regularly review and validate discovered assets
5. **Document everything** - Keep records of all reconnaissance activities for reporting

## Next Steps

1. Obtain API keys from desired services (many offer free trial credits)
2. Configure keys using one of the methods above
3. Enhance the reconnaissance script to utilize these APIs
4. Run enhanced reconnaissance passively
5. Proceed to specialized testing phases with discovered targets

---
*Configuration template for Mercado Libre Bug Bounty Research Agent*
*For authorized security research only*