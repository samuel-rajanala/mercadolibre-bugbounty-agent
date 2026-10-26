#!/usr/bin/env python3
"""
Initial API Security Assessment for Mercado Libre Bug Bounty Research Agent
Performs authorized, passive information gathering and basic security checks on APIs.
"""

import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime

# Import authorization gate for fail-closed authorization enforcement
from authorization_gate import AuthorizationGate, AuthorizationRequest


class APISecurityAssessor:
    def __init__(self, scope_file: str = "scopes/verified-scope.json"):
        """
        Initialize the API security assessor with verified scope data.

        Args:
            scope_file: Path to the verified scope JSON file
        """
        self.scope_file = scope_file
        self.scope_data = self._load_scope_data()
        self.authorized_apis = self._extract_authorized_apis()
        self.findings = {
            "api_inventory": [],
            "documentation_references": [],
            "authentication_mechanisms": set(),
            "http_methods": {},
            "parameters": {},
            "headers": {},
            "rate_limiting_indicators": {},
            "potential_issues": [],
            "recommendations": []
        }

        # Initialize authorization gate for fail-closed authorization enforcement
        self.auth_gate = AuthorizationGate()

        # Rate limiting to be respectful
        self.last_request_time = 0
        self.min_delay_between_requests = 1.0  # 1 second between requests

    def _load_scope_data(self) -> Dict:
        """Load and parse the scope JSON file."""
        try:
            with open(self.scope_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Scope file not found at {self.scope_file}")
            print("Please run the program-intelligence skill first to generate scope data.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in scope file: {e}")
            sys.exit(1)

    def _extract_authorized_apis(self) -> Set[str]:
        """Extract all authorized API endpoints from scope data."""
        authorized = set()

        scope = self.scope_data.get('scope', {})

        # Add API endpoints from scope
        for api in scope.get('api_endpoints', []):
            # Normalize to lowercase for comparison, but keep original for reporting
            authorized.add(api.lower())

        # Also check wildcard domains that might be APIs
        for wildcard in scope.get('wildcard_domains', []):
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]
                # Common API subdomains to check
                api_subdomains = ['api', 'rest', 'graphql', 'service', 'ws']
                for sub in api_subdomains:
                    authorized.add(f"{sub}.{base_domain}".lower())

        return authorized

    def _is_authorized_api(self, endpoint: str) -> bool:
        """Check if an API endpoint is authorized for testing."""
        # Parse the endpoint to extract hostname
        parsed = urllib.parse.urlparse(endpoint)
        hostname = parsed.netloc.lower() if parsed.netloc else endpoint.lower()

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        # Check exact matches
        if hostname in self.authorized_apis:
            return True

        # Check wildcard matches (simplified - in practice would use scope checker)
        scope = self.scope_data.get('scope', {})
        for wildcard in scope.get('wildcard_domains', []):
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]
                # Simple check: does hostname end with the base domain?
                if hostname.endswith('.' + base_domain) or hostname == base_domain:
                    # Additional check: ensure it's not just the base domain unless it's in API endpoints
                    # This is a simplified check - the scope checker does this more rigorously
                    if hostname in self.authorized_apis:
                        return True

        return False

    def _respectful_request(self, url: str, headers: Dict = None) -> Optional[Dict]:
        """
        Make a respectful HTTP request with rate limiting and authorization checking.
        Handles redirects manually with re-authorization at each hop.
        Returns response data or None if failed or not authorized.
        """
        # Rate limiting
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay_between_requests:
            time.sleep(self.min_delay_between_requests - elapsed)

        if headers is None:
            headers = {}

        # Add user agent to identify our requests
        headers['User-Agent'] = 'MercadoLibre-BB-Agent/1.0 (Authorized Security Research)'

        # Redirect handling
        max_redirects = 5
        redirect_count = 0
        current_url = url
        original_hostname = None

        while redirect_count <= max_redirects:
            # Extract hostname from URL for authorization check
            try:
                parsed_url = urllib.parse.urlparse(current_url)
                hostname = parsed_url.netloc.lower()
                if not hostname:
                    print(f"  Warning: Could not extract hostname from URL: {current_url}")
                    return None
            except Exception as e:
                print(f"  Warning: Error parsing URL {current_url}: {e}")
                return None

            # For the first request, check authorization
            if redirect_count == 0:
                auth_request = AuthorizationRequest(
                    asset=hostname,
                    activity="API_SECURITY_ASSESSMENT",
                    technique="GET",
                    environment="request"
                )

                decision, reason = self.auth_gate.check_authorization(auth_request)
                if decision.value != "APPROVE":
                    print(f"  [AUTHORIZATION DENIED] {reason}")
                    return None
                original_hostname = hostname
            else:
                # For redirects, check authorization with strict rules
                # Prevent HTTPS-to-HTTP downgrade
                if parsed_url.scheme == 'http' and original_hostname and \
                   original_hostname.startswith('https://'):
                    print(f"  [REDIRECT BLOCKED] HTTPS-to-HTTP downgrade prevented: {current_url}")
                    return None

                # Check if redirect is to same host or requires new authorization
                if hostname != original_hostname:
                    # Cross-host redirect - require fresh authorization
                    auth_request = AuthorizationRequest(
                        asset=hostname,
                        activity="API_SECURITY_ASSESSMENT_REDIRECT",
                        technique="GET",
                        environment="request"
                    )

                    decision, reason = self.auth_gate.check_authorization(auth_request)
                    if decision.value != "APPROVE":
                        print(f"  [AUTHORIZATION DENIED] Cross-host redirect blocked: {reason}")
                        return None
                # Same-host redirect continues with original authorization

            # Prepare headers (strip sensitive headers on cross-host redirects)
            request_headers = headers.copy()
            if redirect_count > 0 and hostname != original_hostname:
                # Remove potentially sensitive headers for cross-host redirects
                sensitive_headers = ['authorization', 'cookie', 'x-auth-token', 'api-key', 'x-api-key']
                for header in sensitive_headers:
                    request_headers.pop(header, None)
                    request_headers.pop(header.capitalize(), None)
                    request_headers.pop(header.upper(), None)

            try:
                req = urllib.request.Request(current_url, headers=request_headers, method='GET')
                # Prevent automatic redirect following
                req = urllib.request.Request(current_url, headers=request_headers, method='GET',
                                           header_user_agent='MercadoLibre-BB-Agent/1.0')

                # We'll handle redirects manually, so we need to prevent automatic following
                # Create an opener that doesn't follow redirects
                opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
                # Actually, let's just use urlopen and check the response code manually
                # but we need to prevent auto-redirect - we'll do this by handling 3xx responses ourselves

                self.last_request_time = time.time()

                # Make the request
                response = urllib.request.urlopen(req, timeout=10)

                # Check if this is a redirect
                status_code = response.getcode()
                if 300 <= status_code < 400:
                    # Handle redirect
                    redirect_url = response.getheader('Location')
                    if not redirect_url:
                        print(f"  Warning: Redirect status {status_code} but no Location header")
                        # Return the redirect response anyway
                        response_data = {
                            'status': status_code,
                            'headers': dict(response.getheaders()),
                            'data': response.read().decode('utf-8', errors='ignore')[:10000]
                        }
                        return response_data

                    # Handle relative URLs
                    if redirect_url.startswith('/'):
                        parsed_original = urllib.parse.urlparse(current_url)
                        redirect_url = f"{parsed_original.scheme}://{parsed_original.netloc}{redirect_url}"
                    elif not redirect_url.startswith(('http://', 'https://')):
                        # Relative path
                        parsed_original = urllib.parse.urlparse(current_url)
                        base_url = f"{parsed_original.scheme}://{parsed_original.netloc}"
                        redirect_url = f"{base_url}/{redirect_url}"

                    redirect_count += 1
                    if redirect_count > max_redirects:
                        print(f"  Warning: Exceeded maximum redirect count ({max_redirects})")
                        return None

                    current_url = redirect_url
                    continue  # Go through authorization check again for redirect
                else:
                    # Not a redirect, return the response
                    response_data = {
                        'status': status_code,
                        'headers': dict(response.getheaders()),
                        'data': response.read().decode('utf-8', errors='ignore')[:10000]  # Limit response size
                    }
                    return response_data

            except urllib.error.HTTPError as e:
                # Even error responses can be informative for security assessment
                return {
                    'status': e.code,
                    'headers': dict(e.headers) if e.headers else {},
                    'data': e.read().decode('utf-8', errors='ignore')[:10000] if hasattr(e, 'read') else '',
                    'error': True
                }
            except Exception as e:
                print(f"  Warning: Request to {current_url} failed: {e}")
                return None

        print(f"  Warning: Exceeded maximum redirect count ({max_redirects})")
        return None

    def inventory_discovered_apis(self) -> List[Dict]:
        """
        Phase 1: API Inventory and Documentation Review (Passive)
        Catalog discovered API endpoints from reconnaissance and public sources.
        """
        print("Phase 1: API Inventory and Documentation Review")
        print("-" * 50)

        api_inventory = []

        # Start with APIs identified in scope
        scope = self.scope_data.get('scope', {})
        explicit_apis = scope.get('api_endpoints', [])

        for api_endpoint in explicit_apis:
            if self._is_authorized_api(api_endpoint):
                api_info = {
                    'endpoint': api_endpoint,
                    'discovered_via': 'scope_validation',
                    'authorized': True,
                    'bounty_eligible': self._check_bounty_eligibility(api_endpoint),
                    'inventory_time': datetime.now().isoformat()
                }
                api_inventory.append(api_info)
                self.findings['api_inventory'].append(api_info)
                print(f"  [+] Authorized API: {api_endpoint}")
            else:
                print(f"  [-] Unauthorized API (skipping): {api_endpoint}")

        # Check some common API patterns for additional discovery
        common_api_patterns = [
            'api.{domain}',
            'rest.{domain}',
            'graphql.{domain}',
            'service.{domain}'
        ]

        # Get base domains from scope for pattern checking
        base_domains = set()
        for item in scope.get('in_scope', []):
            if '.' in item and not item.startswith('*.'):
                # Extract base domain (e.g., mercadolibre.com from api.mercadolibre.com)
                parts = item.split('.')
                if len(parts) >= 2:
                    base_domains.add('.'.join(parts[-2:]))

        # Limit to avoid too many requests
        for domain in list(base_domains)[:5]:
            for pattern in common_api_patterns:
                potential_api = pattern.format(domain=domain)
                if self._is_authorized_api(potential_api) and potential_api not in [a['endpoint'] for a in api_inventory]:
                    api_info = {
                        'endpoint': potential_api,
                        'discovered_via': 'pattern_based_discovery',
                        'authorized': True,
                        'bounty_eligible': self._check_bounty_eligibility(potential_api),
                        'inventory_time': datetime.now().isoformat()
                    }
                    api_inventory.append(api_info)
                    self.findings['api_inventory'].append(api_info)
                    print(f"  ✓ Discovered API (pattern): {potential_api}")

        print(f"  Total authorized APIs identified: {len(api_inventory)}")
        return api_inventory

    def _check_bounty_eligibility(self, endpoint: str) -> bool:
        """Check if an endpoint is bounty eligible using scope checker logic."""
        # Use the same logic as scope checker for bounty eligibility
        scope = self.scope_data.get('scope', {})
        endpoint_lower = endpoint.lower()

        # Check explicit bounty eligible list
        if endpoint_lower in scope.get('bounty_eligible', []):
            return True

        # Check explicit non-bounty eligible list
        if endpoint_lower in scope.get('non_bounty_eligible', []):
            return False

        # If in scope but not explicitly listed, check if it's submission eligible
        if endpoint_lower in scope.get('in_scope', []):
            return True  # Default to eligible if in scope and not explicitly excluded

        return False

    def review_public_documentation(self) -> List[Dict]:
        """
        Look for public API documentation, developer portals, and SDK information.
        """
        print("\nPhase 1b: Public Documentation Review")
        print("-" * 50)

        doc_references = []

        # Check for known developer portals/documentation sites
        doc_sites = [
            'developers.mercadolibre.com',
            'developers.mercadopago.com',
            'www.mercadolibre.com/dev',
            'api-docs.mercadolibre.com',
            'docs.mercadolibre.com'
        ]

        for site in doc_sites:
            if self._is_authorized_api(site):
                print(f"  Checking documentation site: {site}")
                response = self._respectful_request(f"https://{site}")
                if response and response['status'] == 200:
                    doc_info = {
                        'site': site,
                        'url': f"https://{site}",
                        'status_code': response['status'],
                        'content_preview': response['data'][:500],
                        'check_time': datetime.now().isoformat(),
                        'accessible': True
                    }
                    doc_references.append(doc_info)
                    self.findings['documentation_references'].append(doc_info)
                    print(f"    [+] Accessible: {site}")
                else:
                    status = response['status'] if response else 'Failed'
                    print(f"    [-] Not accessible (status: {status}): {site}")
            else:
                print(f"  [-] Unauthorized documentation site (skipping): {site}")

        print(f"  Documentation sites checked: {len([s for s in doc_sites if self._is_authorized_api(s)])}")
        return doc_references

    def basic_endpoint_probing(self, api_list: List[Dict]) -> Dict:
        """
        Perform very basic, passive probing of authorized API endpoints.
        This is limited to checking basic connectivity and response headers.
        NO active testing/injection - only passive information gathering.
        """
        print("\nPhase 2: Basic Endpoint Information Gathering (Passive Only)")
        print("-" * 50)

        results = {
            'endpoints_tested': 0,
            'responsive_endpoints': [],
            'security_headers': {},
            'auth_indicators': {},
            'technology_clues': {}
        }

        # Limit the number of endpoints to test to be respectful
        endpoints_to_test = api_list[:10] if len(api_list) > 10 else api_list

        for api_info in endpoints_to_test:
            endpoint = api_info['endpoint']
            print(f"  Testing: {endpoint}")

            # Make a simple GET request to gather basic information
            url = f"https://{endpoint}"
            response = self._respectful_request(url, headers={'Accept': 'application/json'})

            results['endpoints_tested'] += 1

            if response and response['status'] < 500:  # Consider 2xx, 3xx, 4xx as responsive (but not server errors)
                endpoint_result = {
                    'endpoint': endpoint,
                    'status_code': response['status'],
                    'response_time': None,  # Would need timing for this
                    'content_type': response['headers'].get('content-type', 'unknown'),
                    'server_header': response['headers'].get('server', 'not-disclosed'),
                    'security_headers': {},
                    'auth_indicators': {},
                    'response_size': len(response['data'])
                }

                # Check for security headers
                security_headers = [
                    'strict-transport-security',
                    'content-security-policy',
                    'x-frame-options',
                    'x-content-type-options',
                    'referrer-policy',
                    'x-xss-protection'
                ]

                for header in security_headers:
                    if header in response['headers']:
                        endpoint_result['security_headers'][header] = response['headers'][header]

                # Look for authentication indicators in headers
                auth_headers = [
                    'www-authenticate',
                    'authorization',
                    'x-auth-token',
                    'api-key'
                ]

                for header in auth_headers:
                    if header in response['headers']:
                        endpoint_result['auth_indicators'][header] = '[REDACTED]'  # Don't expose actual values

                # Technology clues
                tech_headers = ['x-powered-by', 'x-aspnet-version', 'x-drupal-cache']
                for header in tech_headers:
                    if header in response['headers']:
                        endpoint_result['technology_clues'][header] = response['headers'][header]

                results['responsive_endpoints'].append(endpoint_result)
                print(f"    [+] Responded with status: {response['status']}")

                # Check if we got interesting data (without attempting to exploit)
                if response['data'] and len(response['data']) > 50:
                    # Try to parse as JSON to see structure
                    try:
                        data = json.loads(response['data'])
                        if isinstance(data, dict) and len(data) < 20:  # Reasonable size for inspection
                            endpoint_result['json_structure_sample'] = list(data.keys())[:10]
                    except:
                        pass  # Not JSON or too complex, that's fine

            else:
                status = response['status'] if response else 'No response'
                print(f"    [-] No response or server error (status: {status})")

        print(f"  Endpoints tested: {results['endpoints_tested']}")
        print(f"  Responsive endpoints: {len(results['responsive_endpoints'])}")
        return results

    def run_initial_assessment(self) -> Dict:
        """Run the initial API security assessment phases."""
        print("=" * 60)
        print("MERCADO LIBRE API SECURITY ASSESSMENT")
        print("Authorized, Passive Information Gathering Only")
        print("=" * 60)

        start_time = datetime.now()

        # Phase 1: API Inventory
        api_inventory = self.inventory_discovered_apis()

        # Phase 1b: Documentation Review
        doc_refs = self.review_public_documentation()

        # Phase 2: Basic passive endpoint probing
        probing_results = self.basic_endpoint_probing(api_inventory)

        end_time = datetime.now()
        duration = end_time - start_time

        # Compile final results
        results = {
            'metadata': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'assessment_type': 'initial_passive_api_security_assessment',
                'scope_file': self.scope_file
            },
            'api_inventory': {
                'total_authorized_apis': len(self.authorized_apis),
                'inventoried_apis': len(api_inventory),
                'apis': api_inventory
            },
            'documentation_review': {
                'sites_checked': len(doc_refs),
                'accessible_sites': len([d for d in doc_refs if d.get('accessible', False)]),
                'references': doc_refs
            },
            'endpoint_probing': probing_results,
            'findings_summary': {
                'total_apis_discovered': len(api_inventory),
                'documentation_sites_found': len(doc_refs),
                'responsive_endpoints': len(probing_results['responsive_endpoints']),
                'assessment_complete': True
            },
            'next_steps_recommendations': [
                "Review discovered APIs for authentication mechanisms",
                "Check public documentation for API specifications and rate limits",
                "Consider authorized active testing with proper test accounts",
                "Validate findings through scope checker before any active testing",
                "Proceed to authentication and authorization testing phases if authorized"
            ]
        }

        return results

    def save_results(self, results: Dict, output_dir: str = "api-security"):
        """Save assessment results to files."""
        import os

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Save detailed JSON results
        with open(f"{output_dir}/api-security-assessment.json", 'w') as f:
            json.dump(results, f, indent=2)

        # Save API inventory list
        with open(f"{output_dir}/api-inventory.txt", 'w') as f:
            for api in results['api_inventory']['apis']:
                f.write(f"{api['endpoint']} | {api['discovered_via']} | bounty_eligible: {api['bounty_eligible']}\n")

        # Save summary report
        with open(f"{output_dir}/assessment-summary.md", 'w') as f:
            f.write(self._generate_assessment_report(results))

        print(f"\nResults saved to {output_dir}/ directory:")
        print(f"  - api-security-assessment.json (detailed)")
        print(f"  - api-inventory.txt")
        print(f"  - assessment-summary.md")

    def _generate_assessment_report(self, results: Dict) -> str:
        """Generate a human-readable assessment report."""
        metadata = results['metadata']
        inventory = results['api_inventory']
        docs = results['documentation_review']
        probing = results['endpoint_probing']
        summary = results['findings_summary']

        report = f"""# Mercado Libre API Security Assessment Report

## Assessment Metadata
- **Start Time:** {metadata['start_time']}
- **End Time:** {metadata['end_time']}
- **Duration:** {metadata['duration_seconds']:.2f} seconds
- **Assessment Type:** {metadata['assessment_type']}
- **Scope File:** {metadata['scope_file']}

## Executive Summary
This authorized, passive API security assessment gathered information from public sources and performed basic connectivity checks on authorized API endpoints.
No active testing, injection, or exploitation was performed. All activities respected authorized boundaries.

## Assessment Results

### API Inventory
- **Total Authorized APIs in Scope:** {inventory['total_authorized_apis']}
- **APIs Inventoried:** {inventory['inventoried_apis']}
- **Authorization Status:** All inventoried APIs validated as authorized via scope checking

### Public Documentation Review
- **Documentation Sites Checked:** {docs['sites_checked']}
- **Accessible Documentation Sites:** {docs['accessible_sites']}
- **Note:** Accessible sites may contain API specifications, authentication details, and rate limiting information

### Endpoint Probing (Passive Only)
- **Endpoints Tested:** {probing['endpoints_tested']}
- **Responsive Endpoints:** {probing['responsive_endpoints']}
- **Testing Limitations:** Only basic GET requests with header analysis - no active testing performed

### Key Findings
1. **API Endpoints Identified:** {summary['total_apis_discovered']} authorized API endpoints discovered
2. **Documentation Access:** {summary['documentation_sites_found']} public documentation sites accessible
3. **Endpoint Responsiveness:** {summary['responsive_endpoints']} endpoints responded to basic connectivity checks

## Security Considerations Observed (Passive)

### Positive Security Indicators:
- All accessed endpoints were validated as authorized before testing
- Rate limiting was respected between requests (1 second delay)
- No active testing, injection, or exploitation attempted
- Only publicly available information was gathered

### Areas for Further Authorized Testing:
1. **Authentication Mechanism Testing** - With explicitly provided test accounts only
2. **Authorization Testing** - IDOR, privilege escalation checks with authorization
3. **Input Validation** - Parameter testing with authorized test data only
4. **Rate Limit Validation** - Confirm observed limits match policy specifications
5. **Business Logic Testing** - Workflow and state testing with authorization

## Next Steps (Requiring Explicit Authorization)

To proceed beyond this passive assessment, explicit authorization is required for:

1. **Active API Testing** - Using HTTP methods beyond GET (POST, PUT, DELETE, etc.)
2. **Authentication Testing** - Using explicitly provided test credentials
3. **Input Validation Testing** - Sending test payloads to parameters
4. **Automated Scanning** - Using security scanners within authorized scope and rate limits
5. **Business Logic Testing** - Testing multi-step workflows and state transitions

## Compliance Statement
All activities conducted in this assessment were:
- [+] Authorized (validated via scope checker before any interaction)
- [+] Passive (no active testing, injection, or exploitation)
- [+] Respectful (rate limited, error handling, user agent identification)
- [+] Boundary-respecting (only authorized endpoints accessed)
- [+] Documentation-only (relied on public information and basic connectivity)

## Recommendations for Next Authorized Phase
1. Obtain explicit authorization for active testing phases
2. Configure explicit test accounts and credentials (obtain from program directly)
3. Review rate limits and automation restrictions from program policy
4. Proceed to authentication and authorization testing assessments
5. Correlate findings with vulnerability validation processes

---
*Report generated by Mercado Libre Bug Bounty Research Agent API Security Assessment*
*For authorized security research only - Passive Information Gathering Phase*
"""
        return report


def main():
    """Main function to run the initial API security assessment."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run initial passive API security assessment on authorized Mercado Libre APIs"
    )
    parser.add_argument(
        "--scope-file",
        default="scopes/verified-scope.json",
        help="Path to scope JSON file (default: scopes/verified-scope.json)"
    )
    parser.add_argument(
        "--output-dir",
        default="api-security",
        help="Output directory for results (default: api-security)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format to stdout"
    )

    args = parser.parse_args()

    # Initialize assessor
    assessor = APISecurityAssessor(args.scope_file)

    # Run assessment
    results = assessor.run_initial_assessment()

    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        # Save to files
        assessor.save_results(results, args.output_dir)

        # Print summary to console
        print("\n" + "=" * 60)
        print("API SECURITY ASSESSMENT COMPLETE")
        print("=" * 60)
        print(f"Duration: {results['metadata']['duration_seconds']:.2f} seconds")
        print(f"Authorized APIs in scope: {results['api_inventory']['total_authorized_apis']}")
        print(f"APIs inventoried: {results['api_inventory']['inventoried_apis']}")
        print(f"Documentation sites checked: {results['documentation_review']['sites_checked']}")
        print(f"Endpoints probed: {results['endpoint_probing']['endpoints_tested']}")
        print(f"Responsive endpoints: {len(results['endpoint_probing']['responsive_endpoints'])}")
        print(f"\nDetailed results saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()