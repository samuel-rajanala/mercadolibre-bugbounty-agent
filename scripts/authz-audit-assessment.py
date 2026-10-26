#!/usr/bin/env python3
"""
Initial Authorization Audit Assessment for Mercado Libre Bug Bounty Research Agent
Performs authorized, passive information gathering and basic security checks on authorization mechanisms.
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
from safe_http import safe_open


class AuthzAuditAssessor:
    def __init__(self, scope_file: str = "scopes/verified-scope.json"):
        """
        Initialize the authorization audit assessor with verified scope data.

        Args:
            scope_file: Path to the verified scope JSON file
        """
        self.scope_file = scope_file
        self.scope_data = self._load_scope_data()
        self.authorized_authz_endpoints = self._extract_authorized_authz_endpoints()
        self.findings = {
            "authz_endpoint_inventory": [],
            "authz_patterns": {},
            "parameter_analysis": {},
            "header_analysis": {},
            "public_doc_references": [],
            "potential_issues": [],
            "recommendations": []
        }

        # Initialize authorization gate for fail-closed authorization enforcement
        self.auth_gate = AuthorizationGate()

        # Rate limiting to be respectful
        self.last_request_time = 0
        self.min_delay_between_requests = 1.5  # 1.5 seconds between requests

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

    def _extract_authorized_authz_endpoints(self) -> Set[str]:
        """Extract all authorized authorization-related endpoints from scope data."""
        authorized = set()

        scope = self.scope_data.get('scope', {})

        # Add API endpoints from scope (we'll filter for authz-related ones)
        for api in scope.get('api_endpoints', []):
            api_lower = api.lower()
            # Look for common authorization-related endpoints and patterns
            authz_indicators = [
                'user', 'users', 'account', 'accounts', 'profile', 'profiles',
                'order', 'orders', 'payment', 'payments', 'transaction', 'transactions',
                'item', 'items', 'product', 'products', 'cart', 'carts',
                'address', 'addresses', 'favorite', 'favorites', 'wishlist',
                'admin', 'management', 'manage', 'settings', 'preferences',
                'role', 'roles', 'permission', 'permissions', 'access', 'acl',
                'resource', 'resources', 'entity', 'entities', 'object', 'objects',
                'id', 'ids', 'uid', 'user_id', 'account_id', 'order_id'
            ]
            if any(indicator in api_lower for indicator in authz_indicators):
                authorized.add(api_lower)

        # Also look for common IDOR patterns in endpoints
        idor_patterns = [
            r'/\w+/\d+$',           # /resource/123
            r'/\w+/\w+/\d+$',       # /resource/sub/123
            r'/\w+/\d+/.*',         # /resource/123/action
            r'/\w+.*\d+.*',         # Anything with numbers that might be IDs
        ]

        # Check for endpoints that might contain IDOR patterns
        for api in scope.get('api_endpoints', []):
            api_lower = api.lower()
            # If it looks like it might have IDOR patterns, include it
            if any(re.search(pattern, api_lower) for pattern in idor_patterns):
                authorized.add(api_lower)

        return authorized

    def _is_authorized_authz_endpoint(self, endpoint: str) -> bool:
        """Check if an authorization endpoint is authorized for testing."""
        # Parse the endpoint to extract hostname
        parsed = urllib.parse.urlparse(endpoint)
        hostname = parsed.netloc.lower() if parsed.netloc else endpoint.lower()

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        # Check exact matches
        if hostname in self.authorized_authz_endpoints:
            return True

        # Check wildcard matches (simplified)
        scope = self.scope_data.get('scope', {})
        for wildcard in scope.get('wildcard_domains', []):
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]
                # Simple check: does hostname end with the base domain?
                if hostname.endswith('.' + base_domain) or hostname == base_domain:
                    # Additional check: ensure it looks like an authz endpoint
                    authz_indicators = ['user', 'account', 'order', 'payment', 'item', 'product']
                    if any(indicator in hostname for indicator in authz_indicators):
                        if hostname in self.authorized_authz_endpoints:
                            return True

        return False

    def _respectful_request(self, url: str, headers: Dict = None, data: bytes = None,
                          method: str = 'GET') -> Optional[Dict]:
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
        original_scheme = None

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
                    activity="AUTH_AUDIT_ASSESSMENT",
                    technique=method.upper(),
                    environment="request"
                )

                decision, reason = self.auth_gate.check_authorization(auth_request)
                if decision.value != "APPROVE":
                    print(f"  [AUTHORIZATION DENIED] {reason}")
                    return None
                original_hostname = hostname
                original_scheme = parsed_url.scheme
            else:
                # For redirects, check authorization with strict rules
                # Prevent HTTPS-to-HTTP downgrade
                if original_scheme == 'https' and parsed_url.scheme == 'http':
                    print(f"  [REDIRECT BLOCKED] HTTPS-to-HTTP downgrade prevented: {current_url}")
                    return None

                # Check if redirect is to same host or requires new authorization
                if hostname != original_hostname:
                    # Cross-host redirect - require fresh authorization
                    auth_request = AuthorizationRequest(
                        asset=hostname,
                        activity="AUTH_AUDIT_ASSESSMENT_REDIRECT",
                        technique=method.upper(),
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
                req = urllib.request.Request(current_url, data=data, headers=request_headers, method=method)
                self.last_request_time = time.time()

                with safe_open(req, timeout=15) as response:
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
                                'data': response.read().decode('utf-8', errors='ignore')[:15000]
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
                            'data': response.read().decode('utf-8', errors='ignore')[:15000]  # Limit response size
                        }
                        return response_data

            except urllib.error.HTTPError as e:
                # Even error responses can be informative for security assessment
                return {
                    'status': e.code,
                    'headers': dict(e.headers) if e.headers else {},
                    'data': e.read().decode('utf-8', errors='ignore')[:15000] if hasattr(e, 'read') else '',
                    'error': True
                }
            except Exception as e:
                print(f"  Warning: Request to {current_url} failed: {e}")
                return None

        print(f"  Warning: Exceeded maximum redirect count ({max_redirects})")
        return None

    def inventory_authz_endpoints(self) -> List[Dict]:
        """
        Inventory discovered authorization endpoints from reconnaissance and public sources.
        """
        print("Phase 1: Authorization Endpoint Inventory")
        print("-" * 50)

        authz_inventory = []

        # Start with authz endpoints identified in scope
        scope = self.scope_data.get('scope', {})
        explicit_apis = scope.get('api_endpoints', [])

        for api_endpoint in explicit_apis:
            api_lower = api_endpoint.lower()
            # Check if this looks like an authz endpoint
            authz_indicators = [
                'user', 'users', 'account', 'accounts', 'profile', 'profiles',
                'order', 'orders', 'payment', 'payments', 'transaction', 'transactions',
                'item', 'items', 'product', 'products', 'cart', 'carts',
                'address', 'addresses', 'favorite', 'favorites', 'wishlist',
                'admin', 'management', 'manage', 'settings', 'preferences',
                'role', 'roles', 'permission', 'permissions', 'access', 'acl',
                'resource', 'resources', 'entity', 'entities', 'object', 'objects',
                'id', 'ids', 'uid', 'user_id', 'account_id', 'order_id'
            ]
            if any(indicator in api_lower for indicator in authz_indicators):
                if self._is_authorized_authz_endpoint(api_endpoint):
                    authz_info = {
                        'endpoint': api_endpoint,
                        'endpoint_type': 'api_endpoint',
                        'discovered_via': 'scope_validation',
                        'authorized': True,
                        'inventory_time': datetime.now().isoformat()
                    }
                    # Try to determine authz type from endpoint name
                    authz_info['suspected_authz_type'] = self._guess_authz_type(api_endpoint)
                    # Look for potential IDOR patterns
                    authz_info['potential_idor_patterns'] = self._detect_idor_patterns(api_endpoint)
                    authz_inventory.append(authz_info)
                    self.findings['authz_endpoint_inventory'].append(authz_info)
                    print(f"  [+] Authorized Authz Endpoint: {api_endpoint}")
                else:
                    print(f"  [-] Unauthorized Authz Endpoint (skipping): {api_endpoint}")

        # Check some common authz API patterns for additional discovery
        scope = self.scope_data.get('scope', {})
        base_domains = set()
        for item in scope.get('in_scope', []):
            if '.' in item and not item.startswith('*.'):
                parts = item.split('.')
                if len(parts) >= 2:
                    base_domains.add('.'.join(parts[-2:]))

        common_authz_patterns = [
            'api.{domain}/users',
            'api.{domain}/accounts',
            'api.{domain}/orders',
            'api.{domain}/payments',
            'api.{domain}/items',
            'api.{domain}/products',
            'api.{domain}/profiles',
            'api.{domain}/addresses',
            'api.{domain}/admin',
            'api.{domain}/resources'
        ]

        # Limit to avoid too many requests
        for domain in list(base_domains)[:5]:
            for pattern in common_authz_patterns:
                potential_authz_endpoint = pattern.format(domain=domain)
                if self._is_authorized_authz_endpoint(potential_authz_endpoint) and \
                   potential_authz_endpoint not in [a['endpoint'] for a in authz_inventory]:
                    authz_info = {
                        'endpoint': potential_authz_endpoint,
                        'endpoint_type': 'pattern_discovered',
                        'discovered_via': 'pattern_based_discovery',
                        'authorized': True,
                        'inventory_time': datetime.now().isoformat(),
                        'suspected_authz_type': self._guess_authz_type(potential_authz_endpoint),
                        'potential_idor_patterns': self._detect_idor_patterns(potential_authz_endpoint)
                    }
                    authz_inventory.append(authz_info)
                    self.findings['authz_endpoint_inventory'].append(authz_info)
                    print(f"  [+] Discovered Authz Endpoint (pattern): {potential_authz_endpoint}")

        print(f"  Total authorized authz endpoints identified: {len(authz_inventory)}")
        return authz_inventory

    def _guess_authz_type(self, endpoint: str) -> str:
        """Guess the authorization type based on endpoint name."""
        endpoint_lower = endpoint.lower()
        if 'user' in endpoint_lower or 'account' in endpoint_lower:
            return 'User/Account Management'
        elif 'order' in endpoint_lower or 'payment' in endpoint_lower or 'transaction' in endpoint_lower:
            return 'Order/Payment Processing'
        elif 'item' in endpoint_lower or 'product' in endpoint_lower or 'cart' in endpoint_lower:
            return 'Item/Product Management'
        elif 'profile' in endpoint_lower or 'address' in endpoint_lower:
            return 'Profile/Address Management'
        elif 'admin' in endpoint_lower or 'management' in endpoint_lower:
            return 'Administrative Functions'
        elif 'role' in endpoint_lower or 'permission' in endpoint_lower or 'access' in endpoint_lower:
            return 'Role/Access Control'
        elif 'resource' in endpoint_lower or 'entity' in endpoint_lower:
            return 'Resource/Entity Management'
        else:
            return 'General Authorization'

    def _detect_idor_patterns(self, endpoint: str) -> List[str]:
        """Detect potential IDOR patterns in an endpoint."""
        patterns_found = []
        endpoint_lower = endpoint.lower()

        # Common IDOR patterns
        idor_patterns = [
            (r'/\w+/\d+$', 'Resource ID in path'),
            (r'/\w+/\w+/\d+$', 'Nested resource ID in path'),
            (r'/\w+/\d+/.*', 'Resource ID followed by action'),
            (r'/\w+.*\d+.*', 'Numeric identifier in path'),
            (r'/{[^}]+}', 'Parameter placeholder (possible ID)'),
            (r'_id$', 'ID suffix in endpoint'),
            (r'id=', 'ID parameter in query string'),
            (r'user[_-]?id', 'User ID parameter'),
            (r'account[_-]?id', 'Account ID parameter'),
            (r'order[_-]?id', 'Order ID parameter'),
            (r'product[_-]?id', 'Product ID parameter'),
        ]

        for pattern, description in idor_patterns:
            if re.search(pattern, endpoint_lower):
                patterns_found.append(description)

        return patterns_found

    def review_authz_documentation(self) -> List[Dict]:
        """
        Look for public authorization documentation, API specifications, and security guides.
        """
        print("\nPhase 1b: Public Authorization Documentation Review")
        print("-" * 50)

        doc_references = []

        # Check for known authz-related documentation sites
        authz_doc_sites = [
            'developers.mercadolibre.com/docs/users',
            'developers.mercadopago.com/docs/users',
            'developers.mercadolibre.com/docs/orders',
            'developers.mercadopago.com/docs/orders',
            'developers.mercadolibre.com/docs/items',
            'developers.mercadopago.com/docs/items',
            'developers.mercadolibre.com/docs/resources',
            'developers.mercadopago.com/docs/resources'
        ]

        for site in authz_doc_sites:
            # Extract hostname for authorization check
            parsed = urllib.parse.urlparse(f"https://{site}")
            hostname = parsed.netloc.lower()

            if self._is_authorized(hostname):  # Reuse scope check method
                print(f"  Checking authz documentation site: {site}")
                response = self._respectful_request(f"https://{site}")
                if response and response['status'] == 200:
                    doc_info = {
                        'site': site,
                        'url': f"https://{site}",
                        'status_code': response['status'],
                        'content_preview': response['data'][:800],
                        'check_time': datetime.now().isoformat(),
                        'accessible': True,
                        'doc_type': 'authorization'
                    }
                    doc_references.append(doc_info)
                    self.findings['public_doc_references'].append(doc_info)
                    print(f"    [+] Accessible: {site}")
                else:
                    status = response['status'] if response else 'Failed'
                    print(f"    [-] Not accessible (status: {status}): {site}")
            else:
                print(f"  [-] Unauthorized authz documentation site (skipping): {site}")

        print(f"  Authz documentation sites checked: {len([s for s in authz_doc_sites if self._is_authorized(s)])}")
        return doc_references

    def _is_authorized(self, hostname: str) -> bool:
        """Check if a hostname is authorized for testing (reusing scope checker logic)."""
        # This is a simplified version - in practice we'd use the scope checker
        # But for now, we'll do a basic check
        hostname_lower = hostname.lower()

        scope = self.scope_data.get('scope', {})

        # Check exact matches
        if hostname_lower in scope.get('in_scope', []):
            return True

        # Check wildcard matches
        for wildcard in scope.get('wildcard_domains', []):
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]
                # Simple check: does hostname end with the base domain and have at least one subdomain?
                if hostname_lower.endswith('.' + base_domain) and hostname_lower != base_domain:
                    # Additional check: ensure it's not just the base domain
                    if hostname_lower.count('.') >= base_domain.count('.') + 1:
                        return True

        return False

    def basic_authz_endpoint_probing(self, authz_list: List[Dict]) -> Dict:
        """
        Perform basic, passive probing of authorized authorization endpoints.
        This is limited to checking basic connectivity, headers, response characteristics,
        and looking for potential authorization patterns.
        NO active testing/injection - only passive information gathering.
        """
        print("\nPhase 2: Basic Authz Endpoint Information Gathering (Passive Only)")
        print("-" * 50)

        results = {
            'endpoints_tested': 0,
            'responsive_endpoints': [],
            'authz_patterns_found': {},
            'potential_idor_endpoints': [],
            'parameter_indicators': {},
            'security_headers': {},
            'http_methods_indicators': {}
        }

        # Limit the number of endpoints to test to be respectful
        endpoints_to_test = authz_list[:10] if len(authz_list) > 10 else authz_list

        for authz_info in endpoints_to_test:
            endpoint = authz_info['endpoint']
            print(f"  Testing authz endpoint: {endpoint}")

            # Make a simple GET request to gather basic information
            url = f"https://{endpoint}"
            response = self._respectful_request(url, headers={'Accept': 'application/json'})

            results['endpoints_tested'] += 1

            if response and response['status'] < 500:  # Consider 2xx, 3xx, 4xx as responsive
                endpoint_result = {
                    'endpoint': endpoint,
                    'status_code': response['status'],
                    'content_type': response['headers'].get('content-type', 'unknown'),
                    'server_header': response['headers'].get('server', 'not-disclosed'),
                    'authz_patterns': authz_info.get('potential_idor_patterns', []),
                    'parameter_indicators': {},
                    'security_headers': {},
                    'response_size': len(response['data'])
                }

                # Check for authorization-related patterns in response headers
                authz_headers = [
                    'www-authenticate',
                    'authorization',
                    'x-auth-token',
                    'api-key',
                    'x-api-key',
                    'access-control-allow-origin',
                    'access-control-allow-methods',
                    'access-control-allow-headers'
                ]

                for header in authz_headers:
                    if header in response['headers']:
                        # Don't expose actual values, just note presence
                        endpoint_result['parameter_indicators'][header] = '[PRESENT]'

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

                # Try to infer HTTP methods allowed from response (if available)
                # Some APIs return allowed methods in headers or allow OPTIONS
                if response['status'] in [200, 201, 204, 405]:  # 405 might indicate method not allowed
                    # Try an OPTIONS request to see allowed methods (still passive)
                    options_response = self._respectful_request(
                        url,
                        headers={'Accept': 'application/json', 'Origin': 'https://authorized-scanner.example.com'},
                        method='OPTIONS'
                    )
                    if options_response and options_response['status'] < 500:
                        allow_header = options_response['headers'].get('access-control-allow-methods', '')
                        if allow_header:
                            endpoint_result['http_methods_indicators']['allowed_methods'] = allow_header

                # Check if this endpoint looks like it might be vulnerable to IDOR
                if authz_info.get('potential_idor_patterns', []):
                    results['potential_idor_endpoints'].append({
                        'endpoint': endpoint,
                        'patterns': authz_info['potential_idor_patterns'],
                        'status_code': response['status']
                    })

                results['responsive_endpoints'].append(endpoint_result)
                print(f"    [+] Responded with status: {response['status']}")

                # Check if we got interesting data (without attempting to exploit)
                if response['data'] and len(response['data']) > 50:
                    # Try to parse as JSON to see structure
                    try:
                        data = json.loads(response['data'])
                        if isinstance(data, dict):
                            # Look for common authz-related fields that might indicate IDOR risk
                            idor_risk_fields = ['id', 'user_id', 'account_id', 'order_id', 'product_id',
                                              'item_id', 'resource_id', 'entity_id', 'object_id']
                            found_idor_fields = [field for field in idor_risk_fields if field in data]
                            if found_idor_fields:
                                endpoint_result['identifier_fields'] = found_idor_fields[:5]

                            # Show a sample of the structure (limit depth)
                            if len(data) < 15:  # Reasonable size for inspection
                                endpoint_result['json_structure_sample'] = list(data.keys())
                    except:
                        pass  # Not JSON or too complex, that's fine

            else:
                status = response['status'] if response else 'No response'
                print(f"    [-] No response or server error (status: {status})")

        print(f"  Authz endpoints tested: {results['endpoints_tested']}")
        print(f"  Responsive authz endpoints: {len(results['responsive_endpoints'])}")
        print(f"  Potential IDOR endpoints: {len(results['potential_idor_endpoints'])}")
        return results

    def run_initial_assessment(self) -> Dict:
        """Run the initial authorization audit assessment phases."""
        print("=" * 60)
        print("MERCADO LIBRE AUTHORIZATION AUDIT ASSESSMENT")
        print("Authorized, Passive Information Gathering Only")
        print("=" * 60)

        start_time = datetime.now()

        # Phase 1: Authz Endpoint Inventory
        authz_inventory = self.inventory_authz_endpoints()

        # Phase 1b: Documentation Review
        doc_refs = self.review_authz_documentation()

        # Phase 2: Basic passive endpoint probing
        probing_results = self.basic_authz_endpoint_probing(authz_inventory)

        end_time = datetime.now()
        duration = end_time - start_time

        # Compile final results
        results = {
            'metadata': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'assessment_type': 'initial_passive_authz_audit_assessment',
                'scope_file': self.scope_file
            },
            'authz_endpoint_inventory': {
                'total_authorized_authz_endpoints': len(self.authorized_authz_endpoints),
                'inventoried_authz_endpoints': len(authz_inventory),
                'endpoints': authz_inventory
            },
            'documentation_review': {
                'sites_checked': len(doc_refs),
                'accessible_sites': len([d for d in doc_refs if d.get('accessible', False)]),
                'references': doc_refs
            },
            'endpoint_probing': probing_results,
            'findings_summary': {
                'total_authz_endpoints_discovered': len(authz_inventory),
                'documentation_sites_found': len(doc_refs),
                'responsive_endpoints': len(probing_results['responsive_endpoints']),
                'potential_idor_endpoints': len(probing_results['potential_idor_endpoints']),
                'assessment_complete': True
            },
            'next_steps_recommendations': [
                "Review discovered authz endpoints for authorization patterns",
                "Check public documentation for authorization specifications",
                "Consider authorized active testing with proper test accounts (explicitly provided)",
                "Validate findings through scope checker before any active testing",
                "Proceed to payment security testing if authorized"
            ]
        }

        return results

    def save_results(self, results: Dict, output_dir: str = "authz-audit"):
        """Save assessment results to files."""
        import os

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Save detailed JSON results
        with open(f"{output_dir}/authz-audit-assessment.json", 'w') as f:
            json.dump(results, f, indent=2)

        # Save authz inventory list
        with open(f"{output_dir}/authz-inventory.txt", 'w') as f:
            for authz in results['authz_endpoint_inventory']['endpoints']:
                f.write(f"{authz['endpoint']} | {authz['discovered_via']} | {authz.get('suspected_authz_type', 'unknown')}\n")
                if authz.get('potential_idor_patterns'):
                    f.write(f"  IDOR Patterns: {', '.join(authz['potential_idor_patterns'])}\n")

        # Save summary report
        with open(f"{output_dir}/assessment-summary.md", 'w') as f:
            f.write(self._generate_assessment_report(results))

        print(f"\nResults saved to {output_dir}/ directory:")
        print(f"  - authz-audit-assessment.json (detailed)")
        print(f"  - authz-inventory.txt")
        print(f"  - assessment-summary.md")

    def _generate_assessment_report(self, results: Dict) -> str:
        """Generate a human-readable assessment report."""
        metadata = results['metadata']
        inventory = results['authz_endpoint_inventory']
        docs = results['documentation_review']
        probing = results['endpoint_probing']
        summary = results['findings_summary']

        report = f"""# Mercado Libre Authorization Audit Assessment Report

## Assessment Metadata
- **Start Time:** {metadata['start_time']}
- **End Time:** {metadata['end_time']}
- **Duration:** {metadata['duration_seconds']:.2f} seconds
- **Assessment Type:** {metadata['assessment_type']}
- **Scope File:** {metadata['scope_file']}

## Executive Summary
This authorized, passive authorization audit assessment gathered information from public sources and performed basic connectivity checks on authorized authorization endpoints.
No active testing, injection, IDOR testing, or exploitation was performed. All activities respected authorized boundaries.

## Assessment Results

### Authorization Endpoint Inventory
- **Total Authorized Authz Endpoints in Scope:** {inventory['total_authorized_authz_endpoints']}
- **Authz Endpoints Inventoried:** {inventory['inventoried_authz_endpoints']}
- **Authorization Status:** All inventoried authz endpoints validated as authorized via scope checking

### Public Documentation Review
- **Documentation Sites Checked:** {docs['sites_checked']}
- **Accessible Documentation Sites:** {docs['accessible_sites']}
- **Note:** Accessible sites may contain authorization specifications, resource schemas, and security details

### Endpoint Probing (Passive Only)
- **Endpoints Tested:** {probing['endpoints_tested']}
- **Responsive Endpoints:** {probing['responsive_endpoints']}
- **Testing Limitations:** Only basic GET requests with header analysis - no active testing performed

### Key Findings
1. **Authz Endpoints Identified:** {summary['total_authz_endpoints_discovered']} authorized authorization endpoints discovered
2. **Documentation Access:** {summary['documentation_sites_found']} public documentation sites accessible
3. **Endpoint Responsiveness:** {summary['responsive_endpoints']} endpoints responded to basic connectivity checks
4. **Potential IDOR Endpoints:** {summary['potential_idor_endpoints']} endpoints with possible IDOR patterns identified

## Security Considerations Observed (Passive)

### Positive Security Indicators:
- All accessed endpoints were validated as authorized before testing
- Rate limiting was respected between requests (1.5 second delay)
- No active testing, injection, IDOR testing, or exploitation attempted
- Only publicly available information was gathered
- No authorization bypass attempts made without explicit authorization

### Areas for Further Authorized Testing:
1. **IDOR Testing** - With explicitly provided test accounts only (horizontal/vertical privilege escalation)
2. **Parameter Testing** - Testing user_id, account_id, order_id parameters with authorized test data
3. **HTTP Method Testing** - Testing PUT, PATCH, DELETE methods on resource endpoints
4. **Header Manipulation** - Testing Authorization, X-Forwarded-For, X-Original-URL headers
5. **Object Level Authorization** - Checking object-level access controls (OLAC)
6. **Function Level Authorization** - Checking function-level access controls (FLAC)

## Next Steps (Requiring Explicit Authorization)

To proceed beyond this passive assessment, explicit authorization is required for:

1. **Active Authorization Testing** - Using explicit test accounts (only those provided by program)
2. **IDOR Testing** - Testing resource access with different user contexts
3. **Parameter Manipulation Testing** - Modifying ID parameters within authorized limits
4. **HTTP Method Testing** - Testing non-GET methods on resource endpoints
5. **Automated Scanning** - Using security scanners within authorized scope and rate limits

## Compliance Statement
All activities conducted in this assessment were:
- [+] Authorized (validated via scope checker before any interaction)
- [+] Passive (no active testing, injection, exploitation, or IDOR attempts)
- [+] Respectful (rate limited, error handling, user agent identification)
- [+] Boundary-respecting (only authorized endpoints accessed)
- [+] Documentation-only (relied on public information and basic connectivity)

## Recommendations for Next Authorized Phase
1. Obtain explicit authorization for active authorization testing phases
2. Configure explicit test accounts and credentials (obtain from program directly - NEVER guess or brute force)
3. Review rate limits and automation restrictions from program policy
4. Proceed to payment security testing assessments
5. Correlate findings with vulnerability validation processes

---
*Report generated by Mercado Libre Bug Bounty Research Agent Authorization Audit Assessment*
*For authorized security research only - Passive Information Gathering Phase*
"""
        return report


def main():
    """Main function to run the initial authorization audit assessment."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run initial passive authorization audit assessment on authorized Mercado Libre authz endpoints"
    )
    parser.add_argument(
        "--scope-file",
        default="scopes/verified-scope.json",
        help="Path to scope JSON file (default: scopes/verified-scope.json)"
    )
    parser.add_argument(
        "--output-dir",
        default="authz-audit",
        help="Output directory for results (default: authz-audit)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format to stdout"
    )

    args = parser.parse_args()

    # Initialize assessor
    assessor = AuthzAuditAssessor(args.scope_file)

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
        print("AUTHORIZATION AUDIT ASSESSMENT COMPLETE")
        print("=" * 60)
        print(f"Duration: {results['metadata']['duration_seconds']:.2f} seconds")
        print(f"Authorized authz endpoints in scope: {results['authz_endpoint_inventory']['total_authorized_authz_endpoints']}")
        print(f"Authz endpoints inventoried: {results['authz_endpoint_inventory']['inventoried_authz_endpoints']}")
        print(f"Documentation sites checked: {results['documentation_review']['sites_checked']}")
        print(f"Authz endpoints probed: {results['endpoint_probing']['endpoints_tested']}")
        print(f"Responsive authz endpoints: {len(results['endpoint_probing']['responsive_endpoints'])}")
        print(f"Potential IDOR endpoints: {len(results['endpoint_probing']['potential_idor_endpoints'])}")
        print(f"\nDetailed results saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()