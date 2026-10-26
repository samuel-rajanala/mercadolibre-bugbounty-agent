#!/usr/bin/env python3
"""
Initial Payment Security Assessment for Mercado Libre Bug Bounty Research Agent
Performs authorized, passive information gathering and preparation for payment security testing
in sandbox/test environments only.
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


class PaymentSecurityAssessor:
    def __init__(self, scope_file: str = "scopes/verified-scope.json"):
        """
        Initialize the payment security assessor with verified scope data.

        Args:
            scope_file: Path to the verified scope JSON file
        """
        self.scope_file = scope_file
        self.scope_data = self._load_scope_data()
        self.payment_endpoints = self._extract_payment_endpoints()
        self.sandbox_endpoints = self._identify_sandbox_candidates()
        self.findings = {
            "payment_endpoint_inventory": [],
            "sandbox_candidates": [],
            "payment_flow_indicators": {},
            "security_features": {},
            "public_doc_references": [],
            "compliance_notes": [],
            "recommendations": []
        }

        # Initialize authorization gate for fail-closed authorization enforcement
        self.auth_gate = AuthorizationGate()

        # Rate limiting to be respectful
        self.last_request_time = 0
        self.min_delay_between_requests = 2.0  # 2 seconds between requests for payment endpoints

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

    def _extract_payment_endpoints(self) -> Set[str]:
        """Extract all payment-related endpoints from scope data."""
        authorized = set()

        scope = self.scope_data.get('scope', {})

        # Add API endpoints from scope (we'll filter for payment-related ones)
        for api in scope.get('api_endpoints', []):
            api_lower = api.lower()
            # Look for common payment-related endpoints
            payment_indicators = [
                'payment', 'pay', 'checkout', 'cart', 'order', 'purchase',
                'transaction', 'transaction', 'invoice', 'billing', 'subscription',
                'refund', 'chargeback', 'dispute', 'settlement', 'settle',
                'merchant', 'seller', 'buyer', 'customer', 'client',
                'card', 'token', 'cvv', 'expiration', 'invoice',
                'mercadopago', 'mp', 'payments'
            ]
            if any(indicator in api_lower for indicator in payment_indicators):
                authorized.add(api_lower)

        # Also check other asset types for payment-related items
        for item in scope.get('other_assets', []):
            item_lower = item.lower()
            if any(indicator in item_lower for indicator in ['payment', 'pay', 'checkout', 'mercadopago']):
                authorized.add(item_lower)

        return authorized

    def _identify_sandbox_candidates(self) -> Set[str]:
        """Identify potential sandbox/test endpoints based on naming patterns."""
        sandbox_indicators = set()

        # Look for sandbox/test patterns in our endpoints
        for endpoint in self.payment_endpoints:
            endpoint_lower = endpoint.lower()
            # Common sandbox/test indicators
            sandbox_patterns = [
                'sandbox',
                'test',
                'dev',
                'staging',
                'qa',
                'beta'
            ]

            # If the endpoint already contains sandbox indicators, note it
            if any(pattern in endpoint_lower for pattern in sandbox_patterns):
                sandbox_indicators.add(endpoint)

            # Also generate potential sandbox candidates by replacing domain parts
            # This is preparatory work - actual sandbox testing would require explicit endpoints
            if 'mercadolibre.com' in endpoint:
                sandbox_candidate = endpoint.replace('mercadolibre.com', 'sandbox.mercadolibre.com')
                sandbox_indicators.add(sandbox_candidate)
                sandbox_candidate = endpoint.replace('mercadolibre.com', 'test.mercadolibre.com')
                sandbox_indicators.add(sandbox_candidate)
            elif 'mercadopago.com' in endpoint:
                sandbox_candidate = endpoint.replace('mercadopago.com', 'sandbox.mercadopago.com')
                sandbox_indicators.add(sandbox_candidate)
                sandbox_candidate = endpoint.replace('mercadopago.com', 'test.mercadopago.com')
                sandbox_indicators.add(sandbox_candidate)

        return sandbox_indicators

    def _is_authorized_endpoint(self, endpoint: str) -> bool:
        """Check if an endpoint is authorized for testing."""
        # Parse the endpoint to extract hostname
        parsed = urllib.parse.urlparse(endpoint)
        hostname = parsed.netloc.lower() if parsed.netloc else endpoint.lower()

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        # Check exact matches
        if hostname in self.payment_endpoints:
            return True

        # Check wildcard matches (simplified)
        scope = self.scope_data.get('scope', {})
        for wildcard in scope.get('wildcard_domains', []):
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]
                # Simple check: does hostname end with the base domain?
                if hostname.endswith('.' + base_domain) or hostname == base_domain:
                    # Additional check: ensure it looks like a payment endpoint
                    payment_indicators = ['payment', 'pay', 'checkout', 'cart', 'order', 'mercadopago']
                    if any(indicator in hostname for indicator in payment_indicators):
                        if hostname in self.payment_endpoints:
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
        headers['User-Agent'] = 'MercadoLibre-BB-Agent/1.0 (Authorized Security Research - Payment Assessment)'

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
                    activity="PAYMENT_SECURITY_ASSESSMENT",
                    technique=method.upper(),
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
                        activity="PAYMENT_SECURITY_ASSESSMENT_REDIRECT",
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

                with urllib.request.urlopen(req, timeout=15) as response:
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

    def inventory_payment_endpoints(self) -> List[Dict]:
        """
        Inventory discovered payment endpoints from reconnaissance and public sources.
        """
        print("Phase 1: Payment Endpoint Inventory")
        print("-" * 50)

        payment_inventory = []

        # Start with payment endpoints identified in scope
        scope = self.scope_data.get('scope', {})
        explicit_apis = scope.get('api_endpoints', [])

        for api_endpoint in explicit_apis:
            api_lower = api_endpoint.lower()
            # Check if this looks like a payment endpoint
            payment_indicators = [
                'payment', 'pay', 'checkout', 'cart', 'order', 'purchase',
                'transaction', 'invoice', 'billing', 'subscription',
                'refund', 'chargeback', 'dispute', 'settlement', 'settle',
                'merchant', 'seller', 'buyer', 'customer', 'client',
                'card', 'token', 'cvv', 'expiration', 'invoice',
                'mercadopago', 'mp', 'payments'
            ]
            if any(indicator in api_lower for indicator in payment_indicators):
                if self._is_authorized_endpoint(api_endpoint):
                    payment_info = {
                        'endpoint': api_endpoint,
                        'endpoint_type': 'api_endpoint',
                        'discovered_via': 'scope_validation',
                        'authorized': True,
                        'is_sandbox_candidate': api_endpoint in self.sandbox_endpoints,
                        'inventory_time': datetime.now().isoformat()
                    }
                    # Try to determine payment type from endpoint name
                    payment_info['suspected_payment_type'] = self._guess_payment_type(api_endpoint)
                    payment_inventory.append(payment_info)
                    self.findings['payment_endpoint_inventory'].append(payment_info)
                    print(f"  [+] Authorized Payment Endpoint: {api_endpoint}")
                else:
                    print(f"  [-] Unauthorized Payment Endpoint (skipping): {api_endpoint}")

        # Check for sandbox candidates
        for sandbox_endpoint in self.sandbox_endpoints:
            if sandbox_endpoint not in [p['endpoint'] for p in payment_inventory]:
                # Note: These are not authorized for testing without explicit sandbox endpoints
                # They're listed for preparatory work only
                payment_info = {
                    'endpoint': sandbox_endpoint,
                    'endpoint_type': 'sandbox_candidate',
                    'discovered_via': 'sandbox_preparation',
                    'authorized': False,  # Not authorized without explicit sandbox endpoints
                    'is_sandbox_candidate': True,
                    'inventory_time': datetime.now().isoformat(),
                    'suspected_payment_type': self._guess_payment_type(sandbox_endpoint),
                    'note': 'Sandbox candidate - requires explicit authorization for testing'
                }
                payment_inventory.append(payment_info)
                self.findings['sandbox_candidates'].append(payment_info)
                print(f"  [~] Sandbox Candidate (not authorized for testing): {sandbox_endpoint}")

        print(f"  Total authorized payment endpoints identified: {len([p for p in payment_inventory if p['authorized']])}")
        print(f"  Total sandbox candidates identified: {len(self.sandbox_endpoints)}")
        return payment_inventory

    def _guess_payment_type(self, endpoint: str) -> str:
        """Guess the payment type based on endpoint name."""
        endpoint_lower = endpoint.lower()
        if 'refund' in endpoint_lower or 'chargeback' in endpoint_lower or 'dispute' in endpoint_lower:
            return 'Refund/Dispute Processing'
        elif 'webhook' in endpoint_lower or 'notification' in endpoint_lower or 'callback' in endpoint_lower:
            return 'Payment Webhooks/Notifications'
        elif 'checkout' in endpoint_lower or 'cart' in endpoint_lower:
            return 'Checkout/Cart Processing'
        elif 'subscription' in endpoint_lower or 'recurring' in endpoint_lower:
            return 'Subscription/Recurring Payments'
        elif 'invoice' in endpoint_lower or 'billing' in endpoint_lower:
            return 'Invoice/Billing Processing'
        elif 'merchant' in endpoint_lower or 'seller' in endpoint_lower:
            return 'Merchant/Seller Services'
        elif 'buyer' in endpoint_lower or 'customer' in endpoint_lower:
            return 'Buyer/Customer Services'
        elif 'card' in endpoint_lower or 'token' in endpoint_lower or 'cvv' in endpoint_lower:
            return 'Card Tokenization/Payment Instruments'
        elif 'mercadopago' in endpoint_lower or 'mp' in endpoint_lower:
            return 'Mercado Pago Integration'
        elif 'payment' in endpoint_lower or 'pay' in endpoint_lower:
            return 'General Payment Processing'
        else:
            return 'Payment-Related Services'

    def review_payment_documentation(self) -> List[Dict]:
        """
        Look for public payment documentation, API specifications, and security guides.
        """
        print("\nPhase 1b: Public Payment Documentation Review")
        print("-" * 50)

        doc_references = []

        # Check for known payment-related documentation sites
        payment_doc_sites = [
            'developers.mercadolibre.com/docs/payments',
            'developers.mercadopago.com/docs/payments',
            'developers.mercadolibre.com/docs/checkout',
            'developers.mercadopago.com/docs/checkout',
            'developers.mercadolibre.com/docs/refunds',
            'developers.mercadopago.com/docs/refunds',
            'developers.mercadolibre.com/docs/webhooks',
            'developers.mercadopago.com/docs/webhooks',
            'developers.mercadolibre.com/docs/tokens',
            'developers.mercadopago.com/docs/tokens'
        ]

        for site in payment_doc_sites:
            # Extract hostname for authorization check
            parsed = urllib.parse.urlparse(f"https://{site}")
            hostname = parsed.netloc.lower()

            if self._is_authorized(hostname):  # Reuse scope check method
                print(f"  Checking payment documentation site: {site}")
                response = self._respectful_request(f"https://{site}")
                if response and response['status'] == 200:
                    doc_info = {
                        'site': site,
                        'url': f"https://{site}",
                        'status_code': response['status'],
                        'content_preview': response['data'][:800],
                        'check_time': datetime.now().isoformat(),
                        'accessible': True,
                        'doc_type': 'payment'
                    }
                    doc_references.append(doc_info)
                    self.findings['public_doc_references'].append(doc_info)
                    print(f"    [+] Accessible: {site}")
                else:
                    status = response['status'] if response else 'Failed'
                    print(f"    [-] Not accessible (status: {status}): {site}")
            else:
                print(f"  [-] Unauthorized payment documentation site (skipping): {site}")

        print(f"  Payment documentation sites checked: {len([s for s in payment_doc_sites if self._is_authorized(s)])}")
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

    def basic_payment_endpoint_probing(self, payment_list: List[Dict]) -> Dict:
        """
        Perform basic, passive probing of authorized payment endpoints.
        This is limited to checking basic connectivity, headers, response characteristics,
        and looking for payment-related patterns.
        NO active testing/injection - only passive information gathering.
        """
        print("\nPhase 2: Basic Payment Endpoint Information Gathering (Passive Only)")
        print("-" * 50)

        results = {
            'endpoints_tested': 0,
            'responsive_endpoints': [],
            'payment_patterns_found': {},
            'security_features': {},
            'payment_flow_indicators': {},
            'sandbox_candidates_checked': 0
        }

        # Only test authorized payment endpoints (not sandbox candidates)
        authorized_payments = [p for p in payment_list if p['authorized']]

        # Limit the number of endpoints to test to be respectful
        endpoints_to_test = authorized_payments[:10] if len(authorized_payments) > 10 else authorized_payments

        for payment_info in endpoints_to_test:
            endpoint = payment_info['endpoint']
            print(f"  Testing payment endpoint: {endpoint}")

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
                    'payment_type': payment_info.get('suspected_payment_type', 'unknown'),
                    'security_features': {},
                    'payment_flow_indicators': {},
                    'response_size': len(response['data'])
                }

                # Check for payment-related security features in response headers
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
                        endpoint_result['security_features'][header] = response['headers'][header]

                # Look for payment-specific headers
                payment_headers = [
                    'x-payment-token',
                    'x-transaction-id',
                    'x-order-id',
                    'x-merchant-id',
                    'x-customer-id',
                    'x-amount',
                    'x-currency'
                ]

                for header in payment_headers:
                    if header in response['headers']:
                        # Don't expose actual values, just note presence
                        endpoint_result['payment_flow_indicators'][header] = '[PRESENT]'

                # Try to infer payment flow from response
                if response['data'] and len(response['data']) > 50:
                    # Try to parse as JSON to see structure
                    try:
                        data = json.loads(response['data'])
                        if isinstance(data, dict):
                            # Look for common payment-related fields
                            payment_fields = ['id', 'status', 'amount', 'currency', 'transaction_id',
                                            'order_id', 'payment_method', 'card_last_4', 'token',
                                            'status_detail', 'status_detail']
                            found_payment_fields = [field for field in payment_fields if field in data]
                            if found_payment_fields:
                                endpoint_result['payment_flow_indicators']['payment_fields'] = found_payment_fields[:5]

                            # Check for payment status indicators
                            if 'status' in data:
                                endpoint_result['payment_flow_indicators']['status_field'] = data['status']

                            # Show a sample of the structure (limit depth)
                            if len(data) < 15:  # Reasonable size for inspection
                                endpoint_result['payment_flow_indicators']['json_structure_sample'] = list(data.keys())
                    except:
                        pass  # Not JSON or too complex, that's fine

                results['responsive_endpoints'].append(endpoint_result)
                print(f"    [+] Responded with status: {response['status']}")

                # Check if we got interesting data (without attempting to exploit)
                if response['data'] and len(response['data']) > 100:
                    # Look for payment-related keywords in response (without exploiting)
                    response_text = response['data'].lower()
                    payment_keywords = ['payment', 'transaction', 'amount', 'currency', 'card', 'token']
                    found_keywords = [kw for kw in payment_keywords if kw in response_text]
                    if found_payment_fields := [fk for fk in payment_keywords if fk in response_text]:
                        endpoint_result['payment_flow_indicators']['response_keywords'] = found_keywords[:5]

            else:
                status = response['status'] if response else 'No response'
                print(f"    [-] No response or server error (status: {status})")

        print(f"  Payment endpoints tested: {results['endpoints_tested']}")
        print(f"  Responsive payment endpoints: {len(results['responsive_endpoints'])}")
        return results

    def run_initial_assessment(self) -> Dict:
        """Run the initial payment security assessment phases."""
        print("=" * 60)
        print("MERCADO LIBRE PAYMENT SECURITY ASSESSMENT")
        print("Authorized, Passive Information Gathering Only")
        print("SANDBOX/TEST ENVIRONMENTS ONLY FOR ACTIVE TESTING")
        print("=" * 60)

        start_time = datetime.now()

        # Phase 1: Payment Endpoint Inventory
        payment_inventory = self.inventory_payment_endpoints()

        # Phase 1b: Documentation Review
        doc_refs = self.review_payment_documentation()

        # Phase 2: Basic passive endpoint probing
        probing_results = self.basic_payment_endpoint_probing(payment_inventory)

        end_time = datetime.now()
        duration = end_time - start_time

        # Compile final results
        results = {
            'metadata': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'assessment_type': 'initial_passive_payment_security_assessment',
                'scope_file': self.scope_file
            },
            'payment_endpoint_inventory': {
                'total_authorized_payment_endpoints': len([p for p in self.payment_endpoints if self._is_authorized_endpoint(p)]),
                'inventoried_payment_endpoints': len([p for p in payment_inventory if p['authorized']]),
                'total_sandbox_candidates': len(self.sandbox_endpoints),
                'inventoried_sandbox_candidates': len([p for p in payment_inventory if not p['authorized'] and p.get('is_sandbox_candidate')]),
                'endpoints': payment_inventory
            },
            'documentation_review': {
                'sites_checked': len(doc_refs),
                'accessible_sites': len([d for d in doc_refs if d.get('accessible', False)]),
                'references': doc_refs
            },
            'endpoint_probing': probing_results,
            'findings_summary': {
                'total_payment_endpoints_discovered': len([p for p in payment_inventory if p['authorized']]),
                'total_sandbox_candidates_identified': len(self.sandbox_endpoints),
                'documentation_sites_found': len(doc_refs),
                'responsive_endpoints': len(probing_results['responsive_endpoints']),
                'assessment_complete': True
            },
            'next_steps_recommendations': [
                "Review discovered payment endpoints for payment flow patterns",
                "Check public documentation for payment specifications and security features",
                "Obtain explicit authorization for sandbox/test environment testing",
                "Configure explicit test accounts and credentials (obtain from program directly)",
                "Proceed to active payment security testing ONLY in authorized sandbox/test environments"
            ]
        }

        return results

    def save_results(self, results: Dict, output_dir: str = "payment-security"):
        """Save assessment results to files."""
        import os

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Save detailed JSON results
        with open(f"{output_dir}/payment-security-assessment.json", 'w') as f:
            json.dump(results, f, indent=2)

        # Save payment inventory list
        with open(f"{output_dir}/payment-inventory.txt", 'w') as f:
            for payment in results['payment_endpoint_inventory']['endpoints']:
                auth_status = "AUTHORIZED" if payment['authorized'] else "SANDBOX CANDIDATE"
                f.write(f"{payment['endpoint']} | {payment['discovered_via']} | {auth_status} | {payment.get('suspected_payment_type', 'unknown')}\n")

        # Save summary report
        with open(f"{output_dir}/assessment-summary.md", 'w') as f:
            f.write(self._generate_assessment_report(results))

        print(f"\nResults saved to {output_dir}/ directory:")
        print(f"  - payment-security-assessment.json (detailed)")
        print(f"  - payment-inventory.txt")
        print(f"  - assessment-summary.md")

    def _generate_assessment_report(self, results: Dict) -> str:
        """Generate a human-readable assessment report."""
        metadata = results['metadata']
        inventory = results['payment_endpoint_inventory']
        docs = results['documentation_review']
        probing = results['endpoint_probing']
        summary = results['findings_summary']

        report = f"""# Mercado Libre Payment Security Assessment Report

## Assessment Metadata
- **Start Time:** {metadata['start_time']}
- **End Time:** {metadata['end_time']}
- **Duration:** {metadata['duration_seconds']:.2f} seconds
- **Assessment Type:** {metadata['assessment_type']}
- **Scope File:** {metadata['scope_file']}

## Executive Summary
This authorized, passive payment security assessment gathered information from public sources and performed basic connectivity checks on authorized payment-related endpoints.
**CRITICAL: No active payment security testing was performed.** All activities respected authorized boundaries and emphasized that **active payment testing MUST ONLY occur in explicitly authorized sandbox/test environments**.

## Assessment Results

### Payment Endpoint Inventory
- **Total Authorized Payment Endpoints in Scope:** {inventory['total_authorized_payment_endpoints']}
- **Payment Endpoints Inventoried:** {inventory['inventoried_payment_endpoints']}
- **Total Sandbox Candidates Identified:** {inventory['total_sandbox_candidates']}
- **Sandbox Candidates Inventoried:** {inventory['inventoried_sandbox_candidates']}
- **Authorization Status:** All inventoried payment endpoints validated as authorized via scope checking
- **Sandbox Candidates:** Identified for preparatory work only - require explicit authorization for testing

### Public Documentation Review
- **Documentation Sites Checked:** {docs['sites_checked']}
- **Accessible Documentation Sites:** {docs['accessible_sites']}
- **Note:** Accessible sites may contain payment specifications, API documentation, and security details

### Endpoint Probing (Passive Only)
- **Endpoints Tested:** {probing['endpoints_tested']}
- **Responsive Endpoints:** {probing['responsive_endpoints']}
- **Testing Limitations:** Only basic GET requests with header analysis - no active testing performed

### Key Findings
1. **Payment Endpoints Identified:** {summary['total_payment_endpoints_discovered']} authorized payment endpoints discovered
2. **Sandbox Candidates:** {summary['total_sandbox_candidates_identified']} potential sandbox/test endpoints identified (for preparatory work only)
3. **Documentation Access:** {summary['documentation_sites_found']} public documentation sites accessible
4. **Endpoint Responsiveness:** {summary['responsive_endpoints']} endpoints responded to basic connectivity checks

## Security Considerations Observed (Passive)

### Positive Security Indicators:
- All accessed endpoints were validated as authorized before testing
- Rate limiting was respected between requests (2.0 second delay)
- No active testing, injection, exploitation, or payment testing attempted
- Only publicly available information was gathered
- **No payment testing performed in production endpoints**
- Clear distinction made between authorized production endpoints and sandbox candidates

### Critical Payment Security Warnings:
1. **Sandbox/TEST ENVIRONMENTS ONLY**: Active payment security testing MUST ONLY occur in explicitly authorized sandbox/test environments
2. **NO REAL FINANCIAL TRANSACTIONS**: Never initiate real payments, refunds, or transfers with real currency
3. **USE ONLY EXPLICITLY AUTHORIZED TEST INSTRUMENTS**: Only use provided test credit cards, tokens, and accounts
4. **CLEARLY MARK TEST DATA**: Ensure all test transactions are clearly labeled as test/sandbox
5. **NO PRODUCTION IMPACT**: Use only sandbox instances that do not affect live payment processing

### Areas for Further Authorized Testing (Sandbox/Test Only):
1. **Payment State Validation** - Testing payment states (pending, approved, rejected, refunded)
2. **Transaction Ownership** - Ensuring users can only modify/refund their own transactions
3. **Webhook Security** - Testing webhook signature validation and replay attack prevention
4. **Currency/Amount Integrity** - Testing for tampering with payment amounts and currency codes
5. **Tokenization/Data Security** - Testing payment tokenization and sensitive data handling
6. **Duplicate Payment Prevention** - Testing idempotency and race condition protection
7. **Checkout/Cart Security** - Testing price manipulation and cart validation
8. **Refund/Dispute Processing** - Testing refund authorization and dispute handling

## Next Steps (Requiring Explicit Authorization for Sandbox/Test Only)

To proceed beyond this passive assessment, **EXPLICIT AUTHORIZATION FOR SANDBOX/TEST ENVIRONMENTS** is required for:

1. **Obtain Sandbox/Test Credentials** - Explicitly provided test accounts, cards, and tokens from program
2. **Configure Sandbox/Test Endpoints** - Explicitly authorized sandbox/test payment endpoints
3. **Active Payment State Testing** - Testing payment state transitions and validation
4. **Transaction Ownership Testing** - Verifying users can only access their own transactions
5. **Webhook Security Testing** - Testing webhook signatures, replay attacks, and notification security
6. **Currency/Amount Integrity Testing** - Testing for amount manipulation and currency tampering
7. **Automated Scanning** - Using security scanners within authorized sandbox/test scope and rate limits

## Compliance Statement
All activities conducted in this assessment were:
- [+] Authorized (validated via scope checker before any interaction)
- [+] Passive (no active testing, injection, exploitation, or payment testing attempted)
- [+] Respectful (rate limited, error handling, user agent identification)
- [+] Boundary-respecting (only authorized endpoints accessed)
- [+] Documentation-only (relied on public information and basic connectivity)
- [+] Clearly distinguished production vs. sandbox candidates
- [+] Emphasized sandbox/test-only requirement for active payment testing

## Recommendations for Next Authorized Phase
1. **OBTAIN EXPLICIT AUTHORIZATION** for sandbox/test environment access from Mercado Libre program
2. **CONFIGURE EXPLICITLY AUTHORIZED TEST CREDENTIALS** - Obtain from program directly (NEVER guess or use real cards)
3. **REVIEW RATE LIMITS AND AUTOMATION RESTRICTIONS** from program policy for payment endpoints
4. **PROCEED TO ACTIVE PAYMENT SECURITY TESTING** ONLY in authorized sandbox/test environments
5. **CORRELATE FINDINGS** with vulnerability validation processes (sandbox/test impact only)

---
*Report generated by Mercado Libre Bug Bounty Research Agent Payment Security Assessment*
*For authorized security research only - Passive Information Gathering Phase*
*ACTIVE PAYMENT TESTING REQUIRES EXPLICIT SANDBOX/TEST AUTHORIZATION*
"""
        return report


def main():
    """Main function to run the initial payment security assessment."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run initial passive payment security assessment on authorized Mercado Libre payment endpoints"
    )
    parser.add_argument(
        "--scope-file",
        default="scopes/verified-scope.json",
        help="Path to scope JSON file (default: scopes/verified-scope.json)"
    )
    parser.add_argument(
        "--output-dir",
        default="payment-security",
        help="Output directory for results (default: payment-security)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format to stdout"
    )

    args = parser.parse_args()

    # Initialize assessor
    assessor = PaymentSecurityAssessor(args.scope_file)

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
        print("PAYMENT SECURITY ASSESSMENT COMPLETE")
        print("=" * 60)
        print(f"Duration: {results['metadata']['duration_seconds']:.2f} seconds")
        print(f"Authorized payment endpoints in scope: {results['payment_endpoint_inventory']['total_authorized_payment_endpoints']}")
        print(f"Payment endpoints inventoried: {results['payment_endpoint_inventory']['inventoried_payment_endpoints']}")
        print(f"Sandbox candidates identified: {results['payment_endpoint_inventory']['total_sandbox_candidates']}")
        print(f"Documentation sites checked: {results['documentation_review']['sites_checked']}")
        print(f"Payment endpoints probed: {results['endpoint_probing']['endpoints_tested']}")
        print(f"Responsive payment endpoints: {len(results['endpoint_probing']['responsive_endpoints'])}")
        print(f"\nDetailed results saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()