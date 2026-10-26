#!/usr/bin/env python3
"""
Scope Checker for Mercado Libre Bug Bounty Research Agent
Validates whether targets are authorized for security testing based on verified program policy.
Now includes authorization gate enforcement for fail-closed security.
"""

import json
import re
import sys
import urllib.parse
from typing import Dict, List, Tuple, Optional
import os

# Import authorization gate
sys.path.append(os.path.join(os.path.dirname(__file__)))
from authorization_gate import AuthorizationGate, AuthorizationRequest, AuthorizationDecision


class ScopeChecker:
    def __init__(self, scope_file: str = "scopes/mercadolibre-scope.json"):
        """
        Initialize the scope checker with verified policy data.

        Args:
            scope_file: Path to the verified scope JSON file
        """
        self.scope_file = scope_file
        self.scope_data = self._load_scope_data()
        self._compile_patterns()

        # Initialize authorization gate
        self.auth_gate = AuthorizationGate()

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

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        # These will be populated once we have real scope data
        self.in_scope_domains = []
        self.out_of_scope_domains = []
        self.wildcard_patterns = []
        self.ip_ranges = []
        self.bounty_eligible = []
        self.non_bounty_eligible = []

        # Extract data from scope_data if available
        if self.scope_data.get('scope'):
            scope = self.scope_data['scope']
            self.in_scope_domains = scope.get('in_scope', [])
            self.out_of_scope_domains = scope.get('out_of_scope', [])
            self.wildcard_patterns = scope.get('wildcard_domains', [])
            self.ip_ranges = scope.get('ip_ranges', [])
            self.bounty_eligible = scope.get('bounty_eligible', [])
            self.non_bounty_eligible = scope.get('non_bounty_eligible', [])

        # Convert wildcard patterns to regex
        self.wildcard_regex = []
        for pattern in self.wildcard_patterns:
            # Convert *.example.com to regex pattern to match one or more subdomain levels
            # This prevents matching the base domain itself (zero levels) while allowing
            # any number of subdomain levels (one or more)
            # Only allow valid hostname characters (alphanumeric and hyphen) in subdomain components
            if pattern.startswith('*.'):
                base_domain = pattern[2:]  # Remove the '*.' prefix
                regex_pattern = f"^[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.{base_domain}$"
            else:
                # For exact wildcard matches (no * prefix), match exactly
                regex_pattern = f"^{pattern}$"
            try:
                self.wildcard_regex.append(re.compile(regex_pattern, re.IGNORECASE))
            except re.error:
                print(f"Warning: Invalid wildcard pattern: {pattern}")

    def normalize_target(self, target: str) -> str:
        """
        Normalize a target for consistent matching.

        Args:
            target: Target hostname, IP, or URL

        Returns:
            Normalized target string
        """
        # Reject empty targets
        if not target or not target.strip():
            return ""

        # Reject targets with control characters
        if any(ord(c) < 32 for c in target):
            return ""

        # Parse URL if it has a scheme
        parsed = None
        if '://' in target:
            try:
                parsed = urllib.parse.urlparse(target)
                # Reject URLs with username/password (userinfo)
                if parsed.username or parsed.password:
                    return ""  # Reject credentials in URL
                # Reject unexpected schemes - only allow http and https unless explicitly permitted
                # According to policy: "Treat unexpected schemes/ports as DENY unless explicitly permitted"
                if parsed.scheme not in ['http', 'https']:
                    return ""  # Reject unexpected schemes
                # Use netloc (hostname:port) or path if netloc is empty
                target = parsed.netloc or parsed.path
            except Exception:
                return ""  # Reject malformed URLs
        # If no scheme, target might be just hostname:port or hostname

        # Remove path, query, fragment if they somehow got in
        if '/' in target:
            target = target.split('/')[0]
        if '?' in target:
            target = target.split('?')[0]
        if '#' in target:
            target = target.split('#')[0]

        # Remove port for default ports (we'll keep non-standard ports)
        if ':' in target:
            # Split on LAST colon to separate host from port
            # But first check if we have IPv6 address (contains multiple colons)
            if target.count(':') > 1 and target.startswith('[') and target.endswith(']'):
                # IPv6 address format: [::1]:8080 or [::1]
                bracket_end = target.find(']')
                if bracket_end != -1:
                    ipv6_part = target[1:bracket_end]  # Extract the IPv6 address
                    remainder = target[bracket_end+1:]  # Everything after ]
                    if remainder.startswith(':'):
                        port = remainder[1:]  # Remove the leading colon
                        # Validate port
                        if port.isdigit():
                            port_num = int(port)
                            if 0 <= port_num <= 65535:
                                if port_num not in [80, 443]:
                                    target = f"[{ipv6_part}]:{port}"
                                else:
                                    target = f"[{ipv6_part}]"
                            else:
                                return ""  # Invalid port number
                        else:
                            return ""  # Invalid port
                    else:
                        # No port specified, just IPv6 address
                        target = f"[{ipv6_part}]"
                else:
                    return ""  # Malformed IPv6
            else:
                # Regular hostname:port or IPv4 address
                host, port = target.rsplit(':', 1)
                # Validate port is numeric
                if not port.isdigit():
                    return ""  # Invalid port
                port_num = int(port)
                if port_num < 0 or port_num > 65535:
                    return ""  # Port out of range
                # Keep non-standard ports for now - could be made configurable
                if port_num not in [80, 443]:
                    target = f"{host}:{port}"
                else:
                    target = host

        # Determine if target should be treated as an exact identifier (preserve case)
        # or as a hostname (lowercase for case-insensitive matching)
        is_exact_identifier = False

        # Check if it looks like a mobile app ID (starts with com. and contains dots)
        if target.lower().startswith('com.') and '.' in target[4:]:
            is_exact_identifier = True
        # Check if it looks like other exact identifiers (no dots, not an IP address)
        elif '.' not in target and not self.is_ip_address(target):
            is_exact_identifier = True

        if is_exact_identifier:
            # For exact identifiers (mobile apps, hardware, etc.), preserve case but strip whitespace
            return target.strip()
        else:
            # For hostnames and IP addresses, normalize to lowercase
            # Handle potential trailing dot
            if target.endswith('.'):
                # For now, reject trailing dots as ambiguous
                # Could be made configurable based on policy
                return ""
            return target.lower().strip()

    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        ip_pattern = re.compile(
            r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(ip_pattern.match(target))

    def ip_in_range(self, ip: str, ip_range: str) -> bool:
        """
        Check if an IP address is within a CIDR range.

        Args:
            ip: IP address to check
            ip_range: CIDR notation range (e.g., "192.168.1.0/24")

        Returns:
            True if IP is in range, False otherwise
        """
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return False

    def check_scope(self, target: str) -> Tuple[bool, str, List[str]]:
        """
        Check if a target is within scope.

        Args:
            target: Target to check (hostname, IP, or URL)

        Returns:
            Tuple of (is_in_scope, reason, matched_patterns)
        """
        normalized_target = self.normalize_target(target)
        matched_patterns = []

        # Handle empty target
        if not normalized_target:
            return False, "Empty target provided", []

        # Check if it's an IP address
        if self.is_ip_address(normalized_target):
            # Check against IP ranges
            for ip_range in self.ip_ranges:
                if self.ip_in_range(normalized_target, ip_range):
                    matched_patterns.append(f"IP range: {ip_range}")
                    return True, f"Target matches authorized IP range: {ip_range}", matched_patterns

            # If no IP ranges specified, IP might be out of scope by default
            if not self.ip_ranges:
                return False, "No IP ranges authorized in policy", []

            return False, f"IP address {normalized_target} not in authorized ranges", []

        # Check exact matches against in-scope domains
        if normalized_target in self.in_scope_domains:
            matched_patterns.append(f"Exact match: {normalized_target}")
            return True, f"Target exactly matches authorized domain: {normalized_target}", matched_patterns

        # Check exact matches against out-of-scope domains (deny wins)
        if normalized_target in self.out_of_scope_domains:
            matched_patterns.append(f"Exact out-of-scope match: {normalized_target}")
            return False, f"Target explicitly out of scope: {normalized_target}", matched_patterns

        # Check wildcard patterns
        for i, regex_pattern in enumerate(self.wildcard_regex):
            if regex_pattern.match(normalized_target):
                matched_patterns.append(f"Wildcard match: {self.wildcard_patterns[i]}")
                return True, f"Target matches authorized wildcard pattern: {self.wildcard_patterns[i]}", matched_patterns

        # If we get here, target is not explicitly authorized
        # Provide helpful feedback
        reasons = []
        if self.in_scope_domains:
            reasons.append(f"Not in authorized domains: {', '.join(self.in_scope_domains[:3])}{'...' if len(self.in_scope_domains) > 3 else ''}")
        if self.wildcard_patterns:
            reasons.append(f"Not matching authorized wildcards: {', '.join(self.wildcard_patterns[:3])}{'...' if len(self.wildcard_patterns) > 3 else ''}")
        if not self.in_scope_domains and not self.wildcard_patterns:
            reasons.append("No authorized domains or wildcards defined in policy")

        reason = "; ".join(reasons) if reasons else "Target not found in authorized scope"
        return False, reason, matched_patterns

    def is_bounty_eligible(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is eligible for bounty submission.

        Args:
            target: Target to check

        Returns:
            Tuple of (is_eligible, reason)
        """
        # If no bounty eligibility lists are defined, assume all in-scope targets are eligible
        if not self.bounty_eligible and not self.non_bounty_eligible:
            is_in_scope, _, _ = self.check_scope(target)
            if is_in_scope:
                return True, "Target is in scope and no specific bounty eligibility restrictions defined"
            else:
                return False, "Target is out of scope"

        normalized_target = self.normalize_target(target)

        # Check explicit bounty eligible list
        if normalized_target in self.bounty_eligible:
            return True, f"Target explicitly listed as bounty eligible: {normalized_target}"

        # Check explicit non-bounty eligible list (deny wins for bounty eligibility)
        if normalized_target in self.non_bounty_eligible:
            return False, f"Target explicitly listed as non-bounty eligible: {normalized_target}"

        # If target is in scope but not explicitly listed, check policy defaults
        is_in_scope, scope_reason, _ = self.check_scope(target)
        if is_in_scope:
            # Check if we should assume eligibility by default
            return True, f"Target is in scope ({scope_reason}) and not explicitly excluded from bounty"
        else:
            return False, f"Target out of scope: {scope_reason}"

    def check_target_authorization(self, target: str, activity: str = "reconnaissance",
                                 technique: str = "GET", environment: str = "request") -> Dict:
        """
        Comprehensive target check including scope, bounty eligibility, and authorization gate.

        Args:
            target: Target to check
            activity: Activity type (reconnaissance, scanning, exploitation, etc.)
            technique: Specific technique (GET, POST, PUT, etc.)
            environment: Environment (request, response, etc.)

        Returns:
            Dictionary with check results and separate decision outcomes
        """
        # Initialize result with all possible decision outcomes
        result = {
            "target": target,
            "normalized_target": self.normalize_target(target),
            "timestamp": None,
            "activity": activity,
            "technique": technique,
            "environment": environment,

            # Scope check results
            "scope_check": {},

            # Bounty eligibility check
            "bounty_eligible_check": {},

            # Authorization gate checks
            "external_authorization_check": {},
            "human_approval_check": {},
            "technique_permission_check": {},
            "environment_permission_check": {},

            # Final decision outcomes (mutually exclusive)
            "decision": "OUT_OF_SCOPE",  # Default deny
            "decision_reason": "",
            "authorized": False,
            "bounty_eligible": False,
            "recommendation": ""
        }

        # Perform scope check
        is_in_scope, scope_reason, matched_patterns = self.check_scope(target)
        result["scope_check"] = {
            "authorized": is_in_scope,
            "reason": scope_reason,
            "matched_patterns": matched_patterns
        }

        # If out of scope, return early with OUT_OF_SCOPE decision
        if not is_in_scope:
            result["decision"] = "OUT_OF_SCOPE"
            result["decision_reason"] = f"Target out of scope: {scope_reason}"
            result["reason"] = result["decision_reason"]
            result["recommendation"] = "Do NOT test this target - it is out of scope"
            return result

        # Target is in scope, check submission eligibility
        is_submission_eligible, submission_reason = self.is_bounty_eligible(target)
        result["bounty_eligible_check"] = {
            "eligible": is_submission_eligible,
            "reason": submission_reason
        }
        result["bounty_eligible"] = is_submission_eligible

        # If target is in scope but not submission eligible
        if not is_submission_eligible:
            result["decision"] = "IN_SCOPE_NON_BOUNTY"
            result["decision_reason"] = f"Target in scope but not bounty eligible: {submission_reason}"
            result["reason"] = result["decision_reason"]
            result["recommendation"] = "Target can be tested but cannot submit for bounty"
            return result

        # Target is in scope and submission eligible, now check authorization gate
        # Create authorization request
        auth_request = AuthorizationRequest(
            asset=target,
            activity=activity,
            technique=technique,
            environment=environment
        )

        # Check authorization gate
        auth_decision, auth_reason = self.auth_gate.check_authorization(auth_request)

        # Process authorization gate decision
        if auth_decision == AuthorizationDecision.REQUIRE_EXTERNAL_AUTHORIZATION:
            result["decision"] = "EXTERNAL_AUTHORIZATION_MISSING"
            result["decision_reason"] = "External program authorization required"
            result["external_authorization_check"] = {
                "status": "REQUIRED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.REQUIRE_HUMAN_APPROVAL:
            result["decision"] = "HUMAN_APPROVAL_MISSING"
            result["decision_reason"] = "Human approval required for this specific activity"
            result["human_approval_check"] = {
                "status": "REQUIRED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.TECHNIQUE_NOT_PERMITTED:
            result["decision"] = "TECHNIQUE_NOT_PERMITTED"
            result["decision_reason"] = "Requested technique not permitted by authorization gate"
            result["technique_permission_check"] = {
                "status": "DENIED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.ENVIRONMENT_NOT_PERMITTED:
            result["decision"] = "ENVIRONMENT_NOT_PERMITTED"
            result["decision_reason"] = "Requested environment not permitted by authorization gate"
            result["environment_permission_check"] = {
                "status": "DENIED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.APPROVAL_EXPIRED:
            result["decision"] = "APPROVAL_EXPIRED"
            result["decision_reason"] = "Human approval has expired"
            result["human_approval_check"] = {
                "status": "EXPIRED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.MISSING_PROVENANCE:
            result["decision"] = "POLICY_UNKNOWN"
            result["decision_reason"] = "Authorization gate has unknown policy values"
            result["external_authorization_check"] = {
                "status": "UNKNOWN_POLICY",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.PRODUCTION_TESTING_NOT_AUTHORIZED:
            result["decision"] = "ENVIRONMENT_NOT_PERMITTED"  # Treat as environment not permitted
            result["decision_reason"] = "Production testing not authorized"
            result["environment_permission_check"] = {
                "status": "DENIED",
                "reason": auth_reason
            }

        elif auth_decision == AuthorizationDecision.APPROVE:
            result["decision"] = "AUTHORIZED_FOR_EXACT_ACTIVITY"
            result["decision_reason"] = f"Authorized for {technique} on {target} in {environment}"
            result["authorized"] = True

            # Add authorization check details
            result["external_authorization_check"] = {
                "status": "APPROVED" if self.auth_gate._external_authorization else "NOT_LOADED",
                "reason": "External program authorization validated"
            }

            result["human_approval_check"] = {
                "status": "APPROVED" if self.auth_gate._human_approval else "NOT_LOADED",
                "reason": "Human approval validated for exact activity"
            }

        else:
            # Fallback for any other decision
            result["decision"] = "POLICY_UNKNOWN"
            result["decision_reason"] = f"Authorization gate returned unexpected decision: {auth_decision.value}"

        # Set final reason and recommendation
        result["reason"] = result["decision_reason"]

        if result["authorized"]:
            if result["bounty_eligible"]:
                result["recommendation"] = "Target is authorized and bounty eligible for testing"
            else:
                result["recommendation"] = "Target is authorized but NOT bounty eligible (can test but cannot submit for bounty)"
        else:
            result["recommendation"] = "Do NOT proceed with testing - authorization not granted"

        return result

    def check_target(self, target: str, require_bounty_eligible: bool = False) -> Dict:
        """
        Legacy method for backward compatibility.
        Performs basic target check (scope and bounty eligibility only).
        For full authorization checking, use check_target_authorization instead.

        Args:
            target: Target to check
            require_bounty_eligible: If True, also check bounty eligibility

        Returns:
            Dictionary with check results (backward compatible format)
        """
        # Perform scope check
        is_in_scope, scope_reason, matched_patterns = self.check_scope(target)

        # Perform bounty eligibility check if requested
        is_eligible = False
        eligibility_reason = ""
        if require_bounty_eligible:
            is_eligible, eligibility_reason = self.is_bounty_eligible(target)

        # Determine overall authorization (legacy behavior)
        authorized = is_in_scope
        if require_bounty_eligible:
            authorized = is_in_scope and is_eligible

        # Build reason and recommendation
        if authorized:
            reason = "Target is authorized for testing"
            if require_bounty_eligible and is_eligible:
                recommendation = "Target is authorized and bounty eligible"
            elif require_bounty_eligible and not is_eligible:
                recommendation = "Target is authorized but NOT bounty eligible (can test but cannot submit for bounty)"
            else:
                recommendation = "Target is authorized for testing"
        else:
            reason = f"Not authorized: {scope_reason}"
            if require_bounty_eligible and not is_eligible:
                reason += f"; {eligibility_reason}"
            recommendation = "Do NOT test this target without explicit authorization and scope clarification"

        return {
            "target": target,
            "normalized_target": self.normalize_target(target),
            "timestamp": None,
            "scope_check": {
                "authorized": is_in_scope,
                "reason": scope_reason,
                "matched_patterns": matched_patterns
            },
            "bounty_eligible_check": {
                "eligible": is_eligible,
                "reason": eligibility_reason
            },
            "authorized": authorized,
            "bounty_eligible": is_eligible,
            "reason": reason,
            "recommendation": recommendation
        }


def main():
    """Command line interface for the scope checker."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Check if a target is authorized for security testing based on Mercado Libre bug bounty policy"
    )
    parser.add_argument(
        "target",
        help="Target to check (hostname, IP, or URL)"
    )
    parser.add_argument(
        "--bounty-eligible",
        action="store_true",
        help="Also check if target is bounty eligible (not just in scope)"
    )
    parser.add_argument(
        "--scope-file",
        default="scopes/mercadolibre-scope.json",
        help="Path to scope JSON file (default: scopes/mercadolibre-scope.json)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--activity",
        default="reconnaissance",
        help="Activity type (default: reconnaissance)"
    )
    parser.add_argument(
        "--technique",
        default="GET",
        help="Technique/method (default: GET)"
    )
    parser.add_argument(
        "--environment",
        default="request",
        help="Environment (default: request)"
    )

    args = parser.parse_args()

    # Initialize scope checker
    checker = ScopeChecker(args.scope_file)

    # Check if we should use the new authorization-aware method or legacy method
    if args.activity != "reconnaissance" or args.technique != "GET" or args.environment != "request":
        # Use new authorization-aware checking
        result = checker.check_target_authorization(
            args.target,
            args.activity,
            args.technique,
            args.environment
        )
    else:
        # Use legacy method for backward compatibility with existing usage
        result = checker.check_target(args.target, args.bounty_eligible)

    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Target: {result['target']}")
        print(f"Normalized: {result['normalized_target']}")

        # Show different fields based on which method was used
        if "activity" in result:
            print(f"Activity: {result['activity']}")
            print(f"Technique: {result['technique']}")
            print(f"Environment: {result['environment']}")
            print(f"Decision: {result['decision']}")
            if result["decision_reason"]:
                print(f"Decision Reason: {result['decision_reason']}")
        else:
            # Legacy format
            print(f"Authorized: {'YES' if result['authorized'] else 'NO'}")
            if args.bounty_eligible:
                print(f"Bounty Eligible: {'YES' if result['bounty_eligible'] else 'NO'}")

        print(f"Reason: {result['reason']}")
        print(f"Recommendation: {result['recommendation']}")

        # Show detailed scope check info
        print("\n--- Scope Check Details ---")
        print(f"  In Scope: {'YES' if result['scope_check']['authorized'] else 'NO'}")
        print(f"  Reason: {result['scope_check']['reason']}")
        if result['scope_check']['matched_patterns']:
            print(f"  Matched Patterns: {', '.join(result['scope_check']['matched_patterns'])}")

        # Show bounty eligibility check if present
        if result['bounty_eligible_check']:
            print("\n--- Bounty Eligibility Check ---")
            print(f"  Eligible: {'YES' if result['bounty_eligible_check']['eligible'] else 'NO'}")
            print(f"  Reason: {result['bounty_eligible_check']['reason']}")

        # Show authorization checks if using new method
        if "activity" in result:
            print("\n--- Authorization Gate Checks ---")
            print(f"  External Authorization: {result['external_authorization_check'].get('status', 'NOT_CHECKED')}")
            if result['external_authorization_check'].get('reason'):
                print(f"  Reason: {result['external_authorization_check']['reason']}")

            print(f"  Human Approval: {result['human_approval_check'].get('status', 'NOT_CHECKED')}")
            if result['human_approval_check'].get('reason'):
                print(f"  Reason: {result['human_approval_check']['reason']}")

            print(f"  Technique Permission: {result['technique_permission_check'].get('status', 'NOT_CHECKED')}")
            if result['technique_permission_check'].get('reason'):
                print(f"  Reason: {result['technique_permission_check']['reason']}")

            print(f"  Environment Permission: {result['environment_permission_check'].get('status', 'NOT_CHECKED')}")
            if result['environment_permission_check'].get('reason'):
                print(f"  Reason: {result['environment_permission_check']['reason']}")

if __name__ == "__main__":
    main()