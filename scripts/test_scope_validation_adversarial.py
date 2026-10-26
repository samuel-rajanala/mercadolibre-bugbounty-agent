#!/usr/bin/env python3
"""
Adversarial tests for Mercado Libre scope validation.
Tests URL normalization bypass techniques and other evasion attempts.
"""

import sys
import os
# Add the scripts directory to the path so we can import scope_checker
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Import scope_checker module
try:
    from scope_checker import ScopeChecker
except ImportError:
    # Fallback: load the module directly
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "scope_checker",
        os.path.join(os.path.dirname(__file__), "scope-checker.py")
    )
    scope_checker_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scope_checker_module)
    ScopeChecker = scope_checker_module.ScopeChecker


def run_adversarial_tests():
    """Run all adversarial scope validation tests."""
    print("=" * 70)
    print("MERCADO LIBRE SCOPE VALIDATION ADVERSARIAL TESTS")
    print("=" * 70)

    # Initialize scope checker with our updated scope data
    checker = ScopeChecker("../scopes/mercadolibre-scope.json")

    test_results = []

    # Test 1: Userinfo in URLs (should be rejected)
    print("\n1. Testing userinfo in URLs (should be rejected):")
    test_cases = [
        ("http://user:pass@api.mercadolibre.com", False, False, "URL with username:password"),
        ("http://user@api.mercadolibre.com", False, False, "URL with username only"),
        ("http://:pass@api.mercadolibre.com", False, False, "URL with password only"),
        ("http://internal.not-mercadolibre.com@api.mercadolibre.com", False, False, "Userinfo with different domain"),
        ("https://admin:secret@www.mercadolibre.com", False, False, "HTTPS with credentials"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<50} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Userinfo in URL", target, status))

    # Test 2: Alternate ports (should be handled correctly based on policy)
    print("\n2. Testing alternate ports:")
    test_cases = [
        ("api.mercadolibre.com:8080", False, False, "Non-standard port (not 80/443)"),
        ("api.mercadolibre.com:80", True, True, "Standard HTTP port"),
        ("api.mercadolibre.com:443", True, True, "Standard HTTPS port"),
        ("api.mercadolibre.com:0", False, False, "Port zero (invalid)"),
        ("api.mercadolibre.com:65535", False, False, "Maximum port"),
        ("api.mercadolibre.com:65536", False, False, "Port beyond maximum"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Alternate ports", target, status))

    # Test 3: Trailing dots (should be rejected as ambiguous)
    print("\n3. Testing trailing dots:")
    test_cases = [
        ("api.mercadolibre.com.", False, False, "Trailing dot on hostname"),
        ("www.mercadolibre.com.", False, False, "Trailing dot on www subdomain"),
        ("*.mercadolibre.com.", False, False, "Trailing dot on wildcard pattern"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Trailing dots", target, status))

    # Test 4: Unicode lookalike domains / IDN (should be rejected or normalized safely)
    print("\n4. Testing Unicode/IDN hostnames:")
    test_cases = [
        ("xn--mercadolibre-com-9ya.net", False, False, "Punycode domain (fake)"),
        ("ａｐｉ．ｍｅｒｃａｄｏｌｉｂｒｅ．ｃｏｍ", False, False, "Full-width characters"),
        ("аpi.mercadolibre.com", False, False, "Cyrillic 'а' (lookalike for 'a')"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Unicode/IDN", target, status))

    # Test 5: Subdomain confusion attacks
    print("\n5. Testing subdomain confusion:")
    test_cases = [
        ("test.mercadolibre.com.attacker.com", False, False, "Subdomain confusion - extra domain"),
        ("mercadolibre.com.attacker.com", False, False, "Domain confusion - extra domain"),
        ("api.mercadolibre.com.attacker.com", False, False, "API subdomain confusion"),
        ("test.api.mercadolibre.com.br", False, False, "Wrong TLD"),
        ("test.mercadolibre.com.fake", False, False, "Fake TLD"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Subdomain confusion", target, status))

    # Test 6: Encoded hostname attempts
    print("\n6. Testing encoded hostname attempts:")
    test_cases = [
        ("http%3A%2F%2Fapi.mercadolibre.com", False, False, "URL-encoded scheme"),
        ("api%2Emercadolibre%2Ecom", False, False, "URL-encoded dots"),
        ("%61%70%69%2E%6D%65%72%63%61%64%6F%6C%69%62%72%65%2E%63%6F%6D", False, False, "Hex-encoded hostname"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Encoded hostname", target, status))

    # Test 7: Invalid ports and port formats
    print("\n7. Testing invalid ports:")
    test_cases = [
        ("api.mercadolibre.com:abc", False, False, "Non-numeric port"),
        ("api.mercadolibre.com:80a", False, False, "Mixed alphanumeric port"),
        ("api.mercadolibre.com:", False, False, "Trailing colon"),
        ("api.mercadolibre.com: 80", False, False, "Space in port"),
        ("api.mercadolibre.com:-80", False, False, "Negative port"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Invalid ports", target, status))

    # Test 8: IPv4 and IPv6 literals
    print("\n8. Testing IPv4 and IPv6 literals:")
    test_cases = [
        ("192.168.1.1", False, False, "IPv4 address (no IP ranges defined)"),
        ("[::1]", False, False, "IPv6 loopback"),
        ("[2001:db8::1]", False, False, "IPv6 address"),
        ("[::ffff:192.0.2.1]", False, False, "IPv4-mapped IPv6 address"),
        ("192.168.1.1:8080", False, False, "IPv4 with port"),
        ("[::1]:8080", False, False, "IPv6 with port"),
        ("256.256.256.256", False, False, "Invalid IPv4 address"),
        ("[::ffff:ffff:ffff:ffff]", False, False, "Invalid IPv6 address"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("IP literals", target, status))

    # Test 9: URLs containing control characters
    print("\n9. Testing URLs with control characters:")
    test_cases = [
        ("api.mercadolibre.com\x00", False, False, "Null byte"),
        ("api.mercadolibre.com\x01", False, False, "Start of heading"),
        ("api.mercadolibre.com\n", False, False, "Line feed"),
        ("api.mercadolibre.com\r", False, False, "Carriage return"),
        ("api.mercadolibre.com\t", False, False, "Tab"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {repr(target):<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Control characters", repr(target), status))

    # Test 10: Unexpected URL schemes
    print("\n10. Testing unexpected URL schemes:")
    test_cases = [
        ("ftp://api.mercadolibre.com", False, False, "FTP scheme"),
        ("ssh://api.mercadolibre.com", False, False, "SSH scheme"),
        ("mailto://api.mercadolibre.com", False, False, "Mailto scheme"),
        ("file:///etc/passwd", False, False, "File scheme"),
        ("javascript:alert(1)", False, False, "JavaScript scheme"),
        ("data:text/html,<script>alert(1)</script>", False, False, "Data scheme"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Unexpected schemes", target, status))

    # Test 11: Redirect-like scenarios (targets that might appear valid but aren't)
    print("\n11. Testing redirect-like scenarios:")
    test_cases = [
        ("api.mercadolibre.com@evil.com", False, False, "Looks like userinfo but actually invalid host"),
        ("evil.com#api.mercadolibre.com", False, False, "Fragment looks like valid domain"),
        ("evil.com?api.mercadolibre.com", False, False, "Query looks like valid domain"),
        ("//api.mercadolibre.com", False, False, "Protocol-relative URL (no scheme)"),
        ("/api.mercadolibre.com", False, False, "Path-only (looks like domain)"),
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        # Safely handle Unicode characters in output for console
        try:
            print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        except UnicodeEncodeError:
            # If direct formatting fails, try to show ASCII representation for all fields
            try:
                safe_target = target.encode('ascii', 'replace').decode('ascii')
                safe_description = description.encode('ascii', 'replace').decode('ascii')
                print(f"  {status} {safe_target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {safe_description}")
            except UnicodeEncodeError:
                # Final fallback: show field lengths instead of actual content
                print(f"  {status} [TARGET LEN: {len(target)}] | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | [DESC LEN: {len(description)}]")
        test_results.append(("Redirect-like", target, status))

    # Summary
    print("\n" + "=" * 70)
    print("ADVERSARIAL TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, _, status in test_results if status == "✓ PASS")
    failed = sum(1 for _, _, status in test_results if status == "✗ FAIL")
    total = len(test_results)

    print(f"Total tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {passed/total*100:.1f}%")

    if failed > 0:
        print("\nFailed tests:")
        for test_type, target, status in test_results:
            if status == "✗ FAIL":
                # Safely handle Unicode in test output
                try:
                    print(f"  - {test_type}: {target}")
                except UnicodeEncodeError:
                    print(f"  - {test_type}: [TARGET CONTAINS UNICODE]")
        return False
    else:
        # Safely handle Unicode in success message
        try:
            print("\n🎉 All adversarial tests passed!")
        except UnicodeEncodeError:
            print("\n[PASS] All adversarial tests passed!")
        return True


if __name__ == "__main__":
    success = run_adversarial_tests()
    sys.exit(0 if success else 1)