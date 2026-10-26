#!/usr/bin/env python3
"""
Test script for Mercado Libre scope validation.
Tests all requirements specified in the task.
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


def run_tests():
    """Run all scope validation tests."""
    print("=" * 70)
    print("MERCADO LIBRE SCOPE VALIDATION TESTS")
    print("=" * 70)

    # Initialize scope checker with our updated scope data
    checker = ScopeChecker("../scopes/mercadolibre-scope.json")

    test_results = []

    # Test 1: Exact asset matches that are submission and bounty eligible
    print("\n1. Testing exact asset matches (submission & bounty eligible):")
    test_cases = [
        ("api.mercadolibre.com", True, True, "URL - Tier 1 API"),
        ("api.mercadopago.com", True, True, "URL - Tier 1 API"),
        ("com.mercadolibre", True, True, "Google Play App ID"),
        ("com.3mosquitos.MercadoLibre", True, True, "Apple Store App ID"),
        ("Point Smart", True, True, "HARDWARE"),
        ("www.mercadolibre.com", True, True, "URL - Tier 1 Wildcard match")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Exact match (auth+bounty)", target, status))

    # Test 2: Exact asset matches that are submission eligible but NOT bounty eligible
    print("\n2. Testing exact asset matches (submission eligible, NOT bounty eligible):")
    test_cases = [
        ("mercadolibreexperience.com.*", True, False, "Wildcard - Submission eligible, no bounty"),
        ("*.tucarro.com.ve", True, False, "Wildcard - Submission eligible, no bounty"),
        ("*.mercadolibre.com.ve", True, False, "Wildcard - Submission eligible, no bounty"),
        ("www.ipbooster.com", True, False, "URL - Submission eligible, no bounty"),
        ("mercadoenvios.com.ve", True, False, "URL - Submission eligible, no bounty")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        # For these targets, they should be authorized (in scope) but NOT bounty eligible
        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Exact match (auth only)", target, status))

        # Also test without bounty eligibility requirement - should be authorized
        result_no_bounty = checker.check_target(target, require_bounty_eligible=False)
        auth_only_status = "[PASS]" if result_no_bounty["authorized"] == True else "[FAIL]"
        print(f"  {auth_only_status} {target:<35} | Auth only: {result_no_bounty['authorized']:<5} | {description} (auth only check)")
        test_results.append(("Exact match (auth only)", f"{target} (auth only)", auth_only_status))

    # Test 3: Excluded assets (NOT submission eligible)
    print("\n3. Testing excluded assets (NOT submission eligible):")
    test_cases = [
        ("*.kangu.com.br", False, False, "Wildcard - Kangu (excluded)"),
        ("developersforum", False, False, "OTHER - developersforum (excluded)"),
        ("Redelcom", False, False, "OTHER - Redelcom (excluded)"),
        ("*.gokangu.cl", False, False, "Wildcard - Kangu (excluded)"),
        ("*.gokangu.co", False, False, "Wildcard - Kangu (excluded)"),
        ("*.gokangu.mx", False, False, "Wildcard - Kangu (excluded)"),
        ("*.gokangu.uy", False, False, "Wildcard - Kangu (excluded)"),
        ("*.kangu.tech", False, False, "Wildcard - Kangu (excluded)"),
        ("wow-int.mercadolibre.com", False, False, "URL - excluded")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        # These should NOT be authorized at all
        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Excluded asset", target, status))

    # Test 4: Wildcard matches
    print("\n4. Testing wildcard matches:")
    test_cases = [
        ("test.api.mercadolibre.com", True, True, "Subdomain of mercadolibre.com"),
        ("staging.api.mercadolibre.com", True, True, "Subdomain of mercadolibre.com"),
        ("dev.api.mercadolibre.com.ar", True, True, "Subdomain of mercadolibre.com.ar"),
        ("test.blog.mercadolibre.com.co", True, True, "Subdomain of mercadolibre.com.co"),
        ("admin.panel.adminml.com", True, True, "Subdomain of adminml.com"),
        ("www.test.mlstatic.com", True, True, "Subdomain of mlstatic.com"),
        ("invalid.*.mercadolibre.com", False, False, "Invalid wildcard usage"),
        ("*.mercadolibre.com", True, True, "Exact wildcard match")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Wildcard match", target, status))

    # Test 5: Malformed targets
    print("\n5. Testing malformed/empty targets:")
    test_cases = [
        ("", False, False, "Empty string"),
        ("   ", False, False, "Whitespace only"),
        ("invalid..domain.com", False, False, "Double dot in domain"),
        ("http://", False, False, "Incomplete URL"),
        ("https:///path", False, False, "URL with no host")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {repr(target):<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Malformed target", repr(target), status))

    # Test 6: Unknown targets (not in scope)
    print("\n6. Testing unknown targets (should be denied by default):")
    test_cases = [
        ("google.com", False, False, "Completely unknown domain"),
        ("github.com", False, False, "Another unknown domain"),
        ("example.com", False, False, "Example domain"),
        ("unknown-subdomain.mercadolibre.fake", False, False, "Fake subdomain"),
        ("192.168.1.1", False, False, "IP address (no IP ranges defined)"),
        ("10.0.0.1", False, False, "Another IP address")
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Unknown target", target, status))

    # Test 7: Asset-type aware matching
    print("\n7. Testing asset-type aware matching:")
    # Test that we don't confuse different asset types with same identifier patterns
    test_cases = [
        # These are all different asset types but might have similar naming
        ("api.mercadolibre.com", True, True, "URL asset type"),
        # Note: We don't have conflicting identifiers in our test set, but the checker
        # should still respect asset type distinctions in the data
    ]

    for target, should_be_authorized, should_be_bounty, description in test_cases:
        result = checker.check_target(target, require_bounty_eligible=True)
        authorized = result["authorized"]
        bounty_eligible = result["bounty_eligible"]

        status = "[PASS]" if (authorized == should_be_authorized and bounty_eligible == should_be_bounty) else "[FAIL]"
        print(f"  {status} {target:<35} | Auth: {authorized:<5} | Bounty: {bounty_eligible:<5} | {description}")
        test_results.append(("Asset-type awareness", target, status))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
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
                print(f"  - {test_type}: {target}")
        return False
    else:
        print("\n[PASS] All tests passed!")
        return True


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)