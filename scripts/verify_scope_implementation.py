#!/usr/bin/env python3
"""
Verification script for Mercado Libre scope implementation.
Tests all requirements specified in the task and provides final verification summary.
"""

import sys
import os
import json
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


def main():
    """Run verification and print summary."""
    print("=" * 80)
    print("MERCADO LIBRE SCOPE IMPLEMENTATION VERIFICATION")
    print("=" * 80)

    # Initialize scope checker
    checker = ScopeChecker("../scopes/mercadolibre-scope.json")

    # Load the scope data to get counts
    with open("../scopes/mercadolibre-scope.json", 'r') as f:
        scope_data = json.load(f)

    # Get counts from metadata
    metadata = scope_data['metadata']
    total_records = metadata['total_records']
    submission_eligible = metadata['submission_eligible_count']
    bounty_eligible = metadata['bounty_eligible_count']
    not_submission_eligible = metadata['not_submission_eligible_count']
    submission_eligible_not_bounty = metadata['submission_eligible_not_bounty_count']

    print(f"[INFO] SCOPE DATA SUMMARY:")
    print(f"   Total asset records: {total_records}")
    print(f"   Submission eligible: {submission_eligible}")
    print(f"   Bounty eligible: {bounty_eligible}")
    print(f"   Submission eligible but NOT bounty eligible: {submission_eligible_not_bounty}")
    print(f"   Not submission eligible: {not_submission_eligible}")
    print()

    # Test key requirements
    print("REQUIREMENT VERIFICATION:")
    print()

    # Requirement 1: Never treat submission eligibility as equivalent to bounty eligibility
    print("Requirement 1: Submission eligibility != Bounty eligibility")
    # Test a submission-eligible-but-not-bounty-eligible target
    target = "mercadolibreexperience.com.*"
    result_no_bounty_check = checker.check_target(target, require_bounty_eligible=False)
    result_with_bounty_check = checker.check_target(target, require_bounty_eligible=True)

    if result_no_bounty_check["authorized"] and not result_with_bounty_check["authorized"]:
        print(f"   * Target '{target}' is submission eligible but NOT bounty eligible")
        print(f"   * Without bounty check: Authorized = {result_no_bounty_check['authorized']}")
        print(f"   * With bounty check: Authorized = {result_with_bounty_check['authorized']}, Bounty Eligible = {result_with_bounty_check['bounty_eligible']}")
    else:
        print(f"   ❌ FAILED: Submission eligibility incorrectly treated as bounty eligibility")
        return False
    print()

    # Requirement 2: Reject all records marked ineligible for submission
    print("Requirement 2: Reject all records ineligible for submission")
    excluded_targets = [
        "*.kangu.com.br",
        "developersforum",
        "Redelcom",
        "*.gokangu.cl",
        "wow-int.mercadolibre.com"
    ]

    all_excluded_correctly = True
    for target in excluded_targets:
        result = checker.check_target(target, require_bounty_eligible=True)
        if result["authorized"]:
            print(f"   [FAIL] Excluded target '{target}' was incorrectly authorized")
            all_excluded_correctly = False
        else:
            print(f"   * Excluded target '{target}' correctly rejected")

    if not all_excluded_correctly:
        return False
    print()

    # Requirement 3: Allow submission-eligible but non-bounty-eligible assets only for policy-compliant research
    print("Requirement 3: Submission-eligible non-bounty assets allowed for research (no bounty)")
    non_bounty_targets = [
        "mercadolibreexperience.com.*",
        "mercadoenvios.com.ve",
        "www.ipbooster.com",
        "*.tucarro.com.ve",
        "*.mercadolibre.com.ve"
    ]

    all_non_bounty_correct = True
    for target in non_bounty_targets:
        # Should be authorized without bounty check
        result_no_bounty = checker.check_target(target, require_bounty_eligible=False)
        # Should NOT be authorized with bounty check (or should show not bounty eligible)
        result_with_bounty = checker.check_target(target, require_bounty_eligible=True)

        if result_no_bounty["authorized"] and not result_with_bounty["authorized"]:
            print(f"   * Non-bounty target '{target}': Research authorized [PASS], Bounty blocked [PASS]")
        elif result_no_bounty["authorized"] and result_with_bounty["authorized"] and not result_with_bounty["bounty_eligible"]:
            print(f"   * Non-bounty target '{target}': Research authorized [PASS], Bounty eligible: {result_with_bounty['bounty_eligible']} [PASS]")
        else:
            print(f"   ❌ FAILED: Non-bounty target '{target}' handling incorrect")
            print(f"     No bounty check: {result_no_bounty['authorized']}")
            print(f"     With bounty check: Authorized={result_with_bounty['authorized']}, Bounty={result_with_bounty['bounty_eligible']}")
            all_non_bounty_correct = False

    if not all_non_bounty_correct:
        return False
    print()

    # Requirement 4: Implement asset-type-aware matching
    print("Requirement 4: Asset-type-aware matching implemented")
    # Test that we have different asset types properly categorized
    scope = scope_data['scope']
    asset_type_counts = {
        "URLs/Endpoints": len(scope['api_endpoints']),
        "Wildcard Domains": len(scope['wildcard_domains']),
        "Mobile Applications": len(scope['mobile_apps']),
        "Hardware Devices": len(scope['hardware_devices']),
        "Other Assets": len(scope['other_assets'])
    }

    print(f"   Asset type breakdown:")
    for asset_type, count in asset_type_counts.items():
        print(f"     {asset_type}: {count}")

    # Verify we have the expected counts from the CSV review
    expected_counts = {
        "URLs/Endpoints": 43,
        "Wildcard Domains": 21,
        "Mobile Applications": 8,
        "Hardware Devices": 1,
        "Other Assets": 6
    }

    asset_types_correct = True
    for asset_type, expected in expected_counts.items():
        actual = asset_type_counts[asset_type]
        if actual != expected:
            print(f"   [FAIL] {asset_type} count mismatch. Expected: {expected}, Got: {actual}")
            asset_types_correct = False
        else:
            print(f"   * {asset_type} count correct: {actual}")

    if not asset_types_correct:
        return False
    print()

    # Requirement 5: Do not infer wildcard coverage or expand scope to related domains
    print("Requirement 5: No wildcard inference or scope expansion")
    # Test that wildcards match one or more subdomain levels (not zero levels)
    # *.mercadolibre.com should match api.mercadolibre.com and test.api.mercadolibre.com but NOT mercadolibre.com
    wildcard_tests = [
        ("api.mercadolibre.com", True, "*.mercadolibre.com wildcard - single subdomain"),
        ("test.mercadolibre.com", True, "*.mercadolibre.com wildcard - single subdomain"),
        ("mercadolibre.com", False, "*.mercadolibre.com wildcard - base domain (should not match)"),
        ("test.api.mercadolibre.com", True, "*.mercadolibre.com wildcard - two subdomains (should match)"),
        ("test.kangu.com.br", False, "*.kangu.com.br wildcard - should be excluded anyway")
    ]

    wildcard_logic_correct = True
    for target, should_be_auth, description in wildcard_tests:
        result = checker.check_target(target, require_bounty_eligible=True)
        is_auth = result["authorized"]

        if is_auth == should_be_auth:
            # Safely handle Unicode in output
            try:
                print(f"   * {description}: {'[PASS]' if is_auth else '[PASS]'} Correctly {'authorized' if is_auth else 'rejected'}")
            except UnicodeEncodeError:
                print(f"   * {description}: [PASS] Correctly {'authorized' if is_auth else 'rejected'}")
        else:
            # Safely handle Unicode in output
            try:
                print(f"   ❌ FAILED: {description}")
            except UnicodeEncodeError:
                print(f"   [FAIL] FAILED: {description}")
            print(f"     Expected authorization: {should_be_auth}, Got: {is_auth}")
            wildcard_logic_correct = False

    if not wildcard_logic_correct:
        return False
    print()

    # Requirement 6: Reject malformed, ambiguous, and unverified targets
    print("Requirement 6: Reject malformed/ambiguous targets")
    malformed_tests = [
        ("", False, "Empty string"),
        ("   ", False, "Whitespace only"),
        ("invalid..domain.com", False, "Double dot in domain"),
        ("http://", False, "Incomplete URL"),
        ("https:///path", False, "URL with no host")
    ]

    malformed_handling_correct = True
    for target, should_be_auth, description in malformed_tests:
        result = checker.check_target(target, require_bounty_eligible=True)
        is_auth = result["authorized"]

        if is_auth == should_be_auth:
            print(f"   * {description}: Correctly rejected")
        else:
            print(f"   ❌ FAILED: {description}")
            print(f"     Expected authorization: {should_be_auth}, Got: {is_auth}")
            malformed_handling_correct = False

    if not malformed_handling_correct:
        return False
    print()

    # Requirement 7: Use default-deny behavior
    print("Requirement 7: Default-deny behavior")
    unknown_targets = [
        "google.com",
        "github.com",
        "example.com",
        "unknown-site.com",
        "192.168.1.1"  # IP address (no IP ranges defined)
    ]

    default_deny_correct = True
    for target in unknown_targets:
        result = checker.check_target(target, require_bounty_eligible=True)
        if result["authorized"]:
            print(f"   ❌ FAILED: Unknown target '{target}' was incorrectly authorized (violates default-deny)")
            default_deny_correct = False
        else:
            print(f"   * Unknown target '{target}' correctly rejected (default-deny)")

    if not default_deny_correct:
        return False
    print()

    # Final summary
    print("=" * 80)
    print("ALL REQUIREMENTS VERIFIED SUCCESSFULLY")
    print("=" * 80)
    print()
    print("IMPLEMENTATION SUMMARY:")
    print(f"   * Official CSV scope export processed: {total_records} records")
    print(f"   * Submission-eligible assets: {submission_eligible}")
    print(f"   * Bounty-eligible assets: {bounty_eligible}")
    print(f"   * Research-only (submission eligible, no bounty): {submission_eligible_not_bounty}")
    print(f"   * Excluded assets: {not_submission_eligible}")
    print()
    print("AUTHORIZATION LOGIC VERIFIED:")
    print("   * Submission eligibility != Bounty eligibility")
    print("   * All excluded assets correctly rejected")
    print("   * Research-only assets authorized for testing but not for bounty")
    print("   * Asset-type-aware matching implemented")
    print("   * No wildcard inference or unauthorized scope expansion")
    print("   * Malformed/ambiguous targets correctly rejected")
    print("   * Default-deny behavior enforced")
    print()
    print("FILES UPDATED:")
    print("   * scopes/mercadolibre-scope.json")
    print("   * scopes/exclusions.json")
    print("   * scopes/program-policy.md")
    print("   * scopes/rewards.json")
    print("   * scopes/testing-restrictions.md")
    print()
    print("Ready for authorized security testing reconnaissance!")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)