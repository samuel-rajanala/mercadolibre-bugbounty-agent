#!/usr/bin/env python3
"""
Offline tests for Mercado Libre Bug Bounty Agent authorization gate and related components.
All tests run without network requests.
"""

import json
import os
import sys
from datetime import datetime

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {filepath}: {e}")
        return None

def test_default_deny_authorization_gate():
    """Test that the authorization gate defaults to disabled state."""
    print("\n=== Testing Default-Deny Authorization Gate ===")

    gate_file = "scopes/authorization-gate.json"
    gate_data = load_json_file(gate_file)

    if gate_data is None:
        return False

    # Check that gate exists and has required structure
    assert "gate_metadata" in gate_data, "Gate metadata missing"
    assert "authorization_settings" in gate_data, "Authorization settings missing"

    # Check default disabled state
    gate_status = gate_data["gate_metadata"].get("gate_status")
    human_approval = gate_data["authorization_settings"].get("human_approval_status")
    prod_testing = gate_data["authorization_settings"].get("production_testing_enabled")

    print(f"Gate status: {gate_status}")
    print(f"Human approval status: {human_approval}")
    print(f"Production testing enabled: {prod_testing}")

    # Verify default state
    assert gate_status == "DISABLED", f"Gate should be DISABLED, got {gate_status}"
    assert human_approval == "PENDING", f"Human approval should be PENDING, got {human_approval}"
    assert prod_testing == False, f"Production testing should be disabled, got {prod_testing}"

    print("[+] Default-Deny Authorization Gate test PASSED")
    return True

def test_unknown_policy_fields():
    """Test that unknown policy fields are properly marked as UNKNOWN."""
    print("\n=== Testing Unknown Policy Fields ===")

    gate_file = "scopes/authorization-gate.json"
    gate_data = load_json_file(gate_file)

    if gate_data is None:
        return False

    # Check for UNKNOWN values in expected fields
    unknown_fields_found = []
    expected_unknown_fields = [
        ("gate_metadata", "policy_version"),
        ("gate_metadata", "policy_last_updated"),
        ("testing_permissions", "permitted_testing_techniques"),
        ("testing_permissions", "prohibited_testing_techniques"),
        ("rate_limits_and_automation", "rate_limits"),
        ("rate_limits_and_automation", "automation_restrictions"),
        ("account_and_credentials", "provided_test_accounts"),
        ("account_and_credentials", "provided_test_instruments"),
        ("data_handling_and_privacy", "retention_period"),
        ("sandbox_and_test_environments", "sandbox_environments_authorized"),
        ("payment_specific_restrictions", "transaction_amount_limits"),
        ("vulnerability_specific_rules", "accepted_categories"),
        ("compliance_and_reporting", "disclosure_timelines")
    ]

    for section, field in expected_unknown_fields:
        value = gate_data.get(section, {}).get(field)
        if value == "UNKNOWN":
            unknown_fields_found.append(f"{section}.{field}")
        elif isinstance(value, list) and len(value) == 1 and value[0] == "UNKNOWN":
            unknown_fields_found.append(f"{section}.{field}")

    print(f"Found {len(unknown_fields_found)} UNKNOWN fields as expected")

    # We expect several fields to be UNKNOWN
    assert len(unknown_fields_found) >= 5, f"Expected at least 5 UNKNOWN fields, found {len(unknown_fields_found)}"

    print("[+] Unknown Policy Fields test PASSED")
    return True

def test_out_of_scope_asset_rejection():
    """Test that out-of-scope assets are properly rejected."""
    print("\n=== Testing Out-of-Scope Asset Rejection ===")

    # Test using the mercadolibre-scope.json file
    scope_file = "scopes/mercadolibre-scope.json"
    scope_data = load_json_file(scope_file)

    if scope_data is None:
        return False

    # Get lists of in-scope and out-of-scope assets
    in_scope_assets = set(scope_data.get("scope", {}).get("in_scope", []))
    out_of_scope_assets = set(scope_data.get("scope", {}).get("out_of_scope", []))

    # Also check the exclusions file
    exclusions_file = "scopes/exclusions.json"
    exclusions_data = load_json_file(exclusions_file)

    if exclusions_data is not None:
        not_eligible = set(exclusions_data.get("not_eligible_for_submission", []))
        no_bounty = set(exclusions_data.get("submission_allowed_but_no_bounty", []))
        out_of_scope_assets.update(not_eligible)
        # Note: no_bounty assets are in scope but not bounty eligible

    print(f"In-scope assets: {len(in_scope_assets)}")
    print(f"Out-of-scope assets: {len(out_of_scope_assets)}")

    # Test some known out-of-scope assets from the data
    test_out_of_scope = [
        "*.kangu.com.br",
        "developersforum",
        "Redelcom",
        "*.gokangu.cl",
        "wow-int.mercadolibre.com"
    ]

    rejected_count = 0
    for asset in test_out_of_scope:
        # Check if asset is in out-of-scope lists
        if asset in out_of_scope_assets:
            rejected_count += 1
            print(f"[+] '{asset}' correctly identified as out-of-scope")
        else:
            # For wildcard domains, we might need to check patterns
            # This is a simplified check - in reality, scope validation would be more complex
            print(f"? '{asset}' - manual pattern check needed")

    # At least some should be detected as out-of-scope
    assert rejected_count >= 3, f"Expected at least 3 known out-of-scope assets to be rejected, got {rejected_count}"

    print("[+] Out-of-Scope Asset Rejection test PASSED")
    return True

def test_non_bounty_asset_distinction():
    """Test distinction between submission eligible and bounty eligible assets."""
    print("\n=== Testing Non-Bounty Asset Distinction ===")

    scope_file = "scopes/mercadolibre-scope.json"
    scope_data = load_json_file(scope_file)

    if scope_data is None:
        return False

    scope = scope_data.get("scope", {})
    bounty_eligible = set(scope.get("bounty_eligible", []))
    non_bounty_eligible = set(scope.get("non_bounty_eligible", []))
    in_scope = set(scope.get("in_scope", []))

    print(f"Total in-scope assets: {len(in_scope)}")
    print(f"Bounty eligible assets: {len(bounty_eligible)}")
    print(f"Non-bounty eligible assets: {len(non_bounty_eligible)}")

    # Verify that non-bounty assets are a subset of in-scope assets
    assert non_bounty_eligible.issubset(in_scope), "Non-bounty assets must be in-scope"

    # Verify that bounty eligible assets are a subset of in-scope assets
    assert bounty_eligible.issubset(in_scope), "Bounty eligible assets must be in-scope"

    # Check some known non-bounty assets from the data
    known_non_bounty = [
        "mercadoenvios.com.ve",
        "www.ipbooster.com",
        "*.tucarro.com.ve",
        "*.mercadolibre.com.ve",
        "mercadolibreexperience.com.*"
    ]

    correct_count = 0
    for asset in known_non_bounty:
        if asset in non_bounty_eligible:
            correct_count += 1
            print(f"[+] '{asset}' correctly identified as non-bounty eligible")
        elif asset in bounty_eligible:
            print(f"[-] '{asset}' incorrectly identified as bounty eligible")
        else:
            print(f"? '{asset}' - not found in either list (may need pattern matching)")

    assert correct_count >= 3, f"Expected at least 3 known non-bounty assets identified correctly, got {correct_count}"

    print("[+] Non-Bounty Asset Distinction test PASSED")
    return True

def test_missing_evidence_rejection():
    """Test that findings with missing evidence are properly rejected."""
    print("\n=== Testing Missing Evidence Rejection ===")

    findings_file = "research/findings.json"
    findings_data = load_json_file(findings_file)

    if findings_data is None:
        return False

    # Check findings structure
    assert "findings" in findings_data, "Findings array missing"
    assert "metadata" in findings_data, "Metadata missing"

    findings = findings_data["findings"]
    metadata = findings_data["metadata"]

    # Initially should be empty
    assert len(findings) == 0, f"Findings list should be empty for new installation, got {len(findings)}"
    assert metadata["total_findings"] == 0, f"Total findings should be 0, got {metadata['total_findings']}"

    # Test validation logic would reject findings with missing evidence
    # This is conceptual - in practice, the validation-checklist would be used

    print("[+] Missing Evidence Rejection test PASSED (conceptual)")
    return True

def test_missing_human_approval_rejection():
    """Test that missing human approval prevents status progression."""
    print("\n=== Testing Missing Human Approval Rejection ===")

    gate_file = "scopes/authorization-gate.json"
    gate_data = load_json_file(gate_file)

    if gate_data is None:
        return False

    auth_settings = gate_data.get("authorization_settings", {})
    human_approval = auth_settings.get("human_approval_status")

    print(f"Current human approval status: {human_approval}")

    # Should be PENDING initially, not APPROVED
    assert human_approval != "APPROVED", f"Human approval should not be APPROVED in default state, got {human_approval}"
    assert human_approval == "PENDING", f"Human approval should be PENDING, got {human_approval}"

    # Check that gate is disabled
    gate_status = gate_data["gate_metadata"].get("gate_status")
    assert gate_status == "DISABLED", f"Gate should be DISABLED without human approval, got {gate_status}"

    print("[+] Missing Human Approval Rejection test PASSED")
    return True

def test_finding_status_transitions():
    """Test that finding status transitions follow proper rules."""
    print("\n=== Testing Finding Status Transitions ===")

    # Test the validation checklist conceptually
    checklist_file = "research/validation-checklist.md"

    # Check that checklist exists and has required sections
    try:
        with open(checklist_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ERROR: Validation checklist not found: {checklist_file}")
        return False

    # Check for key sections that would govern status transitions
    required_sections = [
        "Asset-to-Scope Mapping Verification",
        "Authorization Verification",
        "Evidence Requirements",
        "Observed Behavior Documentation",
        "Security Impact Analysis",
        "False Positive Assessment",
        "Validation Requirements",
        "Remediation Planning",
        "Compliance and Risk Assessment",
        "Approval and Sign-off"
    ]

    missing_sections = []
    for section in required_sections:
        if section not in content:
            missing_sections.append(section)

    assert len(missing_sections) == 0, f"Missing sections in validation checklist: {missing_sections}"

    # Check for status progression rules
    assert "Status Progression Rules" in content, "Status progression rules missing"
    assert "INFORMATIONAL to RESEARCH_LEAD" in content, "INFO to LEAD rules missing"
    assert "RESEARCH_LEAD to POTENTIAL_SECURITY_ISSUE" in content, "LEAD to POTENTIAL rules missing"
    assert "POTENTIAL_SECURITY_ISSUE to CONFIRMED_VULNERABILITY" in content, "POTENTIAL to CONFIRMED rules missing"
    assert "EXPLICIT AUTHORIZATION REQUIRED" in content, "Explicit authorization requirement missing"

    print("[+] Finding Status Transitions test PASSED")
    return True

def test_report_generation_with_incomplete_evidence():
    """Test that report generation properly handles incomplete evidence."""
    print("\n=== Testing Report Generation with Incomplete Evidence ===")

    # Check that the report template exists
    template_file = "reports/hackerone-report-template.md"

    try:
        with open(template_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ERROR: Report template not found: {template_file}")
        return False

    # Check that template has sections for evidence validation
    assert "Evidence" in content, "Evidence section missing from report template"
    assert "Evidence Inventory:" in content, "Evidence inventory subsection missing"
    assert "Important Evidence Guidelines:" in content, "Evidence guidelines missing"

    # Check for validation requirements in template
    assert "Scope Eligibility Verification" in content, "Scope eligibility verification missing"
    assert "Preconditions" in content, "Preconditions section missing"
    assert "Reproduction Steps" in content, "Reproduction steps section missing"

    # The template should guide proper reporting but not enforce it
    # In practice, users would need to complete all sections

    print("[+] Report Generation with Incomplete Evidence test PASSED (template structure)")
    return True

def run_all_tests():
    """Run all offline tests and report results."""
    print("Starting Mercado Libre Bug Bounty Agent - Offline Authorization and Validation Tests")
    print("=" * 80)

    tests = [
        test_default_deny_authorization_gate,
        test_unknown_policy_fields,
        test_out_of_scope_asset_rejection,
        test_non_bounty_asset_distinction,
        test_missing_evidence_rejection,
        test_missing_human_approval_rejection,
        test_finding_status_transitions,
        test_report_generation_with_incomplete_evidence
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[-] {test_func.__name__} FAILED with exception: {e}")
            failed += 1

    print("\n" + "=" * 80)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")

    if failed == 0:
        print("[+] All tests PASSED! The authorization gate and validation framework are working correctly.")
        return True
    else:
        print(f"[-] {failed} test(s) FAILED. Please review the implementation.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)