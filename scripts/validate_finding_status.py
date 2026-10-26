#!/usr/bin/env python3
"""
Finding Status Transition Validator for Mercado Libre Bug Bounty Research Agent
Validates whether a finding can transition to a new status based on authorization gate state.
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from authorization_gate import AuthorizationGate


class FindingStatusValidator:
    """Validates finding status transitions based on authorization gate state."""

    def __init__(self, gate_file: str = "scopes/authorization-gate.json"):
        """
        Initialize the validator with authorization gate.

        Args:
            gate_file: Path to the authorization gate JSON file
        """
        self.auth_gate = AuthorizationGate(gate_file)

    def validate_status_transition(self,
                                 current_status: str,
                                 new_status: str,
                                 asset: str,
                                 activity: str,
                                 technique: str,
                                 environment: str = "request") -> Tuple[bool, str]:
        """
        Validate if a finding can transition from current_status to new_status.

        Args:
            current_status: Current status of the finding
            new_status: Desired new status for the finding
            asset: Asset/hostname the finding relates to
            activity: Activity type (e.g., API_SECURITY_ASSESSMENT)
            technique: Technique/method being used (e.g., GET, POST)
            environment: Environment (default: "request")

        Returns:
            Tuple of (is_valid, reason)
        """
        # Define status transition rules based on validation-checklist.md
        transition_rules = {
            # From INFORMATIONAL to RESEARCH_LEAD:
            # - Asset-to-scope mapping verified
            # - Basic observational evidence collected
            # - No authorization required beyond passive reconnaissance
            ("INFORMATIONAL", "RESEARCH_LEAD"): {
                "requires_external_auth": False,
                "requires_human_approval": False,
                "description": "Basic observational evidence collection"
            },

            # From RESEARCH_LEAD to POTENTIAL_SECURITY_ISSUE:
            # - All items in sections 1-6 completed
            # - Authorization-gate human approval status: "APPROVED" for research progression
            # - No active testing performed
            # - Evidence supports security impact hypothesis (not proof)
            # - False positive assessment completed
            ("RESEARCH_LEAD", "POTENTIAL_SECURITY_ISSUE"): {
                "requires_external_auth": False,
                "requires_human_approval": True,
                "description": "Research progression requiring human approval"
            },

            # From POTENTIAL_SECURITY_ISSUE to CONFIRMED_VULNERABILITY:
            # - EXPLICIT AUTHORIZATION REQUIRED from Mercado Libre program
            # - All items in sections 1-8 completed
            # - Active testing performed within authorized boundaries
            # - Reproducible evidence obtained
            # - Security impact verified
            # - False positives ruled out through testing
            # - Human approval obtained for specific validation activity
            # - Rate limits and restrictions complied with during testing
            ("POTENTIAL_SECURITY_ISSUE", "CONFIRMED_VULNERABILITY"): {
                "requires_external_auth": True,
                "requires_human_approval": True,
                "description": "Confirmed vulnerability requiring explicit program authorization"
            }
        }

        # Add same-status transitions (no change)
        for s in ["INFORMATIONAL", "RESEARCH_LEAD", "POTENTIAL_SECURITY_ISSUE",
                  "CONFIRMED_VULNERABILITY", "OUT_OF_SCOPE", "REJECTED"]:
            transition_rules[(s, s)] = {
                "requires_external_auth": False,
                "requires_human_approval": False,
                "description": "No status change"
            }

        # Check if this transition is defined in our rules
        rule_key = (current_status, new_status)
        if rule_key not in transition_rules:
            return False, f"Undefined status transition: {current_status} -> {new_status}"

        rule = transition_rules[rule_key]

        # Check external authorization requirement
        if rule["requires_external_auth"]:
            if not self.auth_gate._external_authorization:
                return False, "External program authorization required for this status transition"

            # Validate that the external authorization matches the request
            auth_request = type('AuthRequest', (), {
                'asset': asset,
                'activity': activity,
                'technique': technique,
                'environment': environment
            })()

            auth_errors = self.auth_gate._validate_external_authorization(auth_request)
            if auth_errors:
                return False, f"External authorization mismatch: {'; '.join(auth_errors)}"

        # Check human approval requirement
        if rule["requires_human_approval"]:
            if not self.auth_gate._human_approval:
                return False, "Human approval required for this status transition"

            # Validate that the human approval matches the request
            auth_request = type('AuthRequest', (), {
                'asset': asset,
                'activity': activity,
                'technique': technique,
                'environment': environment
            })()

            approval_errors = self.auth_gate._validate_human_approval(auth_request)
            if approval_errors:
                return False, f"Human approval mismatch: {'; '.join(approval_errors)}"

        # All checks passed
        return True, rule["description"]

    def get_gate_status_for_validation(self) -> Dict:
        """
        Get authorization gate status formatted for finding validation.

        Returns:
            Dictionary with gate status information relevant to finding validation
        """
        gate_status = self.auth_gate.get_gate_status()

        return {
            "gate_status": gate_status["gate_status"],
            "external_authorization_loaded": gate_status["external_authorization_loaded"],
            "human_approval_loaded": gate_status["human_approval_loaded"],
            "production_testing_enabled": gate_status["production_testing_enabled"],
            "human_approval_status": gate_status["human_approval_status"],
            "explicit_authorization_required": gate_status["explicit_authorization_required"],
            "can_proceed_to_research_lead": True,  # No authorization needed
            "can_proceed_to_potential_security_issue": gate_status["human_approval_loaded"],
            "can_proceed_to_confirmed_vulnerability": (
                gate_status["external_authorization_loaded"] and
                gate_status["human_approval_loaded"]
            )
        }


def validate_findings_file(findings_file: str = "research/findings.json") -> Dict:
    """
    Validate all findings in a findings.json file against current authorization gate.

    Args:
        findings_file: Path to the findings JSON file

    Returns:
        Validation results for all findings
    """
    try:
        with open(findings_file, 'r') as f:
            findings_data = json.load(f)
    except FileNotFoundError:
        return {
            "error": f"Findings file not found: {findings_file}",
            "valid": False
        }
    except json.JSONDecodeError as e:
        return {
            "error": f"Invalid JSON in findings file: {e}",
            "valid": False
        }

    validator = FindingStatusValidator()
    gate_status = validator.get_gate_status_for_validation()

    # Validate each finding's status against authorization
    findings = findings_data.get("findings", [])
    validation_results = {
        "total_findings": len(findings),
        "valid_findings": 0,
        "invalid_findings": 0,
        "findings": [],
        "gate_status": gate_status,
        "overall_valid": True
    }

    for i, finding in enumerate(findings):
        # For now, we'll just check if the finding's current status is valid
        # In a full implementation, we would check status transition history
        current_status = finding.get("status", "UNKNOWN")
        asset = finding.get("asset", "unknown")

        # Basic validation: check if current status is allowed given current authorizations
        is_valid = True
        reason = "Status validation passed"

        # If finding claims to be beyond RESEARCH_LEAD, check authorization
        if current_status in ["POTENTIAL_SECURITY_ISSUE", "CONFIRMED_VULNERABILITY"]:
            if current_status == "POTENTIAL_SECURITY_ISSUE" and not gate_status["human_approval_loaded"]:
                is_valid = False
                reason = "POTENTIAL_SECURITY_ISSUE status requires human approval"
            elif current_status == "CONFIRMED_VULNERABILITY":
                if not (gate_status["external_authorization_loaded"] and gate_status["human_approval_loaded"]):
                    is_valid = False
                    reason = "CONFIRMED_VULNERABILITY status requires both external authorization and human approval"

        if is_valid:
            validation_results["valid_findings"] += 1
        else:
            validation_results["invalid_findings"] += 1
            validation_results["overall_valid"] = False

        validation_results["findings"].append({
            "index": i,
            "id": finding.get("id", f"finding_{i}"),
            "status": current_status,
            "asset": asset,
            "valid": is_valid,
            "reason": reason
        })

    return validation_results


def main():
    """Main function to run the finding status validator."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate finding status transitions based on authorization gate state"
    )
    parser.add_argument(
        "--findings-file",
        default="research/findings.json",
        help="Path to findings JSON file (default: research/findings.json)"
    )
    parser.add_argument(
        "--validate-transition",
        nargs=5,
        metavar=("CURRENT_STATUS", "NEW_STATUS", "ASSET", "ACTIVITY", "TECHNIQUE"),
        help="Validate a specific status transition"
    )
    parser.add_argument(
        "--environment",
        default="request",
        help="Environment for validation (default: request)"
    )
    parser.add_argument(
        "--gate-status",
        action="store_true",
        help="Show current authorization gate status for validation"
    )

    args = parser.parse_args()

    if args.gate_status:
        validator = FindingStatusValidator()
        status = validator.get_gate_status_for_validation()
        print("Authorization Gate Status for Finding Validation:")
        for key, value in status.items():
            print(f"  {key}: {value}")
        return

    if args.validate_transition:
        current_status, new_status, asset, activity, technique = args.validate_transition
        validator = FindingStatusValidator()
        is_valid, reason = validator.validate_status_transition(
            current_status, new_status, asset, activity, technique, args.environment
        )

        print(f"Status Transition Validation: {current_status} -> {new_status}")
        print(f"Asset: {asset}")
        print(f"Activity: {activity}")
        print(f"Technique: {technique}")
        print(f"Environment: {args.environment}")
        print(f"Valid: {is_valid}")
        print(f"Reason: {reason}")

        if not is_valid:
            sys.exit(1)
        return

    # Default: validate findings file
    results = validate_findings_file(args.findings_file)

    if "error" in results:
        print(f"ERROR: {results['error']}")
        sys.exit(1)

    print("=" * 60)
    print("FINDING STATUS VALIDATION REPORT")
    print("=" * 60)
    print(f"Total findings: {results['total_findings']}")
    print(f"Valid findings: {results['valid_findings']}")
    print(f"Invalid findings: {results['invalid_findings']}")
    print(f"Overall valid: {results['overall_valid']}")
    print()
    print("Gate Status:")
    gate_status = results['gate_status']
    for key, value in gate_status.items():
        print(f"  {key}: {value}")
    print()

    if results['invalid_findings'] > 0:
        print("Invalid Findings:")
        for finding in results['findings']:
            if not finding['valid']:
                print(f"  [{finding['index']}] {finding['id']} ({finding['status']}) - {finding['reason']}")
        print()
        print("VALIDATION FAILED: Some findings do not meet authorization requirements")
        sys.exit(1)
    else:
        print("VALIDATION PASSED: All findings meet authorization requirements")


if __name__ == "__main__":
    main()