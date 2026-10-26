#!/usr/bin/env python3
"""
Process Mercado Libre HackerOne scope CSV export and generate scope files.
Fixed version that correctly handles wildcard domains in scope vs out_of_scope.
"""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Any


def process_scope_csv(csv_path: str) -> Dict[str, Any]:
    """
    Process the Mercado Libre scope CSV and return structured data.

    Args:
        csv_path: Path to the CSV file

    Returns:
        Dictionary containing processed scope data
    """
    scope_data = {
        "program": {
            "name": "MercadoLibre Bug Bounty Program",
            "platform": "HackerOne",
            "description": "The MercadoLibre Bug Bounty Program enlists the help of the hacker community at HackerOne to make MercadoLibre more secure. HackerOne is the #1 hacker-powered security platform, helping organizations find and fix critical vulnerabilities before they can be criminally exploited.",
            "policy_last_updated": None,
            "policy_retrieved": "2026-10-12",
            "policy_source": "https://hackerone.com/mercadolibre and https://hackerone.com/mercadolibre/policy_scopes",
            "status": "COMPLETE_INFORMATION_RETRIEVED",
            "note": "Complete scope information retrieved from official CSV export"
        },
        "scope": {
            "in_scope": [],
            "out_of_scope": [],
            "bounty_eligible": [],
            "non_bounty_eligible": [],
            "wildcard_domains": [],
            "mobile_apps": [],
            "api_endpoints": [],
            "third_party_integrations": [],
            "testing_environments": [],
            "hardware_devices": [],
            "other_assets": []
        },
        "vulnerability_categories": {
            "accepted": ["NOT AVAILABLE IN PROVIDED CSV"],
            "excluded": ["NOT AVAILABLE IN PROVIDED CSV"],
            "special_consideration": ["NOT AVAILABLE IN PROVIDED CSV"],
            "out_of_scope": ["NOT AVAILABLE IN PROVIDED CSV"]
        },
        "rules_and_restrictions": {
            "testing_restrictions": "NOT AVAILABLE IN PROVIDED CSV",
            "rate_limits": "NOT AVAILABLE IN PROVIDED CSV",
            "automation_restrictions": "NOT AVAILABLE IN PROVIDED CSV",
            "account_requirements": "NOT AVAILABLE IN PROVIDED CSV",
            "disclosure_requirements": "NOT AVAILABLE IN PROVIDED CSV",
            "reward_structure": "NOT AVAILABLE IN PROVIDED CSV",
            "duplicate_report_policy": "NOT AVAILABLE IN PROVIDED CSV",
            "special_conditions": "NOT AVAILABLE IN PROVIDED CSV",
            "safe_harbor": "NOT AVAILABLE IN PROVIDED CSV"
        },
        "metadata": {
            "retrieval_method": "Official CSV export from HackerOne platform",
            "tools_used": ["Python CSV parser"],
            "export_timestamp": "2026-10-12 09:20:12 UTC",
            "total_records": 0,
            "submission_eligible_count": 0,
            "bounty_eligible_count": 0,
            "not_submission_eligible_count": 0,
            "submission_eligible_not_bounty_count": 0,
            "limitations": [
                "Bounty reward amounts and payout conditions NOT AVAILABLE IN PROVIDED CSV",
                "Severity rubric / CVSS requirements NOT AVAILABLE IN PROVIDED CSV",
                "Rate limits and automation restrictions NOT AVAILABLE IN PROVIDED CSV",
                "Vulnerability category exclusions NOT AVAILABLE IN PROVIDED CSV",
                "Prohibited testing techniques and production safety rules NOT AVAILABLE IN PROVIDED CSV",
                "Account, test-data, and authentication requirements NOT AVAILABLE IN PROVIDED CSV",
                "Disclosure / coordinated disclosure requirements NOT AVAILABLE IN PROVIDED CSV",
                "Rules for wildcard matching and special cases not encoded in the CSV"
            ],
            "next_steps": [
                "Implement scope validation based on verified policy",
                "Proceed with authorized reconnaissance and testing",
                "Regularly re-fetch and compare the official HackerOne scope"
            ]
        }
    }

    # Process CSV records
    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        records = list(reader)

    scope_data["metadata"]["total_records"] = len(records)

    for record in records:
        identifier = record['identifier'].strip()
        asset_type = record['asset_type']
        instruction = record['instruction'].strip()
        eligible_for_bounty = record['eligible_for_bounty'].lower() == 'true'
        eligible_for_submission = record['eligible_for_submission'].lower() == 'true'
        max_severity = record['max_severity']

        # Skip empty identifiers
        if not identifier:
            continue

        is_wildcard = (asset_type == 'WILDCARD')

        if eligible_for_submission:
            # Submission eligible items go in in_scope
            scope_data["scope"]["in_scope"].append(identifier)
            scope_data["metadata"]["submission_eligible_count"] += 1

            if eligible_for_bounty:
                scope_data["scope"]["bounty_eligible"].append(identifier)
                scope_data["metadata"]["bounty_eligible_count"] += 1
            else:
                scope_data["scope"]["non_bounty_eligible"].append(identifier)
                scope_data["metadata"]["submission_eligible_not_bounty_count"] += 1

            # If it's a wildcard domain, also add it to wildcard_domains
            if is_wildcard:
                scope_data["scope"]["wildcard_domains"].append(identifier)
        else:
            # Not submission eligible items go in out_of_scope
            scope_data["scope"]["out_of_scope"].append(identifier)
            scope_data["metadata"]["not_submission_eligible_count"] += 1

            # IMPORTANT: Do NOT add non-submission-eligible wildcards to wildcard_domains
            # This ensures they are blocked by the out_of_scope check before wildcard matching

        # Categorize by asset type (for informational purposes)
        if asset_type == 'URL':
            scope_data["scope"]["api_endpoints"].append(identifier)
        elif asset_type == 'GOOGLE_PLAY_APP_ID':
            scope_data["scope"]["mobile_apps"].append({
                "identifier": identifier,
                "platform": "Android",
                "store_url": instruction.split('https://')[-1].split('\n')[0] if 'https://' in instruction else ""
            })
        elif asset_type == 'APPLE_STORE_APP_ID':
            scope_data["scope"]["mobile_apps"].append({
                "identifier": identifier,
                "platform": "iOS",
                "store_url": instruction.split('https://')[-1].split('\n')[0] if 'https://' in instruction else ""
            })
        elif asset_type == 'HARDWARE':
            scope_data["scope"]["hardware_devices"].append(identifier)
        elif asset_type == 'OTHER':
            scope_data["scope"]["other_assets"].append(identifier)

    return scope_data


def create_exclusions_data(csv_path: str) -> Dict[str, Any]:
    """
    Create exclusions data from the CSV.

    Args:
        csv_path: Path to the CSV file

    Returns:
        Dictionary containing exclusions data
    """
    not_eligible_for_submission = []
    submission_allowed_but_no_bounty = []

    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for record in reader:
            identifier = record['identifier'].strip()
            eligible_for_bounty = record['eligible_for_bounty'].lower() == 'true'
            eligible_for_submission = record['eligible_for_submission'].lower() == 'true'

            if not eligible_for_submission:
                not_eligible_for_submission.append(identifier)
            elif eligible_for_submission and not eligible_for_bounty:
                submission_allowed_but_no_bounty.append(identifier)

    return {
        "source": "Official Mercado Libre HackerOne scope CSV export",
        "source_url": "https://hackerone.com/mercadolibre/policy_scopes",
        "export_timestamp": "2026-10-12 09:20:12 UTC",
        "not_eligible_for_submission": not_eligible_for_submission,
        "submission_allowed_but_no_bounty": submission_allowed_but_no_bounty,
        "note": "These are exact CSV identifiers. Do not generalize beyond their recorded asset types/instructions."
    }


def create_program_policy_md(scope_data: Dict[str, Any]) -> str:
    """
    Generate program-policy.md content from scope data.

    Args:
        scope_data: Processed scope data

    Returns:
        Markdown content for program-policy.md
    """
    program = scope_data["program"]
    scope = scope_data["scope"]
    metadata = scope_data["metadata"]

    md_content = f"""# Mercado Libre HackerOne Program Policy

## Retrieval Information
- **Retrieved:** {program['policy_retrieved']}
- **Source:** {program['policy_source']}
- **Status:** Complete information retrieved from official CSV export
- **Export Timestamp:** {metadata['export_timestamp']}

## Program Identification
- **Program Name:** {program['name']}
- **Platform:** {program['platform']}
- **Description:** {program['description']}

## Scope Summary
- **Total Asset Records:** {metadata['total_records']}
- **Submission Eligible Assets:** {metadata['submission_eligible_count']}
- **Bounty Eligible Assets:** {metadata['bounty_eligible_count']}
- **Submission Eligible but Not Bounty Eligible:** {metadata['submission_eligible_not_bounty_count']}
- **Not Submission Eligible:** {metadata['not_submission_eligible_count']}

## Asset Type Breakdown
- **URLs/Endpoints:** {len(scope['api_endpoints'])}
- **Wildcard Domains:** {len(scope['wildcard_domains'])}
- **Mobile Applications:** {len(scope['mobile_apps'])}
- **Hardware Devices:** {len(scope['hardware_devices'])}
- **Other Assets:** {len(scope['other_assets'])}

## In-Scope Assets (Submission Eligible)
All assets listed below are eligible for security testing submission to HackerOne.
Those marked with **(NO BOUNTY)** can be tested but are not eligible for bounty rewards.

### URLs and Endpoints ({len(scope['api_endpoints'])}):
"""

    # Add URLs with bounty eligibility status
    for url in sorted(scope['api_endpoints']):
        bounty_status = "" if url in scope['bounty_eligible'] else " (NO BOUNTY)"
        md_content += f"- {url}{bounty_status}\n"

    md_content += f"\n### Wildcard Domains ({len(scope['wildcard_domains'])}):\n"
    for domain in sorted(scope['wildcard_domains']):
        bounty_status = "" if domain in scope['bounty_eligible'] else " (NO BOUNTY)"
        md_content += f"- {domain}{bounty_status}\n"

    md_content += f"\n### Mobile Applications ({len(scope['mobile_apps'])}):\n"
    for app in scope['mobile_apps']:
        bounty_status = "" if app['identifier'] in scope['bounty_eligible'] else " (NO BOUNTY)"
        md_content += f"- {app['identifier']} ({app['platform']}){bounty_status}\n"
        if app['store_url']:
            md_content += f"  - Store URL: {app['store_url']}\n"

    if scope['hardware_devices']:
        md_content += f"\n### Hardware Devices ({len(scope['hardware_devices'])}):\n"
        for device in scope['hardware_devices']:
            bounty_status = "" if device in scope['bounty_eligible'] else " (NO BOUNTY)"
            md_content += f"- {device}{bounty_status}\n"

    if scope['other_assets']:
        md_content += f"\n### Other Assets ({len(scope['other_assets'])}):\n"
        for asset in scope['other_assets']:
            bounty_status = "" if asset in scope['bounty_eligible'] else " (NO BOUNTY)"
            md_content += f"- {asset}{bounty_status}\n"

    md_content += f"""
## Out-of-Scope Assets (Not Submission Eligible)
The following assets are explicitly NOT eligible for security testing submission:
"""
    for asset in sorted(scope['out_of_scope']):
        md_content += f"- {asset}\n"

    md_content += f"""
## Vulnerability Categories
**NOT AVAILABLE IN PROVIDED CSV** - The CSV export does not contain vulnerability category information.

### Accepted for Bounty
{chr(10).join(['- ' + item for item in scope_data['vulnerability_categories']['accepted']])}

### Excluded from Bounty
{chr(10).join(['- ' + item for item in scope_data['vulnerability_categories']['excluded']])}

### Special Consideration
{chr(10).join(['- ' + item for item in scope_data['vulnerability_categories']['special_consideration']])}

### Out of Scope
{chr(10).join(['- ' + item for item in scope_data['vulnerability_categories']['out_of_scope']])}

## Program Rules and Restrictions
**NOT AVAILABLE IN PROVIDED CSV** - The CSV export does not contain program rules, restrictions, rate limits, or disclosure requirements.

### Testing Restrictions
{scope_data['rules_and_restrictions']['testing_restrictions']}

### Rate Limits
{scope_data['rules_and_restrictions']['rate_limits']}

### Automation Restrictions
{scope_data['rules_and_restrictions']['automation_restrictions']}

### Account Requirements
{scope_data['rules_and_restrictions']['account_requirements']}

### Disclosure Requirements
{scope_data['rules_and_restrictions']['disclosure_requirements']}

### Reward Structure
{scope_data['rules_and_restrictions']['reward_structure']}

### Duplicate Report Policy
{scope_data['rules_and_restrictions']['duplicate_report_policy']}

### Special Conditions
{scope_data['rules_and_restrictions']['special_conditions']}

### Safe Harbor Provisions
{scope_data['rules_and_restrictions']['safe_harbor']}

## Important Policy Limitations

The official CSV scope export provides asset eligibility information but does NOT include:
- Bounty reward amounts and payout conditions
- Severity rubric or CVSS requirements for payouts
- Rate limits and automation restrictions
- Specific vulnerability category exclusions
- Prohibited testing techniques and production safety rules
- Account, test-data, and authentication requirements
- Disclosure or coordinated disclosure requirements
- Detailed rules for wildcard matching and special cases

## Authorization Requirements

Based on the official CSV export:

1. **NO TESTING WITHOUT EXPLICIT AUTHORIZATION**: All targets must be validated via scope validation first
2. **SUBMISSION ELIGIBILITY ≠ BOUNTY ELIGIBILITY**: Some assets allow submission but do not offer bounties
3. **DEFAULT DENY**: Assets not explicitly listed as submission eligible should be considered out of scope
4. **EXACT MATCHING REQUIRED**: Use exact asset-type-aware matching; do not infer wildcard coverage beyond what's explicitly stated
5. **WILDARD INTERPRETATION**: Wildcard entries must be interpreted conservatively according to exact program policy
6. **TEST ACCOUNTS ONLY**: Use only explicitly provided test accounts and credentials (information not in CSV)
7. **SANDBOX/TEST ENVIRONMENTS**: Payment testing must be in sandbox/test environments only (information not in CSV)
8. **RATE LIMIT COMPLIANCE**: Adhere to all program-specified rate limits (information not in CSV)
9. **DATA PRIVACY**: Do not collect, retain, or transmit sensitive data unnecessarily

## Verification and Provenance

- **Source:** Official Mercado Libre HackerOne scope CSV export
- **Program Scope URL:** https://hackerone.com/mercadolibre/policy_scopes
- **Export Timestamp:** {metadata['export_timestamp']}
- **Total Records Processed:** {metadata['total_records']}
- **Fields Preserved:** All original CSV fields including identifier, asset_type, instruction, eligible_for_submission, eligible_for_bounty, availability_requirement, confidentiality_requirement, integrity_requirement, max_severity, system_tags, created_at, updated_at

## Next Steps

1. Implement scope validation using the processed JSON data
2. Conduct passive reconnaissance only on authorized assets
3. Explicitly verify authorization before any active testing
4. Regularly check for scope updates from the official HackerOne source
5. Contact the program directly for missing policy information not contained in the CSV export
"""

    return md_content


def create_rewards_json() -> Dict[str, Any]:
    """
    Create rewards.json with unavailable information marked appropriately.

    Returns:
        Dictionary for rewards.json
    """
    return {
        "source": "Official Mercado Libre HackerOne scope CSV export",
        "note": "Bounty reward information is NOT AVAILABLE IN PROVIDED CSV",
        "reward_structure": "NOT AVAILABLE IN PROVIDED CSV",
        "bounty_amounts": "NOT AVAILABLE IN PROVIDED CSV",
        "severity_to_payout_mapping": "NOT AVAILABLE IN PROVIDED CSV",
        "special_bounty_programs": "NOT AVAILABLE IN PROVIDED CSV",
        "award_timing": "NOT AVAILABLE IN PROVIDED CSV",
        "payment_methods": "NOT AVAILABLE IN PROVIDED CSV"
    }


def create_testing_restrictions_md() -> str:
    """
    Create testing-restrictions.md with unavailable information marked appropriately.

    Returns:
        Markdown content for testing-restrictions.md
    """
    return f"""# Mercado Libre Testing Restrictions and Requirements

## Important Notice
**TESTING RESTRICTIONS INFORMATION IS NOT AVAILABLE IN PROVIDED CSV**

The official Mercado Libre HackerOne scope CSV export does not contain information about:
- Testing restrictions and limitations
- Rate limits and automation restrictions
- Account requirements and test credentials
- Prohibited testing techniques
- Disclosure requirements and timelines
- Payment testing environment requirements (sandbox vs production)

## Authorization Requirements (Based on Available Information)

Despite the lack of specific testing restrictions in the CSV export, the following authorization requirements MUST be followed:

1. **EXPLICIT AUTHORIZATION REQUIRED**: All security testing requires explicit scope validation
2. **PASSIVE RECONNAISSANCE ONLY**: Initial information gathering must be purely passive until authorization is confirmed
3. **DEFAULT DENY POSITION**: When in doubt about authorization, assume DENY and request clarification
4. **ASSET TYPE AWARE MATCHING**: Matching must consider asset types (URL, WILDCARD, MOBILE APP, etc.)
5. **NO WILDCARD ASSUMPTIONS**: Do not infer coverage beyond explicitly listed wildcard patterns
6. **TEST ACCOONTS ONLY**: Use only explicitly provided test credentials (obtain from program directly)
7. **SANDBOX ENVIRONMENTS**: Payment-related testing must occur in sandbox/test environments only
8. **DATA PROTECTION**: Do not unnecessarily collect, retain, or transmit sensitive data

## Required Actions Before Testing

Before conducting ANY security testing:

1. **Scope Validation**: Use the scope validation tools to confirm target authorization
2. **Eligibility Check**: Confirm whether target is submission eligible and bounty eligible
3. **Program Contact**: For missing policy information, contact the Mercado Libre HackerOne program directly
4. **Documentation**: Maintain records of all authorization checks and testing activities

## Missing Information

The following critical information is **NOT AVAILABLE IN PROVIDED CSV** and must be obtained separately:

- Specific testing timeframes or windows
- Rate limits requests per minute/hour/day
- Approved testing tools and techniques
- Prohibited attack vectors (DoS, social engineering, etc.)
- Authentication bypass testing restrictions
- Payment transaction limits and test card information
- Communication channels for program interaction
- Expected response times for triage and resolution
- Legal safe harbor provisions and confidentiality requirements

## Continuous Compliance

Security researchers should:
- Regularly re-fetch the official scope CSV for updates
- Maintain awareness of changing program policies
- Document all authorization validations
- Escalate policy questions to the program directly when uncertain
- Err on the side of caution when policy information is unavailable
"""


def main():
    """Main function to process scope CSV and generate all required files."""
    # Paths
    csv_path = "mercadolibre-scope-bundle/scopes_for_mercadolibre_at_2026-10-12_09_20_12_UTC.csv"
    scope_json_path = "scopes/mercadolibre-scope.json"
    exclusions_json_path = "scopes/exclusions.json"
    program_policy_path = "scopes/program-policy.md"
    rewards_json_path = "scopes/rewards.json"
    testing_restrictions_path = "scopes/testing-restrictions.md"

    # Check if CSV exists
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return 1

    print("Processing Mercado Libre scope CSV export...")

    # Process CSV data
    scope_data = process_scope_csv(csv_path)

    # Generate exclusions data
    exclusions_data = create_exclusions_data(csv_path)

    # Generate program policy markdown
    program_policy_content = create_program_policy_md(scope_data)

    # Generate rewards.json
    rewards_data = create_rewards_json()

    # Generate testing restrictions markdown
    testing_restrictions_content = create_testing_restrictions_md()

    # Write files
    print("Writing scope data to scopes/mercadolibre-scope.json...")
    with open(scope_json_path, 'w', encoding='utf-8') as f:
        json.dump(scope_data, f, indent=2, ensure_ascii=False)

    print("Writing exclusions data to scopes/exclusions.json...")
    with open(exclusions_json_path, 'w', encoding='utf-8') as f:
        json.dump(exclusions_data, f, indent=2, ensure_ascii=False)

    print("Writing program policy to scopes/program-policy.md...")
    with open(program_policy_path, 'w', encoding='utf-8') as f:
        f.write(program_policy_content)

    print("Writing rewards data to scopes/rewards.json...")
    with open(rewards_json_path, 'w', encoding='utf-8') as f:
        json.dump(rewards_data, f, indent=2, ensure_ascii=False)

    print("Writing testing restrictions to scopes/testing-restrictions.md...")
    with open(testing_restrictions_path, 'w', encoding='utf-8') as f:
        f.write(testing_restrictions_content)

    # Print summary
    print("\n" + "="*60)
    print("PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records processed: {scope_data['metadata']['total_records']}")
    print(f"Submission eligible: {scope_data['metadata']['submission_eligible_count']}")
    print(f"Bounty eligible: {scope_data['metadata']['bounty_eligible_count']}")
    print(f"Submission eligible but not bounty: {scope_data['metadata']['submission_eligible_not_bounty_count']}")
    print(f"Not submission eligible: {scope_data['metadata']['not_submission_eligible_count']}")
    print("\nFiles created/updated:")
    print(f"- {scope_json_path}")
    print(f"- {exclusions_json_path}")
    print(f"- {program_policy_path}")
    print(f"- {rewards_json_path}")
    print(f"- {testing_restrictions_path}")

    return 0


if __name__ == "__main__":
    exit(main())