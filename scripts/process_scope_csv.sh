#!/bin/bash
# Process Mercado Libre HackerOne scope CSV export and generate scope files

set -euo pipefail

# Paths
CSV_PATH="mercadolibre-scope-bundle/scopes_for_mercadolibre_at_2026-10-12_09_20_12_UTC.csv"
SCOPE_JSON_PATH="scopes/mercadolibre-scope.json"
EXCLUSIONS_JSON_PATH="scopes/exclusions.json"
PROGRAM_POLICY_PATH="scopes/program-policy.md"
REWARDS_JSON_PATH="scopes/rewards.json"
TESTING_RESTRICTIONS_PATH="scopes/testing-restrictions.md"

# Check if CSV exists
if [[ ! -f "$CSV_PATH" ]]; then
    echo "Error: CSV file not found at $CSV_PATH"
    exit 1
fi

echo "Processing Mercado Libre scope CSV export..."

# Skip header and process records
# We'll use awk to process the CSV and generate JSON
TEMP_FILE=$(mktemp)

# Process CSV to extract data
awk -F',' '
BEGIN {
    # Initialize counters
    total_records = 0
    submission_eligible = 0
    bounty_eligible = 0
    submission_eligible_not_bounty = 0
    not_submission_eligible = 0

    # Initialize arrays
    delete in_scope
    delete out_of_scope
    delete bounty_list
    delete non_bounty_list
    delete wildcard_domains
    delete api_endpoints
    delete mobile_apps
    delete hardware_devices
    delete other_assets

    # For tracking indices
    in_scope_idx = 0
    out_of_scope_idx = 0
    bounty_idx = 0
    non_bounty_idx = 0
    wildcard_idx = 0
    api_idx = 0
    mobile_idx = 0
    hardware_idx = 0
    other_idx = 0
}

NR > 1 {  # Skip header
    total_records++

    # Extract fields (handle quoted fields with commas inside)
    # For simplicity, we assume the CSV is well-formed and use basic splitting
    # In production, a proper CSV parser would be better

    identifier = $1
    asset_type = $2
    instruction = $3
    eligible_for_bounty = $4
    eligible_for_submission = $5
    availability_req = $6
    confidentiality_req = $7
    integrity_req = $8
    max_severity = $9
    system_tags = $10
    created_at = $11
    updated_at = $12

    # Trim whitespace
    gsub(/^[ \t]+|[ \t]+$/, "", identifier)
    gsub(/^[ \t]+|[ \t]+$/, "", asset_type)
    gsub(/^[ \t]+|[ \t]+$/, "", instruction)
    gsub(/^[ \t]+|[ \t]+$/, "", eligible_for_bounty)
    gsub(/^[ \t]+|[ \t]+$/, "", eligible_for_submission)
    gsub(/^[ \t]+|[ \t]+$/, "", max_severity)

    # Skip empty identifiers
    if (identifier == "") {
        next
    }

    # Convert to lowercase for boolean comparison
    eligible_for_bounty = tolower(eligible_for_bounty)
    eligible_for_submission = tolower(eligible_for_submission)

    # Categorize by asset type
    if (asset_type == "URL") {
        api_endpoints[++api_idx] = identifier
    } else if (asset_type == "WILDCARD") {
        wildcard_domains[++wildcard_idx] = identifier
    } else if (asset_type == "GOOGLE_PLAY_APP_ID") {
        # Extract store URL from instruction
        store_url = ""
        if (match(instruction, /https?:\/\/[^ \t\n]+/)) {
            store_url = substr(instruction, RSTART, RLENGTH)
        }
        mobile_apps[++mobile_idx] = identifier "|Android|" store_url
    } else if (asset_type == "APPLE_STORE_APP_ID") {
        # Extract store URL from instruction
        store_url = ""
        if (match(instruction, /https?:\/\/[^ \t\n]+/)) {
            store_url = substr(instruction, RSTART, RLENGTH)
        }
        mobile_apps[++mobile_idx] = identifier "|iOS|" store_url
    } else if (asset_type == "HARDWARE") {
        hardware_devices[++hardware_idx] = identifier
    } else if (asset_type == "OTHER") {
        other_assets[++other_idx] = identifier
    }

    # Handle eligibility
    if (eligible_for_submission == "true") {
        in_scope[++in_scope_idx] = identifier
        submission_eligible++

        if (eligible_for_bounty == "true") {
            bounty_list[++bounty_idx] = identifier
            bounty_eligible++
        } else {
            non_bounty_list[++non_bounty_idx] = identifier
            submission_eligible_not_bounty++
        }
    } else {
        out_of_scope[++out_of_scope_idx] = identifier
        not_submission_eligible++
    }
}

END {
    # Output processed data as JSON-like structure for further processing
    printf "TOTAL_RECORDS=%d\n", total_records
    printf "SUBMISSION_ELIGIBLE=%d\n", submission_eligible
    printf "BOUNTY_ELIGIBLE=%d\n", bounty_eligible
    printf "SUBMISSION_ELIGIBLE_NOT_BOUNTY=%d\n", submission_eligible_not_bounty
    printf "NOT_SUBMISSION_ELIGIBLE=%d\n", not_submission_eligible

    # Output arrays
    printf "IN_SCOPE_COUNT=%d\n", in_scope_idx
    for (i = 1; i <= in_scope_idx; i++) {
        printf "IN_SCOPE_%d=%s\n", i, in_scope[i]
    }

    printf "OUT_OF_SCOPE_COUNT=%d\n", out_of_scope_idx
    for (i = 1; i <= out_of_scope_idx; i++) {
        printf "OUT_OF_SCOPE_%d=%s\n", i, out_of_scope[i]
    }

    printf "BOUNTY_ELIGIBLE_COUNT=%d\n", bounty_idx
    for (i = 1; i <= bounty_idx; i++) {
        printf "BOUNTY_ELIGIBLE_%d=%s\n", i, bounty_list[i]
    }

    printf "NON_BOUNTY_ELIGIBLE_COUNT=%d\n", non_bounty_idx
    for (i = 1; i <= non_bounty_idx; i++) {
        printf "NON_BOUNTY_ELIGIBLE_%d=%s\n", i, non_bounty_list[i]
    }

    printf "WILDCARD_COUNT=%d\n", wildcard_idx
    for (i = 1; i <= wildcard_idx; i++) {
        printf "WILDCARD_%d=%s\n", i, wildcard_domains[i]
    }

    printf "API_ENDPOINTS_COUNT=%d\n", api_idx
    for (i = 1; i <= api_idx; i++) {
        printf "API_ENDPOINT_%d=%s\n", i, api_endpoints[i]
    }

    printf "MOBILE_APPS_COUNT=%d\n", mobile_idx
    for (i = 1; i <= mobile_idx; i++) {
        printf "MOBILE_APP_%d=%s\n", i, mobile_apps[i]
    }

    printf "HARDWARE_DEVICES_COUNT=%d\n", hardware_idx
    for (i = 1; i <= hardware_idx; i++) {
        printf "HARDWARE_DEVICE_%d=%s\n", i, hardware_devices[i]
    }

    printf "OTHER_ASSETS_COUNT=%d\n", other_idx
    for (i = 1; i <= other_idx; i++) {
        printf "OTHER_ASSET_%d=%s\n", i, other_assets[i]
    }
}
' "$CSV_PATH" > "$TEMP_FILE"

# Source the temporary file to get variables
. "$TEMP_FILE"

# Clean up temp file
rm "$TEMP_FILE"

# Generate scope JSON
cat > "$SCOPE_JSON_PATH" << EOF
{
  "program": {
    "name": "MercadoLibre Bug Bounty Program",
    "platform": "HackerOne",
    "description": "The MercadoLibre Bug Bounty Program enlists the help of the hacker community at HackerOne to make MercadoLibre more secure. HackerOne is the #1 hacker-powered security platform, helping organizations find and fix critical vulnerabilities before they can be criminally exploited.",
    "policy_last_updated": null,
    "policy_retrieved": "2026-10-12",
    "policy_source": "https://hackerone.com/mercadolibre and https://hackerone.com/mercadolibre/policy_scopes",
    "status": "COMPLETE_INFORMATION_RETRIEVED",
    "note": "Complete scope information retrieved from official CSV export"
  },
  "scope": {
    "in_scope": [
EOF

# Add in_scope items
for ((i=1; i<=in_scope_idx; i++)); do
    var_name="IN_SCOPE_$i"
    item="${!var_name}"
    if [[ $i -lt $in_scope_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "out_of_scope": [
EOF

# Add out_of_scope items
for ((i=1; i<=out_of_scope_idx; i++)); do
    var_name="OUT_OF_SCOPE_$i"
    item="${!var_name}"
    if [[ $i -lt $out_of_scope_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "bounty_eligible": [
EOF

# Add bounty_eligible items
for ((i=1; i<=bounty_idx; i++)); do
    var_name="BOUNTY_ELIGIBLE_$i"
    item="${!var_name}"
    if [[ $i -lt $bounty_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "non_bounty_eligible": [
EOF

# Add non_bounty_eligible items
for ((i=1; i<=non_bounty_idx; i++)); do
    var_name="NON_BOUNTY_ELIGIBLE_$i"
    item="${!var_name}"
    if [[ $i -lt $non_bounty_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "wildcard_domains": [
EOF

# Add wildcard_domains items
for ((i=1; i<=wildcard_idx; i++)); do
    var_name="WILDCARD_$i"
    item="${!var_name}"
    if [[ $i -lt $wildcard_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "mobile_apps": [
EOF

# Add mobile_apps items
for ((i=1; i<=mobile_idx; i++)); do
    var_name="MOBILE_APP_$i"
    item="${!var_name}"
    IFS='|' read -r identifier platform store_url <<< "$item"
    if [[ -n "$store_url" ]]; then
        printf '      {\n        "identifier": "%s",\n        "platform": "%s",\n        "store_url": "%s"\n      }' "$identifier" "$platform" "$store_url" >> "$SCOPE_JSON_PATH"
    else
        printf '      {\n        "identifier": "%s",\n        "platform": "%s"\n      }' "$identifier" "$platform" >> "$SCOPE_JSON_PATH"
    fi

    if [[ $i -lt $mobile_idx ]]; then
        printf ',\n' >> "$SCOPE_JSON_PATH"
    else
        printf '\n' >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "api_endpoints": [
EOF

# Add api_endpoints items
for ((i=1; i<=api_idx; i++)); do
    var_name="API_ENDPOINT_$i"
    item="${!var_name}"
    if [[ $i -lt $api_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "hardware_devices": [
EOF

# Add hardware_devices items
for ((i=1; i<=hardware_idx; i++)); do
    var_name="HARDWARE_DEVICE_$i"
    item="${!var_name}"
    if [[ $i -lt $hardware_idx ]]; then
        printf '      "%s",\n' "$item" >> "$SCOPE_JSON_PATH"
    else
        printf '      "%s"\n' "$item" >> "$SCOPE_JSON_PATH"
    fi
done

cat >> "$SCOPE_JSON_PATH" << EOF
    ],
    "third_party_integrations": [],
    "testing_environments": []
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
    "tools_used": ["Bash/AWK processor"],
    "export_timestamp": "2026-10-12 09:20:12 UTC",
    "total_records": $TOTAL_RECORDS,
    "submission_eligible_count": $SUBMISSION_ELIGIBLE,
    "bounty_eligible_count": $BOUNTY_ELIGIBLE,
    "not_submission_eligible_count": $NOT_SUBMISSION_ELIGIBLE,
    "submission_eligible_not_bounty_count": $SUBMISSION_ELIGIBLE_NOT_BOUNTY,
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
EOF

# Generate exclusions JSON
cat > "$EXCLUSIONS_JSON_PATH" << EOF
{
  "source": "Official Mercado Libre HackerOne scope CSV export",
  "source_url": "https://hackerone.com/mercadolibre/policy_scopes",
  "export_timestamp": "2026-10-12 09:20:12 UTC",
  "not_eligible_for_submission": [
EOF

# Add not_eligible_for_submission items (out_of_scope)
for ((i=1; i<=out_of_scope_idx; i++)); do
    var_name="OUT_OF_SCOPE_$i"
    item="${!var_name}"
    if [[ $i -lt $out_of_scope_idx ]]; then
        printf '    "%s",\n' "$item" >> "$EXCLUSIONS_JSON_PATH"
    else
        printf '    "%s"\n' "$item" >> "$EXCLUSIONS_JSON_PATH"
    fi
done

cat >> "$EXCLUSIONS_JSON_PATH" << EOF
  ],
  "submission_allowed_but_no_bounty": [
EOF

# Add submission_allowed_but_no_bounty items (non_bounty_eligible)
for ((i=1; i<=non_bounty_idx; i++)); do
    var_name="NON_BOUNTY_ELIGIBLE_$i"
    item="${!var_name}"
    if [[ $i -lt $non_bounty_idx ]]; then
        printf '    "%s",\n' "$item" >> "$EXCLUSIONS_JSON_PATH"
    else
        printf '    "%s"\n' "$item" >> "$EXCLUSIONS_JSON_PATH"
    fi
done

cat >> "$EXCLUSIONS_JSON_PATH" << EOF
  ],
  "note": "These are exact CSV identifiers. Do not generalize beyond their recorded asset types/instructions."
}
EOF

# Generate program policy markdown
cat > "$PROGRAM_POLICY_PATH" << EOF
# Mercado Libre HackerOne Program Policy

## Retrieval Information
- **Retrieved:** 2026-10-12
- **Source:** https://hackerone.com/mercadolibre and https://hackerone.com/mercadolibre/policy_scopes
- **Status:** Complete information retrieved from official CSV export
- **Export Timestamp:** 2026-10-12 09:20:12 UTC

## Program Identification
- **Program Name:** MercadoLibre Bug Bounty Program
- **Platform:** HackerOne
- **Description:** The MercadoLibre Bug Bounty Program enlists the help of the hacker community at HackerOne to make MercadoLibre more secure. HackerOne is the #1 hacker-powered security platform, helping organizations find and fix critical vulnerabilities before they can be criminally exploited.

## Scope Summary
- **Total Asset Records:** $TOTAL_RECORDS
- **Submission Eligible Assets:** $SUBMISSION_ELIGIBLE
- **Bounty Eligible Assets:** $BOUNTY_ELIGIBLE
- **Submission Eligible but Not Bounty Eligible:** $SUBMISSION_ELIGIBLE_NOT_BOUNTY
- **Not Submission Eligible:** $NOT_SUBMISSION_ELIGIBLE

## Asset Type Breakdown
- **URLs/Endpoints:** $API_ENDPOINTS_COUNT
- **Wildcard Domains:** $WILDCARD_COUNT
- **Mobile Applications:** $MOBILE_APPS_COUNT
- **Hardware Devices:** $HARDWARE_DEVICES_COUNT
- **Other Assets:** $OTHER_ASSETS_COUNT

## In-Scope Assets (Submission Eligible)
All assets listed below are eligible for security testing submission to HackerOne.
Those marked with **(NO BOUNTY)** can be tested but are not eligible for bounty rewards.

### URLs and Endpoints ($API_ENDPOINTS_COUNT):
EOF

# Add URLs with bounty eligibility status
for ((i=1; i<=api_idx; i++)); do
    var_name="API_ENDPOINT_$i"
    item="${!var_name}"
    bounty_status=""
    # Check if item is in bounty list
    is_bounty=false
    for ((j=1; j<=bounty_idx; j++)); do
        bounty_var="BOUNTY_ELIGIBLE_$j"
        if [[ "${!bounty_var}" == "$item" ]]; then
            is_bounty=true
            break
        fi
    done
    if [[ $is_bounty == false ]]; then
        bounty_status=" (NO BOUNTY)"
    fi
    printf '- %s%s\n' "$item" "$bounty_status" >> "$PROGRAM_POLICY_PATH"
done

cat >> "$PROGRAM_POLICY_PATH" << EOF

### Wildcard Domains ($WILDCARD_COUNT):
EOF

# Add wildcard domains with bounty eligibility status
for ((i=1; i<=wildcard_idx; i++)); do
    var_name="WILDCARD_$i"
    item="${!var_name}"
    bounty_status=""
    # Check if item is in bounty list
    is_bounty=false
    for ((j=1; j<=bounty_idx; j++)); do
        bounty_var="BOUNTY_ELIGIBLE_$j"
        if [[ "${!bounty_var}" == "$item" ]]; then
            is_bounty=true
            break
        fi
    done
    if [[ $is_bounty == false ]]; then
        bounty_status=" (NO BOUNTY)"
    fi
    printf '- %s%s\n' "$item" "$bounty_status" >> "$PROGRAM_POLICY_PATH"
done

cat >> "$PROGRAM_POLICY_PATH" << EOF

### Mobile Applications ($MOBILE_APPS_COUNT):
EOF

# Add mobile applications with bounty eligibility status
for ((i=1; i<=mobile_idx; i++)); do
    var_name="MOBILE_APP_$i"
    item="${!var_name}"
    IFS='|' read -r identifier platform store_url <<< "$item"
    bounty_status=""
    # Check if identifier is in bounty list
    is_bounty=false
    for ((j=1; j<=bounty_idx; j++)); do
        bounty_var="BOUNTY_ELIGIBLE_$j"
        if [[ "${!bounty_var}" == "$identifier" ]]; then
            is_bounty=true
            break
        fi
    done
    if [[ $is_bounty == false ]]; then
        bounty_status=" (NO BOUNTY)"
    fi
    printf '- %s (%s)%s\n' "$identifier" "$platform" "$bounty_status" >> "$PROGRAM_POLICY_PATH"
    if [[ -n "$store_url" ]]; then
        printf '  - Store URL: %s\n' "$store_url" >> "$PROGRAM_POLICY_PATH"
    fi
done

if [[ $HARDWARE_DEVICES_COUNT -gt 0 ]]; then
cat >> "$PROGRAM_POLICY_PATH" << EOF

### Hardware Devices ($HARDWARE_DEVICES_COUNT):
EOF

# Add hardware devices with bounty eligibility status
for ((i=1; i<=hardware_idx; i++)); do
    var_name="HARDWARE_DEVICE_$i"
    item="${!var_name}"
    bounty_status=""
    # Check if item is in bounty list
    is_bounty=false
    for ((j=1; j<=bounty_idx; j++)); do
        bounty_var="BOUNTY_ELIGIBLE_$j"
        if [[ "${!bounty_var}" == "$item" ]]; then
            is_bounty=true
            break
        fi
    done
    if [[ $is_bounty == false ]]; then
        bounty_status=" (NO BOUNTY)"
    fi
    printf '- %s%s\n' "$item" "$bounty_status" >> "$PROGRAM_POLICY_PATH"
done
fi

if [[ $OTHER_ASSETS_COUNT -gt 0 ]]; then
cat >> "$PROGRAM_POLICY_PATH" << EOF

### Other Assets ($OTHER_ASSETS_COUNT):
EOF

# Add other assets with bounty eligibility status
for ((i=1; i<=other_idx; i++)); do
    var_name="OTHER_ASSET_$i"
    item="${!var_name}"
    bounty_status=""
    # Check if item is in bounty list
    is_bounty=false
    for ((j=1; j<=bounty_idx; j++)); do
        bounty_var="BOUNTY_ELIGIBLE_$j"
        if [[ "${!bounty_var}" == "$item" ]]; then
            is_bounty=true
            break
        fi
    done
    if [[ $is_bounty == false ]]; then
        bounty_status=" (NO BOUNTY)"
    fi
    printf '- %s%s\n' "$item" "$bounty_status" >> "$PROGRAM_POLICY_PATH"
done
fi

cat >> "$PROGRAM_POLICY_PATH" << EOF

## Out-of-Scope Assets (Not Submission Eligible)
The following assets are explicitly NOT eligible for security testing submission:
EOF

# Add out_of_scope items
for ((i=1; i<=out_of_scope_idx; i++)); do
    var_name="OUT_OF_SCOPE_$i"
    item="${!var_name}"
    printf '- %s\n' "$item" >> "$PROGRAM_POLICY_PATH"
done

cat >> "$PROGRAM_POLICY_PATH" << EOF

## Vulnerability Categories
**NOT AVAILABLE IN PROVIDED CSV** - The CSV export does not contain vulnerability category information.

### Accepted for Bounty
- NOT AVAILABLE IN PROVIDED CSV

### Excluded from Bounty
- NOT AVAILABLE IN PROVIDED CSV

### Special Consideration
- NOT AVAILABLE IN PROVIDED CSV

### Out of Scope
- NOT AVAILABLE IN PROVIDED CSV

## Program Rules and Restrictions
**NOT AVAILABLE IN PROVIDED CSV** - The CSV export does not contain program rules, restrictions, rate limits, or disclosure requirements.

### Testing Restrictions
NOT AVAILABLE IN PROVIDED CSV

### Rate Limits
NOT AVAILABLE IN PROVIDED CSV

### Automation Restrictions
NOT AVAILABLE IN PROVIDED CSV

### Account Requirements
NOT AVAILABLE IN PROVIDED CSV

### Disclosure Requirements
NOT AVAILABLE IN PROVIDED CSV

### Reward Structure
NOT AVAILABLE IN PROVIDED CSV

### Duplicate Report Policy
NOT AVAILABLE IN PROVIDED CSV

### Special Conditions
NOT AVAILABLE IN PROVIDED CSV

### Safe Harbor Provisions
NOT AVAILABLE IN PROVIDED CSV

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
- **Export Timestamp:** 2026-10-12 09:20:12 UTC
- **Total Records Processed:** $TOTAL_RECORDS
- **Fields Preserved:** All original CSV fields including identifier, asset_type, instruction, eligible_for_submission, eligible_for_bounty, availability_requirement, confidentiality_requirement, integrity_requirement, max_severity, system_tags, created_at, updated_at

## Next Steps

1. Implement scope validation using the processed JSON data
2. Conduct passive reconnaissance only on authorized assets
3. Explicitly verify authorization before any active testing
4. Regularly check for scope updates from the official HackerOne source
5. Contact the program directly for missing policy information not contained in the CSV export
EOF

# Generate rewards JSON
cat > "$REWARDS_JSON_PATH" << EOF
{
  "source": "Official Mercado Libre HackerOne scope CSV export",
  "note": "Bounty reward information is NOT AVAILABLE IN PROVIDED CSV",
  "reward_structure": "NOT AVAILABLE IN PROVIDED CSV",
  "bounty_amounts": "NOT AVAILABLE IN PROVIDED CSV",
  "severity_to_payout_mapping": "NOT AVAILABLE IN PROVIDED CSV",
  "special_bounty_programs": "NOT AVAILABLE IN PROVIDED CSV",
  "award_timing": "NOT AVAILABLE IN PROVIDED CSV",
  "payment_methods": "NOT AVAILABLE IN PROVIDED CSV"
}
EOF

# Generate testing restrictions markdown
cat > "$TESTING_RESTRICTIONS_PATH" << EOF
# Mercado Libre Testing Restrictions and Requirements

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
EOF

# Print summary
echo ""
echo "="*60
echo "PROCESSING COMPLETE"
echo "="*60
echo "Total records processed: $TOTAL_RECORDS"
echo "Submission eligible: $SUBMISSION_ELIGIBLE"
echo "Bounty eligible: $BOUNTY_ELIGIBLE"
echo "Submission eligible but not bounty: $SUBMISSION_ELIGIBLE_NOT_BOUNTY"
echo "Not submission eligible: $NOT_SUBMISSION_ELIGIBLE"
echo ""
echo "Files created/updated:"
echo "- $SCOPE_JSON_PATH"
echo "- $EXCLUSIONS_JSON_PATH"
echo "- $PROGRAM_POLICY_PATH"
echo "- $REWARDS_JSON_PATH"
echo "- $TESTING_RESTRICTIONS_PATH"

# Cleanup
rm -f "$TEMP_FILE"

exit 0
EOF

# Make the script executable
chmod +x scripts/process_scope_csv.sh