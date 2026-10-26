# Authorization Provenance Design

## Overview
This document describes the cryptographic authorization provenance mechanism for the Mercado Libre Bug Bounty Research Agent authorization gate. The design addresses the requirement for verifiable authorization records with trusted signatures.

## Design Goals
1. Implement cryptographic signature verification for external authorization and human approval records
2. Bind human approval to the exact external authorization record
3. Ensure approvals are bound to exact asset, activity, technique, environment, policy version, and expiration
4. Reject unsigned, invalidly signed, expired, altered, or incorrectly scoped records
5. Never rely on hash alone for authenticity
6. Maintain fail-closed authorization behavior

## Cryptographic Approach
Given the constraints of not including private keys in the repository and not generating realistic approval records, we will implement a signature verification framework that:
- Defines clear signature formats and verification procedures
- Uses placeholder public keys for demonstration (to be replaced with real keys in deployment)
- Maintains fail-closed behavior when proper signatures cannot be verified
- Documents the trust model clearly

## Data Structure Design

### External Authorization Record
```json
{
  "policy_source": "string (URL or identifier)",
  "policy_version": "string (semantic version)",
  "policy_last_updated": "string (ISO 8601 timestamp)",
  "approved_asset": "string (exact hostname or identifier)",
  "permitted_technique": "string (HTTP method)",
  "environment": "string (environment type)",
  "restrictions": ["string"],
  "verification_date": "string (ISO 8601 timestamp)",
  "policy_reference": "string (URL to policy document)",
  "signature": "string (base64-encoded signature)",
  "signature_algorithm": "string (e.g., 'RSA-SHA256', 'ECDSA-SHA256')",
  "key_id": "string (identifier for verification key)"
}
```

### Human Approval Record
```json
{
  "approver_id": "string (identifier of approving researcher)",
  "approval_timestamp": "string (ISO 8601 timestamp)",
  "expiration_timestamp": "string (ISO 8601 timestamp)",
  "asset": "string (must match external authorization approved_asset)",
  "activity": "string (must match external authorization activity context)",
  "technique": "string (must match external authorization permitted_technique)",
  "environment": "string (must match external authorization environment)",
  "rationale": "string (justification for approval)",
  "external_authorization_reference": "string (reference to external authorization)",
  "signature": "string (base64-encoded signature)",
  "signature_algorithm": "string (e.g., 'RSA-SHA256', 'ECDSA-SHA256')",
  "key_id": "string (identifier for verification key)"
}
```

## Trust Model

### Root of Trust
1. **Program Policy Public Key**: Used to verify external authorization signatures
2. **Researcher Public Key**: Used to verify human approval signatures
3. These keys must be distributed through secure out-of-band channels

### Signature Creation Process (Out-of-Band)
1. External authorization is created by Mercado Libre program administrators
2. It is signed using the program's private key
3. Human approval is created by authorized security researchers
4. It is signed using the researcher's private key
5. Both records are distributed to security researchers through secure channels

### Verification Process (In-Agent)
1. On load, verify external authorization signature using program policy public key
2. Verify human approval signature using researcher public key
3. Verify that human approval references match the loaded external authorization
4. Verify all field bindings (asset, activity, technique, environment, etc.)
5. Check expiration timestamps
6. Only if all verifications pass, authorize the records

## Implementation Approach

Given the security requirements and constraints, the implementation will:

1. **Maintain Fail-Closed Behavior**: If proper cryptographic verification cannot be performed (missing keys, invalid signatures, etc.), authorization will be denied

2. **Provide Verification Framework**: Implement signature verification functions that can be enabled when proper keys are available

3. **Clear Documentation**: Document exactly what is needed for full cryptographic verification

4. **Placeholder Keys for Testing**: Include clearly marked placeholder keys for testing the verification framework (these will fail verification with real data, maintaining security)

## Signature Algorithms Supported
- RSA-SHA256
- ECDSA-SHA256 (P-256)

## Key Management
- Public keys for verification should be stored separately from the authorization records
- Key rotation mechanisms should be defined in production deployment
- Keys must be distributed through secure channels (not included in this repository)

## Backward Compatibility
This design is not backward compatible with the existing authorization gate format. Migration would require:
1. New authorization records with proper signatures
2. Distribution of verification public keys
3. Updated loading procedures

## Security Properties
When properly implemented with trusted keys:
- **Unforgeability**: Only parties with private keys can create valid records
- **Integrity**: Any alteration invalidates the signature
- **Authentication**: Verifies the identity of the signer
- **Non-repudiation**: Signer cannot deny having signed the record
- **Binding**: Human approval is cryptographically bound to external authorization

## Limitations Acknowledged
1. Without trusted public keys distributed through secure channels, the system remains fail-closed
2. The signature verification framework provides the mechanism but requires real keys for full functionality
3. Key distribution and management is outside the scope of this implementation but critical for production use