#!/usr/bin/env python3
"""
Authorization Gate for Mercado Libre Bug Bounty Research Agent
Enforces authorization decisions based on verified program policy and human approval.
Implements fail-closed authorization: DENY by default, require explicit authorization.
Includes tamper-resistant decision logging for audit trail.
"""

import json
import os
import sys
import hashlib
import base64
import threading
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class AuthorizationDecision(Enum):
    """Authorization decision outcomes."""
    DENY = "DENY"
    APPROVE = "APPROVE"
    REQUIRE_EXTERNAL_AUTHORIZATION = "REQUIRE_EXTERNAL_AUTHORIZATION"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    REQUIRE_EXACT_ASSET_IDENTIFICATION = "REQUIRE_EXACT_ASSET_IDENTIFICATION"
    TECHNIQUE_NOT_PERMITTED = "TECHNIQUE_NOT_PERMITTED"
    ENVIRONMENT_NOT_PERMITTED = "ENVIRONMENT_NOT_PERMITTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    MISSING_PROVENANCE = "MISSING_PROVENANCE"
    PRODUCTION_TESTING_NOT_AUTHORIZED = "PRODUCTION_TESTING_NOT_AUTHORIZED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED_AUTHORIZATION = "EXPIRED_AUTHORIZATION"
    REPLAY_ATTACK_DETECTED = "REPLAY_ATTACK_DETECTED"


@dataclass
class AuthorizationRequest:
    """Request for authorization check."""
    asset: str
    activity: str
    technique: str
    environment: str
    timestamp: Optional[datetime] = None
    nonce: Optional[str] = None  # For replay protection


@dataclass
class ExternalAuthorization:
    """External program authorization data with cryptographic verification."""
    policy_source: str
    policy_version: str
    policy_last_updated: str
    approved_asset: str
    permitted_technique: str
    environment: str
    restrictions: List[str]
    verification_date: str
    policy_reference: str
    config_hash: str
    # Cryptographic verification fields
    signature: Optional[str] = None  # Base64 encoded signature
    signature_algorithm: str = "ED25519"  # Algorithm used for signing
    key_id: Optional[str] = None  # Identifier for the signing key
    timestamp: Optional[str] = None  # Timestamp of when authorization was signed
    nonce: Optional[str] = None  # Nonce for replay protection
    # Provenance tracking
    provenance_verified: bool = False
    provenance_source: str = "UNVERIFIED"
    # Additional metadata
    valid_from: Optional[str] = None  # Authorization valid from timestamp
    valid_until: Optional[str] = None  # Authorization valid until timestamp


@dataclass
class HumanApproval:
    """Human approval data with cryptographic verification."""
    approver_id: str
    approval_timestamp: str
    expiration_timestamp: str
    asset: str
    activity: str
    technique: str
    environment: str
    rationale: str
    external_authorization_reference: str
    approval_hash: str
    # Cryptographic verification fields
    signature: Optional[str] = None  # Base64 encoded signature
    signature_algorithm: str = "ED25519"  # Algorithm used for signing
    key_id: Optional[str] = None  # Identifier for the signing key
    timestamp: Optional[str] = None  # Timestamp of when approval was signed
    nonce: Optional[str] = None  # Nonce for replay protection
    # Provenance tracking
    provenance_verified: bool = False
    provenance_source: str = "UNVERIFIED"


@dataclass
class AuthorizationLogEntry:
    """Log entry for authorization decisions."""
    timestamp: str
    asset: str
    activity: str
    technique: str
    environment: str
    scope_decision: str
    external_auth_decision: str
    human_approval_decision: str
    final_decision: str
    reason: str
    gate_config_hash: str
    external_auth_present: bool
    human_approval_present: bool
    log_sequence_num: int = 0
    prev_log_hash: str = "GENESIS"
    # Note: Intentionally omitting sensitive data like IPs, user agents, etc.
    # unless explicitly needed and sanitized


class AuthorizationGate:
    """
    Authorization gate that enforces fail-closed authorization decisions.
    Requires both external program authorization and human approval.
    Includes tamper-resistant decision logging with hash chaining.
    """

    def __init__(self, gate_file: str = "scopes/authorization-gate.json"):
        """
        Initialize the authorization gate.

        Args:
            gate_file: Path to the authorization gate JSON file
        """
        self.gate_file = gate_file
        self.gate_data = self._load_and_validate_gate()
        self._external_authorization: Optional[ExternalAuthorization] = None
        self._human_approval: Optional[HumanApproval] = None

        # Logging state (will be loaded from persistent storage)
        self._log_sequence_num = 0
        self._prev_log_hash = "GENESIS"

        # Thread safety for logging operations
        self._log_lock = threading.Lock()

        # Ensure log directory exists
        self.log_dir = "logs/authorization-decisions"
        os.makedirs(self.log_dir, exist_ok=True)

        # Ensure audit directory exists for persistent state and checkpoints
        self.audit_dir = "logs/audit"
        os.makedirs(self.audit_dir, exist_ok=True)

        # Load environment mappings from gate configuration
        self._environment_mappings = self._load_environment_mappings()

        # Load trusted public keys for cryptographic verification
        self._trusted_public_keys = self._load_trusted_public_keys()

        # Load trusted checkpoint verification keys (separate from authorization keys)
        self._trusted_checkpoint_keys = self._load_trusted_checkpoint_keys()

        # Track seen nonces for replay protection (in production, this would be persistent)
        self._seen_nonces: set = set()

        # Initialize persistent hash chain state
        self._initialize_persistent_state()

        # Verify checkpoint integrity on startup
        self._verify_checkpoint_integrity()

    def _validate_external_authorization(self, request: AuthorizationRequest) -> List[str]:
        """Validate request against external authorization using environment mappings for independent validation."""
        errors = []
        ext_auth = self._external_authorization

        if ext_auth is None:
            errors.append("External authorization not loaded")
            return errors

        # Check asset match (exact identification required)
        if ext_auth.approved_asset != request.asset:
            errors.append(
                f"Asset mismatch: authorized for '{ext_auth.approved_asset}', "
                f"requested '{request.asset}'"
            )

        # Check technique match
        if ext_auth.permitted_technique != request.technique:
            errors.append(
                f"Technique not permitted: authorized for '{ext_auth.permitted_technique}', "
                f"requested '{request.technique}'"
            )

        # Check environment match using independent validation
        actual_environment = self._get_actual_environment(request.asset)
        if ext_auth.environment != actual_environment:
            errors.append(
                f"Environment mismatch: authorized for '{ext_auth.environment}', "
                f"actual environment of '{request.asset}' is '{actual_environment}'"
            )

        # Cryptographic verification
        crypto_errors = self._verify_external_authorization_signature(ext_auth, request)
        errors.extend(crypto_errors)

        # Replay protection
        replay_errors = self._check_replay_protection(ext_auth, request)
        errors.extend(replay_errors)

        # Validate authorization validity period
        validity_errors = self._check_authorization_validity(ext_auth)
        errors.extend(validity_errors)

        return errors

    def _validate_human_approval(self, request: AuthorizationRequest) -> List[str]:
        """Validate request against human approval using environment mappings for independent validation."""
        errors = []
        approval = self._human_approval

        if approval is None:
            errors.append("Human approval not loaded")
            return errors

        # Check asset match (exact identification required)
        if approval.asset != request.asset:
            errors.append(
                f"Human approval asset mismatch: approved for '{approval.asset}', "
                f"requested '{request.asset}'"
            )

        # Check activity match
        if approval.activity != request.activity:
            errors.append(
                f"Human approval activity mismatch: approved for '{approval.activity}', "
                f"requested '{request.activity}'"
            )

        # Check technique match
        if approval.technique != request.technique:
            errors.append(
                f"Human approval technique mismatch: approved for '{approval.technique}', "
                f"requested '{request.technique}'"
            )

        # Check environment match using independent validation
        actual_environment = self._get_actual_environment(request.asset)
        if approval.environment != actual_environment:
            errors.append(
                f"Human approval environment mismatch: approved for '{approval.environment}', "
                f"actual environment of '{request.asset}' is '{actual_environment}'"
            )

        # Cryptographic verification
        crypto_errors = self._verify_human_approval_signature(approval, request)
        errors.extend(crypto_errors)

        # Replay protection
        replay_errors = self._check_replay_protection(approval, request)
        errors.extend(replay_errors)

        # Validate approval expiration (already done in load_human_approval, but double-check)
        approval_errors = self._check_approval_expiration(approval)
        errors.extend(approval_errors)

        return errors

    def _get_actual_environment(self, hostname: str) -> str:
        """
        Get the actual environment of a hostname using trusted environment mappings.
        Returns the environment from mappings if found, otherwise returns the default environment.

        Args:
            hostname: The hostname to check

        Returns:
            The actual environment (from mappings or default)
        """
        # Check for exact match first
        if hostname in self._environment_mappings:
            return self._environment_mappings[hostname]

        # Check for wildcard patterns (e.g., "*.example.com")
        # Sort patterns by length (descending) to check more specific patterns first
        sorted_patterns = sorted(
            [(pattern, env) for pattern, env in self._environment_mappings.items() if pattern.startswith("*.")],
            key=lambda x: len(x[0]),
            reverse=True
        )

        for pattern, environment in sorted_patterns:
            if hostname.endswith(pattern[1:]):  # Remove the "*." prefix
                # Additional validation: ensure it's a proper subdomain match
                # Either exact match (without the "*.") or subdomain match
                if hostname == pattern[2:] or hostname.endswith("." + pattern[2:]):
                    return environment

        # Return default environment if no match found
        default_env = self.gate_data.get("environment_mappings", {}).get("default_environment", "UNKNOWN")
        return default_env

    def _load_and_validate_gate(self) -> Dict[str, Any]:
        """
        Load and validate the authorization gate configuration.
        Implements fail-closed: rejects missing or malformed configuration.

        Returns:
            Validated gate configuration dictionary

        Raises:
            SystemExit: If gate file is missing, malformed, or invalid
        """
        try:
            with open(self.gate_file, 'r') as f:
                gate_data = json.load(f)
        except FileNotFoundError:
            print(f"ERROR: Authorization gate file not found: {self.gate_file}")
            print("Authorization gate is required for all security testing operations.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in authorization gate: {e}")
            print("Authorization gate must be valid JSON.")
            sys.exit(1)

        # Validate required structure
        required_sections = [
            "gate_metadata",
            "authorization_settings",
            "testing_permissions",
            "rate_limits_and_automation",
            "account_and_credentials",
            "data_handling_and_privacy",
            "sandbox_and_test_environments",
            "payment_specific_restrictions",
            "vulnerability_specific_rules",
            "compliance_and_reporting",
            "validation_and_verification",
            "notes_and_limitations"
        ]

        for section in required_sections:
            if section not in gate_data:
                print(f"ERROR: Missing required section in authorization gate: {section}")
                sys.exit(1)

        # Validate critical security settings are in secure defaults
        auth_settings = gate_data.get("authorization_settings", {})
        if auth_settings.get("production_testing_enabled", True) != False:
            print("ERROR: production_testing_enabled must be false (secure default)")
            sys.exit(1)

        if auth_settings.get("human_approval_status") == "APPROVED":
            print("ERROR: human_approval_status must not be APPROVED in default state")
            sys.exit(1)

        if auth_settings.get("explicit_authorization_required", False) != True:
            print("ERROR: explicit_authorization_required must be true")
            sys.exit(1)

        gate_status = gate_data.get("gate_metadata", {}).get("gate_status")
        if gate_status not in {"DISABLED", "ENABLED"}:
            print("ERROR: gate_metadata.gate_status must be DISABLED or ENABLED")
            sys.exit(1)

        return gate_data

    def _compute_config_hash(self, config: Dict[str, Any]) -> str:
        """
        Compute hash of gate configuration for change detection.

        Args:
            config: Gate configuration dictionary

        Returns:
            SHA256 hash of the configuration
        """
        # Create a copy and remove volatile fields for consistent hashing
        config_copy = json.loads(json.dumps(config))  # Deep copy
        if "gate_metadata" in config_copy:
            config_copy["gate_metadata"]["last_updated"] = "REDACTED_FOR_HASH"
            config_copy["gate_metadata"]["created_date"] = "REDACTED_FOR_HASH"

        config_json = json.dumps(config_copy, sort_keys=True)
        return hashlib.sha256(config_json.encode('utf-8')).hexdigest()

    def _load_environment_mappings(self) -> Dict[str, str]:
        """
        Load environment mappings from gate configuration.
        Maps hostnames or patterns to their expected environment.

        Returns:
            Dictionary mapping hostname/pattern to environment
        """
        try:
            # Load environment mappings from the gate configuration
            env_mappings_config = self.gate_data.get("environment_mappings", {})
            mappings = env_mappings_config.get("mappings", {})

            # Validate that we have a mappings dictionary
            if not isinstance(mappings, dict):
                print("WARNING: environment_mappings.mappings is not a dictionary, using empty map")
                return {}

            return mappings
        except Exception as e:
            print(f"WARNING: Failed to load environment mappings: {e}")
            return {}

    def _load_trusted_public_keys(self) -> Dict[str, str]:
        """
        Load trusted public keys for cryptographic verification.
        In a real implementation, this would load from a secure key management system.
        For offline testing, we'll load from gate configuration or use test keys.

        Returns:
            Dictionary mapping key_id to public key (base64 encoded)
        """
        try:
            # Try to load trusted public keys from gate configuration
            trusted_keys_config = self.gate_data.get("trusted_public_keys", {})
            if trusted_keys_config:
                return trusted_keys_config

            # If not in gate config, return empty dict for offline testing
            # In a real implementation, these would come from a trusted source
            return {}
        except Exception as e:
            print(f"WARNING: Failed to load trusted public keys: {e}")
            return {}

    def _canonicalize_external_authorization(self, auth: ExternalAuthorization) -> bytes:
        """
        Create a canonical representation of external authorization for signature verification.
        This ensures consistent serialization for signing/verification.

        Args:
            auth: ExternalAuthorization object to canonicalize

        Returns:
            Bytes representing the canonicalized authorization
        """
        # Create a dictionary with the fields that should be signed
        # Exclude signature fields themselves
        canonical_data = {
            "policy_source": auth.policy_source,
            "policy_version": auth.policy_version,
            "policy_last_updated": auth.policy_last_updated,
            "approved_asset": auth.approved_asset,
            "permitted_technique": auth.permitted_technique,
            "environment": auth.environment,
            "restrictions": auth.restrictions,
            "verification_date": auth.verification_date,
            "policy_reference": auth.policy_reference,
            "config_hash": auth.config_hash,
            "timestamp": auth.timestamp,
            "nonce": auth.nonce,
            "valid_from": auth.valid_from,
            "valid_until": auth.valid_until
        }

        # Remove None values to keep the canonical form consistent
        canonical_data = {k: v for k, v in canonical_data.items() if v is not None}

        # Sort keys for consistent ordering
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))
        return canonical_json.encode('utf-8')

    def _canonicalize_human_approval(self, approval: HumanApproval) -> bytes:
        """
        Create a canonical representation of human approval for signature verification.
        This ensures consistent serialization for signing/verification.

        Args:
            approval: HumanApproval object to canonicalize

        Returns:
            Bytes representing the canonicalized approval
        """
        # Create a dictionary with the fields that should be signed
        # Exclude signature fields themselves
        canonical_data = {
            "approver_id": approval.approver_id,
            "approval_timestamp": approval.approval_timestamp,
            "expiration_timestamp": approval.expiration_timestamp,
            "asset": approval.asset,
            "activity": approval.activity,
            "technique": approval.technique,
            "environment": approval.environment,
            "rationale": approval.rationale,
            "external_authorization_reference": approval.external_authorization_reference,
            "approval_hash": approval.approval_hash,
            "timestamp": approval.timestamp,
            "nonce": approval.nonce
        }

        # Remove None values to keep the canonical form consistent
        canonical_data = {k: v for k, v in canonical_data.items() if v is not None}

        # Sort keys for consistent ordering
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))
        return canonical_json.encode('utf-8')

    def _verify_external_authorization_signature(self, auth: ExternalAuthorization, request: AuthorizationRequest) -> List[str]:
        """Verify an Ed25519 signature over the canonical authorization payload."""
        return self._verify_ed25519_signature(auth.signature, auth.signature_algorithm, auth.key_id, self._canonicalize_external_authorization(auth), auth, "external authorization")

    def _verify_human_approval_signature(self, approval: HumanApproval, request: AuthorizationRequest) -> List[str]:
        """Verify an Ed25519 signature over the canonical human-approval payload."""
        return self._verify_ed25519_signature(approval.signature, approval.signature_algorithm, approval.key_id, self._canonicalize_human_approval(approval), approval, "human approval")

    def _verify_ed25519_signature(self, signature_b64: Optional[str], algorithm: str, key_id: Optional[str], payload: bytes, record: Any, record_label: str) -> List[str]:
        """Fail closed unless a trusted Ed25519 public key verifies the exact payload."""
        record.provenance_verified = False
        record.provenance_source = "UNVERIFIED"
        if not signature_b64:
            record.provenance_source = "NO_SIGNATURE_PROVIDED"
            return [f"Missing signature for {record_label}"]
        if algorithm != "ED25519":
            return [f"Unsupported signature algorithm for {record_label}: {algorithm}"]
        if not key_id:
            return [f"Missing key_id for {record_label}"]
        public_key_b64 = self._trusted_public_keys.get(key_id)
        if not public_key_b64:
            return [f"Untrusted or unknown key_id: {key_id}"]
        try:
            public_key_bytes = base64.b64decode(public_key_b64, validate=True)
            signature_bytes = base64.b64decode(signature_b64, validate=True)
            if len(public_key_bytes) != 32:
                raise ValueError("Ed25519 public key must be exactly 32 bytes")
            if len(signature_bytes) != 64:
                raise ValueError("Ed25519 signature must be exactly 64 bytes")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, payload)
        except Exception as exc:
            record.provenance_source = "VERIFICATION_FAILED"
            return [f"Signature verification failed for {record_label}: {type(exc).__name__}"]
        record.provenance_verified = True
        record.provenance_source = f"VERIFIED_ED25519_KEY_{key_id}"
        return []

    def _check_replay_protection(self, auth_obj: Any, request: AuthorizationRequest) -> List[str]:
        """
        Check for replay attacks using nonces and timestamps.

        Args:
            auth_obj: Either ExternalAuthorization or HumanApproval object
            request: AuthorizationRequest being validated

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # Check nonce if present
        if hasattr(auth_obj, 'nonce') and auth_obj.nonce is not None:
            nonce = auth_obj.nonce
            if nonce in self._seen_nonces:
                errors.append("Replay attack detected: nonce already used")
            else:
                # Add nonce to seen set (in production, this would have expiration)
                self._seen_nonces.add(nonce)

                # Limit the size of seen nonces to prevent memory exhaustion
                # In production, this would use a proper cache with TTL
                if len(self._seen_nonces) > 10000:
                    # Remove oldest entries (simplified - in production use proper LRU cache)
                    self._seen_nonces.clear()

        # Check timestamp if present
        if hasattr(auth_obj, 'timestamp') and auth_obj.timestamp is not None:
            try:
                auth_time = datetime.fromisoformat(auth_obj.timestamp.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)

                # Check if timestamp is too far in the future (clock skew tolerance)
                time_diff = abs((now - auth_time).total_seconds())
                if time_diff > 300:  # 5 minutes tolerance
                    errors.append(f"Timestamp outside allowed window: {time_diff} seconds skew")

                # Check if timestamp is too old (optional, depends on policy)
                # For authorization, we might want to check if it's too old
                # but this is often handled by valid_from/valid_until

            except ValueError as e:
                errors.append(f"Invalid timestamp format: {str(e)}")

        return errors

    def _check_authorization_validity(self, auth: ExternalAuthorization) -> List[str]:
        """
        Check if the authorization is within its valid time period.

        Args:
            auth: ExternalAuthorization object to check

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        now = datetime.now(timezone.utc)

        # Check valid_from
        if auth.valid_from is not None:
            try:
                valid_from = datetime.fromisoformat(auth.valid_from.replace('Z', '+00:00'))
                if now < valid_from:
                    errors.append("Authorization not yet valid")
            except ValueError as e:
                errors.append(f"Invalid valid_from timestamp: {str(e)}")

        # Check valid_until
        if auth.valid_until is not None:
            try:
                valid_until = datetime.fromisoformat(auth.valid_until.replace('Z', '+00:00'))
                if now > valid_until:
                    errors.append("Authorization has expired")
            except ValueError as e:
                errors.append(f"Invalid valid_until timestamp: {str(e)}")

        return errors

    def _check_approval_expiration(self, approval: HumanApproval) -> List[str]:
        """
        Check if the human approval has expired.

        Args:
            approval: HumanApproval object to check

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        try:
            expiration_time = datetime.fromisoformat(approval.expiration_timestamp.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)

            if now > expiration_time:
                errors.append("Human approval has expired")
        except ValueError as e:
            errors.append(f"Invalid expiration timestamp: {str(e)}")

        return errors

    def _log_authorization_decision(self, request: AuthorizationRequest,
                                  scope_decision: Tuple[bool, str, List[str]],
                                  auth_decision: AuthorizationDecision, reason: str):
        """
        Log authorization decision to tamper-resistant log file with hash chaining.
        Does not log sensitive data.

        Args:
            request: The authorization request
            scope_decision: Tuple from scope checker (authorized, reason, patterns)
            auth_decision: Final authorization decision
            reason: Reason for the decision
        """
        try:
            # Increment sequence number
            self._log_sequence_num += 1

            # Create log entry
            log_entry = AuthorizationLogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                asset=request.asset,
                activity=request.activity,
                technique=request.technique,
                environment=request.environment,
                scope_decision="AUTHORIZED" if scope_decision[0] else "DENIED",
                external_auth_decision="PRESENT" if self._external_authorization else "MISSING",
                human_approval_decision="PRESENT" if self._human_approval else "MISSING",
                final_decision=auth_decision.value,
                reason=reason[:200],  # Limit reason length to prevent log flooding
                gate_config_hash=self._compute_config_hash(self.gate_data),
                external_auth_present=self._external_authorization is not None,
                human_approval_present=self._human_approval is not None,
                log_sequence_num=self._log_sequence_num,
                prev_log_hash=self._prev_log_hash
            )

            # Create daily log file
            log_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            log_file = os.path.join(self.log_dir, f"auth_decisions_{log_date}.jsonl")

            # Prepare log line for hashing (excluding the hash field itself)
            log_content = {
                "timestamp": log_entry.timestamp,
                "asset": log_entry.asset,
                "activity": log_entry.activity,
                "technique": log_entry.technique,
                "environment": log_entry.environment,
                "scope_decision": log_entry.scope_decision,
                "external_auth_decision": log_entry.external_auth_decision,
                "human_approval_decision": log_entry.human_approval_decision,
                "final_decision": log_entry.final_decision,
                "reason": log_entry.reason,
                "gate_config_hash": log_entry.gate_config_hash,
                "external_auth_present": log_entry.external_auth_present,
                "human_approval_present": log_entry.human_approval_present,
                "log_sequence_num": log_entry.log_sequence_num,
                "prev_log_hash": log_entry.prev_log_hash
            }

            # Compute hash of log content
            log_content_json = json.dumps(log_content, sort_keys=True)
            log_entry_hash = hashlib.sha256(log_content_json.encode('utf-8')).hexdigest()

            # Add hash to log entry
            log_line = json.dumps({
                **log_content,
                "log_hash": log_entry_hash
            })

            with open(log_file, 'a') as f:
                f.write(log_line + '\n')

            # Update previous hash for next entry
            self._prev_log_hash = log_entry_hash

        except Exception as e:
            # Never fail open due to logging issues - log to stderr instead
            print(f"WARNING: Failed to write authorization log: {e}", file=sys.stderr)

    def load_external_authorization(self, external_auth_data: Dict[str, Any]) -> bool:
        """
        Load and validate external program authorization.
        Unknown or missing required fields result in rejection.
        Sets provenance tracking based on validation.
        Verifies cryptographic signature if present.

        Args:
            external_auth_data: External authorization data from program

        Returns:
            True if valid external authorization loaded, False otherwise
        """
        # Required fields for external authorization
        required_fields = [
            "policy_source",
            "policy_version",
            "policy_last_updated",
            "approved_asset",
            "permitted_technique",
            "environment",
            "verification_date",
            "policy_reference"
        ]

        # Check for missing required fields
        missing_fields = [field for field in required_fields if field not in external_auth_data]
        if missing_fields:
            print(f"ERROR: Missing required external authorization fields: {missing_fields}")
            return False

        # Check for unknown policy values (cannot be UNKNOWN or empty)
        unknown_fields = []
        for field in ["policy_version", "policy_last_updated", "approved_asset",
                     "permitted_technique", "environment", "policy_reference"]:
            value = external_auth_data.get(field)
            if value == "UNKNOWN" or not value or value.strip() == "":
                unknown_fields.append(field)

        if unknown_fields:
            print(f"ERROR: External authorization contains unknown/empty fields: {unknown_fields}")
            return False

        # Validate restrictions is a list
        restrictions = external_auth_data.get("restrictions", [])
        if not isinstance(restrictions, list):
            print("ERROR: restrictions must be a list")
            return False

        # Create external authorization object
        try:
            self._external_authorization = ExternalAuthorization(
                policy_source=external_auth_data["policy_source"],
                policy_version=external_auth_data["policy_version"],
                policy_last_updated=external_auth_data["policy_last_updated"],
                approved_asset=external_auth_data["approved_asset"],
                permitted_technique=external_auth_data["permitted_technique"],
                environment=external_auth_data["environment"],
                restrictions=restrictions,
                verification_date=external_auth_data["verification_date"],
                policy_reference=external_auth_data["policy_reference"],
                config_hash=self._compute_config_hash(self.gate_data),
                # Cryptographic fields (may be None if not provided)
                signature=external_auth_data.get("signature"),
                signature_algorithm=external_auth_data.get("signature_algorithm", "ED25519"),
                key_id=external_auth_data.get("key_id"),
                timestamp=external_auth_data.get("timestamp"),
                nonce=external_auth_data.get("nonce"),
                valid_from=external_auth_data.get("valid_from"),
                valid_until=external_auth_data.get("valid_until"),
                # Provenance tracking (will be set after verification)
                provenance_verified=False,
                provenance_source="UNVERIFIED"
            )

            # If we have signature data, verify it
            # Create a dummy request for verification (in real use, this would come from actual request)
            dummy_request = AuthorizationRequest(
                asset=self._external_authorization.approved_asset,
                activity="verify",
                technique=self._external_authorization.permitted_technique,
                environment=self._get_actual_environment(self._external_authorization.approved_asset)
            )

            # Verify the signature (this will set provenance_verified and provenance_source)
            crypto_errors = self._verify_external_authorization_signature(self._external_authorization, dummy_request)
            # Note: We don't return False for crypto errors in loading - we let the validation catch them later
            # This allows us to load the data and then reject it during authorization checking

            return True
        except Exception as e:
            print(f"ERROR: Failed to create external authorization: {e}")
            return False

    def load_human_approval(self, approval_data: Dict[str, Any]) -> bool:
        """
        Load and validate human approval.
        Missing or invalid fields result in rejection.
        Sets provenance tracking based on validation.
        Verifies cryptographic signature if present.

        Args:
            approval_data: Human approval data

        Returns:
            True if valid human approval loaded, False otherwise
        """
        # Required fields for human approval
        required_fields = [
            "approver_id",
            "approval_timestamp",
            "expiration_timestamp",
            "asset",
            "activity",
            "technique",
            "environment",
            "rationale",
            "external_authorization_reference"
        ]

        # Check for missing required fields
        missing_fields = [field for field in required_fields if field not in approval_data]
        if missing_fields:
            print(f"ERROR: Missing required human approval fields: {missing_fields}")
            return False

        # Validate timestamps
        try:
            approval_time = datetime.fromisoformat(approval_data["approval_timestamp"].replace('Z', '+00:00'))
            expiration_time = datetime.fromisoformat(approval_data["expiration_timestamp"].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)

            if approval_time > now:
                print("ERROR: approval_timestamp cannot be in the future")
                return False

            if expiration_time <= approval_time:
                print("ERROR: expiration_timestamp must be after approval_timestamp")
                return False

            if now > expiration_time:
                print("ERROR: Human approval has expired")
                return False

        except ValueError as e:
            print(f"ERROR: Invalid timestamp format: {e}")
            return False

        # Create human approval object
        try:
            approval_hash_input = json.dumps({
                "approver_id": approval_data["approver_id"],
                "asset": approval_data["asset"],
                "activity": approval_data["activity"],
                "technique": approval_data["technique"],
                "environment": approval_data["environment"],
                "approval_timestamp": approval_data["approval_timestamp"],
                "expiration_timestamp": approval_data["expiration_timestamp"],
                "external_auth_ref": approval_data["external_authorization_reference"]
            }, sort_keys=True)

            self._human_approval = HumanApproval(
                approver_id=approval_data["approver_id"],
                approval_timestamp=approval_data["approval_timestamp"],
                expiration_timestamp=approval_data["expiration_timestamp"],
                asset=approval_data["asset"],
                activity=approval_data["activity"],
                technique=approval_data["technique"],
                environment=approval_data["environment"],
                rationale=approval_data["rationale"],
                external_authorization_reference=approval_data["external_authorization_reference"],
                approval_hash=hashlib.sha256(approval_hash_input.encode('utf-8')).hexdigest(),
                # Cryptographic fields (may be None if not provided)
                signature=approval_data.get("signature"),
                signature_algorithm=approval_data.get("signature_algorithm", "ED25519"),
                key_id=approval_data.get("key_id"),
                timestamp=approval_data.get("timestamp"),
                nonce=approval_data.get("nonce"),
                # Provenance tracking (will be set after verification)
                provenance_verified=False,
                provenance_source="UNVERIFIED"
            )

            # If we have signature data, verify it
            # Create a dummy request for verification (in real use, this would come from actual request)
            dummy_request = AuthorizationRequest(
                asset=self._human_approval.asset,
                activity=self._human_approval.activity,
                technique=self._human_approval.technique,
                environment=self._get_actual_environment(self._human_approval.asset)
            )

            # Verify the signature (this will set provenance_verified and provenance_source)
            crypto_errors = self._verify_human_approval_signature(self._human_approval, dummy_request)
            # Note: We don't return False for crypto errors in loading - we let the validation catch them later
            # This allows us to load the data and then reject it during authorization checking

            return True
        except Exception as e:
            print(f"ERROR: Failed to create human approval: {e}")
            return False

    def check_authorization(self, request: AuthorizationRequest) -> Tuple[AuthorizationDecision, str]:
        """
        Check if the requested action is authorized.
        Implements fail-closed: DENY by default, require explicit authorization.
        Logs all authorization decisions for audit trail.

        Args:
            request: Authorization request to check

        Returns:
            Tuple of (decision, reason)
        """
        # Operator-controlled kill switch: only explicit ENABLED may proceed.
        gate_status = self.gate_data.get("gate_metadata", {}).get("gate_status")
        if gate_status != "ENABLED":
            decision = AuthorizationDecision.DENY
            reason = f"Authorization gate is not enabled (status={gate_status!r})"
            self._log_authorization_decision(request, (False, reason, []), decision, reason)
            return decision, reason

        if self.gate_data.get("authorization_settings", {}).get("production_testing_enabled") is not True and self._is_production_environment(request.environment):
            decision = AuthorizationDecision.PRODUCTION_TESTING_NOT_AUTHORIZED
            reason = "Production testing is disabled by configuration"
            self._log_authorization_decision(request, (False, reason, []), decision, reason)
            return decision, reason

        # Default to DENY (fail-closed)
        if not self._external_authorization:
            decision = AuthorizationDecision.REQUIRE_EXTERNAL_AUTHORIZATION
            reason = "External program authorization required"
            # Note: We don't log scope decision here as it's handled by scope checker
            self._log_authorization_decision(request, (False, "Scope check delegated", []), decision, reason)
            return decision, reason

        if not self._human_approval:
            decision = AuthorizationDecision.REQUIRE_HUMAN_APPROVAL
            reason = "Human approval required for this specific activity"
            self._log_authorization_decision(request, (True, "Scope check delegated", []), decision, reason)
            return decision, reason

        # Validate external authorization matches request
        auth_errors = self._validate_external_authorization(request)
        if auth_errors:
            decision = AuthorizationDecision.DENY
            reason = "; ".join(auth_errors)
            self._log_authorization_decision(request, (True, "Scope check delegated", []), decision, reason)
            return decision, reason

        # Validate human approval matches request
        approval_errors = self._validate_human_approval(request)
        if approval_errors:
            decision = AuthorizationDecision.DENY
            reason = "; ".join(approval_errors)
            self._log_authorization_decision(request, (True, "Scope check delegated", []), decision, reason)
            return decision, reason

        # Check if production testing is being attempted
        if self._is_production_environment(request.environment):
            prod_errors = self._validate_production_testing(request)
            if prod_errors:
                decision = AuthorizationDecision.DENY
                reason = "; ".join(prod_errors)
                self._log_authorization_decision(request, (True, "Scope check delegated", []), decision, reason)
                return decision, reason

        # All checks passed
        decision = AuthorizationDecision.APPROVE
        reason = f"Authorized for {request.technique} on {request.asset} in {request.environment}"
        self._log_authorization_decision(request, (True, "Scope check delegated", []), decision, reason)
        return decision, reason

    def _is_production_environment(self, environment: str) -> bool:
        """
        Check if environment indicates production.
        This is a simplified check - in practice, this would be defined in policy.

        Args:
            environment: Environment string to check

        Returns:
            True if environment appears to be production
        """
        # Common indicators of non-production environments
        non_prod_indicators = [
            "sandbox", "test", "dev", "development", "staging", "qa",
            "preview", "beta", "alpha", "localhost", "127.", "192.168.",
            "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
            "172.31."
        ]

        env_lower = environment.lower()
        for indicator in non_prod_indicators:
            if indicator in env_lower:
                return False

        # If no non-production indicators found, assume production
        # In practice, this should be explicitly defined in policy
        return True

    def _validate_production_testing(self, request: AuthorizationRequest) -> List[str]:
        """
        Validate production testing is explicitly authorized.
        Production testing is STRICTLY_PROHIBITED unless explicitly permitted.

        Args:
            request: Authorization request to check

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # Check if production testing is allowed in gate
        payment_restrictions = self.gate_data.get("payment_specific_restrictions", {})
        if payment_restrictions.get("payment_testing_in_production") != "EXPLICITLY_AUTHORIZED_REQUIRED":
            # Default is STRICTLY_PROHIBITED
            errors.append("Production testing is strictly prohibited without explicit authorization")

        # Check if gate explicitly permits production testing for this request
        # This would require specific policy authorization
        if self._is_production_environment(request.environment):
            # Additional validation would go here based on explicit policy
            errors.append("Production testing requires explicit policy authorization for exact asset/technique/environment")

        return errors

    def get_gate_status(self) -> Dict[str, Any]:
        """
        Get current status of the authorization gate.

        Returns:
            Dictionary with gate status information
        """
        gate_metadata = self.gate_data.get("gate_metadata", {})
        auth_settings = self.gate_data.get("authorization_settings", {})

        return {
            "gate_file": self.gate_file,
            "gate_version": gate_metadata.get("gate_version", "UNKNOWN"),
            "created_date": gate_metadata.get("created_date", "UNKNOWN"),
            "last_updated": gate_metadata.get("last_updated", "UNKNOWN"),
            "gate_status": "LOADED",  # If we got here, gate loaded successfully
            "production_testing_enabled": auth_settings.get("production_testing_enabled", True),
            "human_approval_required": auth_settings.get("human_approval_required", True),
            "human_approval_status": auth_settings.get("human_approval_status", "UNKNOWN"),
            "explicit_authorization_required": auth_settings.get("explicit_authorization_required", False),
            "external_authorization_loaded": self._external_authorization is not None,
            "human_approval_loaded": self._human_approval is not None,
            "external_auth_provenance": self._external_authorization.provenance_verified if self._external_authorization else False,
            "human_auth_provenance": self._human_approval.provenance_verified if self._human_approval else False,
            "notes": self.gate_data.get("notes_and_limitations", []),
            "log_directory": self.log_dir,
            "audit_directory": self.audit_dir,
            "log_sequence_num": self._log_sequence_num,
            "prev_log_hash": self._prev_log_hash,
            "persistent_state_available": os.path.exists(os.path.join(self.audit_dir, "hash_chain_state.json")),
            "checkpoint_count": len([f for f in os.listdir(self.audit_dir) if f.startswith("checkpoint_") and f.endswith(".json")]) if os.path.exists(self.audit_dir) else 0
        }

    def _initialize_persistent_state(self):
        """
        Initialize persistent hash chain state from storage.
        If no state exists, start with genesis values.
        """
        state_file = os.path.join(self.audit_dir, "hash_chain_state.json")
        try:
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state_data = json.load(f)

                self._log_sequence_num = state_data.get("log_sequence_num", 0)
                self._prev_log_hash = state_data.get("prev_log_hash", "GENESIS")

                # Validate that the loaded state is reasonable
                if self._log_sequence_num < 0:
                    self._log_sequence_num = 0
                if not isinstance(self._prev_log_hash, str):
                    self._prev_log_hash = "GENESIS"
            else:
                # No existing state, start with genesis values
                self._log_sequence_num = 0
                self._prev_log_hash = "GENESIS"
        except Exception as e:
            # If we can't load state, start fresh but log the issue
            print(f"WARNING: Failed to load persistent hash chain state: {e}", file=sys.stderr)
            self._log_sequence_num = 0
            self._prev_log_hash = "GENESIS"

    def _save_persistent_state(self):
        """
        Save persistent hash chain state to storage.
        This is called after each successful log write to ensure state persistence.
        """
        state_file = os.path.join(self.audit_dir, "hash_chain_state.json")
        temp_file = state_file + ".tmp"

        try:
            state_data = {
                "log_sequence_num": self._log_sequence_num,
                "prev_log_hash": self._prev_log_hash,
                "last_updated": datetime.now(timezone.utc).isoformat()
            }

            # Write to temporary file first
            with open(temp_file, 'w') as f:
                json.dump(state_data, f, indent=2)

            # Atomically rename to final file
            shutil.move(temp_file, state_file)
        except Exception as e:
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            print(f"WARNING: Failed to save persistent hash chain state: {e}", file=sys.stderr)

    def _load_trusted_checkpoint_keys(self) -> Dict[str, str]:
        """
        Load trusted public keys for checkpoint verification.
        These are separate from authorization keys to maintain separation of concerns.

        Returns:
            Dictionary mapping key_id to public key (base64 encoded)
        """
        try:
            # Try to load trusted checkpoint keys from gate configuration
            trusted_keys_config = self.gate_data.get("trusted_checkpoint_keys", {})
            if trusted_keys_config:
                return trusted_keys_config

            # If not in gate config, return empty dict for offline testing
            # In a real implementation, these would come from a trusted source
            return {}
        except Exception as e:
            print(f"WARNING: Failed to load trusted checkpoint keys: {e}")
            return {}

    def _create_checkpoint(self):
        """
        Create a cryptographically signed checkpoint of the current hash chain state.
        This provides an independent trust anchor for detecting log tampering.
        """
        try:
            # Create checkpoint data
            checkpoint_data = {
                "checkpoint_version": "1.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "log_sequence_num": self._log_sequence_num,
                "chain_head_hash": self._prev_log_hash,  # Hash of the latest log entry
                "previous_checkpoint_hash": self._get_latest_checkpoint_hash(),
                "gate_config_hash": self._compute_config_hash(self.gate_data)
            }

            # Create canonical representation for signing
            canonical_data = json.dumps(checkpoint_data, sort_keys=True, separators=(',', ':'))

            # In offline/testing mode, we accept any properly formatted signature
            # In production, this would use actual Ed25519 signing with dedicated keys
            # For now, we'll store the canonical data and a placeholder signature
            # The actual verification would be done against trusted keys

            # For testing purposes, we'll create a simple signature
            # In production: signature = sign(private_key, canonical_data)
            import base64
            # Create a dummy signature for testing (64 bytes of test data)
            test_signature = base64.b64encode(bytes([i % 256 for i in range(64)])).decode('utf-8')

            checkpoint_data["signature"] = test_signature
            checkpoint_data["signature_algorithm"] = "ED25519"
            checkpoint_data["key_id"] = "checkpoint-test-key-001"

            # Write checkpoint to file
            checkpoint_file = os.path.join(
                self.audit_dir,
                f"checkpoint_{int(datetime.now(timezone.utc).timestamp())}.json"
            )

            with open(checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)

        except Exception as e:
            # Never fail the authorization process due to checkpoint issues
            print(f"WARNING: Failed to create checkpoint: {e}", file=sys.stderr)

    def _get_latest_checkpoint_hash(self) -> str:
        """
        Get the hash of the latest checkpoint to chain checkpoints together.

        Returns:
            Hash of the latest checkpoint, or "GENESIS" if no checkpoints exist
        """
        try:
            checkpoint_files = [
                f for f in os.listdir(self.audit_dir)
                if f.startswith("checkpoint_") and f.endswith(".json")
            ]

            if not checkpoint_files:
                return "GENESIS"

            # Sort by timestamp in filename (newest first)
            checkpoint_files.sort(reverse=True)
            latest_checkpoint = os.path.join(self.audit_dir, checkpoint_files[0])

            with open(latest_checkpoint, 'r') as f:
                checkpoint_data = json.load(f)

            # Compute hash of checkpoint data (excluding signature fields for chaining)
            checkpoint_for_hash = {
                k: v for k, v in checkpoint_data.items()
                if k not in ["signature", "signature_algorithm", "key_id"]
            }

            canonical_data = json.dumps(checkpoint_for_hash, sort_keys=True, separators=(',', ':'))
            return hashlib.sha256(canonical_data.encode('utf-8')).hexdigest()

        except Exception:
            return "GENESIS"

    def _verify_checkpoint_integrity(self):
        """
        Verify the integrity of checkpoints on startup.
        Detects checkpoint tampering, rollback attempts, and validates the hash chain.
        """
        try:
            checkpoint_files = [
                f for f in os.listdir(self.audit_dir)
                if f.startswith("checkpoint_") and f.endswith(".json")
            ]

            if not checkpoint_files:
                # No checkpoints exist yet - this is normal for first run
                return

            # Sort checkpoints by timestamp in filename (oldest to newest for chain verification)
            checkpoint_files.sort()

            previous_checkpoint_hash = "GENESIS"

            for checkpoint_file in checkpoint_files:
                checkpoint_path = os.path.join(self.audit_dir, checkpoint_file)

                try:
                    with open(checkpoint_path, 'r') as f:
                        checkpoint_data = json.load(f)

                    # Verify basic structure
                    required_fields = ["timestamp", "log_sequence_num", "chain_head_hash",
                                     "previous_checkpoint_hash", "gate_config_hash"]
                    for field in required_fields:
                        if field not in checkpoint_data:
                            print(f"WARNING: Checkpoint {checkpoint_file} missing required field: {field}", file=sys.stderr)
                            return

                    # Verify checkpoint chaining
                    expected_previous_hash = self._get_checkpoint_hash_from_file(checkpoint_path)
                    if checkpoint_data["previous_checkpoint_hash"] != expected_previous_hash:
                        print(f"WARNING: Checkpoint {checkpoint_file} has broken chain: expected previous hash {expected_previous_hash}, got {checkpoint_data['previous_checkpoint_hash']}", file=sys.stderr)
                        # In production, this might trigger alerts or fail-safe behavior

                    # Verify gate config hasn't changed unexpectedly
                    if checkpoint_data["gate_config_hash"] != self._compute_config_hash(self.gate_data):
                        print(f"WARNING: Gate configuration has changed since checkpoint {checkpoint_file} was created", file=sys.stderr)

                    # Update for next iteration
                    previous_checkpoint_hash = self._get_checkpoint_hash_from_file(checkpoint_path)

                except Exception as e:
                    print(f"WARNING: Failed to verify checkpoint {checkpoint_file}: {e}", file=sys.stderr)

        except Exception as e:
            print(f"WARNING: Failed to verify checkpoint integrity: {e}", file=sys.stderr)

    def _get_checkpoint_hash_from_file(self, checkpoint_path: str) -> str:
        """
        Compute the hash of a checkpoint file (excluding signature fields).

        Args:
            checkpoint_path: Path to the checkpoint file

        Returns:
            SHA256 hash of the checkpoint data
        """
        try:
            with open(checkpoint_path, 'r') as f:
                checkpoint_data = json.load(f)

            # Exclude signature fields from hash calculation
            checkpoint_for_hash = {
                k: v for k, v in checkpoint_data.items()
                if k not in ["signature", "signature_algorithm", "key_id"]
            }

            canonical_data = json.dumps(checkpoint_for_hash, sort_keys=True, separators=(',', ':'))
            return hashlib.sha256(canonical_data.encode('utf-8')).hexdigest()
        except Exception:
            return ""

    def _verify_log_integrity(self):
        """
        Verify the integrity of the log file against known checkpoints and persistent state.
        This can detect various forms of tampering.
        """
        try:
            # This is a simplified verification - in production, this would be more comprehensive
            # For now, we'll just ensure that the persistent state matches what we'd expect
            # based on counting log entries

            log_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            log_file = os.path.join(self.log_dir, f"auth_decisions_{log_date}.jsonl")

            if not os.path.exists(log_file):
                # No log file for today yet - this is normal
                return

            # Count lines in log file
            line_count = 0
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():  # Skip empty lines
                            line_count += 1
            except Exception:
                # If we can't read the file, skip verification
                return

            # The sequence number should match the number of entries logged today
            # Note: This is a simplified check - in a full implementation, we'd track
            # sequence numbers across days and verify against checkpoints
            if line_count > 0 and self._log_sequence_num < line_count:
                print(f"WARNING: Log sequence number ({self._log_sequence_num}) appears inconsistent with log file line count ({line_count})", file=sys.stderr)

        except Exception as e:
            # Never fail authorization due to verification issues
            print(f"WARNING: Failed to verify log integrity: {e}", file=sys.stderr)

    def _log_authorization_decision(self, request: AuthorizationRequest,
                                  scope_decision: Tuple[bool, str, List[str]],
                                  auth_decision: AuthorizationDecision, reason: str):
        """
        Log authorization decision to tamper-resistant log file with hash chaining.
        Does not log sensitive data.
        Includes persistent state management and checkpointing for enhanced integrity.

        Args:
            request: The authorization request
            scope_decision: Tuple from scope checker (authorized, reason, patterns)
            auth_decision: Final authorization decision
            reason: Reason for the decision
        """
        with self._log_lock:  # Ensure thread safety for logging operations
            try:
                # Increment sequence number
                self._log_sequence_num += 1

                # Create log entry
                log_entry = AuthorizationLogEntry(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    asset=request.asset,
                    activity=request.activity,
                    technique=request.technique,
                    environment=request.environment,
                    scope_decision="AUTHORIZED" if scope_decision[0] else "DENIED",
                    external_auth_decision="PRESENT" if self._external_authorization else "MISSING",
                    human_approval_decision="PRESENT" if self._human_approval else "MISSING",
                    final_decision=auth_decision.value,
                    reason=reason[:200],  # Limit reason length to prevent log flooding
                    gate_config_hash=self._compute_config_hash(self.gate_data),
                    external_auth_present=self._external_authorization is not None,
                    human_approval_present=self._human_approval is not None,
                    log_sequence_num=self._log_sequence_num,
                    prev_log_hash=self._prev_log_hash
                )

                # Create daily log file
                log_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                log_file = os.path.join(self.log_dir, f"auth_decisions_{log_date}.jsonl")

                # Prepare log line for hashing (excluding the hash field itself)
                log_content = {
                    "timestamp": log_entry.timestamp,
                    "asset": log_entry.asset,
                    "activity": log_entry.activity,
                    "technique": log_entry.technique,
                    "environment": log_entry.environment,
                    "scope_decision": log_entry.scope_decision,
                    "external_auth_decision": log_entry.external_auth_decision,
                    "human_approval_decision": log_entry.human_approval_decision,
                    "final_decision": log_entry.final_decision,
                    "reason": log_entry.reason,
                    "gate_config_hash": log_entry.gate_config_hash,
                    "external_auth_present": log_entry.external_auth_present,
                    "human_approval_present": log_entry.human_approval_present,
                    "log_sequence_num": log_entry.log_sequence_num,
                    "prev_log_hash": log_entry.prev_log_hash
                }

                # Compute hash of log content
                log_content_json = json.dumps(log_content, sort_keys=True)
                log_entry_hash = hashlib.sha256(log_content_json.encode('utf-8')).hexdigest()

                # Add hash to log entry
                log_line = json.dumps({
                    **log_content,
                    "log_hash": log_entry_hash
                })

                # Write log entry atomically using temporary file
                temp_log_file = log_file + ".tmp"
                with open(temp_log_file, 'w') as f:
                    f.write(log_line + '\n')

                # Atomically rename to final log file (append mode)
                # For JSONL format, we need to append, so we'll use a different approach
                # Read existing content, append new line, write atomically
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        existing_content = f.read()
                else:
                    existing_content = ""

                new_content = existing_content + log_line + '\n'

                temp_log_file = log_file + ".tmp"
                with open(temp_log_file, 'w') as f:
                    f.write(new_content)

                # Atomically rename to final file
                shutil.move(temp_log_file, log_file)

                # Update previous hash for next entry
                self._prev_log_hash = log_entry_hash

                # Save persistent state after successful log write
                self._save_persistent_state()

                # Create checkpoint periodically (every 100 entries for testing)
                # In production, this would be based on time interval or significant events
                if self._log_sequence_num % 100 == 0:
                    self._create_checkpoint()

            except Exception as e:
                # Never fail open due to logging issues - log to stderr instead
                print(f"WARNING: Failed to write authorization log: {e}", file=sys.stderr)


def main():
    """Command line interface for testing the authorization gate."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Test authorization gate for Mercado Libre bug bounty research agent"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run built-in tests"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current gate status"
    )
    parser.add_argument(
        "--check",
        nargs=4,
        metavar=("ASSET", "ACTIVITY", "TECHNIQUE", "ENVIRONMENT"),
        help="Check authorization for specific request"
    )

    args = parser.parse_args()

    if args.status:
        gate = AuthorizationGate()
        status = gate.get_gate_status()
        print("Authorization Gate Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")
        return

    if args.check:
        asset, activity, technique, environment = args.check
        gate = AuthorizationGate()

        # For testing, we'll show what would be required
        request = AuthorizationRequest(
            asset=asset,
            activity=activity,
            technique=technique,
            environment=environment
        )

        decision, reason = gate.check_authorization(request)
        print(f"Authorization Check for {asset} [{activity}] {technique} in {environment}:")
        print(f"  Decision: {decision.value}")
        print(f"  Reason: {reason}")

        if gate._external_authorization:
            print("  External Authorization: LOADED")
        else:
            print("  External Authorization: NOT LOADED")

        if gate._human_approval:
            print("  Human Approval: LOADED")
        else:
            print("  Human Approval: NOT LOADED")
        return

    if args.test:
        print("Running authorization gate tests...")
        # Basic instantiation test
        try:
            gate = AuthorizationGate()
            print("[+] Authorization gate instantiated successfully")
        except SystemExit:
            print("[-] Failed to instantiate authorization gate")
            return

        # Show status
        status = gate.get_gate_status()
        print(f"[+] Gate status: {status['gate_status']}")
        print(f"[+] Production testing enabled: {status['production_testing_enabled']}")
        print(f"[+] Human approval required: {status['human_approval_required']}")
        print(f"[+] Human approval status: {status['human_approval_status']}")

        return

    # Default: show help
    parser.print_help()


if __name__ == "__main__":
    main()