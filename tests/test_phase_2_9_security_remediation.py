"""Offline regression tests for Phase 2.9 authorization hardening."""
import base64
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authorization_gate import AuthorizationDecision, AuthorizationGate, AuthorizationRequest


def _bare_gate(status="DISABLED"):
    gate = AuthorizationGate.__new__(AuthorizationGate)
    gate.gate_data = {"gate_metadata": {"gate_status": status}, "authorization_settings": {"production_testing_enabled": False}}
    gate._external_authorization = object()
    gate._human_approval = object()
    gate._log_authorization_decision = lambda *args, **kwargs: None
    return gate


def test_disabled_gate_never_approves_even_with_records_loaded():
    gate = _bare_gate()
    req = AuthorizationRequest("api.sandbox.mercadolibre.com", "documentation_review", "GET", "SANDBOX")
    decision, reason = gate.check_authorization(req)
    assert decision is AuthorizationDecision.DENY
    assert "not enabled" in reason


def test_unknown_gate_state_never_approves():
    gate = _bare_gate("UNKNOWN")
    req = AuthorizationRequest("api.sandbox.mercadolibre.com", "documentation_review", "GET", "SANDBOX")
    assert gate.check_authorization(req)[0] is AuthorizationDecision.DENY


def test_ed25519_verifies_exact_payload_and_rejects_forgery():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = b"canonical authorization record"
    signature = private.sign(payload)
    gate = AuthorizationGate.__new__(AuthorizationGate)
    gate._trusted_public_keys = {"test-key": base64.b64encode(public).decode("ascii")}
    record = SimpleNamespace(provenance_verified=False, provenance_source="UNVERIFIED")
    assert gate._verify_ed25519_signature(base64.b64encode(signature).decode("ascii"), "ED25519", "test-key", payload, record, "test authorization") == []
    assert record.provenance_verified
    forged = SimpleNamespace(provenance_verified=False, provenance_source="UNVERIFIED")
    errors = gate._verify_ed25519_signature(base64.b64encode(signature).decode("ascii"), "ED25519", "test-key", b"altered", forged, "test authorization")
    assert errors and not forged.provenance_verified


def test_missing_signature_is_rejected():
    gate = AuthorizationGate.__new__(AuthorizationGate)
    gate._trusted_public_keys = {}
    record = SimpleNamespace(provenance_verified=False, provenance_source="UNVERIFIED")
    assert gate._verify_ed25519_signature(None, "ED25519", "key", b"payload", record, "test authorization")
    assert not record.provenance_verified


def test_malformed_public_key_is_rejected():
    gate = AuthorizationGate.__new__(AuthorizationGate)
    gate._trusted_public_keys = {"bad": base64.b64encode(b"short").decode("ascii")}
    record = SimpleNamespace(provenance_verified=False, provenance_source="UNVERIFIED")
    sig = base64.b64encode(b"x" * 64).decode("ascii")
    assert gate._verify_ed25519_signature(sig, "ED25519", "bad", b"payload", record, "test authorization")
    assert not record.provenance_verified

def test_request_cannot_label_a_production_asset_as_sandbox():
    gate = _bare_gate("ENABLED")
    gate._get_actual_environment = lambda asset: "PRODUCTION"
    gate._is_production_environment = lambda env: env == "PRODUCTION"
    req = AuthorizationRequest("api.mercadolibre.com", "documentation_review", "GET", "SANDBOX")
    decision, reason = gate.check_authorization(req)
    assert decision is AuthorizationDecision.ENVIRONMENT_NOT_PERMITTED
    assert "does not match asset mapping" in reason
