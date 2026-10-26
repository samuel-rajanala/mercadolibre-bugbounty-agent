# Phase 2.9 — Security Remediation

## Changes
- Enforce the operator-controlled authorization gate status. Only literal ENABLED proceeds; DISABLED, missing, malformed, and unknown states deny.
- Keep production testing disabled unless explicitly enabled in configuration. The checked-in configuration remains disabled.
- Replace signature-length acceptance with actual Ed25519 verification of canonical authorization and approval payloads.
- Reject missing signatures, unsupported algorithms, unknown key IDs, malformed keys/signatures, and invalid signatures.
- Bind human approval to the exact external authorization policy reference.
- Remove duplicate validator definitions that shadowed stronger checks.
- Add offline regression tests for the disabled gate and Ed25519 verification.

## Operational warning
The checked-in gate remains DISABLED. Existing configured public keys are placeholders and must be replaced with independently verified public keys before signed authorization can succeed. Do not enable the gate to make tests pass.

These tests are offline only. They do not contact Mercado Libre, perform scans, exploit vulnerabilities, or interact with accounts.

## Run locally
```powershell
python -m pip install -r requirements.txt
python -m pytest -q tests/test_phase_2_9_security_remediation.py
python -m py_compile scripts/authorization_gate.py
```

Historical tests that expect placeholder signatures to pass must be updated to use ephemeral Ed25519 key pairs or to assert rejection. Do not weaken the new checks.
