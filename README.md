# Mercado Libre Bug Bounty Research Agent

An offline-first security research workspace for organizing public-source research, scope evidence, authorization decisions, and security assessment preparation for the Mercado Libre HackerOne program.

## Current safety status

**Authorization gate: DISABLED. Production testing: DISABLED.**

The checked-in scope and authorization material is research context, not a substitute for checking the live program policy and obtaining explicit permission for a specific asset, activity, technique, and environment. No active testing is authorized by this repository.

- Confirmed vulnerabilities recorded: 0
- Hypotheses and research leads are tracked separately from confirmed findings.
- Do not perform active scanning, exploitation, credential testing, payment/transaction testing, or other prohibited activity.
- Do not enable the authorization gate using placeholder keys or inferred policy.

## Main components

- `scripts/authorization_gate.py`: fail-closed authorization decision logic, provenance verification, and decision logging.
- `scripts/scope-checker.py`: scope data validation.
- `scripts/*assessment.py`: assessment preparation and research utilities.
- `scripts/safe_http.py`: HTTP helper that surfaces redirects without automatically following them.
- `scopes/`: imported scope and policy research material.
- `research/`: hypotheses, evidence, and investigation notes.
- `reports/`: audit and remediation reports.
- `tests/`: offline regression tests.

## Security notes

The gate now requires actual Ed25519 verification for authorization and human-approval records. The public keys currently checked into the gate configuration are placeholders, not trusted program keys. Replace them only with keys obtained and verified through an independently trusted process. Keep the gate disabled until the policy, scope, key ownership, authorization records, and operational controls have all been independently verified.

HTTP redirect handling is explicit. The assessment clients use a no-follow opener and must re-check every redirect target before continuing. HTTPS-to-HTTP downgrades are rejected.

## Setup and offline tests

```powershell
python -m pip install -r requirements.txt
python -m pytest -q tests/test_phase_2_9_security_remediation.py tests/test_safe_http.py
python -m py_compile scripts/authorization_gate.py scripts/safe_http.py scripts/api-security-assessment.py scripts/auth-audit-assessment.py scripts/authz-audit-assessment.py scripts/payment-security-assessment.py scripts/passive-reconnaissance.py
```

The offline redirect test uses a local loopback HTTP server only. No external target is contacted.

## Limitations

- The repository's historical tests include legacy assumptions that accepted placeholder signatures; they need to be migrated to real ephemeral Ed25519 keys or negative assertions.
- The current configured public keys are placeholders.
- The current gate configuration remains DISABLED.
- This repository is a research and preparation tool, not a production-ready autonomous testing agent.
