#!/usr/bin/env python3
import sys
import os
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

# Initialize scope checker with our updated scope data
checker = ScopeChecker("../scopes/mercadolibre-scope.json")

# Test the invalid wildcard case
target = "invalid.*.mercadolibre.com"
print(f"Testing: {target}")

result = checker.check_target(target, require_bounty_eligible=True)
print(f"Authorized: {result['authorized']}")
print(f"Bounty Eligible: {result['bounty_eligible']}")
print(f"Normalized target: {result['normalized_target']}")
print(f"Scope check: {result['scope_check']}")

# This should be rejected (not authorized)
if not result['authorized']:
    print("[PASS] CORRECTLY REJECTED invalid wildcard usage")
else:
    print("✗ INCORRECTLY AUTHORIZED invalid wildcard usage")