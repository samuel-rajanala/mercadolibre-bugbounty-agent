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

# Test the failing cases
test_cases = [
    ("com.3mosquitos.MercadoLibre", True, True, "Apple Store App ID"),
    ("Point Smart", True, True, "HARDWARE"),
]

for target, should_be_authorized, should_be_bounty, description in test_cases:
    print(f"\nTesting: {target}")
    print(f"Description: {description}")
    print(f"Expected: Auth={should_be_authorized}, Bounty={should_be_bounty}")

    result = checker.check_target(target, require_bounty_eligible=True)
    authorized = result["authorized"]
    bounty_eligible = result["bounty_eligible"]

    print(f"Actual: Auth={authorized}, Bounty={bounty_eligible}")
    print(f"Normalized target: {result['normalized_target']}")
    print(f"Scope check: {result['scope_check']}")
    if 'bounty_eligible_check' in result:
        print(f"Bounty check: {result['bounty_eligible_check']}")