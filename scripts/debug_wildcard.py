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

# Test the wildcard case
target = "test.api.mercadolibre.com"
print(f"Testing: {target}")

result = checker.check_target(target, require_bounty_eligible=True)
print(f"Authorized: {result['authorized']}")
print(f"Bounty Eligible: {result['bounty_eligible']}")
print(f"Normalized target: {result['normalized_target']}")
print(f"Scope check: {result['scope_check']}")

# Let's also check what wildcard patterns are loaded
print(f"Number of wildcard patterns loaded: {len(checker.wildcard_patterns)}")
print(f"First few wildcard patterns: {checker.wildcard_patterns[:5]}")

# Check if *.mercadolibre.com is in the patterns
if "*.mercadolibre.com" in checker.wildcard_patterns:
    print("*.mercadolibre.com is in wildcard patterns")
else:
    print("*.mercadolibre.com is NOT in wildcard patterns")

# Check the regex patterns
print(f"Number of wildcard regex patterns: {len(checker.wildcard_regex)}")
for i, pattern in enumerate(checker.wildcard_regex):
    if "mercadolibre.com" in checker.wildcard_patterns[i]:
        print(f"Regex pattern {i}: {checker.wildcard_patterns[i]} -> {pattern.pattern}")
        test_match = pattern.match("test.api.mercadolibre.com")
        print(f"  Matches 'test.api.mercadolibre.com': {test_match is not None}")
        if test_match:
            print(f"  Match groups: {test_match.groups()}")