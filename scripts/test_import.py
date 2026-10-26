#!/usr/bin/env python3
import sys
import os
print("Current directory:", os.getcwd())
print("Sys path:", sys.path)
print("Files in directory:", os.listdir('.'))
try:
    import scope_checker
    print("Import successful!")
    # Try to instantiate it with correct scope path
    try:
        checker = scope_checker.ScopeChecker("../scopes/mercadolibre-scope.json")
        print("ScopeChecker instantiated successfully with correct path")
    except Exception as inst_e:
        print(f"ScopeChecker instantiation failed: {inst_e}")
except Exception as e:
    print("Import failed:", e)
    # Try to load the file directly but avoid executing main
    try:
        with open('scope-checker.py', 'r') as f:
            code = f.read()
            # Remove the main execution part to avoid argument parsing
            if 'if __name__ == "__main__":' in code:
                code = code.split('if __name__ == "__main__":')[0]
            exec(code)
            print("Exec successful - checking if ScopeChecker class exists")
            if 'ScopeChecker' in locals():
                print("ScopeChecker class found in locals")
                # Try to instantiate it with correct scope path
                try:
                    checker = locals()['ScopeChecker']("../scopes/mercadolibre-scope.json")
                    print("ScopeChecker instantiated successfully with correct path")
                except Exception as inst_e:
                    print(f"ScopeChecker instantiation failed: {inst_e}")
            else:
                print("ScopeChecker class NOT found in locals")
    except Exception as e2:
        print("Exec also failed:", e2)