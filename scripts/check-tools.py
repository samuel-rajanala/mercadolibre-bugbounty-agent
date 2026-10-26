#!/usr/bin/env python3
"""
Tool Checker for Mercado Libre Bug Bounty Research Agent
Checks availability of security tools mentioned in the project requirements.
"""

import subprocess
import sys
import os


def check_tool_direct(tool_name, test_command, version_flag="--version"):
    """
    Check if a tool is available using direct command path.

    Args:
        tool_name: Name of the tool to check
        test_command: Full path to the tool executable
        version_flag: Flag to get version information

    Returns:
        Tuple of (available, version_string_or_error)
    """
    try:
        # Try to run the tool with version flag
        result = subprocess.run(
            [test_command, version_flag],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Extract version from stdout or stderr
            version_output = result.stdout.strip() or result.stderr.strip()
            # Take first line if multiple lines
            version_lines = version_output.split('\n')
            version = version_lines[0] if version_lines else "Unknown version"
            return True, version
        else:
            # Tool exists but version command failed
            return False, f"Tool found but version check failed: {result.stderr.strip()}"

    except FileNotFoundError:
        return False, "Tool not found or not executable"
    except subprocess.TimeoutExpired:
        return False, "Tool timeout on version check"
    except Exception as e:
        return False, f"Error checking tool: {str(e)}"


def check_tool_path(tool_name, version_flag="--version"):
    """
    Check if a tool is available in PATH.

    Args:
        tool_name: Name of the tool to check
        version_flag: Flag to get version information

    Returns:
        Tuple of (available, version_string_or_error)
    """
    try:
        # Try to run the tool with version flag
        result = subprocess.run(
            [tool_name, version_flag],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Extract version from stdout or stderr
            version_output = result.stdout.strip() or result.stderr.strip()
            # Take first line if multiple lines
            version_lines = version_output.split('\n')
            version = version_lines[0] if version_lines else "Unknown version"
            return True, version
        else:
            # Tool exists but version command failed
            return False, f"Tool found but version check failed: {result.stderr.strip()}"

    except FileNotFoundError:
        return False, "Tool not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "Tool timeout on version check"
    except Exception as e:
        return False, f"Error checking tool: {str(e)}"


def main():
    """Main function to check all required tools."""
    print("=" * 60)
    print("Mercado Libre Bug Bounty Research Agent - Tool Check")
    print("=" * 60)
    print()

    # Python 3 path we know works
    python3_path = "/c/Users/srstu/AppData/Local/Programs/Python/Python312/python.exe"

    # List of tools to check as specified in the mission
    # Format: (tool_name, test_command_or_none_for_PATH, version_flag)
    tools_to_check = [
        ("Semgrep", None, "--version"),
        ("Gitleaks", None, "--version"),
        ("Nuclei", None, "--version"),
        ("Subfinder", None, "--version"),
        ("HTTPX", None, "--version"),
        ("Katana", None, "--version"),
        ("OWASP ZAP", None, "-version"),  # ZAP uses different version flag
        ("FFUF", None, "--version"),
        ("OWASP Dependency-Check", None, "--version"),
        ("Trivy", None, "--version"),
        ("CodeQL", None, "--version"),
        ("Python 3", python3_path, "--version"),  # Use direct path
        ("curl", None, "--version"),
        ("grep", None, "--version"),
        ("awk", None, "--version"),
        ("sed", None, "--version"),
    ]

    available_tools = []
    unavailable_tools = []

    print("Checking tool availability...")
    print("-" * 60)

    for tool_info in tools_to_check:
        tool_name = tool_info[0]
        test_command = tool_info[1]
        version_flag = tool_info[2] if len(tool_info) > 2 else "--version"

        if test_command is None:
            # Check via PATH
            available, version_info = check_tool_path(tool_name, version_flag)
        else:
            # Check via direct path
            available, version_info = check_tool_direct(tool_name, test_command, version_flag)

        if available:
            available_tools.append((tool_name, version_info))
            status = "[PASS]"
        else:
            unavailable_tools.append((tool_name, version_info))
            status = "[FAIL]"

        print(f"{tool_name:<25} {status:<10} {version_info}")

    print("-" * 60)
    print()

    print(f"Summary: {len(available_tools)} available, {len(unavailable_tools)} unavailable")
    print()

    if available_tools:
        print("Available Tools:")
        for tool, version in available_tools:
            print(f"  • {tool}: {version}")
        print()

    if unavailable_tools:
        print("Unavailable Tools:")
        for tool, reason in unavailable_tools:
            print(f"  • {tool}: {reason}")
        print()

    # Provide recommendations
    print("Recommendations:")
    if unavailable_tools:
        print("  Consider installing unavailable tools if authorized and needed for your testing.")
        print("  Some tools may have alternative names or installation methods.")
    else:
        print("  All required tools are available! You're ready to begin security research.")
    print()

    # Save results to file for the dashboard
    results = {
        "check_timestamp": subprocess.run(["date"], capture_output=True, text=True).stdout.strip(),
        "available_tools": [{"name": name, "version": version} for name, version in available_tools],
        "unavailable_tools": [{"name": name, "reason": reason} for name, reason in unavailable_tools],
        "total_checked": len(tools_to_check),
        "total_available": len(available_tools),
        "total_unavailable": len(unavailable_tools)
    }

    # Create directory if it doesn't exist
    os.makedirs("../logs", exist_ok=True)

    # Save as JSON for potential use by dashboard
    import json
    with open("../logs/tools-check.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"Detailed results saved to: logs/tools-check.json")


if __name__ == "__main__":
    main()