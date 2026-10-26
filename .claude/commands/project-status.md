# Project Status Command

Read and summarize the current state of the Mercado Libre Bug Bounty Research Agent project.

## What This Command Does

1. Reads CLAUDE.md for project instructions
2. Reads all relevant memory files to understand project state
3. Inspects current Git status and recent commits (if applicable)
4. Checks the latest phase report
5. Identifies the last completed task
6. Identifies unfinished work and blockers
7. Provides a concise session recovery summary

## Output Format

The command will output:
- Current phase and completion status
- Key accomplishments from completed phases
- Current blockers or pending authorizations
- Next priority actions
- Relevant files and their status
- Test results and verification status

## Implementation

This command is implemented by reading the following files:
- CLAUDE.md
- memory/PROJECT_STATE.md
- memory/SESSION_LOG.md (latest entries)
- memory/DECISIONS.md (recent decisions)
- memory/NEXT_STEPS.md
- memory/SECURITY_RULES.md
- memory/KNOWN_ISSUES.md
- reports/ (latest phase reports)
- scopes/ (scope files)
- scripts/authorization_gate.py (core enforcement)
- test results from test suites

The output provides a comprehensive but concise summary suitable for resuming work in a new session.