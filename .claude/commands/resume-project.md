# Resume Project Command

Recover project context and identify the next task to continue work from where it was left off.

## What This Command Does

1. Reads CLAUDE.md for project instructions and requirements
2. Reads all relevant memory files to understand project history and state
3. Inspects the current git status and recent commits (if applicable)
4. Checks the latest phase report for completion status
5. Identifies the last completed task from session logs
6. Identifies unfinished work, blockers, and pending items
7. Provides clear guidance on the next task to work on

## Output Format

The command will output:
- Project overview and current phase status
- Summary of completed phases and their verification status
- Current project state including key accomplishments
- List of blockers or pending authorizations
- Clear next priority actions with explanations
- Relevant files to consult for detailed information
- Any critical security rules or limitations to remember

## Implementation Process

When executed, this command performs the following recovery steps:

### 1. Read Project Instructions
- Loads CLAUDE.md to understand project purpose, usage, workflow, and authorization requirements

### 2. Load Memory Files
- **PROJECT_STATE.md**: Gets current phase, completed work, pending items, and security posture
- **SESSION_LOG.md**: Reviews recent session entries to understand what was last worked on
- **DECISIONS.md**: Reviews recent decisions to understand current architectural and implementation choices
- **NEXT_STEPS.md**: Gets prioritized list of next actions
- **SECURITY_RULES.md**: Reviews permanent safety and authorization requirements
- **KNOWN_ISSUES.md**: Checks for any current limitations or issues to be aware of

### 3. Check Current State
- Reviews git status for any uncommitted changes (if applicable)
- Checks latest phase reports for completion verification
- Validates that core components are in place (authorization gate, assessment scripts, etc.)
- Confirms test suite status if recently run

### 4. Identify Recovery Point
- Determines the last completed task from session logs
- Identifies what work was in progress or blocked
- Notes any pending authorizations or approvals awaited
- Lists any issues discovered in the last session

### 5. Provide Resume Guidance
- Clear statement of current phase and completion status
- Summary of what has been accomplished and verified
- List of any blockers preventing forward progress
- Prioritized next actions with specific file references
- Security rules and limitations to keep in mind
- Suggested starting point for continuing work

## Example Output Structure

```
# Mercado Libre Bug Bounty Research Agent - Session Recovery

## Project Overview
[Brief description of project purpose and current phase]

## Completed Phases
[List of completed phases with verification status]

## Current Project State
- Key accomplishments: [list]
- Authorization gate status: [status]
- Test results: [recent test outcomes]
- Key components: [list of implemented components]

## Blockers & Pending Items
- [List of items blocking progress]
- [List of pending authorizations or approvals awaited]

## Next Priority Actions
1. [Specific action with file/reference details]
2. [Specific action with file/reference details]
3. [Specific action with file/reference details]

## Security Rules to Remember
[Key permanent security rules applicable to next work]

## Suggested Starting Point
[Specific file to examine or task to begin with]

Last Recovery: [timestamp]
```

## When to Use This Command

- At the beginning of every new Claude Code session
- When returning to the project after a break
- After reviewing session logs to understand where to continue
- When needing to orient oneself to the current project state
- Before starting work to ensure alignment with project state and decisions

## Benefits

- Eliminates need to re-explain project history and current state
- Prevents redoing already completed work
- Ensures adherence to previously made decisions and security rules
- Provides clear direction for next steps
- Maintains continuity across sessions and team members
- Reduces onboarding time for new contributors

This command enables true session persistence and project state recovery, allowing seamless continuation of work across Claude Code sessions.