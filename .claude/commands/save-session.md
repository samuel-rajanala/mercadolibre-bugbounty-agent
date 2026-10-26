# Save Session Command

Update all memory files to record the current session state before ending a session or after completing a major task.

## What This Command Does

1. Updates PROJECT_STATE.md with current project status, completed phases, and pending work
2. Appends a dated entry to SESSION_LOG.md detailing what was done in this session
3. Records important architectural, security, and implementation decisions in DECISIONS.md
4. Updates NEXT_STEPS.md with exact next actions in priority order
5. Updates KNOWN_ISSUES.md when necessary with newly discovered issues or resolved items
6. Preserves previous session history rather than overwriting it

## What Gets Recorded

### In PROJECT_STATE.md:
- Current phase and completion status
- Project overview and key components implemented
- Completed phases with verification status
- Current status including test results and verification
- Key components implemented
- Pending work and blockers
- Security posture summary
- Next priority actions
- Last updated timestamp

### In SESSION_LOG.md:
- Session date and duration
- Work completed during the session
- Files created or modified
- Commands executed and their results
- Tests executed and their real results
- Issues discovered during the session
- Work not completed or blocked
- Exact next action from this session
- Decisions made during the session

### In DECISIONS.md:
- New architectural decisions made during the session
- New implementation decisions
- New security rule decisions or clarifications
- Each decision includes: date, description, reason, and verification/status

### In NEXT_STEPS.md:
- Updated immediate next actions in priority order
- Updated ongoing maintenance actions
- Updated contingency actions
- Updated long-term goals
- Clear priority ordering of next steps

### In KNOWN_ISSUES.md:
- Newly discovered issues or limitations
- Status updates on existing issues (resolved, ongoing, etc.)
- Newly identified audit findings
- Resolution progress on known issues
- Planned enhancements or future considerations

## When to Use This Command

- Before ending a Claude Code session
- After completing a major task or milestone
- After finishing a phase of work
- After executing significant tests or verifications
- When making important architectural or implementation decisions
- When discovering new issues or limitations
- When updating next steps based on completed work

## Implementation

This command would typically be implemented as a script that:
1. Reads current project state from various sources
2. Updates PROJECT_STATE.md with current information
3. Appends formatted session entry to SESSION_LOG.md
4. Records new decisions in DECISIONS.md
5. Updates NEXT_STEPS.md based on completed work
6. Updates KNOWN_ISSUES.md with session findings
7. Preserves all existing historical data

The actual implementation would be customized based on the specific session's activities and outcomes.