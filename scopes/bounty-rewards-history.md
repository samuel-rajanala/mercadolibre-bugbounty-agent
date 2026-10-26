# Mercado Libre HackerOne Bounty Rewards - Historical Data

## Source Information
- **Source:** Uploaded HackerOne bounty table (HackerOne.pdf)
- **Historical Version:** 2026-05-07T17:36:21.015Z
- **Data Type:** Historical bounty reward values
- **Status:** Historical reference only - not current reward structure

## Historical Bounty Reward Table
Extracted exactly from the source document:

| Category / Tier | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|
| Tier 3 | $75 | $200 | $750 | $1,000 |
| RCE | — | — | — | $8,000–$15,000 |
| Tier 2 | $100 | $350 | $3,500–$4,450 | $4,500–$5,000 |
| ATO | — | — | $8,000–$10,000 | $10,000–$15,000 |
| Tier 1 | $200 | $500 | $7,000–$8,900 | $9,000–$10,000 |

## Important Notes
1. **Historical Data Only**: This table represents reward values from 2026-05-07 and may not reflect the current bounty structure.
2. **No Permission Implication**: Reward eligibility does not constitute authorization to test. All testing requires explicit external program authorization AND human approval.
3. **No Tier Mapping**: Do not infer how scope asset tiers map to these reward tiers.
4. **Separate from Policy**: This historical data is kept separate from the current program policy and authorization gate configuration.
5. **Exact Values Preserved**: Missing values are represented as "—" exactly as in the source - no values have been invented or inferred.
6. **Authorization Required**: The authorization gate remains fail-closed (DENY by default) regardless of reward values.

## Relationship to Current Program
- This file is strictly for historical reference
- Current bounty amounts (if any) must be obtained from the official HackerOne program policy
- Authorization decisions are based on current policy, not historical reward data
- No modifications to authorization-gate.json or related security controls should be made based on this historical data