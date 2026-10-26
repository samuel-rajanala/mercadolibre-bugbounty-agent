# MercadoLibre HackerOne scope export review

## Provenance

- Source: user-provided HackerOne CSV export.
- Program scope URL: https://hackerone.com/mercadolibre/policy_scopes
- Export timestamp encoded in filename: `2026-10-12 09:20:12 UTC`.
- Export contains 85 rows.
- This document describes the CSV as exported; it does not establish that the program has not changed since export.

## Summary

| Metric | Count |
|---|---:|
| Total asset rows | 85 |
| Eligible for submission | 76 |
| Not eligible for submission | 9 |
| Eligible for bounty | 71 |
| Submission eligible, but not bounty eligible | 5 |
| Critical maximum severity | 82 |
| High maximum severity | 1 |
| No maximum severity (`none`) | 2 |

### Asset types

| Type | Rows |
|---|---:|
| `URL` | 43 |
| `WILDCARD` | 27 |
| `OTHER` | 6 |
| `GOOGLE_PLAY_APP_ID` | 6 |
| `APPLE_STORE_APP_ID` | 2 |
| `HARDWARE` | 1 |

## Not eligible for submission

| Identifier | Type | Instruction |
|---|---|---|
| `*.kangu.com.br` | `WILDCARD` | Kangu |
| `developersforum` | `OTHER` | Any asset related to developersforum ; Including but not limited to:; https://developersforum.mercadolibre.com.ar/; https://developersforum.mercadolibre.com.co/; https://developersforum.mercadolibre.cl/; https://developersforum.mercadolibre.com.mx/; https://developersforum.mercadolibre.com.ve/ |
| `Redelcom` | `OTHER` | Any other asset related to redelcom |
| `*.gokangu.cl` | `WILDCARD` | Kangu |
| `*.gokangu.co` | `WILDCARD` | Kangu |
| `*.gokangu.mx` | `WILDCARD` | Kangu |
| `*.gokangu.uy` | `WILDCARD` | Kangu |
| `*.kangu.tech` | `WILDCARD` | Kangu |
| `wow-int.mercadolibre.com` | `URL` | Not specified |

## Submission eligible but not eligible for bounty

| Identifier | Type | Instruction |
|---|---|---|
| `mercadoenvios.com.ve` | `URL` | Tier 2 |
| `www.ipbooster.com` | `URL` | Not specified |
| `*.tucarro.com.ve` | `WILDCARD` | Not specified |
| `*.mercadolibre.com.ve` | `WILDCARD` | Not specified |
| `mercadolibreexperience.com.*` | `WILDCARD` | Tier 2 |

## Important interpretation notes

- `eligible_for_submission` and `eligible_for_bounty` are separate fields. Do not collapse them into a single in-scope flag.
- Nine rows are marked not eligible for submission and not eligible for bounty.
- Five rows are marked eligible for submission but not eligible for bounty. They must not be described as bounty-eligible.
- The CSV marks maximum severity per asset. It does **not** provide bounty amounts or severity-to-payment mappings.
- The three impact requirement fields (`availability_requirement`, `confidentiality_requirement`, `integrity_requirement`) are `not_defined` for 11 rows and blank for 74 rows. Blank is not the same as an explicit `not_defined` value.
- The CSV does not contain the complete program policy, testing rules, rate limits, prohibited techniques, disclosure rules, or account requirements.
- Wildcard entries must be interpreted according to the exact program policy. Do not assume wildcard coverage includes every related domain, country TLD, third-party service, or excluded asset.
- Keep active testing disabled for any asset unless the exact target is positively matched against this exported scope and all applicable program restrictions are available and satisfied.

## Missing policy material

Mark these as `NOT AVAILABLE IN PROVIDED CSV` rather than inferring them:

- Bounty reward amounts and payout conditions
- Severity rubric / CVSS requirements
- Rate limits and automation restrictions
- Vulnerability category exclusions
- Prohibited testing techniques and production safety rules
- Account, test-data, and authentication requirements
- Disclosure / coordinated disclosure requirements
- Mobile testing requirements beyond the listed app identifiers and instructions
- Rules for wildcard matching and special cases not encoded in the CSV

## Recommended agent behavior

1. Load `mercadolibre-scope.json` as the asset inventory.
2. Require exact asset-type-aware matching; treat wildcard entries as patterns only after implementing and testing a conservative matcher.
3. Deny testing if `eligible_for_submission` is false.
4. Deny bounty expectation if `eligible_for_bounty` is false, even when submission is allowed.
5. Deny active testing when restrictions are missing or target matching is ambiguous.
6. Log the matched CSV row and the eligibility fields for every proposed target.
7. Re-fetch and compare the official HackerOne scope before each new testing campaign.