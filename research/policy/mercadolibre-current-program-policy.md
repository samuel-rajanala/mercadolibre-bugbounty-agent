# Mercado Libre HackerOne Bug Bounty Program - Current Policy Status

## Policy Retrieval Attempt
- **Retrieval Date**: 2026-10-15
- **Official Sources Attempted**:
  1. https://hackerone.com/mercadolibre
  2. https://hackerone.com/mercadolibre/policy_scopes
- **Retrieval Method**: Automated HTTP GET via WebFetch tool
- **Result**: Both URLs returned only the header "HackerOne" without any policy details

## Policy Accessibility Assessment
**Limitation Identified**: The Mercado Libre HackerOne program policy content is dynamically loaded via JavaScript and cannot be accessed through automated HTTP requests without JavaScript execution capability.

**Evidence from Project Documentation**:
- PROJECT_STATE.md (2026-10-14): "Detailed policy content requires JavaScript execution and cannot be accessed via automated tools"
- README.md: "The HackerOne platform loads its policy content dynamically via JavaScript, which cannot be executed in this environment to extract the detailed policy information"
- Multiple references to "NOT AVAILABLE IN PROVIDED CSV" for critical policy sections

## Available Policy Components
Despite the inability to retrieve the complete policy via automated means, the following components are available through alternative means:

### 1. Program Identification (Retrieved)
- **Program Name**: MercadoLibre Bug Bounty Program
- **Platform**: HackerOne
- **Description**: "The MercadoLibre Bug Bounty Program enlists the help of the hacker community at HackerOne to make MercadoLibre more secure. HackerOne is the #1 hacker-powered security platform, helping organizations find and fix critical vulnerabilities before they can be criminally exploited."
- **Source**: Retrieved via automated fetch (header information)
- **Retrieval Date**: 2026-10-12 (per scope files)

### 2. Scope Information (Available via CSV Export)
The following scope data was obtained through an official CSV export from the HackerOne platform:

#### In-Scope Assets
- Mobile Applications: com.mercadopago.wallet, com.mercadopago.MercadoPago, com.mercadolibre, com.3mosquitos.MercadoLibre, com.mercadoenvios.driver, com.mercadoenvios.crowdsourcing, com.mercadolibre.android.mplay_tv
- Domains and Subdomains: *.adminml.com, *.mercadolibre.cl, *.mercadolibre.com, *.mercadolibre.com.ar, *.mercadolibre.com.co, *.mercadolibre.com.mx, *.mercadolibre.com.pe, *.mercadolibre.com.uy, *.mercadolivre.com.br, *.mercadopago.cl, *.mercadopago.com, *.mercadopago.com.ar, *.mercadopago.com.br, *.mercadopago.com.co, *.mercadopago.com.mx, *.mercadopago.com.pe, *.mercadopago.com.uy, *.mlstatic.com
- API Endpoints: api.mercadopago.com, api.mercadolibre.com, logistica.redelcom.cl, and numerous regional variants
- Other Assets: Point Smart, Crypto, Leaked Credentials, Tier 3, Wonder, biolibre domains, meliplay domains, mercadoplay domains, portal inmobiliario domains, tucarro domains, tumoto domain, furycloud.io, furydocs.io, sustentabilidadmercadolibre.com/, mercadoenvios.com.ve, mercadopago.com.ve, mpago.li, mpago.la, mercadobackoffice.com, www.ipbooster.com
- Sources: scopes/verified-scope.json, scopes/mercadolibre-scope.json, scopes/program-policy.md

#### Out-of-Scope Assets
- *.kangu.com.br
- developersforum
- Redelcom
- *.gokangu.cl, *.gokangu.co, *.gokangu.mx, *.gokangu.uy
- *.kangu.tech
- wow-int.mercadolibre.com
- Source: scopes/verified-scope.json

#### Submission Eligibility vs Bounty Eligibility
From the CSV export metadata:
- Total records: 85
- Submission eligible count: 76
- Bounty eligible count: 71
- Not submission eligible count: 9
- Submission eligible not bounty count: 5
- Source: scopes/verified-scope.json metadata

## Missing Policy Components
The following policy components are **NOT AVAILABLE** through the CSV export and remain inaccessible via automated retrieval:

### Explicitly UNKNOWN (Not Specified in Available Sources)
1. **Vulnerability Categories**
   - Accepted vulnerability categories
   - Excluded vulnerability categories
   - Special consideration vulnerability categories
   - Out-of-scope vulnerability categories

2. **Program Rules and Restrictions**
   - Testing restrictions and limitations
   - Rate limits and request frequency restrictions
   - Automation restrictions and permissive techniques
   - Account and credential requirements
   - Disclosure and confidentiality requirements
   - Coordinated disclosure requirements and timelines
   - Reward structure (bounty amounts, payout conditions, severity rubric)
   - CVSS requirements and severity classification mapping
   - Duplicate report policy and handling procedures
   - Special conditions and program-specific requirements
   - Safe harbor provisions and protections

3. **Authorization Details**
   - Specific vulnerability categories permitted for testing
   - Authorized testing techniques and HTTP methods
   - Payment testing environment authorization (sandbox/test only)
   - Account requirements (explicitly provided test accounts/credentials)

## Policy Comparison Analysis
### Compared to scopes/verified-scope.json
- **Matches**: Scope information (in-scope/out-of-scope/assets, eligibility status)
- **Missing**: All rule and restriction sections, vulnerability categories, reward structure

### Compared to scopes/authorization-gate.json
*(File would need to be checked if exists)*
- Authorization gate requires complete policy for configuration
- Currently operating with incomplete policy data

## Status Assessment
**Current Policy Status**: PARTIALLY AVAILABLE
- Available: Program identification, scope information, eligibility data
- Missing: All regulatory and operational policy components required for authorization decisions

**Authorization Readiness**: NOT ACHIEVED
- External authorization cannot be granted without complete policy
- Human approval cannot be informed without complete policy
- Validation testing cannot proceed without explicit policy authorization

## Recommendations
1. **Manual Retrieval Required**: Human review of https://hackerone.com/mercadolibre and https://hackerone.com/mercadolibre/policy_scopes via JavaScript-enabled browser
2. **Policy Documentation**: Complete policy should be manually copied and added to the project
3. **Regular Updates**: Establish process for periodic policy review and updates
4. **Authorization Workflow**: Once complete policy is obtained, proceed with external authorization request

## Verification Notes
All information preserved exactly as retrieved from available sources.
No inferences made about missing sections.
All unavailable sections explicitly marked as UNKNOWN.
Retrieval limitations documented per instructions.