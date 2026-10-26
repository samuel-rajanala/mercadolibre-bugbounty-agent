# Payment Security Skill

## Purpose
Conduct authorized security testing of payment processing systems to identify vulnerabilities in payment state validation, transaction ownership, webhook security, and payment logic within explicitly authorized boundaries and using only sandbox/test environments.

## When to Use
- After identifying payment-related endpoints and Mercado Pago integration points
- When testing payment workflows, checkout processes, and transaction lifecycle
- To investigate payment state manipulation, refund authorization, and duplicate payment prevention
- For evaluating webhook signature validation and payment notification security
- When testing currency and amount integrity in payment transactions
- To assess payment tokenization, encryption, and sensitive data handling
- ONLY in sandbox or test environments with explicit authorization - NEVER with real funds

## Inputs
- Authorized payment endpoints and API specifications (sandbox/test versions only)
- Only explicitly authorized test credit cards, tokens, and payment instruments (sandbox/test)
- Only explicitly authorized test merchant and buyer accounts (sandbox/test)
- Payment webhook endpoints and notification URLs (only authorized test endpoints)
- Test transaction amounts that do not involve real currency movement
- Rate limiting and concurrency constraints from program policy
- Test data that is clearly marked as test/sandbox and cannot be confused with production
- Access to sandbox dashboard or test environment for transaction inspection
- Documentation of sandbox reset procedures and test data cleanup

## Outputs
- Payment state validation vulnerabilities (inconsistent states, manipulation opportunities)
- Transaction ownership verification flaws (unauthorized transaction modification or refund)
- Webhook signature validation bypass (tampering with payment notifications)
- Duplicate payment prevention failures (race conditions in payment processing)
- Refund authorization vulnerabilities (unauthorized refunds to arbitrary accounts)
- Currency and amount integrity flaws (tampering with payment amounts or currency codes)
- Payment tokenization and encryption weaknesses (exposure of sensitive payment data)
- Checkout authorization bypass (incomplete cart validation, price manipulation)
- Transaction lifecycle inconsistencies (state transitions without proper validation)
- Payment gateway misconfigurations (exposed test credentials, insecure configurations)
- Sensitive data leakage in payment responses (partial card numbers, CVV, etc.)
- All findings with reproduction steps using ONLY sandbox/test instruments
- Clear indication that testing was performed in sandbox/test environments only

## Workflow

### Phase 1: Payment Endpoint and Flow Mapping
```
- Identify all payment-related endpoints (checkout, payment processing, refunds, etc.)
- Map Mercado Pago integration points and API usage
- Document payment workflow stages (cart -> checkout -> payment -> confirmation -> delivery)
- Identify webhook endpoints for payment notifications and status updates
- Note payment tokenization, encryption, and sensitive data handling points
- Identify fee calculation, tax application, and currency conversion points
- Document refund, chargeback, and dispute processing flows
- Map session handling and state persistence throughout payment process
```

### Phase 2: Payment State Validation Testing
```
- Test for proper validation of payment states (pending, approved, rejected, refunded)
- Evaluate for state manipulation via parameter tampering or race conditions
- Check for proper authorization on state-changing operations
- Test for inconsistent state transitions (bypassing required steps)
- Evaluate for proper validation of payment completion before order fulfillment
- Test for state persistence across services and microservices
- Check for atomicity of payment state updates
- Evaluate for proper handling of concurrent state modification attempts
```

### Phase 3: Transaction Ownership and Authorization Testing
```
- Test that users can only modify or refund their own transactions
- Evaluate for proper ownership verification on refund and cancellation operations
- Check for transaction ID predictability and enumeration vulnerability
- Test for authorization bypass via transaction ID manipulation
- Evaluate for proper validation of transaction amounts and currency
- Test for modification of transaction details after payment completion
- Check for proper audit logging of transaction modifications
- Evaluate for segregation of duties in transaction processing
```

### Phase 4: Webhook and Notification Security Testing
```
- Test webhook signature validation for tampering detection
- Evaluate for proper validation of webhook timestamps and nonces
- Check for replay attack prevention in webhook processing
- Test for webhook endpoint authorization and source IP validation
- Evaluate for proper handling of duplicate webhook deliveries
- Test for webhook timeout and retry mechanisms
- Check for secure transmission of webhook payloads (HTTPS only)
- Evaluate for proper validation of webhook payload structure and content
```

### Phase 5: Currency and Amount Integrity Testing
```
- Test for proper validation of payment amounts and currency codes
- Evaluate for tampering with payment amounts (negative values, zero amounts)
- Check for proper handling of currency conversion and exchange rates
- Test for amount manipulation via parameter tampering or encoding
- Evaluate for proper rounding and precision handling in financial calculations
- Test for currency code validation and rejection of invalid currencies
- Check for proper tax calculation and application
- Evaluate for discount and coupon application integrity
```

### Phase 6: Payment Tokenization and Data Security Testing
```
- Test for proper tokenization of sensitive payment data (card numbers, CVV)
- Evaluate for exposure of partial sensitive data in logs or responses
- Check for encryption of stored payment data at rest and in transit
- Test for proper handling of PCI DSS scope reduction techniques
- Evaluate for exposure of test payment card numbers in sandbox environments
- Check for proper validation of payment tokens and cryptograms
- Test for resistance to token guessing or brute force attacks
- Evaluate for proper deletion or anonymization of test payment data
```

### Phase 7: Duplicate Payment and Race Condition Testing
```
- Test for proper prevention of duplicate payments via idempotency tokens
- Evaluate for race conditions in payment processing under concurrent requests
- Check for proper locking mechanisms during payment state transitions
- Test for payment processing consistency under high concurrency
- Evaluate for financial impact of race conditions (duplicate charges, etc.)
- Test for proper handling of interrupted or timed-out payment requests
- Check for rollback mechanisms on failed payment transactions
- Evaluate for proper idempotency key validation and reuse prevention
```

### Phase 8: Checkout and Cart Security Testing
```
- Test for proper validation of cart contents and pricing before payment
- Evaluate for price manipulation via parameter tampering or editing
- Check for proper validation of item quantities and availability
- Test for cart persistence across sessions and devices
- Evaluate for proper taxation and fee calculation on cart totals
- Test for authorization checks on cart modification operations
- Check for proper validation of coupon and discount applications
- Test for exposure of cart contents to unauthorized users
- Evaluate for proper clearing of cart data after payment completion or abandonment
```

### Phase 9: Refund and Dispute Processing Testing
```
- Test that refunds can only be issued to original payment method or account
- Evaluate for proper validation of refund amounts against original transaction
- Check for authorization requirements on refund operations (typically higher privilege)
- Test for proper handling of partial refunds and multiple refund attempts
- Evaluate for proper validation of refund reasons and documentation requirements
- Test for prevention of refund cycles or money laundering vectors
- Check for proper audit trail of refund operations and communications
- Evaluate for proper handling of disputed transactions and chargebacks
```

## Safety Requirements
- **SANDBOX/TEST ENVIRONMENTS ONLY**: Never test with real payment instruments or real funds
- **USE ONLY EXPLICITLY AUTHORIZED TEST INSTRUMENTS**: Only use provided test credit cards, tokens, and accounts
- **NO REAL FINANCIAL TRANSACTIONS**: Never initiate real payments, refunds, or transfers
- **CLEARLY MARK TEST DATA**: Ensure all test transactions are clearly labeled as test/sandbox
- **NO PRODUCTION IMPACT**: Use only sandbox instances that do not affect live payment processing
- **RESPECT RATE LIMITS**: Adhere to program-specified rate limits for payment endpoints
- **NO DESTRUCTIVE TESTING**: Do not test for financial system disruption or data corruption
- **DATA PRIVACY**: Do not collect or retain real payment card information
- **TEST ACCOUNT ISOLATION**: Ensure test merchant/buyer accounts cannot affect real accounts
- **WEBHOOK TESTING CAUTION**: Only test webhooks with explicit authorization and safe test payloads
- **THIRD-PARTY PAYMENT GATEWAY**: Verify explicit authorization before testing payment processor integrations
- **TEST ENVIRONMENT CLEANUP**: Properly clean up test data and reset sandbox state after testing
- **NO CHARGEBACK TESTING WITH REAL ACCOUNTS**: Never initiate real chargebacks or disputes

## Required Tools
- HTTP clients: curl, HTTPie, Postman (authorized sandbox/test use only)
- Payment testing tools: Only authorized sandbox/test card numbers and tokens
- JSON/JWT analysis: For examining payment tokens and webhook payloads
- Cryptographic tools: Only for authorized test data analysis (hashing, encryption checking)
- Webhook testing tools: Only for authorized test endpoints with safe payloads
- Database inspection tools: Only for authorized sandbox database access
- Log analysis tools: Only for authorized sandbox/log access
- Proxy tools: Burp Suite, OWASP ZAP (only within explicitly authorized sandbox/test scope)
- Network analysis: Only for authorized sandbox/test traffic observation
- Test data generators: Only for authorized test scenarios with clear test markings

## Output Files
- `payment/state-validation.json` - payment state validation test results
- `payment/transaction-ownership.json` - transaction ownership and authorization test results
- `payment/webhook-security.json` - webhook signature validation and notification test results
- `payment/currency-amount.json` - currency and amount integrity test results
- `payment/tokenization-data.json` - payment tokenization and sensitive data security test results
- `payment/duplicate-race.json` - duplicate payment prevention and race condition test results
- `payment/checkout-cart.json` - checkout and cart security test results
- `payment/refund-dispute.json` - refund and dispute processing test results
- `payment/reproduction-steps.md` - detailed reproduction instructions using ONLY test instruments
- `payment/impact-assessment.json` - business and technical impact analysis (test impact only)
- `logs/payment-security.log` - detailed audit trail of all payment security testing (test only)

## Integration Points
- Receives authorized payment endpoints from reconnaissance and scope validation
- Provides findings to vulnerability validation for confirmation (sandbox/test only)
- Feeds remediation skill with specific code fix recommendations for payment logic
- Updates program dashboard with payment security testing progress (test environment)
- Works with api-security skill for payment API authorization and input validation
- References authentication-audit skill for payment authentication mechanisms
- Works with authorization-audit skill for payment transaction authorization logic
- All findings clearly marked as occurring in sandbox/test environments only

## Example Usage
```
/payment-security test_state --endpoint https://api.sandbox.mercadolibre.com/payments/{id} --method PATCH
/payment-security test_ownership --endpoint https://api.sandbox.mercadolibre.com/refunds/{id} --method POST
/payment-security test_webhook --endpoint https://test.mercadolibre.com/webhooks/payment --method POST
/payment-security test_amount --param amount --value -100 --endpoint https://api.sandbox.mercadolibre.com/payments
/payment-security test_tokenization --endpoint https://api.sandbox.mercadolibre.com/cards --method POST
/payment-security test_duplicate --endpoint https://api.sandbox.mercadolibre.com/payments --method POST --concurrent
/payment-security test_checkout --endpoint https://www.sandbox.mercadolibre.com/checkout --method POST
/payment-security test_refund --endpoint https://api.sandbox.mercadolibre.com/refunds/{id} --method POST
```

## Error Conditions
- Real payment instrument detected: HALT IMMEDIATELY and use only authorized test instruments
- Production endpoint detected: HALT and request scope clarification for sandbox/test equivalents
- Real user account affected: IMMEDIATELY STOP and initiate incident response
- Rate limit exceeded: BACK OFF and respect program restrictions
- Sandbox/test account invalid: VERIFY with program administrator or reset test environment
- Unexpected payment behavior: INVESTIGATE but do not exploit without explicit authorization
- Test environment unavailable: HALT and verify sandbox/test environment status