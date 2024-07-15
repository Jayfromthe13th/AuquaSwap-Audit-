# AquaSwap: Security Audit Report

## Overview

AquaSwap is a decentralized exchange (DEX) platform designed to facilitate token swaps with enhanced security and efficiency. This report outlines the findings from a comprehensive security audit conducted for AquaSwap. The audit targeted the project's smart contract suite with the objective of identifying and mitigating potential vulnerabilities, thereby strengthening the security and robustness of the project's blockchain infrastructure.

## Audit Summary

This report outlines the findings from a comprehensive security audit conducted for **AquaSwap**. The audit targeted the project's smart contract suite with the objective of identifying and mitigating potential vulnerabilities, thereby strengthening the security and robustness of the project's blockchain infrastructure.



## Vulnerabilities Overview

| ID       | Title                              | Impact                                                                                                       | Severity | Status    |
|----------|------------------------------------|--------------------------------------------------------------------------------------------------------------|----------|-----------|
| VUL-001  | Improper Owner Access Control       | Unrestricted order cancellation allows unauthorized asset transfers.                                         | Critical | Unresolved|
| VUL-002  | Absence of Generics Checking        | Malicious actor could drain all liquidity by canceling orders with incorrect coin type.                      | Critical | Unresolved|
| VUL-003  | Unbounded Execution - DOS           | Potential denial-of-service due to unbounded loops in order-related functions.                                | Critical | Unresolved|
| VUL-004  | Manipulable Price Oracle            | An attacker can manipulate token prices to drain the liquidity pool.                                          | Critical | Unresolved|
| VUL-005  | Arithmetic Precision Errors         | Users can bypass fees when performing operations due to rounding errors.                                      | Medium   | Unresolved|
| VUL-006  | No Check for Account Registration   | Failure to verify account registration could block order execution.                                           | Medium   | Unresolved|
| VUL-007  | Arithmetic Errors – Overflow        | Susceptibility to overflow errors can cause denial of service in various functions.                           | Medium   | Unresolved|

### Finding Count by Severity

- **Critical Severity**: 4
- **Medium Severity**: 3

### Critical Findings

## VUL-001: Improper Owner Access Control

**Severity**: Critical  
**Likelihood**: High  
**Location**: `public fun revoke_trade<BaseTokenType>`

**Description**:  
The `revoke_trade` function does not make any assertion that the signer is the owner of the trade before being able to cancel the trade and transfer assets to the caller.

**Affected Code**:
```rust
public fun revoke_trade<BaseTokenType>(
    user: &signer,
    trade_id: u64
) acquires TradeStore, TokenStore {
    // [...]
    transfer_tokens<BaseTokenType>(trade_store, address_of(user), trade.base_amount);
    // [...]
}
```
Impact:
An attacker could potentially drain all locked liquidity for any token type by canceling every user’s trades.

Proof of Concept:

``` rust

#[test(admin=@aquaswap, user=@0x3333)]
fun WHEN_exploit_improper_access_control(admin: &signer, user: &signer) acquires TokenCapability {
    setup_with_liquidity(admin, user);

    // let's say the admin deposits some ETH
    let my_eth = 500000000000000;
    mint<ETH>(my_eth, address_of(admin));
    let trade_id = market::limit_trade<ETH, BLU>(admin, my_eth, 500000000000000);

    // now, let's try stealing ETH from the admin
    assert!(token::balance<ETH>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(token::balance<BLU>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);

    market::revoke_trade<ETH>(user, trade_id); // trade owned by admin, but signer is user!

    assert!(token::balance<ETH>(address_of(user)) == my_eth, ERR_UNEXPECTED_BALANCE);
    assert!(token::balance<BLU>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE); // received BLU?
}

```
Correct Implementation:

```rust
assert!(trade.user_address == address_of(user), ERR_PERMISSION_DENIED);
```
## VUL-002: Absence of Generics Checking

**Severity**: Critical  
**Likelihood**: High  
**Location**: `public fun cancel_order`

**Description**:  
The `cancel_order` function does not assert that the generic type `BaseCoinType` matches the `base_type` stored in the `Order` resource. This enables a malicious actor to drain all liquidity by canceling orders with incorrect coin types.

**Correct Implementation**:  
```rust
assert!(order.base_type == type_info::type_of<BaseCoinType>(), ERR_ORDER_WRONG_COIN_TYPE);
```

## VUL-003: Unbounded Execution - DOS

**Severity**: Critical  
**Likelihood**: High  
**Location**: `get_order_by_id`, `cancel_order`, `fulfill_order`

**Description**:  
These functions can lead to unbounded execution because they iterate over potentially large lists. An attacker could exploit this by registering a large number of orders, causing the functions to block and leading to denial-of-service (DOS).

**Correct Implementation**:
- Avoid looping over every order.
- Limit the number of iterations each loop can perform.
- Structure fees to incentivize users to fulfill each other’s orders.

## VUL-004: Manipulable Price Oracle

**Severity**: Critical  
**Likelihood**: High  
**Location**: `fun get_price_internal`

**Description**:  
The contract uses the ratio of the liquidity sizes of the tokens to determine the value of the liquidity token. This can be manipulated by an attacker to drain the pool.

**Correct Implementation**:  
Use an external price oracle that provides reliable and tamper-resistant price data. Additionally, augment internal price calculations with checks against the external oracle.

## VUL-005: Arithmetic Precision Errors

**Severity**: Medium  
**Likelihood**: High  
**Location**: `public fun calculate_protocol_fees`

**Description**:  
The `calculate_protocol_fees` function rounds down to zero for small order sizes, allowing users to bypass fees.

**Correct Implementation**:  
Ensure the order size is greater than the minimum amount and set protocol fees to an amount greater than zero.

## VUL-006: No Check for Account Registration

**Severity**: Medium  
**Likelihood**: High  
**Location**: `public fun limit_swap<BaseCoinType, QuoteCoinType>`

**Description**:  
The `execute_limit_order` function fails to verify if the recipient account is registered to receive the quote coin, potentially blocking order execution.

**Correct Implementation**:  
```rust
coin::register<BaseCoinType>(user);
coin::register<QuoteCoinType>(user);
```

## VUL-007: Arithmetic Errors – Overflow

**Severity**: Medium  
**Likelihood**: Medium  
**Location**: `fun calculate_lp_coin_amount_internal`, `fun calculate_protocol_fees`

**Description**:  
Susceptibility to overflow errors can cause denial of service in various functions.

**Correct Implementation**:  
Cast operands to `u128` before multiplication and ensure the result fits within `u64` limits to prevent overflow errors.


**Correct Implementation**:  
Store resources within the user’s account.

