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
**Location**: `public fun revoke_trade<BaseTokenType>`

**Description**:  
The `revoke_trade` function does not assert that the inputted `BaseTokenType` generic type matches the `base_type` `TypeInfo` stored on the `Trade` resource.

This function unlocks the liquidity for a given base token type and returns the stored amount of the token to the user:

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
An attacker could potentially drain liquidity from the AMM by placing a limit trade order and canceling the order — passing the incorrect token type.

Proof of Concept:

```rust
#[test(admin=@aquaswap, user=@0x3333)]
fun WHEN_exploit_lack_of_type_checking(admin: &signer, user: &signer) acquires TokenCapability {
    let (my_eth, trade_id) = setup_with_limit_trade(admin, user, 500000000000000);

    // let's say the admin deposits some BLU
    mint<BLU>(my_eth, address_of(admin));
    let _admin_trade_id = market::limit_trade<BLU, ETH>(admin, my_eth, 500000000000000);

    // now, let's try stealing from the admin
    assert!(token::balance<ETH>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(token::balance<BLU>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);

    market::revoke_trade<BLU>(user, trade_id); // BLU is not the right token type!

    assert!(token::balance<ETH>(address_of(user)) == 0, ERR_UNEXPECTED_BALANCE);
    assert!(token::balance<BLU>(address_of(user)) == my_eth, ERR_UNEXPECTED_BALANCE); // received BLU?
}
```

Recommendations:
Add the following type-checking assertion to the revoke_trade function:

```rust
assert!(trade.base_type == type_info::type_of<BaseTokenType>(), ERR_TRADE_WRONG_TOKEN_TYPE);

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
**Location**: `fun calculate_lp_token_amount_internal`, `fun calculate_protocol_fees`

**Description**:  
Susceptibility to overflow errors can cause denial of service in various functions.

**Proof of Concept**:
```rust
#[test(admin=@aquaswap, user=@0x3333)]
#[expected_failure(arithmetic_error, location=market)]
fun WHEN_exploit_overflow_revert(admin: &signer, user: &signer) acquires TokenCapability {
    setup_with_liquidity(admin, user);

    // add extra AQUA liquidity
    let admin_aqua = 1000000000000000;
    mint<AQUA>(admin_aqua, address_of(admin));
    market::admin_deposit_aqua(admin, admin_aqua);

    // place a reasonable order size for OCEAN
    let user_ocean = 1000000000000000;
    mint<OCEAN>(user_ocean, address_of(user));
    market::limit_swap<OCEAN, BLU>(user, user_ocean, 0);

    // inadvertently fulfill limit order
    let admin_blu = 10000;
    mint<BLU>(admin_blu, address_of(admin));
    market::add_liquidity<BLU>(admin, admin_blu);
}
```
***Spec (MP)***
``` rust
module AquaSwap::LiquidityPool {

  ///
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
    }

    spec calculate_lp_token_amount_internal(aqua_amount: u64, ocean_amount: u64) {
        aborts_if (aqua_amount == 0 || ocean_amount == 0);
        aborts_if (aqua_amount as u128) * (ocean_amount as u128) > u64::MAX as u128;
        ensures result == calculate_lp_token_amount_internal(aqua_amount, ocean_amount);
    }

    spec calculate_protocol_fees(lp_tokens: u64, fee_rate: u64) {
        aborts_if (lp_tokens == 0 || fee_rate == 0);
        aborts_if (lp_tokens as u128) * (fee_rate as u128) > u64::MAX as u128;
        ensures result == calculate_protocol_fees(lp_tokens, fee_rate);
    }
}
```

**Correct Implementation**:  
- Cast operands to `u128` before multiplication and ensure the result fits within `u64` limits to prevent overflow errors.

- Store resources within the user’s account.

