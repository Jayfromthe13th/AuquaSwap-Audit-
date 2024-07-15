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

### VUL-001: Improper Owner Access Control

**Severity**: Critical  
**Likelihood**: High  
**Location**: `public fun cancel_order`

**Description**:  
The `cancel_order` function does not make any assertion that the signer is the owner of the order before being able to cancel the order and transfer assets to the caller.

**Correct Implementation**:  
```rust
assert!(order.user_address == address_of(user), ERR_PERMISSION_DENIED);

