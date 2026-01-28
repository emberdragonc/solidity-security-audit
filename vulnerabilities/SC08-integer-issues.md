# SC08: Integer Overflow/Underflow

**Severity:** High  
**Mitigated in Solidity 0.8+**

## Description

Integer overflow occurs when a number exceeds its maximum value and wraps around. Underflow is the opposite - going below zero wraps to max value. Solidity 0.8+ has built-in protection, but unchecked blocks and older contracts remain vulnerable.

## Versions

| Solidity Version | Protection |
|------------------|------------|
| < 0.8.0 | None - must use SafeMath |
| >= 0.8.0 | Automatic checks (reverts) |
| 0.8+ with `unchecked` | No checks (intentional) |

## Vulnerable Patterns

### 1. Pre-0.8 Without SafeMath
```solidity
// VULNERABLE (Solidity < 0.8)
pragma solidity ^0.7.0;

function transfer(address to, uint256 amount) public {
    balances[msg.sender] -= amount;  // Underflow if amount > balance
    balances[to] += amount;          // Overflow if balance too high
}

// FIXED - use SafeMath
import "@openzeppelin/contracts/math/SafeMath.sol";
using SafeMath for uint256;

function transfer(address to, uint256 amount) public {
    balances[msg.sender] = balances[msg.sender].sub(amount);
    balances[to] = balances[to].add(amount);
}
```

### 2. Unsafe Unchecked Blocks (0.8+)
```solidity
// POTENTIALLY VULNERABLE - unchecked arithmetic
pragma solidity ^0.8.0;

function iterate(uint256 n) public {
    unchecked {
        for (uint256 i = 0; i < n; i++) {
            // What if n is type(uint256).max?
        }
    }
}

function unsafeDecrement(uint256 x) public pure returns (uint256) {
    unchecked {
        return x - 1;  // Underflows if x == 0
    }
}
```

### 3. Type Casting Issues
```solidity
// VULNERABLE - downcasting without checks
function unsafeCast(uint256 value) public pure returns (uint128) {
    return uint128(value);  // Truncates if value > type(uint128).max
}

// FIXED - check before casting
function safeCast(uint256 value) public pure returns (uint128) {
    require(value <= type(uint128).max, "Overflow");
    return uint128(value);
}

// BEST - use OpenZeppelin SafeCast
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
using SafeCast for uint256;

function safeCast(uint256 value) public pure returns (uint128) {
    return value.toUint128();  // Reverts on overflow
}
```

### 4. Multiplication Before Division
```solidity
// VULNERABLE - can overflow before division helps
function badCalculation(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
    return a * b / c;  // a * b might overflow even if result fits
}

// FIXED - use mulDiv
import "@openzeppelin/contracts/utils/math/Math.sol";

function safeCalculation(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
    return Math.mulDiv(a, b, c);  // Handles full 256-bit intermediate
}
```

## Detection

### Slither Detectors
- Not applicable for 0.8+ (built-in protection)
- For < 0.8: manual review for SafeMath usage

### Manual Checks
1. What Solidity version?
2. Any `unchecked` blocks?
3. Type casting without validation?
4. Multiplication overflow before division?

## Remediation

### 1. Use Solidity 0.8+
```solidity
pragma solidity ^0.8.20;  // Built-in overflow protection
```

### 2. SafeMath for Older Contracts
```solidity
pragma solidity ^0.7.0;
import "@openzeppelin/contracts/math/SafeMath.sol";
using SafeMath for uint256;
```

### 3. Careful with Unchecked
```solidity
// Only use unchecked when you KNOW overflow is impossible
unchecked {
    // Example: loop counter that can't realistically overflow
    for (uint256 i = 0; i < 100; ++i) {
        // 100 iterations can't overflow uint256
    }
}
```

### 4. Use SafeCast for Type Conversion
```solidity
using SafeCast for uint256;
uint128 smallValue = bigValue.toUint128();  // Reverts if too big
```

## Real-World Exploits

- **BeautyChain (2018):** $900M in "value" - Integer overflow in batchTransfer
- **PoWH Coin (2018):** $800K - Underflow exploit
- **SMT Token (2018):** Unlimited minting via overflow
